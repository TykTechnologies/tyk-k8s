package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/TykTechnologies/tyk-k8s/logger"
	"github.com/TykTechnologies/tyk-k8s/tyk"
	"github.com/TykTechnologies/tyk/certs"
	"github.com/cloudflare/cfssl/api/client"
	"github.com/cloudflare/cfssl/auth"
	"github.com/cloudflare/cfssl/csr"
	"github.com/globalsign/mgo"
	uuid "github.com/satori/go.uuid"
	"gopkg.in/mgo.v2/bson"
	"io/ioutil"
	"time"
)

var log = logger.GetLogger("tyk-ca")

const (
	CACol string = "k8s_ca"
)

type Config struct {
	Addr              string          `yaml:"addr"`
	Key               string          `yaml:"key"`
	DefaultNames      []csr.Name      `yaml:"defaultNames"`
	DefaultKeyRequest *csr.KeyRequest `yaml:"defaultKeyRequest"`
	MongoConnStr      string          `yaml:"mongoConnStr"`
	CertPath          string          `yaml:"certPath"`
	Secure            bool
	SkipCACheck       bool
}

type CertClient interface {
	GenerateCert(string) (*Bundle, error)
	StoreCert(*CertModel) (*CertModel, error)
	GetCertByFingerprint(string) (*CertModel, error)
	GetServerCertByLinkedAPIID(string) (*CertModel, error)
	GetStore() *mgo.Session
}

type Client struct {
	CA        *Config
	storeInit bool
	storeSess *mgo.Session
	caCert    []byte
}

type APICertSignRequest struct {
	Hostname string `json:"hostname"`
	CSR      string `json:"certificate_request"`
}

type Bundle struct {
	PrivateKey  []byte
	Certificate []byte
	Bundled     []byte
	Fingerprint string // Hash of cert for identification
}

type CertModel struct {
	MID             bson.ObjectId `bson:"_id"`
	UID             string
	Bundle          *Bundle
	BundleHistory   []Bundle // On renewal, move bundle here
	Created         time.Time
	Expires         time.Time
	ClientEgressIDs []string // If cert is used as a client cert, IDs of APIs it is attached to
	ServiceID       string   // If cert is used as a server cert, ID of API it belongs to
	IsMeshCert      bool
}

func (b *Bundle) Combine() []byte {
	var x []byte = make([]byte, len(b.PrivateKey)+len(b.Certificate))
	x = append(x, b.PrivateKey...)
	x = append(x, b.Certificate...)

	return x
}

func New(cfg *Config) (*Client, error) {
	c := &Client{
		CA: cfg,
	}

	log.Info(cfg)
	if cfg.CertPath == "" {
		return nil, fmt.Errorf("root CA certificate is required for bundling")
	}

	f, err := ioutil.ReadFile(cfg.CertPath)
	if err != nil {
		return nil, err
	}

	c.caCert = f

	err = c.initStorage()
	if err != nil {
		return nil, err
	}

	return c, nil
}

func (c *Client) GetStore() *mgo.Session {
	return c.storeSess
}

func (c *Client) getAuthenticatedClient() (*client.AuthRemote, error) {
	var tlsOptions *tls.Config
	if c.CA.Secure {
		tlsOptions = &tls.Config{
			InsecureSkipVerify: c.CA.SkipCACheck,
		}
	}

	pr, err := auth.New(c.CA.Key, nil)
	if err != nil {
		return nil, err
	}

	return client.NewAuthServer(c.CA.Addr, tlsOptions, pr), nil

}

func (c *Client) prepareRequest() *csr.CertificateRequest {
	req := csr.New()

	req.Names = c.CA.DefaultNames
	if c.CA.DefaultNames == nil {
		req.Names = []csr.Name{
			{
				C:  "GB",
				L:  "London",
				O:  "Tyk Technologies Ltd.",
				OU: "Default Services",
				ST: "England",
			},
		}
	}

	req.KeyRequest = c.CA.DefaultKeyRequest
	if c.CA.DefaultKeyRequest == nil {
		req.KeyRequest = csr.NewKeyRequest()
	}

	// set expiry
	req.CA.Expiry = time.Now().Add((time.Hour * 24) * 30).String()
	return req
}

func (c *Client) GenerateCert(CN string) (*Bundle, error) {
	if CN == "" {
		return nil, fmt.Errorf("hostname can't be empty")
	}

	// Prepare a default request
	req := c.prepareRequest()
	req.Hosts = []string{CN}
	req.CN = CN

	// API Client for CFSSL
	rem, err := c.getAuthenticatedClient()
	if err != nil {
		return nil, err
	}

	// Create a signer (private key) for the CSR
	priv, err := req.KeyRequest.Generate()
	if err != nil {
		return nil, err
	}

	// Create the actual CSR block
	csrReq, err := csr.Generate(priv.(crypto.Signer), req)
	if err != nil {
		return nil, err
	}

	x := APICertSignRequest{
		Hostname: CN,
		CSR:      string(csrReq),
	}

	asJS, err := json.Marshal(&x)
	if err != nil {
		return nil, err
	}

	cert, err := rem.Sign(asJS)
	if err != nil {
		return nil, err
	}

	// We need the private key in PEM format for Tyk
	pKey, err := c.getPrivateKeyAsPem(priv, req.KeyRequest)
	if err != nil {
		return nil, err
	}

	bundled := make([]byte, 0)
	bundled = append(bundled, cert...)
	bundled = append(bundled, c.caCert...)

	cpb, _ := pem.Decode(bundled)
	cObj, e := x509.ParseCertificate(cpb.Bytes)
	if e != nil {
		return nil, e
	}

	var certSHA string
	certSHA = certs.HexSHA256(cObj.Raw)

	return &Bundle{PrivateKey: pKey, Certificate: cert, Fingerprint: certSHA, Bundled: bundled}, nil
}

func (c *Client) getPrivateKeyAsPem(pKey crypto.PrivateKey, kr *csr.KeyRequest) ([]byte, error) {
	switch kr.Algo() {
	case "rsa":
		pemData := pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(pKey.(*rsa.PrivateKey)),
			},
		)

		return pemData, nil

	case "ecdsa":
		marshalled, err := x509.MarshalECPrivateKey(pKey.(*ecdsa.PrivateKey))
		if err != nil {
			return nil, err
		}
		pemData := pem.EncodeToMemory(
			&pem.Block{
				Type:  "EC PRIVATE KEY",
				Bytes: marshalled,
			},
		)

		return pemData, nil

	}
	return nil, errors.New("format not supported")
}

func (c *Client) initStorage() error {
	sess, err := mgo.Dial(c.CA.MongoConnStr)
	if err != nil {
		return err
	}

	c.storeInit = true
	c.storeSess = sess
	return nil
}

func (c *Client) StoreCert(cert *CertModel) (*CertModel, error) {
	m := c.storeSess.Clone()
	defer m.Close()
	if cert.MID.Hex() == "" {
		cert.MID = bson.NewObjectId()
	}

	return cert, m.DB("").C(CACol).Insert(cert)
}

func (c *Client) GetCertByFingerprint(fp string) (*CertModel, error) {
	m := c.storeSess.Clone()
	defer m.Close()

	cert := &CertModel{}
	err := m.DB("").C(CACol).Find(bson.M{"Bundle.Fingerprint": fp}).One(cert)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func (c *Client) GetServerCertByLinkedAPIID(serviceID string) (*CertModel, error) {
	m := c.storeSess.Clone()
	defer m.Close()

	cert := &CertModel{}
	err := m.DB("").C(CACol).Find(bson.M{"ServiceID": serviceID}).One(cert)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func (c *Client) GetOrCreateMeshCertID() (string, error) {
	m := c.storeSess.Clone()
	foundCerts := make([]*CertModel, 0)
	err := m.DB("").C(CACol).Find(
		bson.M{
			"IsMeshCert": true,
			"Expires": bson.M{
				"$gt": time.Now(),
			},
		}).Sort("-Expires").All(&foundCerts)
	if err != nil {
		return "", err
	}

	if len(foundCerts) > 0 {
		// return the last expiring cert
		return foundCerts[0].Bundle.Fingerprint, nil
	}

	// no cert, let's make one
	bdl, err := c.GenerateCert("mesh")
	if err != nil {
		return "", err
	}

	// Store it
	id, err := tyk.CreateCertificate(bdl.Certificate, bdl.PrivateKey)
	if err != nil {
		return "", err
	}
	newModel := NewCertModel(bdl)
	newModel.Bundle.Fingerprint = id
	newModel.IsMeshCert = true

	cm, err := c.StoreCert(newModel)
	if err != nil {
		return "", err
	}

	return cm.Bundle.Fingerprint, nil

}

func NewCertModel(bundle *Bundle) *CertModel {
	c := &CertModel{}
	c.Bundle = bundle
	c.BundleHistory = make([]Bundle, 0)
	c.Created = time.Now()
	c.UID = uuid.NewV4().String()

	cpb, _ := pem.Decode(bundle.Certificate)
	cObj, e := x509.ParseCertificate(cpb.Bytes)
	if e != nil {
		log.Fatal("failed to generate certificate model: ", e)
	}

	c.Expires = cObj.NotAfter
	return c
}

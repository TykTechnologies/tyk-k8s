package cert_rotate

import (
	"fmt"
	"github.com/TykTechnologies/tyk-k8s/ca"
	"github.com/TykTechnologies/tyk-k8s/logger"
	"github.com/TykTechnologies/tyk-k8s/tyk"
	"github.com/globalsign/mgo"
	"github.com/globalsign/mgo/bson"
	"time"
)

var log = logger.GetLogger("tyk-ca-rotate")

type Manager struct {
	stopCh    chan struct{}
	storeSess *mgo.Session
	ca        ca.CertClient
	ticker    *time.Ticker
}

func New(session *mgo.Session) (*Manager, error) {
	if session == nil {
		return nil, fmt.Errorf("session canot be nil")
	}

	return &Manager{
		storeSess: session,
		stopCh:    make(chan struct{}),
		ticker:    time.NewTicker(24 * time.Hour)}, nil
}

func (m *Manager) StartCheckLoop() {
	go func() {
		for {
			select {
			case <-m.stopCh:
				return
			case <-m.ticker.C:
				certs, err := m.getExpiringCerts()
				if err != nil {
					log.Error(err)
					continue
				}

				err = m.processExpiringCertificates(certs)
				if err != nil {
					log.Error(err)
					continue
				}
			}
		}
	}()
}

func (m *Manager) StopCheckLoop() {
	m.ticker.Stop()
	m.stopCh <- struct{}{}
}

func (m *Manager) getExpiringCerts() ([]*ca.CertModel, error) {
	s := m.storeSess.Clone()
	defer s.Close()

	certs := make([]*ca.CertModel, 0)
	daysFromNow := time.Now().Add(15 * (24 * time.Hour))
	err := s.DB("").C(ca.CACol).Find(bson.M{"Bundle.Expires": bson.M{"$lte": daysFromNow}}).All(certs)
	if err != nil {
		return nil, err
	}

	return certs, nil
}

func (m *Manager) processExpiringCertificates(expCerts []*ca.CertModel) error {
	for _, c := range expCerts {
		// Fetch the API from Tyk
		svc, err := tyk.GetByObjectID(c.ServiceID)
		if err != nil {
			log.Errorf("failed to get api def: %s from DB, skipping, err was: %v", c.ServiceID, err)
			continue
		}

		// Generate a new certificate for it's service
		newBdl, err := m.ca.GenerateCert(svc.Domain)
		if err != nil {
			log.Errorf("failed to create cert for id: %s and CN: %s, err was: %v", c.ServiceID, svc.Domain, err)
			continue
		}

		// Upload it to the certificate store and get it's fingerprint ID
		certID, err := tyk.CreateCertificate(newBdl.Certificate, newBdl.PrivateKey)
		if err != nil {
			log.Errorf("failed to add new cert to cert store for %s, err: %v", c.ServiceID, err)
			continue
		}

		// Update the ID so that we always have the canonical fingerprint
		newBdl.Fingerprint = certID

		// FInd the old certificate to replace
		indexToReplace := -1
		for i, oldID := range svc.Certificates {
			if oldID == c.Bundle.Fingerprint {
				indexToReplace = i
			}
		}

		// replace the ID and update the API in Tyk
		svc.Certificates[indexToReplace] = certID
		err = tyk.UpdateAPI(&svc.APIDefinition)
		if err != nil {
			log.Errorf("failed to update certificate ID for service: %s, err: %v", svc.Domain, err)
			continue
		}
	}

	return nil
}

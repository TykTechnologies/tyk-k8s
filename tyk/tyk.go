package tyk

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/TykTechnologies/tyk/apidef"
	"path"
	"regexp"
	"strings"
	"text/template"

	"github.com/TykTechnologies/tyk-sync/clients/dashboard"
	"github.com/TykTechnologies/tyk-sync/clients/gateway"
	"github.com/TykTechnologies/tyk-sync/clients/interfaces"
	"github.com/TykTechnologies/tyk-sync/clients/objects"
	"github.com/TykTechnologies/tyk-k8s/logger"
	"github.com/TykTechnologies/tyk-k8s/processor"
	"github.com/satori/go.uuid"
	"github.com/spf13/viper"
)

func cleanSlug(s string) string {
	r, _ := regexp.Compile("[^a-zA-Z0-9-_/.]")
	s = r.ReplaceAllString(s, "")
	r2, _ := regexp.Compile("(//+)")
	s = r2.ReplaceAllString(s, "")
	//trim ends:
	s = strings.Trim(s, "/")

	if len(s) == 0 {
		s = "0"
	}
	return s
}

type TykConf struct {
	URL                string `yaml:"url"`
	Secret             string `yaml:"secret"`
	Org                string `yaml:"org"`
	Templates          string `yaml:"templates"`
	IsGateway          bool   `yaml:"is_gateway"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	IsHybrid           bool   `yaml:"is_hybrid"`
}

type APIDefOptions struct {
	Name          string
	Target        string
	ListenPath    string
	TemplateName  string
	Hostname      string
	Slug          string
	Tags          []string
	APIID         string
	ID            string
	LegacyAPIDef  *objects.DBApiDefinition
	Annotations   map[string]string
	CertificateID []string
}

var cfg *TykConf
var log = logger.GetLogger("tyk-api")
var templates *template.Template
var defaultIngressTemplates *template.Template

const (
	DefaultIngressTemplate = "default"
	DefaultMeshTemplate    = "default-mesh"
	DefaultInboundTemplate = "default-inbound"
	TemplateNameKey        = "template.service.tyk.io"
)

func Init(forceConf *TykConf) {
	defaultIngressTemplates = template.Must(template.New("default").Parse(apiTemplates))

	if forceConf != nil {
		cfg = forceConf
	}

	if cfg == nil {
		cfg = &TykConf{}
		err := viper.UnmarshalKey("Tyk", cfg)
		if err != nil {
			log.Fatalf("failed to load config: %v", err)
		}
	}

	if cfg.Templates != "" {
		log.Info("template directory detected, loading from ", cfg.Templates)
		templates = template.Must(template.ParseGlob(path.Join(cfg.Templates, "*.json")))
	}

	if cfg.InsecureSkipVerify {
		log.Warning("TLS is not being validated, please ensure certificates are valid")
	}

}

func newClient() interfaces.UniversalClient {
	var cl interfaces.UniversalClient
	var err error

	cl, err = dashboard.NewDashboardClient(cfg.URL, cfg.Secret)
	if cfg.IsGateway {
		cl, err = gateway.NewGatewayClient(cfg.URL, cfg.Secret)
	}

	if err != nil {
		log.Fatalf("failed to create tyk API client: %v", err)
	}

	if cfg.InsecureSkipVerify {
		log.Warn("TLS certificate will not be verified")
		cl.SetInsecureTLS(cfg.InsecureSkipVerify)
	}

	return cl
}

func getTemplate(name string) (*template.Template, error) {
	if cfg.Templates == "" {
		log.Warning("using default template")
		return defaultIngressTemplates, nil
	}

	if templates == nil {
		return defaultIngressTemplates, errors.New("no templates loaded")
	}

	tpl := templates.Lookup(name)
	if tpl == nil {
		return defaultIngressTemplates, errors.New("template not found")
	}

	return tpl, nil

}

func TemplateService(opts *APIDefOptions) ([]byte, error) {
	if opts.TemplateName == "" {
		opts.TemplateName = DefaultIngressTemplate
	}

	defTpl, err := getTemplate(opts.TemplateName)
	if err != nil {
		return nil, err
	}
	// In hybrid gateway we want slug to be a human readable path - not the Ingress ID
	if cfg.IsHybrid {
		opts.Slug = opts.ListenPath
	} else {
		opts.Slug = cleanSlug(opts.Slug)
	}

	tplVars := map[string]interface{}{
		"Name":          opts.Name,
		"Slug":          opts.Slug,
		"Org":           cfg.Org,
		"ListenPath":    opts.ListenPath,
		"Target":        opts.Target,
		"GatewayTags":   opts.Tags,
		"HostName":      opts.Hostname,
		"CertificateID": opts.CertificateID,
	}

	var apiDefStr bytes.Buffer
	err = defTpl.Execute(&apiDefStr, tplVars)
	if err != nil {
		return nil, err
	}

	return apiDefStr.Bytes(), nil
}

func CreateCertificate(crt, key []byte) (string, error) {
	cl := newClient()
	combined := make([]byte, 0)
	combined = append(combined, crt...)
	combined = append(combined, key...)

	id, err := cl.CreateCertificate(combined)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "id already exists") {
			rx := regexp.MustCompile("([a-f0-9]{10,})")
			items := rx.FindAllString(err.Error(), 1)
			if len(items) != 1 {
				return "", errors.New("could not extract existing ID")
			}

			return items[0], nil
		}

		return "", err
	}

	return id, nil
}

func CreateService(opts *APIDefOptions) (string, error) {
	adBytes, err := TemplateService(opts)
	if err != nil {
		return "", err
	}

	postProcessedDef := string(adBytes)
	log.Debug(postProcessedDef)
	if opts.Annotations != nil {
		postProcessedDef, err = processor.Process(opts.Annotations, string(adBytes))
		if err != nil {
			return "", err
		}
	}

	apiDef := objects.NewDefinition()
	err = json.Unmarshal([]byte(postProcessedDef), apiDef)
	if err != nil {
		return "", err
	}

	cl := newClient()

	// IDs are not generated by the GW
	_, isGW := cl.(*gateway.Client)
	if isGW {
		log.Warning("setting new API ID for gateway")
		apiDef.APIID = uuid.NewV4().String()
	}

	return cl.CreateAPI(apiDef)

}

func DeleteBySlug(slug string) error {
	cl := newClient()

	allServices, err := cl.FetchAPIs()
	if err != nil {
		return err
	}

	cSlug := cleanSlug(slug)
	for _, s := range allServices {
		if cSlug == s.Slug {
			log.Warning("found API entry, deleting: ", s.Id.Hex())
			return cl.DeleteAPI(cl.GetActiveID(&s.APIDefinition))
		}
	}

	return fmt.Errorf("service with name %s not found for removal, remove manually", slug)
}

func UpdateAPIs(svcs map[string]*APIDefOptions) error {
	cl := newClient()

	allServices, err := cl.FetchAPIs()
	if err != nil {
		return err
	}

	errs := make([]error, 0)
	toUpdate := map[string]*APIDefOptions{}
	toCreate := map[string]*APIDefOptions{}

	// To update
	for ingressID, o := range svcs {
		cSlug := cleanSlug(ingressID)
		for _, s := range allServices {
			if cSlug == s.Slug {
				o.LegacyAPIDef = &s
				toUpdate[cSlug] = o
			}
		}
	}

	// To create
	for ingressID, o := range svcs {
		cSlug := cleanSlug(ingressID)
		_, updatingAlready := toUpdate[cSlug]
		if updatingAlready {
			// skip
			continue
		}

		toCreate[cSlug] = o
	}

	for _, opts := range toUpdate {
		adBytes, err := TemplateService(opts)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		apiDef := objects.NewDefinition()
		err = json.Unmarshal(adBytes, apiDef)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		// Retain identity
		apiDef.Id = opts.LegacyAPIDef.Id
		apiDef.APIID = opts.LegacyAPIDef.APIID
		apiDef.OrgID = opts.LegacyAPIDef.OrgID

		err = cl.UpdateAPI(apiDef)
		if err != nil {
			errs = append(errs, err)
			continue
		}

	}

	for _, opts := range toCreate {
		id, err := CreateService(opts)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		log.Info("created: ", id)
	}

	if len(errs) > 0 {
		msg := ""
		for i, e := range errs {
			if i != 0 {
				msg = e.Error()
			}
			msg += "; " + msg
		}

		return fmt.Errorf(msg)
	}

	return nil

}

func GetBySlug(slug string) (*objects.DBApiDefinition, error) {
	cl := newClient()

	allServices, err := cl.FetchAPIs()
	if err != nil {
		return nil, err
	}

	cSlug := cleanSlug(slug)
	for _, s := range allServices {
		if cSlug == s.Slug {
			return &s, nil
		}
	}

	return nil, fmt.Errorf("service with name %s not found", slug)
}

func DeleteByID(id string) error {
	cl := newClient()
	return cl.DeleteAPI(id)
}

func GetByObjectID(id string) (*objects.DBApiDefinition, error) {
	cl := newClient()

	allServices, err := cl.FetchAPIs()
	if err != nil {
		return nil, err
	}

	for _, s := range allServices {
		if id == s.Id.Hex() {
			return &s, nil
		}
	}

	return nil, fmt.Errorf("service with id %s not found", id)
}

func UpdateAPI(def *apidef.APIDefinition) error {
	cl := newClient()
	return cl.UpdateAPI(def)
}

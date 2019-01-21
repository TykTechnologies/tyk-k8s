package tyk

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/TykTechnologies/tyk-git/clients/dashboard"
	"github.com/TykTechnologies/tyk-git/clients/objects"
	"github.com/TykTechnologies/tyk-k8s/logger"
	"github.com/spf13/viper"
	"regexp"
	"strings"
	"text/template"
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
	URL    string `yaml:"url"`
	Secret string `yaml:"secret"`
	OrgID  string `yaml:"org_id"`
}

var cfg *TykConf
var log = logger.GetLogger("tyk-api")

const (
	DefaultTemplate = "default"
)

func Init() {
	if cfg == nil {
		cfg = &TykConf{}
		err := viper.UnmarshalKey("Tyk", cfg)
		if err != nil {
			log.Fatalf("failed to load config: %v", err)
		}
	}

}

func newClient() *dashboard.Client {
	cl, err := dashboard.NewDashboardClient(cfg.URL, cfg.Secret)
	if err != nil {
		log.Fatalf("failed to create tyk dashboard client: %v", err)
	}

	return cl
}

func getTemplate(name string) (string, error) {
	return "", errors.New("not implemented")
}

func CreateService(name, target, listenPath, templateName, hostname, slug string, tags []string) (string, error) {
	defTpl := defaultAPITemplate
	if templateName != DefaultTemplate {
		var err error
		defTpl, err = getTemplate(templateName)
		if err != nil {
			return "", err
		}
	}

	tplVars := map[string]interface{}{
		"Name":        name,
		"Slug":        cleanSlug(slug),
		"OrgID":       cfg.OrgID,
		"ListenPath":  listenPath,
		"Target":      target,
		"GatewayTags": tags,
		"HostName":    hostname,
	}

	var apiDefStr bytes.Buffer
	tpl := template.Must(template.New("inject").Parse(defTpl))
	err := tpl.Execute(&apiDefStr, tplVars)
	if err != nil {
		return "", err
	}

	//log.Warning(apiDefStr.String())

	apiDef := objects.NewDefinition()
	err = json.Unmarshal(apiDefStr.Bytes(), apiDef)
	if err != nil {
		return "", err
	}

	cl := newClient()

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
			return cl.DeleteAPI(s.Id.Hex())
		}
	}

	return fmt.Errorf("service with name %s not found for removal, remove manually", slug)
}

func GetBySlug(slug string) (*dashboard.DBApiDefinition, error) {
	cl := newClient()

	allServices, err := cl.FetchAPIs()
	if err != nil {
		return nil, err
	}

	cSlug := cleanSlug(slug)
	for _, s := range allServices {
		if cSlug == s.Slug {
			log.Warning("found API entry, deleting: ", s.Id.Hex())
			return &s, nil
		}
	}

	return nil, fmt.Errorf("service with name %s not found", slug)
}

var defaultAPITemplate = `
{
    "name": "{{.Name}}{{ range $i, $e := .GatewayTags }} #{{$e}}{{ end }}",
	"slug": "{{.Slug}}",
    "org_id": "{{.OrgID}}",
    "use_keyless": true,
    "definition": {
        "location": "header",
        "key": "x-api-version",
        "strip_path": true
    },
    "version_data": {
        "not_versioned": true,
        "versions": {
            "Default": {
                "name": "Default",
                "use_extended_paths": true,
				"paths": {
                    "ignored": [],
                    "white_list": [],
                    "black_list": []
                }
            }
        }
    },
    "proxy": {
        "listen_path": "{{.ListenPath}}",
        "target_url": "{{.Target}}",
        "strip_listen_path": true
    },
	"domain": "{{.HostName}}",
	"response_processors": [],
	 "custom_middleware": {
        "pre": [],
        "post": [],
        "post_key_auth": [],
        "auth_check": {
            "name": "",
            "path": "",
            "require_session": false
        },
        "response": [],
        "driver": "",
        "id_extractor": {
            "extract_from": "",
            "extract_with": "",
            "extractor_config": {}
        }
    },
	"config_data": {},
	"allowed_ips": [],
    "disable_rate_limit": true,
    "disable_quota": true,
    "cache_options": {
        "cache_timeout": 60,
        "enable_cache": true
    },
    "active": true,
    "tags": [{{ range $i, $e := .GatewayTags }}{{ if $i }},{{ end }}"{{ $e }}"{{ end }}],
    "enable_context_vars": true
}
`

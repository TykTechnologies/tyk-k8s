package injector

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/TykTechnologies/tyk-git/clients/dashboard"
	"github.com/TykTechnologies/tyk-git/clients/objects"
	"github.com/golang/glog"
	"github.com/spf13/viper"
	"text/template"
)

type TykConf struct {
	URL    string `yaml:"url"`
	Secret string `yaml:"secret"`
	OrgID  string `yaml:"org_id"`
}

var cfg *TykConf

const (
	DefaultTemplate = "default"
)

func newClient() *dashboard.Client {
	if cfg == nil {
		err := viper.UnmarshalKey("Tyk", cfg)
		if err != nil {
			glog.Fatalf("failed to load config: %v", err)
		}
	}

	cl, err := dashboard.NewDashboardClient(cfg.URL, cfg.Secret)
	if err != nil {
		glog.Fatalf("failed to create tyk dashboard client: %v", err)
	}

	return cl
}

func getTemplate(name string) (string, error) {
	return "", errors.New("not implemented")
}

func CreateService(name, target, listenPath, templateName, hostname string, tags []string) (string, error) {
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

	apiDef := objects.NewDefinition()
	err = json.Unmarshal(apiDefStr.Bytes(), apiDef)
	if err != nil {
		return "", err
	}

	cl := newClient()

	return cl.CreateAPI(apiDef)

}

var defaultAPITemplate = `
{
    "name": "{{.Name}} #{{.GatewayTag}}",
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
            }
        }
    },
    "proxy": {
        "listen_path": "{{.ListenPath}}",
        "target_url": "{{.Target}}",
        "strip_listen_path": true,
    },
	"domain": "{{.HostName}}",
    "disable_rate_limit": true,
    "disable_quota": true,
    "cache_options": {
        "cache_timeout": 60,
        "enable_cache": true,
    },
    "active": true,
    "tags": [{{ range $i, $e := .GatewayTag }}{{ if $i }},{{ end }}{{ $e }}{{ end }}],
    "enable_context_vars": true,
}
`

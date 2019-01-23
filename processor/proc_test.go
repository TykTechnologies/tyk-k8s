package processor

import (
	"encoding/json"
	"github.com/TykTechnologies/tyk/apidef"
	"testing"
)

var js = `
{
    "name": "MyGateway #myTag",
	"slug": "mygateway",
    "org_id": "1",
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
        "listen_path": "/",
        "target_url": "http://app.service:1234",
        "strip_listen_path": true
    },
	"domain": "",
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
    "tags": ["ingress"],
    "enable_context_vars": true
}
`

func TestProc(t *testing.T) {
	testAnnotations := map[string]string{
		"service.tyk.io/bool/use_keyless":                                    "false",
		"service.tyk.io/string/proxy.target_url":                             "http://foo.bar/bazington",
		"service.tyk.io/num/cache_options.cache_timeout":                     "20",
		"service.tyk.io/object/version_data.versions.Default.extended_paths": `{"hard_timeouts":[{"path":"{all}","method":"GET","timeout":60,"fromDashboard":true}]}`,
	}

	def, err := Process(testAnnotations, js)
	if err != nil {
		t.Fatal(err)
	}

	asDefObj := &apidef.APIDefinition{}
	err = json.Unmarshal([]byte(def), asDefObj)
	if err != nil {
		t.Fatal(err)
	}

	if asDefObj.UseKeylessAccess != false {
		t.Fatal("bool not set")
	}

	if asDefObj.Proxy.TargetURL != "http://foo.bar/bazington" {
		t.Fatal("string not set")
	}

	if asDefObj.CacheOptions.CacheTimeout != 20 {
		t.Fatal("num not set")
	}

	if asDefObj.VersionData.Versions["Default"].ExtendedPaths.HardTimeouts[0].Path != "{all}" {
		t.Fatal("object not set")
	}

}

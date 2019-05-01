package ingress

import (
	"encoding/json"
	"fmt"
	"github.com/TykTechnologies/tyk-git/clients/objects"
	"github.com/TykTechnologies/tyk-k8s/tyk"
	"io/ioutil"
	"k8s.io/api/extensions/v1beta1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"net/http"
	"testing"
)

var lastResponse = ""
var running = false

func serverSetup() {
	if running {
		return
	}

	type resp struct {
		Echo   string
		Status string
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			panic(err)
		}

		lastResponse = string(body)

		d := &resp{
			Echo:   string(body),
			Status: "OK",
		}

		js, _ := json.Marshal(d)

		fmt.Fprintf(w, string(js))
	})

	running = true
	http.ListenAndServe(":9696", nil)
	running = false
}

func TestControlServer_getAPIName(t *testing.T) {
	x := NewController()
	n := x.getAPIName("foo", "bar")
	if n != "foo:bar" {
		t.Fatal("expected 'foo:bar' got ", n)
	}
}

func TestControlServer_doAdd(t *testing.T) {
	go serverSetup()
	x := NewController()
	ing := &v1beta1.Ingress{
		ObjectMeta: v1.ObjectMeta{
			Name:      "foo-name",
			Namespace: "bar-namespace",
			Annotations: map[string]string{
				IngressAnnotation: IngressAnnotationValue,
			},
		},
		Spec: v1beta1.IngressSpec{
			Rules: []v1beta1.IngressRule{
				{
					Host: "foo.com",
					IngressRuleValue: v1beta1.IngressRuleValue{
						HTTP: &v1beta1.HTTPIngressRuleValue{
							Paths: []v1beta1.HTTPIngressPath{
								{
									Path: "/",
									Backend: v1beta1.IngressBackend{
										ServiceName: "foo-service",
										ServicePort: intstr.IntOrString{IntVal: 80, StrVal: "80"},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	tykConf := &tyk.TykConf{}
	tykConf.URL = "http://localhost:9696"
	tykConf.Secret = "foo"

	tyk.Init(tykConf)

	err := x.doAdd(ing)
	if err != nil {
		t.Fatal(err)
	}

	def := &objects.DBApiDefinition{}
	err = json.Unmarshal([]byte(lastResponse), def)
	if err != nil {
		t.Fatal(err)
	}

	exp := "foo-name:foo-service #ingress"
	if def.Name != exp {
		t.Fatal("api name should be ", exp, ", got: ", def.Name)
	}

	if def.UseStandardAuth {
		t.Fatal("default template is open, using standard auth")
	}
	lastResponse = ""
}

func TestControlServer_doAddWithCustomTemplate(t *testing.T) {
	go serverSetup()
	x := NewController()
	ing := &v1beta1.Ingress{
		ObjectMeta: v1.ObjectMeta{
			Name:      "foo-auth-name",
			Namespace: "bar-namespace",
			Annotations: map[string]string{
				IngressAnnotation:   IngressAnnotationValue,
				tyk.TemplateNameKey: "tokenAuth",
			},
		},
		Spec: v1beta1.IngressSpec{
			Rules: []v1beta1.IngressRule{
				{
					Host: "foo.com",
					IngressRuleValue: v1beta1.IngressRuleValue{
						HTTP: &v1beta1.HTTPIngressRuleValue{
							Paths: []v1beta1.HTTPIngressPath{
								{
									Path: "/",
									Backend: v1beta1.IngressBackend{
										ServiceName: "foo-service",
										ServicePort: intstr.IntOrString{IntVal: 80, StrVal: "80"},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	tykConf := &tyk.TykConf{}
	tykConf.URL = "http://localhost:9696"
	tykConf.Secret = "foo"
	tykConf.Templates = "../templates"

	tyk.Init(tykConf)

	err := x.doAdd(ing)
	if err != nil {
		t.Fatal(err)
	}

	def := &objects.DBApiDefinition{}
	err = json.Unmarshal([]byte(lastResponse), def)
	if err != nil {
		t.Fatal(err)
	}

	exp := "foo-auth-name:foo-service #ingress"
	if def.Name != exp {
		t.Fatal("api name should be ", exp, ", got: ", def.Name)
	}

	if !def.UseStandardAuth {
		t.Fatal("custom template uses standard auth, this API is open")
	}

	if def.VersionDefinition.Key != "x-api-version-foo" {
		t.Fatal("version location should be custom, got ", def.VersionDefinition.Key)
	}

	lastResponse = ""
}

package injector

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http/httptest"
	"testing"

	"github.com/TykTechnologies/tyk-k8s/_test_util"
	"github.com/TykTechnologies/tyk-k8s/ca"
	"github.com/TykTechnologies/tyk-k8s/tyk"
	"github.com/ghodss/yaml"
)

func TestWebhookServer_Serve(t *testing.T) {
	cfg := &Config{}
	if err := yaml.Unmarshal([]byte(testCfg), cfg); err != nil {
		t.Fatal(err)
	}

	if len(cfg.Containers) != 1 {
		t.Fatalf("yaml should contain at least one container, got %v", len(cfg.Containers))
	}

	whs := WebhookServer{
		SidecarConfig: cfg,
	}

	svr := _test_util.DashServerMock{}
	svr.Start(":8989")
	defer svr.Stop()

	scenarios := []struct {
		Payload      string
		ResponseCode int
		IsPatched    bool
		Operations   int
	}{
		{
			AdmissionReviewJson,
			200,
			true,
			2,
		},
		{
			AdmissionReviewJsonSkip,
			200,
			false,
			0,
		},
		{
			AdmissionReviewJsonNoInject,
			200,
			false,
			0,
		},
	}

	for _, sc := range scenarios {
		req := httptest.NewRequest("POST", "http://localhost:9797/inject", bytes.NewReader([]byte(sc.Payload)))
		req.Header.Add("Content-Type", "application/json")
		rec := httptest.NewRecorder()

		whs.SidecarConfig.CreateRoutes = true
		whs.SidecarConfig.EnableMeshTLS = true
		whs.CAClient = &ca.Mock{}
		tyk.Init(&tyk.TykConf{
			URL:       "http://localhost:8989",
			Secret:    "foo",
			Org:       "1",
			IsGateway: false,
		})

		whs.Serve(rec, req)

		if rec.Code != sc.ResponseCode {
			t.Fatalf("expected code %v got %v", 200, rec.Code)
		}

		body, err := ioutil.ReadAll(rec.Body)
		if err != nil {
			t.Fatal(err)
		}

		var resp map[string]interface{}
		err = json.Unmarshal(body, &resp)
		if err != nil {
			t.Fatal(err)
		}

		responseSec, ok := resp["response"]
		if !ok {
			t.Fatalf("no response section in response obect: %v", string(body))
		}

		patch, ok := responseSec.(map[string]interface{})["patch"]
		if ok != sc.IsPatched {
			t.Fatalf("expected patch section: %v, got section %v, payload: %v", sc.IsPatched, ok, string(body))
		}

		if sc.IsPatched {
			pStr := patch.(string)

			sDec, _ := base64.StdEncoding.DecodeString(pStr)

			type jsonPatch struct {
				Op    string `json:"op"`
				Path  string `json:"path"`
				Value string `json:"value"`
			}
			patchArr := make([]jsonPatch, 0)

			err = json.Unmarshal(sDec, &patchArr)

			if len(patchArr) != sc.Operations {
				t.Fatalf("not enough patch operations in response: %v", string(sDec))
			}
		}

	}
}

var testCfg = `
containers:
- name: sidecar-nginx
  image: nginx:1.12.2
  imagePullPolicy: IfNotPresent
  ports:
  - containerPort: 80
initContainers:
- image: centos
  imagePullPolicy: Always
  name: run-iptables
  securityContext:
    privileged: true
  command:
  - "sh"
  - "-c"
  - 'yum -y install iptables; iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to-destination 127.0.0.1:8080; iptables -t nat -A OUTPUT -p tcp --dport 6767 -j DNAT --to-destination 127.0.0.1:80'
`

var AdmissionReviewJson = `
{
  "kind": "AdmissionReview",
  "apiVersion": "admission.k8s.io/v1beta1",
  "request": {
    "uid": "0df28fbd-5f5f-11e8-bc74-36e6bb280816",
    "kind": {
      "group": "",
      "version": "v1",
      "kind": "Pod"
    },
    "resource": {
      "group": "",
      "version": "v1",
      "resource": "pods"
    },
    "namespace": "dummy",
    "operation": "CREATE",
    "userInfo": {
      "username": "system:serviceaccount:kube-system:replicaset-controller",
      "uid": "a7e0ab33-5f29-11e8-8a3c-36e6bb280816",
      "groups": [
        "system:serviceaccounts",
        "system:serviceaccounts:kube-system",
        "system:authenticated"
      ]
    },
    "object": {
      "metadata": {
        "generateName": "service-deployment-12345-",
        "creationTimestamp": null,
        "labels": {
          "app": "my-service",
          "pod-template-hash": "2710681425"
        },
        "annotations": {
          "injector.tyk.io/inject": "true"
        },
        "ownerReferences": [
          {
            "apiVersion": "extensions/v1beta1",
            "kind": "ReplicaSet",
            "name": "service-deployment-12345",
            "uid": "16c2b355-5f5d-11e8-ac91-36e6bb280816",
            "blockOwnerDeletion": true
          }
        ]
      },
      "spec": {
        "volumes": [
          {
            "name": "default-token-tq5lq",
            "secret": {
              "secretName": "default-token-tq5lq"
            }
          }
        ],
        "containers": [
          {
            "name": "nginx",
            "image": "nginx:1.7.9",
            "ports": [
              {
                "containerPort": 80,
                "protocol": "TCP"
              }
            ],
            "resources": {},
            "volumeMounts": [
              {
                "name": "default-token-tq5lq",
                "readOnly": true,
                "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount"
              }
            ],
            "terminationMessagePath": "/dev/termination-log",
            "terminationMessagePolicy": "File",
            "imagePullPolicy": "IfNotPresent",
            "securityContext": {
              "capabilities": {
                "drop": [
                  "KILL",
                  "MKNOD",
                  "SETGID",
                  "SETUID"
                ]
              },
              "runAsUser": 1000080000
            }
          }
        ],
        "restartPolicy": "Always",
        "terminationGracePeriodSeconds": 30,
        "dnsPolicy": "ClusterFirst",
        "serviceAccountName": "default",
        "serviceAccount": "default",
        "securityContext": {
          "seLinuxOptions": {
            "level": "s0:c9,c4"
          },
          "fsGroup": 1000080000
        },
        "imagePullSecrets": [
          {
            "name": "default-dockercfg-kksdv"
          }
        ],
        "schedulerName": "default-scheduler"
      },
      "status": {}
    },
    "oldObject": null
  }
}
`

var AdmissionReviewJsonNoInject = `
{
  "kind": "AdmissionReview",
  "apiVersion": "admission.k8s.io/v1beta1",
  "request": {
    "uid": "0df28fbd-5f5f-11e8-bc74-36e6bb280816",
    "kind": {
      "group": "",
      "version": "v1",
      "kind": "Pod"
    },
    "resource": {
      "group": "",
      "version": "v1",
      "resource": "pods"
    },
    "namespace": "dummy",
    "operation": "CREATE",
    "userInfo": {
      "username": "system:serviceaccount:kube-system:replicaset-controller",
      "uid": "a7e0ab33-5f29-11e8-8a3c-36e6bb280816",
      "groups": [
        "system:serviceaccounts",
        "system:serviceaccounts:kube-system",
        "system:authenticated"
      ]
    },
    "object": {
      "metadata": {
        "generateName": "service-deployment-12345-",
        "creationTimestamp": null,
        "labels": {
          "app": "my-service",
          "pod-template-hash": "2710681425"
        },
        "annotations": {
          "foo.bar.baz/quz": "banana"
        },
        "ownerReferences": [
          {
            "apiVersion": "extensions/v1beta1",
            "kind": "ReplicaSet",
            "name": "service-deployment-12345",
            "uid": "16c2b355-5f5d-11e8-ac91-36e6bb280816",
            "blockOwnerDeletion": true
          }
        ]
      },
      "spec": {
        "volumes": [
          {
            "name": "default-token-tq5lq",
            "secret": {
              "secretName": "default-token-tq5lq"
            }
          }
        ],
        "containers": [
          {
            "name": "nginx",
            "image": "nginx:1.7.9",
            "ports": [
              {
                "containerPort": 80,
                "protocol": "TCP"
              }
            ],
            "resources": {},
            "volumeMounts": [
              {
                "name": "default-token-tq5lq",
                "readOnly": true,
                "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount"
              }
            ],
            "terminationMessagePath": "/dev/termination-log",
            "terminationMessagePolicy": "File",
            "imagePullPolicy": "IfNotPresent",
            "securityContext": {
              "capabilities": {
                "drop": [
                  "KILL",
                  "MKNOD",
                  "SETGID",
                  "SETUID"
                ]
              },
              "runAsUser": 1000080000
            }
          }
        ],
        "restartPolicy": "Always",
        "terminationGracePeriodSeconds": 30,
        "dnsPolicy": "ClusterFirst",
        "serviceAccountName": "default",
        "serviceAccount": "default",
        "securityContext": {
          "seLinuxOptions": {
            "level": "s0:c9,c4"
          },
          "fsGroup": 1000080000
        },
        "imagePullSecrets": [
          {
            "name": "default-dockercfg-kksdv"
          }
        ],
        "schedulerName": "default-scheduler"
      },
      "status": {}
    },
    "oldObject": null
  }
}
`

var AdmissionReviewJsonSkip = `
{
  "kind": "AdmissionReview",
  "apiVersion": "admission.k8s.io/v1beta1",
  "request": {
    "uid": "0df28fbd-5f5f-11e8-bc74-36e6bb280816",
    "kind": {
      "group": "",
      "version": "v1",
      "kind": "Pod"
    },
    "resource": {
      "group": "",
      "version": "v1",
      "resource": "pods"
    },
    "namespace": "dummy",
    "operation": "CREATE",
    "userInfo": {
      "username": "system:serviceaccount:kube-system:replicaset-controller",
      "uid": "a7e0ab33-5f29-11e8-8a3c-36e6bb280816",
      "groups": [
        "system:serviceaccounts",
        "system:serviceaccounts:kube-system",
        "system:authenticated"
      ]
    },
    "object": {
      "metadata": {
        "generateName": "service-deployment-12345-",
        "creationTimestamp": null,
        "labels": {
          "app": "my-service",
          "pod-template-hash": "2710681425"
        },
        "annotations": {
          "injector.tyk.io/status":"injected"
        },
        "ownerReferences": [
          {
            "apiVersion": "extensions/v1beta1",
            "kind": "ReplicaSet",
            "name": "service-deployment-12345",
            "uid": "16c2b355-5f5d-11e8-ac91-36e6bb280816",
            "blockOwnerDeletion": true
          }
        ]
      },
      "spec": {
        "volumes": [
          {
            "name": "default-token-tq5lq",
            "secret": {
              "secretName": "default-token-tq5lq"
            }
          }
        ],
        "containers": [
          {
            "name": "nginx",
            "image": "nginx:1.7.9",
            "ports": [
              {
                "containerPort": 80,
                "protocol": "TCP"
              }
            ],
            "resources": {},
            "volumeMounts": [
              {
                "name": "default-token-tq5lq",
                "readOnly": true,
                "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount"
              }
            ],
            "terminationMessagePath": "/dev/termination-log",
            "terminationMessagePolicy": "File",
            "imagePullPolicy": "IfNotPresent",
            "securityContext": {
              "capabilities": {
                "drop": [
                  "KILL",
                  "MKNOD",
                  "SETGID",
                  "SETUID"
                ]
              },
              "runAsUser": 1000080000
            }
          }
        ],
        "restartPolicy": "Always",
        "terminationGracePeriodSeconds": 30,
        "dnsPolicy": "ClusterFirst",
        "serviceAccountName": "default",
        "serviceAccount": "default",
        "securityContext": {
          "seLinuxOptions": {
            "level": "s0:c9,c4"
          },
          "fsGroup": 1000080000
        },
        "imagePullSecrets": [
          {
            "name": "default-dockercfg-kksdv"
          }
        ],
        "schedulerName": "default-scheduler"
      },
      "status": {}
    },
    "oldObject": null
  }
}
`

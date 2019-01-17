package ingress

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"github.com/TykTechnologies/tyk-k8s/logger"
	"github.com/TykTechnologies/tyk-k8s/tyk"
	"k8s.io/api/core/v1"
	"k8s.io/api/extensions/v1beta1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"
)

type Config struct{}

var ctrl *ControlServer
var log = logger.GetLogger("ingress")
var opLog = sync.Map{}

const (
	IngressAnnotation      = "kubernetes.io/ingress.class"
	IngressAnnotationValue = "tyk"
)

type ControlServer struct {
	cfg        *Config
	client     *kubernetes.Clientset
	store      cache.Store
	controller cache.Controller
	stopCh     chan struct{}
}

func NewController() *ControlServer {
	if ctrl == nil {
		ctrl = &ControlServer{}
	}

	return ctrl
}

func Controller() *ControlServer {
	if ctrl == nil {
		return NewController()
	}

	return ctrl
}

func (c *ControlServer) getClient() (*kubernetes.Clientset, error) {
	cfgF := os.Getenv("TYK_K8S_KUBECONF")
	var config *rest.Config
	var err error

	if cfgF != "" {
		config, err = clientcmd.BuildConfigFromFlags("", cfgF)
	} else {
		config, err = rest.InClusterConfig()
	}

	// in cluster access
	if err != nil {
		return nil, err
	}

	return kubernetes.NewForConfig(config)
}

func (c *ControlServer) Start() error {
	var err error
	c.client, err = c.getClient()
	if err != nil {
		return err
	}

	c.watchIngresses()
	return nil
}

func (c *ControlServer) Stop() error {
	if c.stopCh == nil {
		return fmt.Errorf("not started")
	}

	select {
	case c.stopCh <- struct{}{}:
		return nil
	case <-time.After(1 * time.Second):
		return fmt.Errorf("failed to stop after timeout")
	}
}

func getAPIName(name, service string) string {
	v := fmt.Sprintf("%s:%s", name, service)
	log.Info("service name is: ", v)
	return v
}

func generateIngressID(ingressName, ns string, p v1beta1.HTTPIngressPath) string {
	serviceFQDN := fmt.Sprintf("%s.%s.%s/%s", ingressName, ns, p.Backend.ServiceName, p.Path)
	hasher := sha1.New()
	hasher.Write([]byte(serviceFQDN))
	sha := base64.URLEncoding.EncodeToString(hasher.Sum(nil))

	return sha
}

func doAdd(ing *v1beta1.Ingress) error {
	tags := []string{"ingress"}
	hName := ""
	if len(ing.Spec.Rules) > 0 {
		r0 := ing.Spec.Rules[0]
		hName = r0.Host

		for _, p := range r0.HTTP.Paths {
			listenOn := p.Path
			svcN := p.Backend.ServiceName
			svcP := p.Backend.ServicePort.IntVal
			serviceName := getAPIName(ing.Name, svcN)
			target := fmt.Sprintf("http://%s.%s:%d", svcN, ing.Namespace, svcP)
			ingressID := generateIngressID(ing.Name, ing.Namespace, p)

			_, ok := opLog.Load("add" + ingressID)
			if ok {
				log.Info("ingress already processed")
				continue
			}

			_, err := tyk.CreateService(serviceName, target, listenOn, tyk.DefaultTemplate, hName, ingressID, tags)
			if err != nil {
				log.Error(err)
			} else {
				// remember we processed this
				opLog.Store("add-"+ingressID, struct{}{})
			}
		}
	}

	return nil
}

func (c *ControlServer) handleIngressAdd(obj interface{}) {
	ing, ok := obj.(*v1beta1.Ingress)
	if !ok {
		log.Errorf("type not allowed: %v", reflect.TypeOf(obj))
		return
	}

	if !c.checkIngressManaged(ing) {
		return
	}

	err := doAdd(ing)
	if err != nil {
		log.Error(err)
	}
}

func (c *ControlServer) handleIngressUpdate(oldObj interface{}, newObj interface{}) {
	oldIng, ok := oldObj.(*v1beta1.Ingress)
	if !ok {
		log.Errorf("type not allowed: %v", reflect.TypeOf(oldIng))
		return
	}

	if !c.checkIngressManaged(oldIng) {
		return
	}

	newIng, ok := newObj.(*v1beta1.Ingress)
	if !ok {
		log.Errorf("type not allowed: %v", reflect.TypeOf(newIng))
		return
	}

	if !c.checkIngressManaged(newIng) {
		return
	}

	if !c.ingressChanged(oldIng, newIng) {
		return
	}

	err := c.doDelete(oldIng)
	if err != nil {
		log.Error(err)
	}

	err = doAdd(newIng)
	if err != nil {
		log.Error(err)
	}

}

func (c *ControlServer) ingressChanged(old *v1beta1.Ingress, new *v1beta1.Ingress) bool {
	if len(new.Spec.Rules) > 0 {
		r0 := new.Spec.Rules[0]
		hName := r0.Host

		// If hostname changed, re-create
		if hName != old.Spec.Rules[0].Host {
			return true
		}

		// New or deleted paths
		if len(r0.HTTP.Paths) != len(old.Spec.Rules[0].HTTP.Paths) {
			return true
		}

		// TODO: Handle if a path is changed
	}

	return false

}

func (c *ControlServer) doDelete(oldIng *v1beta1.Ingress) error {
	if len(oldIng.Spec.Rules) > 0 {
		r0 := oldIng.Spec.Rules[0]

		for _, p := range r0.HTTP.Paths {
			sid := generateIngressID(oldIng.Name, oldIng.Namespace, p)
			err := tyk.DeleteBySlug(sid)
			if err != nil {
				log.Error(err)
			} else {
				log.Info("deleted: ", sid)
			}
		}
	}

	return nil
}

func (c *ControlServer) handleIngressDelete(obj interface{}) {
	ing, ok := obj.(*v1beta1.Ingress)
	if !ok {
		log.Errorf("type not allowed: %v", reflect.TypeOf(obj))
		return
	}

	if !c.checkIngressManaged(ing) {
		return
	}

	err := c.doDelete(ing)
	if err != nil {
		log.Error(err)
	}
}

func (c *ControlServer) checkIngressManaged(ing *v1beta1.Ingress) bool {
	for k, v := range ing.Annotations {
		if k == IngressAnnotation {
			if strings.ToLower(v) == IngressAnnotationValue {
				return true
			}
		}
	}

	return false
}

func (c *ControlServer) watchIngresses() {
	watchList := cache.NewListWatchFromClient(c.client.ExtensionsV1beta1().RESTClient(), "ingresses", v1.NamespaceAll,
		fields.Everything())
	c.store, c.controller = cache.NewInformer(
		watchList,
		&v1beta1.Ingress{},
		time.Second*10,
		cache.ResourceEventHandlerFuncs{
			AddFunc:    c.handleIngressAdd,
			UpdateFunc: c.handleIngressUpdate,
			DeleteFunc: c.handleIngressDelete,
		},
	)

	c.stopCh = make(chan struct{})
	go c.controller.Run(c.stopCh)
}

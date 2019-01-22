package ingress

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"github.com/TykTechnologies/tyk-k8s/injector"
	"github.com/TykTechnologies/tyk-k8s/logger"
	"github.com/TykTechnologies/tyk-k8s/tyk"
	"k8s.io/api/core/v1"
	"k8s.io/api/extensions/v1beta1"
	v12 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	cfg               *Config
	client            *kubernetes.Clientset
	store             cache.Store
	ingressController cache.Controller
	podController     cache.Controller
	stopCh            chan struct{}
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
	c.watchPods()
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
	for _, r0 := range ing.Spec.Rules {
		hName = r0.Host

		for _, p := range r0.HTTP.Paths {
			opts := &tyk.APIDefOptions{}
			opts.ListenPath = p.Path
			svcN := p.Backend.ServiceName
			svcP := p.Backend.ServicePort.IntVal
			opts.Name = getAPIName(ing.Name, svcN)
			opts.Target = fmt.Sprintf("http://%s.%s:%d", svcN, ing.Namespace, svcP)
			opts.Slug = generateIngressID(ing.Name, ing.Namespace, p)
			opts.TemplateName = tyk.DefaultTemplate
			opts.Hostname = hName
			opts.Tags = tags

			_, ok := opLog.Load("add" + opts.Slug)
			if ok {
				log.Info("ingress already processed")
				continue
			}

			_, err := tyk.CreateService(opts)
			if err != nil {
				log.Error(err)
			} else {
				// remember we processed this
				opLog.Store("add-"+opts.Slug, struct{}{})
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

	tags := []string{"ingress"}
	hName := ""
	createOrUpdateList := map[string]*tyk.APIDefOptions{}

	for _, r0 := range newIng.Spec.Rules {
		hName = r0.Host

		for _, p := range r0.HTTP.Paths {
			opts := &tyk.APIDefOptions{}
			opts.ListenPath = p.Path
			svcN := p.Backend.ServiceName
			svcP := p.Backend.ServicePort.IntVal
			opts.Name = getAPIName(newIng.Name, svcN)
			opts.Target = fmt.Sprintf("http://%s.%s:%d", svcN, newIng.Namespace, svcP)
			opts.Slug = generateIngressID(newIng.Name, newIng.Namespace, p)
			opts.TemplateName = tyk.DefaultTemplate
			opts.Hostname = hName
			opts.Tags = tags

			createOrUpdateList[opts.Slug] = opts
		}
	}

	err := tyk.UpdateAPIs(createOrUpdateList)
	if err != nil {
		log.Error(err)
	}

	return

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
	for _, r0 := range oldIng.Spec.Rules {
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
	log.Info("Watching for ingress activity")
	watchList := cache.NewListWatchFromClient(c.client.ExtensionsV1beta1().RESTClient(), "ingresses", v1.NamespaceAll,
		fields.Everything())
	c.store, c.ingressController = cache.NewInformer(
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
	go c.ingressController.Run(c.stopCh)
}

func (c *ControlServer) watchPods() {
	log.Info("Watching for pod deletion")
	watchList := cache.NewListWatchFromClient(c.client.CoreV1().RESTClient(), "pods", v1.NamespaceAll,
		fields.Everything())
	c.store, c.podController = cache.NewInformer(
		watchList,
		&v1.Pod{},
		time.Second*10,
		cache.ResourceEventHandlerFuncs{
			DeleteFunc: c.handlePodDelete,
		},
	)

	c.stopCh = make(chan struct{})
	go c.podController.Run(c.stopCh)
}

func (c *ControlServer) handlePodDelete(obj interface{}) {
	pd, ok := obj.(*v1.Pod)
	log.Info("detected pod deletion:  ", pd.Name)
	log.Info(pd.Annotations)
	if !ok {
		log.Errorf("type not allowed for RS watcher: %v", reflect.TypeOf(obj))
		return
	}

	v, proc := pd.Annotations[injector.AdmissionWebhookAnnotationStatusKey]
	if !proc {
		return
	}

	if v != "injected" {
		return
	}

	log.Info("pod is injector-managed")

	remPds, err := c.client.CoreV1().Pods(pd.Namespace).List(v12.ListOptions{})
	if err != nil {
		log.Error(err)
	}
	log.Info("found ", len(remPds.Items), " in namespace")

	rem := false
	for _, pds := range remPds.Items {
		v, rem = pds.Annotations[injector.AdmissionWebhookAnnotationStatusKey]
		if rem {
			if v == "injected" {
				log.Info("still pods remaining, not deleting routes")
				return
			}
		}
	}

	// Last pod
	serviceID, ok := pd.Annotations[injector.AdmissionWebhookAnnotationInboundServiceIDKey]
	if !ok {
		log.Error("service ID not found in annotations, skipping cleanup")
		return
	}

	meshID, ok := pd.Annotations[injector.AdmissionWebhookAnnotationMeshServiceIDKey]
	if !ok {
		log.Error("mesh ID not found in annotations, skipping cleanup")
		return
	}

	log.Info("deleting...")
	err = tyk.DeleteByID(serviceID)
	if err != nil {
		log.Error("failed to remove service API: ", err)
		return
	}

	err = tyk.DeleteByID(meshID)
	if err != nil {
		log.Error("failed to remove mesh API: ", err)
		return
	}

	log.Info("successfully removed ", serviceID, " and ", meshID)
}

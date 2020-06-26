package ingress

import (
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/TykTechnologies/tyk-k8s/injector"
	"github.com/TykTechnologies/tyk-k8s/logger"
	"github.com/TykTechnologies/tyk-k8s/tyk"
	"k8s.io/api/core/v1"
	"k8s.io/api/extensions/v1beta1"
	netv1beta1 "k8s.io/api/networking/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/version"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

type Config struct {
	WatchNamespaces []string
}

var ctrl *ControlServer
var log = logger.GetLogger("ingress")
var opLog = sync.Map{}
var runtimeScheme = runtime.NewScheme()

const (
	IngressAnnotation      = "kubernetes.io/ingress.class"
	IngressAnnotationValue = "tyk"
	defaultResync          = 2 * time.Minute
)

type ControlServer struct {
	cfg                 *Config
	client              *kubernetes.Clientset
	stopCh              chan struct{}
	factories           map[string]informers.SharedInformerFactory
	isNetworkingIngress bool
}

func init() {
	v1beta1.AddToScheme(runtimeScheme)
	netv1beta1.AddToScheme(runtimeScheme)
}

func convertIngress(obj interface{}) (*netv1beta1.Ingress, bool) {
	extIngress, ok := obj.(*v1beta1.Ingress)
	if ok {
		netIngress := &netv1beta1.Ingress{}
		if err := runtimeScheme.Convert(extIngress, netIngress, nil); err != nil {
			log.Errorf("error converting ingress from extensions/v1beta1: %v", err)
			return nil, false
		}

		return netIngress, true
	}

	if ing, ok := obj.(*netv1beta1.Ingress); ok {
		return ing, true
	}

	return nil, false
}

func NewController() *ControlServer {
	if ctrl == nil {
		ctrl = &ControlServer{
			factories: make(map[string]informers.SharedInformerFactory),
		}
	}

	return ctrl
}

func Controller() *ControlServer {
	if ctrl == nil {
		return NewController()
	}

	return ctrl
}

func (c *ControlServer) Config(cfg *Config) *ControlServer {
	c.cfg = cfg
	return c
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
	c.setNetworkingIngress()

	return c.watchAll()
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

func (c *ControlServer) getAPIName(name, service string) string {
	v := fmt.Sprintf("%s:%s", name, service)
	log.Info("service name is: ", v)
	return v
}

func (c *ControlServer) generateIngressID(ingressName, ns string, p netv1beta1.HTTPIngressPath) string {
	serviceFQDN := fmt.Sprintf("%s.%s.%s/%s", ingressName, ns, p.Backend.ServiceName, p.Path)
	hasher := sha1.New()
	hasher.Write([]byte(serviceFQDN))
	sha := base64.URLEncoding.EncodeToString(hasher.Sum(nil))

	return sha
}

func (c *ControlServer) handleTLS(ing *netv1beta1.Ingress) (map[string]string, error) {
	log.Info("checking for TLS entries")
	certMap := map[string]string{}
	for _, iTLS := range ing.Spec.TLS {
		log.Info("found TLS entry: ", iTLS.String())
		sec, err := c.client.CoreV1().Secrets(ing.Namespace).Get(iTLS.SecretName, metav1.GetOptions{})
		if err != nil {
			return nil, err
		}

		crt, ok := sec.Data["tls.crt"]
		if !ok {
			return nil, errors.New("no certificate found")
		}

		key, ok := sec.Data["tls.key"]
		if !ok {
			return nil, errors.New("no key found")
		}

		log.Info("creating certificate")
		id, err := tyk.CreateCertificate(crt, key)
		if err != nil {
			return nil, err
		}
		log.Info("certificate created with ID: ", id)

		// map the certificate ID to all the host-names
		for _, n := range iTLS.Hosts {
			certMap[n] = id
		}
	}

	return certMap, nil

}

func checkAndGetTemplate(ing *netv1beta1.Ingress) string {
	for k, v := range ing.Annotations {
		if k == tyk.TemplateNameKey {
			log.Infof("template annotation found with value: %v", v)
			return v
		}
	}

	return tyk.DefaultIngressTemplate
}

func (c *ControlServer) doAdd(ing *netv1beta1.Ingress) error {
	tags := []string{"ingress"}
	hName := ""

	certs, err := c.handleTLS(ing)
	if err != nil {
		return err
	}

	for _, r0 := range ing.Spec.Rules {
		hName = r0.Host
		certID, addCert := certs[hName]
		log.Info("checking if cert for host exists: ", r0.Host, ", (", addCert, ")")

		if r0.HTTP == nil {
			return fmt.Errorf("rule has nil paths, can't route without explicit back end: %v", hName)
		}

		if len(r0.HTTP.Paths) == 0 {
			return fmt.Errorf("rule has 0 paths, can't route without explicit back end: %v", hName)
		}

		for _, p := range r0.HTTP.Paths {
			opts := &tyk.APIDefOptions{}
			opts.ListenPath = p.Path
			svcN := p.Backend.ServiceName
			svcP := p.Backend.ServicePort.IntVal
			opts.Name = c.getAPIName(ing.Name, svcN)
			opts.Target = fmt.Sprintf("http://%s.%s:%d", svcN, ing.Namespace, svcP)
			opts.Slug = c.generateIngressID(ing.Name, ing.Namespace, p)
			opts.TemplateName = checkAndGetTemplate(ing)
			opts.Hostname = hName
			opts.Tags = tags
			opts.Annotations = ing.Annotations

			if addCert {
				log.Info("injecting certificate ID")
				opts.CertificateID = []string{certID}
			}

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
	ing, ok := convertIngress(obj)
	if !ok {
		log.Errorf("type not allowed: %v", reflect.TypeOf(obj))
		return
	}

	if !c.checkIngressManaged(ing) {
		return
	}

	err := c.doAdd(ing)
	if err != nil {
		log.Error(err)
	}
}

func (c *ControlServer) handleIngressUpdate(oldObj interface{}, newObj interface{}) {
	oldIng, ok := convertIngress(oldObj)
	if !ok {
		log.Errorf("type not allowed: %v", reflect.TypeOf(oldIng))
		return
	}

	if !c.checkIngressManaged(oldIng) {
		return
	}

	newIng, ok := convertIngress(newObj)
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
			opts.Name = c.getAPIName(newIng.Name, svcN)
			opts.Target = fmt.Sprintf("http://%s.%s:%d", svcN, newIng.Namespace, svcP)
			opts.Slug = c.generateIngressID(newIng.Name, newIng.Namespace, p)
			opts.TemplateName = checkAndGetTemplate(newIng)
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

func (c *ControlServer) ingressChanged(old *netv1beta1.Ingress, new *netv1beta1.Ingress) bool {

	//first check top level changes like annotations
	// try and get out early with a simple length check
	if len(old.Annotations) != len(new.Annotations) {
		return true
	}
	// check regular string annotations
	for k, v := range new.Annotations {
		if old.Annotations[k] != v && k != tyk.TemplateNameKey {
			return true
		}
	}

	if len(new.Spec.Rules) > 0 {
		for ruleNum := 0; ruleNum < len(new.Spec.Rules); ruleNum++ {

			newRule := new.Spec.Rules[ruleNum]
			oldRule := old.Spec.Rules[ruleNum]
			hName := newRule.Host

			// If hostname changed, re-create
			if hName != old.Spec.Rules[0].Host {
				return true
			}

			// New or deleted paths
			if len(newRule.HTTP.Paths) != len(oldRule.HTTP.Paths) {
				return true
			}

			// Handle if a path is changed
			for pathNum := 0; pathNum < len(oldRule.HTTP.Paths); pathNum++ {

				if oldRule.HTTP.Paths[pathNum] != newRule.HTTP.Paths[pathNum] {
					return true
				}
				// check for changed service names and ports
				if oldRule.HTTP.Paths[ruleNum].Backend.ServiceName != newRule.HTTP.Paths[pathNum].Backend.ServiceName ||
					oldRule.HTTP.Paths[pathNum].Backend.ServicePort != newRule.HTTP.Paths[pathNum].Backend.ServicePort {
					return true
				}
			}
		}
	}

	return false

}

func (c *ControlServer) doDelete(oldIng *netv1beta1.Ingress) error {
	for _, r0 := range oldIng.Spec.Rules {
		for _, p := range r0.HTTP.Paths {
			sid := c.generateIngressID(oldIng.Name, oldIng.Namespace, p)
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
	ing, ok := convertIngress(obj)
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

func (c *ControlServer) checkIngressManaged(ing *netv1beta1.Ingress) bool {
	for k, v := range ing.Annotations {
		if k == IngressAnnotation {
			if strings.ToLower(v) == IngressAnnotationValue {
				return true
			}
		}
	}

	return false
}

// Checks whether k8s version is 1.14+ and therefore uses networking API for ingresses
func (c *ControlServer) setNetworkingIngress() {
	version114, err := version.ParseGeneric("v1.14.0")
	if err != nil {
		log.Errorf("error parsing version: %v", err)
		return
	}

	discoveredVersion, err := c.client.Discovery().ServerVersion()
	if err != nil {
		log.Errorf("error discovering k8s version: %v", err)
		return
	}

	k8sVersion, err := version.ParseGeneric(discoveredVersion.String())
	if err != nil {
		log.Errorf("error parsing discovered k8s version: %v", err)
		return
	}

	c.isNetworkingIngress = k8sVersion.AtLeast(version114)
}

// Watches k8s resources required for ingress controller operations using shared informers
func (c *ControlServer) watchAll() error {
	namespaces := c.cfg.WatchNamespaces
	if len(namespaces) == 0 {
		namespaces = []string{v1.NamespaceAll}
	}

	for _, ns := range namespaces {
		log.Infof("Registering informers for namespace %s", ns)
		factory := informers.NewSharedInformerFactoryWithOptions(c.client, defaultResync, informers.WithNamespace(ns))

		// Watch ingresses
		var ingressesInformer cache.SharedIndexInformer
		if c.isNetworkingIngress {
			ingressesInformer = factory.Networking().V1beta1().Ingresses().Informer()
		} else {
			ingressesInformer = factory.Extensions().V1beta1().Ingresses().Informer()
			log.Info("Using deprecated extensions/v1beta1 ingresses API")
		}
		ingressesInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc:    c.handleIngressAdd,
			UpdateFunc: c.handleIngressUpdate,
			DeleteFunc: c.handleIngressDelete,
		})

		// Watch pods
		factory.Core().V1().Pods().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
			AddFunc:    nil,
			UpdateFunc: nil,
			DeleteFunc: c.handlePodDelete,
		})

		c.factories[ns] = factory
		factory.Start(c.stopCh)

		for t, ok := range factory.WaitForCacheSync(c.stopCh) {
			if !ok {
				return fmt.Errorf("failed while syncing %s caches for ns %s", t.String(), ns)
			}
		}
	}

	return nil
}

func (c *ControlServer) handlePodDeleteForMesh(pd *v1.Pod) {
	log.Info("pod is injector-managed")

	remPds, err := c.client.CoreV1().Pods(pd.Namespace).List(metav1.ListOptions{})
	if err != nil {
		log.Error(err)
	}
	log.Info("found ", len(remPds.Items), " in namespace")

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

	var sid, mid string
	serviceIDFound, meshIDFound := false, false
	for _, pds := range remPds.Items {
		sid, serviceIDFound = pds.Annotations[injector.AdmissionWebhookAnnotationInboundServiceIDKey]
		mid, meshIDFound = pds.Annotations[injector.AdmissionWebhookAnnotationMeshServiceIDKey]
		if serviceIDFound && meshIDFound {
			if (sid == serviceID) && (mid == meshID) {
				log.Info("pods still remaining for mesh set, not deleting routes until final pod")
				return
			}
		}
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

	switch v {
	case "injected":
		c.handlePodDeleteForMesh(pd)
		return
	default:
		return
	}
}

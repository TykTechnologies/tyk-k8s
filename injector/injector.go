package injector

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/TykTechnologies/tyk-k8s/logger"
	"github.com/TykTechnologies/tyk-k8s/tyk"
	"io/ioutil"
	"k8s.io/apimachinery/pkg/util/intstr"
	"net/http"
	"strings"

	"github.com/ghodss/yaml"
	"k8s.io/api/admission/v1beta1"
	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
)

var log = logger.GetLogger("injector")

var (
	runtimeScheme = runtime.NewScheme()
	codecs        = serializer.NewCodecFactory(runtimeScheme)
	deserializer  = codecs.UniversalDeserializer()
)

var ignoredNamespaces = []string{
	metav1.NamespaceSystem,
	metav1.NamespacePublic,
}

const (
	AdmissionWebhookAnnotationInjectKey           = "injector.tyk.io/inject"
	AdmissionWebhookAnnotationStatusKey           = "injector.tyk.io/status"
	admissionWebhookAnnotationRouteKey            = "injector.tyk.io/route"
	AdmissionWebhookAnnotationInboundServiceIDKey = "injector.tyk.io/inbound-service-id"
	AdmissionWebhookAnnotationMeshServiceIDKey    = "injector.tyk.io/mesh-service-id"

	meshTag = "mesh"
)

type WebhookServer struct {
	SidecarConfig *Config
}

type Config struct {
	Containers     []corev1.Container `yaml:"containers"`
	InitContainers []corev1.Container `yaml:"initContainers"`
	CreateRoutes   bool               `yaml:"createRoutes"`
}

type namedThing struct {
	metav1.TypeMeta `json:",inline"`
	// Standard object's metadata.
	// More info: https://git.k8s.io/community/contributors/devel/api-conventions.md#metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
}

type patchOperation struct {
	Op    string      `json:"op"`
	Path  string      `json:"path"`
	Value interface{} `json:"value,omitempty"`
}

func init() {
	_ = corev1.AddToScheme(runtimeScheme)
	_ = admissionregistrationv1beta1.AddToScheme(runtimeScheme)
}

func loadConfig(configFile string) (*Config, error) {
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		return nil, err
	}
	log.Infof("New configuration: sha256sum %x", sha256.Sum256(data))

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// Check whether the target resoured need to be mutated
func mutationRequired(ignoredList []string, metadata *metav1.ObjectMeta) bool {
	// skip special kubernete system namespaces
	for _, namespace := range ignoredList {
		if metadata.Namespace == namespace {
			log.Infof("Skip mutation for %v, special namespace:%v", metadata.Name, metadata.Namespace)
			return false
		}
	}

	annotations := metadata.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}

	status := annotations[AdmissionWebhookAnnotationStatusKey]

	// determine whether to perform mutation based on annotation for the target resource
	var required bool
	if strings.ToLower(status) == "injected" {
		required = false
	} else {
		switch strings.ToLower(annotations[AdmissionWebhookAnnotationInjectKey]) {
		default:
			required = false
		case "y", "yes", "true", "on":
			required = true
		}
	}

	log.Infof("Mutation policy for %v/%v: status: %q required:%v", metadata.Namespace, metadata.Name, status, required)
	return required
}

func addContainer(target, added []corev1.Container, basePath string) (patch []patchOperation) {
	first := len(target) == 0
	var value interface{}
	for _, add := range added {
		value = add
		path := basePath
		if first {
			first = false
			value = []corev1.Container{add}
		} else {
			path = path + "/-"
		}
		patch = append(patch, patchOperation{
			Op:    "add",
			Path:  path,
			Value: value,
		})
	}
	return patch
}

func updateAnnotation(target map[string]string, added map[string]string) (patch []patchOperation) {
	if target == nil {
		target = map[string]string{}
	}

	patch = append(patch, patchOperation{
		Op:    "add",
		Path:  "/metadata/annotations",
		Value: added,
	})

	return patch
}

func mutateService(svc *corev1.Service, basePath string) (patch []patchOperation) {

	sidecarSvcPort := &corev1.ServicePort{
		Name: "tyk-sidecar",
		Port: 8080,
		TargetPort: intstr.IntOrString{
			IntVal: 8080,
		},
	}

	opp := "replace"
	path := "/spec/ports/0"
	if len(svc.Spec.Ports) > 1 {
		opp = "add"
		path = "/spec/ports"
	}

	patch = append(patch, patchOperation{
		Op:    opp,
		Path:  path,
		Value: sidecarSvcPort,
	})

	return patch
}

// add tags to the gateway container
const tagVarName = "TYK_GW_DBAPPCONFOPTIONS_TAGS"

// TODO: For some reason this starts appending the same (or different) tags after multiple deployments
func preProcessContainerTpl(pod *corev1.Pod, containers []corev1.Container) []corev1.Container {
	sName, ok := pod.Labels["app"]
	if !ok {
		sName = pod.GenerateName + "please-set-app-label"
	}

	tags := fmt.Sprintf("mesh,%s", sName)
	tagEnv := corev1.EnvVar{Name: tagVarName, Value: tags}
	for i, cnt := range containers {
		if strings.ToLower(cnt.Name) == "tyk-mesh" {
			for ei, envVal := range containers[i].Env {
				if envVal.Name == tagVarName {
					// update the existing variable
					containers[i].Env[ei] = tagEnv
					return containers
				}
			}

			// no exiting var found, create
			containers[i].Env = append(cnt.Env, corev1.EnvVar{Name: tagVarName, Value: tags})
			break
		}
	}

	return containers
}

// create mutation patch for resoures
func createPatch(pod *corev1.Pod, svc *corev1.Service, sidecarConfig *Config, annotations map[string]string) ([]byte, error) {
	var patch []patchOperation

	if svc != nil {
		patch = append(patch, mutateService(svc, "/spec/ports")...)
		return json.Marshal(patch)
	}

	patch = append(patch, addContainer(pod.Spec.Containers, preProcessContainerTpl(pod, sidecarConfig.Containers), "/spec/containers")...)
	patch = append(patch, addContainer(pod.Spec.InitContainers, sidecarConfig.InitContainers, "/spec/initContainers")...)
	patch = append(patch, updateAnnotation(pod.Annotations, annotations)...)
	return json.Marshal(patch)
}

// create service routes
func createServiceRoutes(pod *corev1.Pod, annotations map[string]string, namespace string) (map[string]string, error) {
	_, idExists := annotations[AdmissionWebhookAnnotationInboundServiceIDKey]
	if idExists {
		return annotations, nil
	}

	sName, ok := pod.Labels["app"]
	if !ok {
		return annotations, errors.New("app label is required")
	}

	ns := namespace
	if ns == "" {
		ns = "default"
	}

	hName := fmt.Sprintf("%s.%s", sName, ns)
	slugID := sName + "-inbound"
	// inbound listener
	opts := &tyk.APIDefOptions{
		Slug:         slugID,
		Target:       "http://localhost:6767",
		ListenPath:   "/",
		TemplateName: tyk.DefaultTemplate,
		Hostname:     hName,
		Name:         slugID,
		Tags:         []string{sName},
		Annotations:  annotations,
	}

	ibID := ""
	inboundDef, doNotSkip := tyk.GetBySlug(opts.Slug)
	if doNotSkip != nil {
		// error means this service hasn't been created yet
		inboundID, err := tyk.CreateService(opts)
		if err != nil {
			return annotations, fmt.Errorf("failed to create inbound service %v: %v", slugID, err.Error())
		}

		ibID = inboundID
	} else {
		ibID = inboundDef.Id.Hex()
	}

	annotations[AdmissionWebhookAnnotationInboundServiceIDKey] = ibID

	// mesh route
	var pt int32
	pt = 8080

	tgt := fmt.Sprintf("http://%s:%d", hName, pt)
	listenPath := sName
	for k, v := range pod.Annotations {
		if k == admissionWebhookAnnotationRouteKey {
			listenPath = v
		}
	}

	meshID := ""
	meshSlugID := sName + "-mesh"
	meshOpts := &tyk.APIDefOptions{
		Slug:         meshSlugID,
		Target:       tgt,
		ListenPath:   listenPath,
		TemplateName: tyk.DefaultTemplate,
		Hostname:     "",
		Name:         meshSlugID,
		Tags:         []string{meshTag},
	}

	meshDef, doNotSkipMesh := tyk.GetBySlug(meshOpts.Slug)
	if doNotSkipMesh != nil {
		// error means this service hasn't been created yet
		mId, err := tyk.CreateService(meshOpts)
		if err != nil {
			return annotations, fmt.Errorf("failed to create mesh service %v: %v", meshSlugID, err.Error())
		}
		meshID = mId
	} else {
		meshID = meshDef.Id.Hex()
	}

	annotations[AdmissionWebhookAnnotationMeshServiceIDKey] = meshID

	return annotations, nil
}

func (whsvr *WebhookServer) processPodMutations(ar *v1beta1.AdmissionReview) *v1beta1.AdmissionResponse {
	req := ar.Request
	var pod corev1.Pod
	if err := json.Unmarshal(req.Object.Raw, &pod); err != nil {
		log.Errorf("Could not unmarshal raw object: %v", err)
		return &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	log.Infof("AdmissionReview for Kind=%v, Namespace=%v Name=%v (%v) UID=%v patchOperation=%v UserInfo=%v",
		req.Kind, req.Namespace, req.Name, pod.Name, req.UID, req.Operation, req.UserInfo)

	// determine whether to perform mutation
	if !mutationRequired(ignoredNamespaces, &pod.ObjectMeta) {
		log.Infof("Skipping mutation for %s/%s due to policy check", pod.Namespace, pod.Name)
		return &v1beta1.AdmissionResponse{
			Allowed: true,
		}
	}

	annotations := pod.Annotations
	annotations[AdmissionWebhookAnnotationStatusKey] = "injected"
	delete(annotations, AdmissionWebhookAnnotationInjectKey)

	// We create the service routes first, because we need the IDs
	if whsvr.SidecarConfig.CreateRoutes {
		var err error
		annotations, err = createServiceRoutes(&pod, annotations, ar.Request.Namespace)
		if err != nil {
			return &v1beta1.AdmissionResponse{
				Result: &metav1.Status{
					Message: err.Error(),
				},
			}
		}
	}

	// Create the patch
	patchBytes, err := createPatch(&pod, nil, whsvr.SidecarConfig, annotations)
	if err != nil {
		return &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	log.Infof("AdmissionResponse: patch=%v\n", string(patchBytes))
	return &v1beta1.AdmissionResponse{
		Allowed: true,
		Patch:   patchBytes,
		PatchType: func() *v1beta1.PatchType {
			pt := v1beta1.PatchTypeJSONPatch
			return &pt
		}(),
	}
}

func (whsvr *WebhookServer) processServiceMutations(ar *v1beta1.AdmissionReview) *v1beta1.AdmissionResponse {
	req := ar.Request
	var service corev1.Service
	if err := json.Unmarshal(req.Object.Raw, &service); err != nil {
		log.Errorf("Could not unmarshal raw object: %v", err)
		return &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	log.Infof("AdmissionReview for Kind=%v, Namespace=%v Name=%v (%v) UID=%v patchOperation=%v UserInfo=%v",
		req.Kind, req.Namespace, req.Name, service.Name, req.UID, req.Operation, req.UserInfo)

	// determine whether to perform mutation
	if !mutationRequired(ignoredNamespaces, &service.ObjectMeta) {
		log.Infof("Skipping mutation for %s/%s due to policy check", service.Namespace, service.Name)
		return &v1beta1.AdmissionResponse{
			Allowed: true,
		}
	}

	annotations := service.Annotations
	annotations[AdmissionWebhookAnnotationStatusKey] = "injected"
	delete(annotations, AdmissionWebhookAnnotationInjectKey)

	// Create the patch
	patchBytes, err := createPatch(nil, &service, whsvr.SidecarConfig, annotations)
	if err != nil {
		return &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	}

	log.Infof("AdmissionResponse: patch=%v\n", string(patchBytes))
	return &v1beta1.AdmissionResponse{
		Allowed: true,
		Patch:   patchBytes,
		PatchType: func() *v1beta1.PatchType {
			pt := v1beta1.PatchTypeJSONPatch
			return &pt
		}(),
	}
}

// main mutation process
func (whsvr *WebhookServer) mutate(ar *v1beta1.AdmissionReview) *v1beta1.AdmissionResponse {
	req := ar.Request

	log.Info("object is: ", req.Kind)
	switch strings.ToLower(req.Kind.Kind) {
	case "pod":
		return whsvr.processPodMutations(ar)
	case "service":
		return whsvr.processServiceMutations(ar)
	default:
		return &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: "type not supported",
			},
		}
	}
}

// Serve method for webhook server
func (whsvr *WebhookServer) Serve(w http.ResponseWriter, r *http.Request) {
	var body []byte
	if r.Body != nil {
		if data, err := ioutil.ReadAll(r.Body); err == nil {
			body = data
		}
	}
	if len(body) == 0 {
		log.Error("empty body")
		http.Error(w, "empty body", http.StatusBadRequest)
		return
	}

	// verify the content type is accurate
	contentType := r.Header.Get("Content-Type")
	if contentType != "application/json" {
		log.Errorf("Content-Type=%s, expect application/json", contentType)
		http.Error(w, "invalid Content-Type, expect `application/json`", http.StatusUnsupportedMediaType)
		return
	}

	var admissionResponse *v1beta1.AdmissionResponse
	ar := v1beta1.AdmissionReview{}
	if _, _, err := deserializer.Decode(body, nil, &ar); err != nil {
		log.Errorf("can't decode body: %v", err)
		admissionResponse = &v1beta1.AdmissionResponse{
			Result: &metav1.Status{
				Message: err.Error(),
			},
		}
	} else {
		admissionResponse = whsvr.mutate(&ar)
	}

	admissionReview := v1beta1.AdmissionReview{}
	if admissionResponse != nil {
		admissionReview.Response = admissionResponse
		if ar.Request != nil {
			admissionReview.Response.UID = ar.Request.UID
		}
	}

	resp, err := json.Marshal(admissionReview)
	if err != nil {
		log.Errorf("can't encode response: %v", err)
		http.Error(w, fmt.Sprintf("could not encode response: %v", err), http.StatusInternalServerError)
	}
	log.Infof("ready to write reponse ...")
	if _, err := w.Write(resp); err != nil {
		log.Errorf("can't write response: %v", err)
		http.Error(w, fmt.Sprintf("could not write response: %v", err), http.StatusInternalServerError)
	}
}

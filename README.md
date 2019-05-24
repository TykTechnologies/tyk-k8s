# Tyk Kubernetes Controller

This application performs two core functions:

1. Provides an Ingress controller for a Tyk Pro (Dashboard) installation
2. Provides a (Beta) sidecar injector for Service Mesh installations

## Ingress Controller

The ingress controller will watch the Kubernetes API for new ingresses, any new ingresses that are tagged to the controller will then cause the controller to generate a corresponding open service definition in your Tyk Dashboard installation.

Removing an ingress will then remove the corresponding API definition. 

### Installation

It is recommended to use the [Tyk for Kubernetes Helm chart which is available here](https://github.com/TykTechnologies/tyk-helm-chart).

### Usage:

To use the ingress controller, simply add the ingress annotation to your definition:

    kubernetes.io/ingress.class: "tyk"

## Service Mesh

The service mesh controller will expose an Admission Controller Mutating Webhook for the K8s API to intercept Pod activities. The controller will modify those pods to include a gateway sidecar and a firewall to route traffic to the sidecar. These containers are still under heavy development and will definetely change in future.

This feature is still TBC

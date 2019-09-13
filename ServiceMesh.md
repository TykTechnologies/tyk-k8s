# Tyk Service Mesh Notes

This guide assumes you have installed Tyk using the helm chart and have installed the Tyk K8s controller already.

## How does Tyk Service Mesh work?

Tyk's service mesh is entirely managed by the `tyk-k8s` controller and the Tyk Dashboard API. When a meshed service is created by kubernetes, the controller performs the following actions:

1. Creates a "mesh" API for this service, this is the public route that callers can access the service on
2. Creates an "inbound" API for this service, this is the listener that the service sidecar will wait for requests on.
3. Modifies the pod specification to add the Tyk Gateway sidecar
4. Adds an initialisation container to fix the routing of services so that all outbound requests from the service on ports 80 and 443 are routed to the sidecar and a rule that all traffic to port 6767 is routed to port 80
5. If a service is also deployed, and has been annotated, it will modify the service to ensure trafficis routed to the sidecar instead of directly to the service

### What's with the port manipulation?

The two port changes make the following possible:

The service must listen on port 80 (currently, this is on the roadmap to be made flexible), because this is known the sidecar needs a way to route traffic comming into the gateway to the managed service, this is done via 6767->80 tunnel

Many services will also make outbound calls, and in order for those to work we need to ensure the traffic goes to the sidecar gateway. Ideally we do not want to change anything in the software, so for it to "just work", all outbound requests on port 8- and 443 are routed to the gateway automatically. 

There is a caveat when using last-mile-TLS, since TLS certificates are bound to hostnames, so in this scenario the routes *do* need to be changed to point at `https://mesh/<service-route>`

## Gateway Tagging and Sharding

To make the mesh work, we make excessive use of Ty's sharding capability - the ability to selectively load service routes on different gateways depending on how they are tagged. 

All sidecars are tagged with a `<service-name>` tag and a `mesh` tag, the mesh group is all the routes that can be used by callers to access other services, while the `<service-name`> tags guarantee that the listener service (inbound) are only loaded by their respective pods.

This means for every one meshed service, there are two APIs created in the dashboard. One for cluster-wide access, and one as a listener on the pod itself.

Because we have both of these APIs, it means we can easily protect inbound listeners with service-address based TLS certificates, and we can also use mTLS or other validation mechanisms to authorize traffic between callers and callee's, wither through mutual TLS and client certificates to shared keys and even JWTs.

## How does last-mile TLS work?

The k8s controller can handle generating TLS certificates for each of your services on the fly if it is configured to do so. The `tyk-k8s` controller makes use of an external Certificate Authority server, currently only CFSSL is supported. 

When a meshed service is created, Tyk adds a few new steps to the standard service flow:

1. Creates a "mesh" API for this service, this is the public route that callers can access the service on
2. Attaches the cluster-wide mesh certificate (this is auto-created) to the mesh API
3. Creates an "inbound" API for this service, this is the listener that the service sidecar will wait for requests on.
4. Generates a TLS certificate for the "inbound" service
5. Stores the mesh certificate in the Tyk secure certificate store and attaches it to the inbound API
6. Modifies the pod specification to add the Tyk Gateway sidecar
7. Injects the Tyk CA certificate into the container certificate store so requests validate
8. Adds an initialisation container to fix the routing of services
9. Modifies services (if necessary)

At this point it also adds a host alias for the hostname `mesh` to the pod, this is so that services can make outbound calls to other services on the mesh in a secure way. Instead of being able to call any URL, the service must now call `https://mesh/<service-name>`, this is because certificates are bound to hostnames.
 
This means the encryption chain for connectivity in the mesh is as follows:
 
```
caller service --TLS--> caller sidecar --TLS--> callee sidecar --HTTP--> callee service
```

## How to use the Service Mesh

Assuming the mesh has been installed (see below), creating a meshed service is trivial through the use of annotations:

```yaml
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: echo-dep
spec:
  replicas: 1
  selector:
    matchLabels:
      app: echo
  template:
    metadata:
      annotations:
        # Ensure that the injector annotations are in place
        injector.tyk.io/inject: "true"        # <--- manage the service
        injector.tyk.io/route: "/echo-svc"    # <--- the route to use on the mesh
      labels:
        # App label is required for a deployment to function
        app: echo
    spec:
      containers:
        - name: echo
          image: jmalloc/echo-server
          ports:
            # All meshed applications must listen on port 80
            - containerPort: 80
          env:
            - name: PORT
              value: "80"
---
apiVersion: v1
kind: Service
metadata:
  # The service name should match the app name
  name: echo

  # Remember to annotate the service too, this ensures the ports are correctly rewritten for the sidecar
  annotations:
    injector.tyk.io/inject: "true"
spec:
  ports:
    - port: 80
      targetPort: 80
      protocol: TCP
      name: http
  selector:
    app: echo

```

You can then deploy this with `kubectl` and you will see two APIs in your dashboard. Now let's create a caller:

```yaml
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: sleep
spec:
  replicas: 1
  template:
    metadata:
      labels:
        app: sleep
      annotations:
        # This container has no actual inbound listener, but you can use it to test outbound
        # `curl` commands against a sidecar, remove this annotation to test the mesh
        # endpoint directly
        injector.tyk.io/inject: "true"
        injector.tyk.io/route: "/sleepy-time"
    spec:
      containers:
      - name: sleep
        image: tutum/curl
        command: ["/bin/sleep","infinity"]
        imagePullPolicy: IfNotPresent

```

This will create a deployment you can run `curl` from, and all requests will be automatically routed through the mesh, for example:

```shell script
kubectl get pods

## OUTPUT ---------------------------------------------------------------------------
NAME                                                READY   STATUS    RESTARTS   AGE
cfssl-5944f54df-vbm6d                               1/1     Running   0          2d
dashboard-torpid-penguin-tyk-pro-5ccf8bfdb8-mcbbj   1/1     Running   0          45h
echo-dep-cc77f8bbf-5tbv7                            2/2     Running   0          81m
gateway-torpid-penguin-tyk-pro-5m7j8                1/1     Running   0          2d15h
gateway-torpid-penguin-tyk-pro-8g45x                1/1     Running   0          2d15h
gateway-torpid-penguin-tyk-pro-mxbgj                1/1     Running   0          2d15h
gateway-torpid-penguin-tyk-pro-w992k                1/1     Running   0          2d15h
pump-torpid-penguin-tyk-pro-6cbb95f6b4-khb9b        1/1     Running   0          16d
sleep-6776d7dd78-zjr6k                              2/2     Running   0          81m
tyk-k8s-7dddc5575-zgfs5                             1/1     Running   0          82m
```

Here, `echo-dep-cc77f8bbf-5tbv7` is the echo service we just launched and `sleep-6776d7dd78-zjr6k` is our launchpad where we can run commands.

Now you can exec into that container using:

```shell script
kubectl exec -it --namespace default sleep-6776d7dd78-zjr6k --container sleep  /bin/bash
```

This should give you a shell prompt, you can now try out the mesh, if not using TLS:

```shell script
curl -v http://localhost/echo-svc
```

And if using TLS:

```shell script
curl -v https://mesh/echo-svc
```

You may get an error with curl here, because curl insists on signing certificates to be part of `ca-certificates.crt`, since we want to test inter-container connectivity, we can use the `-k`  flag here to allow the request through to the first sidecar: `curl https://mesh/echo-svc -k`

You should see an injected header from the inbound gateway that specifies the request ID, that was sent, s well as several rate-limiting headers inserted by the sidecars.

# Setting up Last-mile TLS

The guide below should provide enough notes to set up your CA authority and update the tyk-k8s controller to generate certificates for you.

## 1. Update the tyk-k8s.conf file to add the CA section:

```yaml
CA:
  addr: "http://cfssl-svc.default"
  key: "6dcb98e9d24cc68ed627017e4a1a03b8"
  mongoConnStr: "mongodb://mongodb-mongodb-replicaset.mongodb:27017/tyk-dashboard"
  defaultNames:
    - C: GB
      L: London
      O: Tyk Technologies Ltd.
      OU: Bleeding Edge Services
      ST: England
  defaultKeyRequest:
    A: rsa
    S: 4096
```

*The settings for this new section are as follows:*

- `addr`: The address of your CFSSL instance
- `key`: The secret for the CFSSL API (TODO: This should be stored in a secret)
- `mongoConnStr`: THe mongo DB connection string to store certificate expiration data
- `defaultNames`: Corresponds to the default data to be used for the SSL holder
- `defaultKeyRequest`: The key request algorithm and strength to use

You will also need to explicitly enable last-mile TLS in the injector section so it looks like this:

```yaml
 Injector:
    createRoutes: true
    enableMeshTLS: true
    meshCertificateID: "a really long ID here" # (we'll generate this below)
    # ...
```

Lastly, you will need to enable TLS on your sidecars, add the following to the env section of the `tyk-mesh` container definitoon in the `containers` section:

```yaml
# ...
- name: TYK_GW_HTTPSERVEROPTIONS_USESSL
  value: "true"
# ...
```

*Restart*: You will then need to restart the tyk-k8s service, you can do this by scaling it down and up, or by modifying it's YAML (for example, introducing an ENV var that holds a revision number)

## 2. Prepare and create your CFSSL deployment

This is possibly the most complicated step, first you will need to create a PKI, thankfully this is relatively easy using CFSSL:

```shell script
mkdir -p ca-quickstart
cd ca-quickstart
cat >> config_ca.json << EOF
{
  "signing": {
    "profiles": {
      "CA": {
        "usages": ["cert sign"],
        "expiry": "8760h",
        "auth_key": "ca-auth"
      }
    },
    "default": {
      "usages": [
        "signing",
         "key encipherment",
         "server auth",
         "client auth"
      ],
      "expiry": "8760h"
    }
  },
  "auth_keys": {
    "ca-auth": {
      "type":"standard",
      "key":"6dcb98e9d24cc68ed627017e4a1a03b8"
    }
  }
}
EOF
cat >> csr_ca.json << EOF
{
  "CN": "Mesh Internal Signing CA",
  "key": {
    "algo": "rsa",
    "size": 4096
  },
    "names": [
       {
         "C": "GB",
         "L": "London",
         "O": "Tyk Technologies Ltd.",
         "OU": "Tyk Kubernetes CA Service",
         "ST": "London"
       }
    ]
}
EOF
cfssl gencert -initca csr_ca.json | cfssljson -bare ca
```

This should create a few files:

- `ca.csr`: This is your certificate signing request, this was used to create your root cert and key
- `ca-key.pem`: This is the CA server private key, keep this safe
- `ca.pem`: This is your CA certificate, (you will need your services to trust this certificate, we'll get to that in a minute).

The last two are the important ones, we will be using these to set up the CFSSL server and it's configuration:

```shell script
kubectl create configmap config-ca-json --from-file=config_ca.json=config_ca.json
kubectl create configmap ca-key-pem --from-file=ca-key.pem=ca-key.pem
kubectl create configmap ca-pem --from-file=ca.pem=ca.pem
```

Now we can deploy CFSSL, you can get the deployment file mentioned below from the tyk-k8s repo (`docker/cfssl-k8s/ca-quickstart/k8s/eployment.yaml`)

```shell script
kubectl create -f ./deployment.yaml
```

## 3. Create some services

There are three services included in the `docker/cfssl-k8s/samples` folder:

1. `echo`: This just echoes back your request: you will notice that the service itself is not configured for TLS at all, it is just a standard deployment (with an ingress).
2. `sleep`: (`launchpad-mesh.yaml`): This is a dormant container, it doesn;t do anything, but you can `kubectl exec` into it to run test curl commands against `echo`. This container is also mesh-managed. In order to call the echo service, you would run something like: `curl -k https://localhost/echo-svc/foo`, we can use _any_ hostname, the sidecar will intercept any traffic on port `80` and `443` coming from within the container and route it through the gateway
3. `curl` (`launchpad.yaml`): this is a dormant container, but is not meshed, you can `kubectl exec` into this container to test your internal service inbound endpoints from outside the mesh. To call the echo service from this container you would run `curl -k https://echo.default/foo`

All of the above will give you a "failed to proxy" error currently since these APIs are all validating the issuer and the CA cert has not been added to these containers yet. That's still a major TODO.


## Caveat 
This software is provided as is and the mesh functionality is still in the early stages of development, this means the API may become unstable and settings, fields and names are prone to change.

## TODO:
- [x] Auto-inject the CA root to services
- [ ] Automatic certificate renewal and rotation
- [ ] Mutual TLS grants
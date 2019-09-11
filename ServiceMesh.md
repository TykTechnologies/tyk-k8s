# Tyk Service Mesh Notes

This guide assumes you have installed Tyk using the helm chart and have installed the Tyk K8s controller already.

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
    "default": {
      "auth_key": "key1",
      "expiry": "8760h",
      "usages": [
         "signing",
         "key encipherment",
         "server auth",
         "client auth"
       ]
     }
  },
  "auth_keys": {
    "key1": {
      "key": "6dcb98e9d24cc68ed627017e4a1a03b8",
      "type": "standard"
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

## 3. TBC
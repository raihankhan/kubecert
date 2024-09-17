# kubecert

A Kubernetes controller that automates the generation of self-signed TLS certificates for applications, simplifying the deployment process and ensuring secure communication. kubecert kubernetes controller continuously watches and reconciles `Certificate` custom resource to generate kubenetes native `Secret` resource using provided specifications. The `Secret` is expected to contain a `tls.crt` and a `tls.key` file which are actually a self-signed certificate and private key.

It is a requirement to install cert-manager prior to installing kubecert controller. Cert-manager is used to inject self-signed certificates for controller manager webhook server. Use the following command to install cert-manager using helm CLI. 

```bash
helm repo add jetstack https://charts.jetstack.io --force-update
helm install \
          cert-manager jetstack/cert-manager \
          --namespace cert-manager \
          --create-namespace \
          --version v1.15.3 \
          --set crds.enabled=true  
```

You can also install the cert-manager release manifest using kubectl CLI as well.
```bash
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.15.3/cert-manager.yaml
```

Simply, `cd` into the project directory and install the controller using the following commands.

```bash
cd kubecert
export IMG=raihankhanraka/kubecert:v1.0.0
make deploy
```

You can also self-build the docker image and install the controller using that image. 
```bash
export IMG=<docker-registry>/kubecert:<tag>
make docker-build
make docker-push
make deploy
```

Now, Try with the sample yaml from [here](https://raw.githubusercontent.com/raihankhan/kubecert/master/config/samples/certs_v1_certificate.yaml)

Let's take a look at the configurable fields in the custom resource object and their default values.

| certificate.spec.          | Default                                     | Accepted Types                                                                                                                                                                                                                                                                                                                                                                                                          |
|----------------------------|---------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| subject.organizations      |                                             | []string                                                                                                                                                                                                                                                                                                                                                                                                                |
| subject.countries          |                                             | []string                                                                                                                                                                                                                                                                                                                                                                                                                |
| subject.organizaionalUnits |                                             | []string                                                                                                                                                                                                                                                                                                                                                                                                                |
| subject.localities         |                                             | []string                                                                                                                                                                                                                                                                                                                                                                                                                |
| subject.provinces          |                                             | []string                                                                                                                                                                                                                                                                                                                                                                                                                |
| subject.streetAddresses    |                                             | []string                                                                                                                                                                                                                                                                                                                                                                                                                |
| subject.postalCodes        |                                             | []string                                                                                                                                                                                                                                                                                                                                                                                                                |
| commonName                 |                                             | string                                                                                                                                                                                                                                                                                                                                                                                                                  |
| duration                   | 90d                                         | units( "ms", "s", "m", "h", "d", "w", "y" )                                                                                                                                                                                                                                                                                                                                                                             |
| dnsNames                   |                                             | []string                                                                                                                                                                                                                                                                                                                                                                                                                |
| ipAddresses                |                                             | []string                                                                                                                                                                                                                                                                                                                                                                                                                |
| uris                       |                                             | []string                                                                                                                                                                                                                                                                                                                                                                                                                |
| emailAddresses             |                                             | []string                                                                                                                                                                                                                                                                                                                                                                                                                |
| secretRef.name             | <certificate-name>-secret                   | []string, Accepted usages -                                                                                                                                                                                                                                                                                                                                                                                             |
| usages                     | `digital signature`,<br/>`key encipherment` | `digital signature`,<br/>`content commitment`<br/>`key encipherment`<br/>`key agreement`<br/>`data encipherment`<br/>`cert sign`<br/>`crl sign`<br/>`encipher only`<br/>`decipher only`<br/>`any`<br/>`server auth`<br/>`client auth`<br/>`code signing`<br/>`email protection`<br/>`ipsec end system`<br/>`ipsec tunnel`<br/>`ipsec user`<br/>`timestamping`<br/>`ocsp signing`<br/>`microsoft sgc`<br/>`netscape sgc` |
| privateKey.encoding        | pkcs8                                       | `pkcs1`<br/>`pkcs8`                                                                                                                                                                                                                                                                                                                                                                                                     |
| privateKey.algorithm       | RSA                                         | `RSA`<br/>`ECDSA`<br/>`Ed25519`                                                                                                                                                                                                                                                                                                                                                                                         |
| privateKey.size            | 2048                                        | for RSA - `2048`,`4096`,`8192`<br/>for ECDSA - `256`, `384`, `521`<br/>`Ed25519`                                                                                                                                                                                                                                                                                                                                        |


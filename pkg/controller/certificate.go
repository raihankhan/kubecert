package controller

import (
	crand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	v1 "github.com/raihankhan/kubecert/api/v1"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/client-go/util/keyutil"
	"math/big"
	"math/rand"
	"time"
)

type certificateOptions struct {
	serialNumber *big.Int
	notBefore    time.Time
	notAfter     time.Time
}

func (r *CertificateReconciler) CreateCertificateAndPrivateKey(cert *v1.Certificate, opts certificateOptions) ([]byte, []byte, error) {
	privateKey, err := generatePrivateKey(cert.Spec.PrivateKey.Algorithm, cert.Spec.PrivateKey.Size)
	if err != nil {
		return nil, nil, err
	}

	signatureAlgoFunc := func() x509.SignatureAlgorithm {
		if cert.Spec.PrivateKey.Algorithm == v1.RSAKeyAlgorithm {
			return x509.SHA256WithRSA
		} else if cert.Spec.PrivateKey.Algorithm == v1.ECDSAKeyAlgorithm {
			return x509.ECDSAWithSHA256
		} else {
			return x509.PureEd25519
		}
	}

	if opts.serialNumber == nil {
		opts.serialNumber = big.NewInt(rand.Int63n(20))
		opts.notAfter = time.Now().Add(time.Duration(*cert.Spec.Duration))
		opts.notBefore = time.Now()
	}

	certTemplate := &x509.Certificate{
		SignatureAlgorithm: signatureAlgoFunc(),
		SerialNumber:       opts.serialNumber,
		Subject: pkix.Name{
			Country:            cert.Spec.Subject.Countries,
			Organization:       cert.Spec.Subject.Organizations,
			OrganizationalUnit: cert.Spec.Subject.OrganizationalUnits,
			Locality:           cert.Spec.Subject.Localities,
			Province:           cert.Spec.Subject.Provinces,
			StreetAddress:      cert.Spec.Subject.StreetAddresses,
			PostalCode:         cert.Spec.Subject.PostalCodes,
			CommonName:         cert.Spec.CommonName,
		},
		NotBefore:      opts.notBefore,
		NotAfter:       opts.notAfter,
		KeyUsage:       getKeyUsages(cert),
		ExtKeyUsage:    getKeyExtUsages(cert),
		IsCA:           true,
		DNSNames:       cert.Spec.DNSNames,
		EmailAddresses: cert.Spec.EmailAddresses,
		IPAddresses:    cert.ConvertStringToIPAddresses(),
		URIs:           cert.ConvertStringToURLs(),
	}

	parentCertTemplate := certTemplate

	// Generate the certificate using the correct public key type
	certDER, err := x509.CreateCertificate(crand.Reader, certTemplate, parentCertTemplate, privateKey.publicKey(), privateKey.privateKey())
	if err != nil {
		return nil, nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: certutil.CertificateBlockType, Bytes: certDER})

	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey.privateKey())
	if err != nil {
		return nil, nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: keyutil.PrivateKeyBlockType, Bytes: keyDER})

	return certPEM, keyPEM, nil
}

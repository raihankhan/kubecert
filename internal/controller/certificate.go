package controller

import (
	crand "crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	v1 "github.com/raihankhan/kubecert/api/v1"
	certutil "k8s.io/client-go/util/cert"
	"math/big"
	"math/rand"
	"time"
)

var (
	keyUsagesList = []v1.KeyUsage{
		"digital signature",
		"content commitment",
		"key encipherment",
		"data encipherment",
		"key agreement",
		"cert sign",
		"crl sign",
		"encipher only",
		"decipher only",
	}
	extKeyUsagesList = []v1.KeyUsage{
		"any",
		"server auth",
		"client auth",
		"code signing",
		"email protection",
		"ipsec end system",
		"ipsec tunnel",
		"ipsec user",
		"timestamping",
		"ocsp signing",
		"microsoft sgc",
		"netscape sgc",
	}
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
		KeyUsage:       r.getKeyUsages(cert),
		ExtKeyUsage:    r.getKeyExtUsages(cert),
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
	keyPEM, err := x509.MarshalPKCS8PrivateKey(privateKey.privateKey())
	if err != nil {
		return nil, nil, err
	}

	return certPEM, keyPEM, nil
}

func (r *CertificateReconciler) getKeyUsages(cert *v1.Certificate) x509.KeyUsage {
	usage := x509.KeyUsage(1)
	for id, UsageInList := range keyUsagesList {
		for _, usageInSpec := range cert.Spec.Usages {
			if usageInSpec == UsageInList {
				usage = usage << id
			}
		}
	}
	return usage
}

func (r *CertificateReconciler) getKeyExtUsages(cert *v1.Certificate) []x509.ExtKeyUsage {
	var usages []x509.ExtKeyUsage
	for id, UsageInList := range extKeyUsagesList {
		for _, usageInSpec := range cert.Spec.Usages {
			if usageInSpec == UsageInList {
				usages = append(usages, x509.ExtKeyUsage(id))
			}
		}
	}
	return usages
}

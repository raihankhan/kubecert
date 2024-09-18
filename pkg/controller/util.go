package controller

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	v1 "github.com/raihankhan/kubecert/api/v1"
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

type PrivateKey interface {
	privateKey() interface{}
	publicKey() interface{}
}

type RSAPrivateKey struct {
	*rsa.PrivateKey
}

func (r *RSAPrivateKey) privateKey() interface{} {
	return r.PrivateKey
}

func (r *RSAPrivateKey) publicKey() interface{} {
	return &r.PrivateKey.PublicKey
}

type ECDSAPrivateKey struct {
	*ecdsa.PrivateKey
}

func (r *ECDSAPrivateKey) privateKey() interface{} {
	return r.PrivateKey
}

func (r *ECDSAPrivateKey) publicKey() interface{} {
	return &r.PrivateKey.PublicKey
}

type Ed25519PrivateKey struct {
	ed25519.PrivateKey
	ed25519.PublicKey
}

func (e *Ed25519PrivateKey) privateKey() interface{} {
	return &e.PrivateKey
}

func (e *Ed25519PrivateKey) publicKey() interface{} {
	return &e.PublicKey
}

func generatePrivateKey(keyType v1.PrivateKeyAlgorithm, size int) (PrivateKey, error) {
	switch keyType {
	case v1.RSAKeyAlgorithm:
		privateKey, err := rsa.GenerateKey(rand.Reader, size)
		if err != nil {
			return nil, err
		}
		return &RSAPrivateKey{privateKey}, nil
	case v1.ECDSAKeyAlgorithm:
		curveFunc := func() elliptic.Curve {
			if size == 384 {
				return elliptic.P384()
			} else if size == 521 {
				return elliptic.P521()
			} else {
				return elliptic.P256()
			}
		}
		privateKey, err := ecdsa.GenerateKey(curveFunc(), rand.Reader)
		if err != nil {
			return nil, err
		}
		return &ECDSAPrivateKey{privateKey}, nil
	case v1.Ed25519KeyAlgorithm:
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		return &Ed25519PrivateKey{privateKey, publicKey}, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s", keyType)
	}
}

func getKeyUsages(cert *v1.Certificate) x509.KeyUsage {
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

func getKeyExtUsages(cert *v1.Certificate) []x509.ExtKeyUsage {
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

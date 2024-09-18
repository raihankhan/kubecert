package controller

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	apiv1 "github.com/raihankhan/kubecert/api/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"time"
)

func (r *CertificateReconciler) ensureSecret(ctx context.Context, cert *apiv1.Certificate) error {
	log := ctrl.LoggerFrom(ctx)

	var isSecretNotFound bool
	var secret corev1.Secret

	secret.ObjectMeta = metav1.ObjectMeta{
		Name:      cert.Spec.SecretRef.Name,
		Namespace: cert.Namespace,
	}

	err := r.Get(ctx, types.NamespacedName{
		Namespace: secret.Namespace,
		Name:      secret.Name,
	}, &secret)
	if err != nil {
		if client.IgnoreNotFound(err) != nil {
			log.Error(err, "Unable to fetch Secret")
			return err
		}
		isSecretNotFound = true
		log.V(3).Info("Secret not found")
	}

	opts := certificateOptions{}

	if !isSecretNotFound {
		certData, exist := secret.Data["tls.crt"]
		if !exist || len(certData) == 0 {
			return errors.New("secret missing the tls.crt file")
		}
		// Parse the PEM-encoded certificate and key
		block, _ := pem.Decode(certData)
		if block == nil {
			return errors.New("certificate block is empty")
		}
		parsedCert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return err
		}
		opts.serialNumber = parsedCert.SerialNumber
		opts.notBefore = parsedCert.NotBefore
		opts.notAfter = parsedCert.NotAfter
	}
	certPEM, privateKeyPEM, err := r.CreateCertificateAndPrivateKey(cert, opts)
	if err != nil {
		return err
	}

	ownerReference := metav1.OwnerReference{
		APIVersion: cert.APIVersion,
		Kind:       cert.Kind,
		Name:       cert.Name,
		UID:        cert.UID,
		Controller: ptr.To(true),
	}

	opsResult, err := controllerutil.CreateOrPatch(ctx, r.Client, &secret, func() error {
		secret.Labels = cert.Spec.SecretTemplate.Labels
		secret.Annotations = cert.Spec.SecretTemplate.Annotations
		secret.Data = map[string][]byte{
			"tls.crt": certPEM,
			"tls.key": privateKeyPEM,
		}
		secret.SetOwnerReferences([]metav1.OwnerReference{ownerReference})
		return nil
	})
	if err != nil {
		return err
	}

	if opsResult == controllerutil.OperationResultCreated {
		log.Info("Secret created")
	}

	return nil
}

func (r *CertificateReconciler) verifySecret(ctx context.Context, cert *apiv1.Certificate) error {
	secret := &corev1.Secret{}
	err := r.Get(ctx, types.NamespacedName{
		Namespace: cert.Namespace,
		Name:      cert.Spec.SecretRef.Name,
	}, secret)
	if err != nil {
		statusErr := r.updateStatusCondition(ctx, cert, apiv1.CertificateCondition{
			Type:               apiv1.CertificateConditionReady,
			Status:             "False",
			LastTransitionTime: &metav1.Time{Time: time.Now()},
			Message:            fmt.Sprintf("Failed to get secret because of %v error", err),
			ObservedGeneration: cert.Generation,
		})
		if statusErr != nil {
			return errors.Join([]error{statusErr, err}...)
		}
		return err
	}

	parsedCert, err := r.verifyCertificateAndKey(secret)
	if err != nil {
		statusErr := r.updateStatusCondition(ctx, cert, apiv1.CertificateCondition{
			Type:               apiv1.CertificateConditionReady,
			Status:             "False",
			LastTransitionTime: &metav1.Time{Time: time.Now()},
			Message:            fmt.Sprintf("Certificates Validations failed because of %v error", err),
			ObservedGeneration: cert.Generation,
		})
		if statusErr != nil {
			return errors.Join([]error{statusErr, err}...)
		}
		return err
	}

	statusErr := r.updateStatusCondition(ctx, cert, apiv1.CertificateCondition{
		Type:               apiv1.CertificateConditionReady,
		Status:             "True",
		LastTransitionTime: &metav1.Time{Time: time.Now()},
		Message:            fmt.Sprint("Secret is ready to use"),
		ObservedGeneration: cert.Generation,
	})

	cert.Status.NotAfter = &metav1.Time{Time: parsedCert.NotAfter}

	if statusErr != nil {
		return statusErr
	}

	return nil
}

func (r *CertificateReconciler) verifyCertificateAndKey(secret *corev1.Secret) (*x509.Certificate, error) {
	var verificationErrors []error

	certData, exist := secret.Data["tls.crt"]
	if !exist || len(certData) == 0 {
		verificationErrors = append(verificationErrors, errors.New("username is missing"))
		return nil, errors.Join(verificationErrors...)
	}

	keyData, exist := secret.Data["tls.key"]
	if !exist || len(keyData) == 0 {
		verificationErrors = append(verificationErrors, errors.New("password is missing"))
		return nil, errors.Join(verificationErrors...)
	}

	// Parse the PEM-encoded certificate and key
	block, _ := pem.Decode(certData)
	if block == nil {
		verificationErrors = append(verificationErrors, errors.New("failed to decode certificate PEM"))
	}
	parsedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		verificationErrors = append(verificationErrors, fmt.Errorf("failed to parse certificate: %w", err))
	}

	// Check if the certificate is expired
	if time.Now().After(parsedCert.NotAfter) {
		// Calculate the number of days since expiration
		daysSinceExpiration := time.Now().Sub(parsedCert.NotAfter).Hours() / 24
		verificationErrors = append(verificationErrors,
			fmt.Errorf("Certificate expired %f days ago\n", daysSinceExpiration))
	}

	if verificationErrors != nil {
		return nil, errors.Join(verificationErrors...)
	}

	return parsedCert, nil
}

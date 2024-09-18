package controller

import (
	"context"
	apiv1 "github.com/raihankhan/kubecert/api/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"time"
)

func (r *CertificateReconciler) updateCertificateStatus(ctx context.Context, cert *apiv1.Certificate) error {
	if cert.Status.Conditions == nil {
		statusErr := r.updateStatusCondition(ctx, cert, apiv1.CertificateCondition{
			Type:               apiv1.CertificateConditionIssuing,
			Status:             "True",
			LastTransitionTime: &metav1.Time{Time: time.Now()},
			Message:            "Certificate is currently issuing",
			ObservedGeneration: cert.Generation,
		})
		if statusErr != nil {
			return statusErr
		}
	}

	for _, condition := range cert.Status.Conditions {
		if condition.Type == apiv1.CertificateConditionReady {
			if condition.Status == "False" {
				statusErr := r.updateStatusCondition(ctx, cert, apiv1.CertificateCondition{
					Type:               apiv1.CertificateConditionIssuing,
					Status:             "True",
					LastTransitionTime: &metav1.Time{Time: time.Now()},
					Message:            "Certificate is currently issuing",
					ObservedGeneration: cert.Generation,
				})
				if statusErr != nil {
					return statusErr
				}
			} else {
				statusErr := r.removeStatusCondition(ctx, cert, apiv1.CertificateConditionIssuing)
				if statusErr != nil {
					return statusErr
				}
			}
		}
	}

	return nil
}

func (r *CertificateReconciler) updateStatusCondition(ctx context.Context, cert *apiv1.Certificate, condition apiv1.CertificateCondition) error {
	log := ctrl.LoggerFrom(ctx)

	var isConditionUpserted, isConditionExists bool
	for index, certificateCondition := range cert.Status.Conditions {
		if certificateCondition.Type == condition.Type {
			isConditionExists = true
			if certificateCondition.Status != condition.Status {
				cert.Status.Conditions[index] = condition
				isConditionUpserted = true
			}
		}
	}
	if !isConditionUpserted && !isConditionExists {
		cert.Status.Conditions = append(cert.Status.Conditions, condition)
	}
	err := r.Status().Update(ctx, cert)
	if err != nil {
		return err
	}

	cert, err = r.getUpdatedCertificate(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: cert.Namespace,
			Name:      cert.Name,
		},
	})
	if err != nil {
		if client.IgnoreNotFound(err) != nil {
			log.Error(err, "Unable to fetch Certificate")
		}
		log.V(3).Info("Certificate not found")
		return err
	}

	return nil
}

func (r *CertificateReconciler) removeStatusCondition(ctx context.Context, cert *apiv1.Certificate, conditionType apiv1.CertificateConditionType) error {
	log := ctrl.LoggerFrom(ctx)

	var isConditionRemoved bool
	for index, certificateCondition := range cert.Status.Conditions {
		if certificateCondition.Type == conditionType {
			cert.Status.Conditions = append(cert.Status.Conditions[:index], cert.Status.Conditions[index+1:]...)
			isConditionRemoved = true
		}
	}

	if isConditionRemoved {
		err := r.Status().Update(ctx, cert)
		if err != nil {
			return err
		}
	}

	cert, err := r.getUpdatedCertificate(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{
			Namespace: cert.Namespace,
			Name:      cert.Name,
		},
	})
	if err != nil {
		if client.IgnoreNotFound(err) != nil {
			log.Error(err, "Unable to fetch Certificate")
		}
		log.V(3).Info("Certificate not found")
		return err
	}

	return nil
}

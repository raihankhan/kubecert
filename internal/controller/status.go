package controller

import (
	"context"
	apiv1 "raihankhan/kubecert/api/v1"
)

func (r *CertificateReconciler) updateStatusCondition(ctx context.Context, cert *apiv1.Certificate, condition apiv1.CertificateCondition) error {
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

	return nil
}

func (r *CertificateReconciler) removeStatusCondition(cert *apiv1.Certificate, conditionType apiv1.CertificateConditionType) {
	for index, certificateCondition := range cert.Status.Conditions {
		if certificateCondition.Type == conditionType {
			cert.Status.Conditions = append(cert.Status.Conditions[:index], cert.Status.Conditions[index+1:]...)
			break
		}
	}
}

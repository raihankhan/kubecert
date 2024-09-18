package controller

import (
	certsv1 "github.com/raihankhan/kubecert/api/v1"
	v1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
)

// SetupWithManager sets up the controller with the Manager.
func (r *CertificateReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&certsv1.Certificate{}).
		Owns(&v1.Secret{}).
		Complete(r)
}

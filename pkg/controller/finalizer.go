package controller

import (
	"context"
	"fmt"
	apiv1 "github.com/raihankhan/kubecert/api/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func (r *CertificateReconciler) ensureFinalizer(ctx context.Context, cert *apiv1.Certificate) error {
	log := ctrl.LoggerFrom(ctx)

	// remove finalizer if object on deletion
	if cert.DeletionTimestamp != nil {
		if controllerutil.ContainsFinalizer(cert, CleanupFinalizer) {
			if controllerutil.RemoveFinalizer(cert, CleanupFinalizer) {
				err := r.Update(ctx, cert)
				if err != nil {
					log.Error(err, "Failed to remove finalizer for the cert")
					return err
				}
				log.Info("Finalizers removed")
			}
		}
	}

	// Add finalizer if it doesn't exist
	if !controllerutil.ContainsFinalizer(cert, CleanupFinalizer) {
		if ok := controllerutil.AddFinalizer(cert, CleanupFinalizer); !ok {
			log.Error(nil, "Failed to add finalizer for the Certificate")
			return fmt.Errorf("failed to add finalizer")
		}
		if err := r.Update(ctx, cert); err != nil {
			return fmt.Errorf("failed to update certificate: %w", err)
		}
		log.Info("Finalizers Added")
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

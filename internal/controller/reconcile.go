/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"fmt"
	apiv1 "github.com/raihankhan/kubecert/api/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"time"
)

const (
	CleanupFinalizer = "certs.k8c.io/cleanup"
)

// CertificateReconciler reconciles a Certificate object
type CertificateReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=certs.k8c.io,resources=certificates,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=certs.k8c.io,resources=certificates/status,verbs=get;list;watch;update;patch;
// +kubebuilder:rbac:groups=certs.k8c.io,resources=certificates/finalizers,verbs=update
// +kubebuilder:rbac:groups=core,resources=secrets,verbs=get;list;watch;create;update;patch;delete

func (r *CertificateReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx)

	log.V(2).Info("reconciling Certificate")

	certificate := &apiv1.Certificate{}
	err := r.Get(ctx, req.NamespacedName, certificate)
	if err != nil {
		if client.IgnoreNotFound(err) != nil {
			log.Error(err, "Unable to fetch Certificate")
		}
		log.V(3).Info("Certificate not found")
		return ctrl.Result{}, nil
	}

	log.V(5).Info("processing", "Certificate", certificate)

	if certificate.DeletionTimestamp != nil {
		if controllerutil.ContainsFinalizer(certificate, CleanupFinalizer) {
			if controllerutil.RemoveFinalizer(certificate, CleanupFinalizer) {
				err := r.Update(ctx, certificate)
				if err != nil {
					log.Error(err, "Failed to remove finalizer for the certificate")
					return ctrl.Result{}, err
				}
			}
			return reconcile.Result{}, nil
		}
	}

	// Add finalizer if it doesn't exist
	if !controllerutil.ContainsFinalizer(certificate, CleanupFinalizer) {
		if ok := controllerutil.AddFinalizer(certificate, CleanupFinalizer); !ok {
			log.Error(nil, "Failed to add finalizer for the Certificate")
			return ctrl.Result{Requeue: true}, nil
		}

		if err := r.Update(ctx, certificate); err != nil {
			return reconcile.Result{}, fmt.Errorf("failed to add finalizer: %w", err)
		}
	}

	err = r.updateCertificateStatus(ctx, certificate)
	if err != nil {
		log.Error(err, "Failed to update the Certificate Status")
		return reconcile.Result{}, err
	}

	certificate, _ = r.getUpdatedCertificate(ctx, req)
	if err != nil {
		if client.IgnoreNotFound(err) != nil {
			log.Error(err, "Unable to fetch Certificate")
		}
		log.V(3).Info("Certificate not found")
		return ctrl.Result{}, nil
	}

	err = r.ensureSecret(ctx, certificate)
	if err != nil {
		log.Error(err, "Failed to ensure secret the Certificate")
		return reconcile.Result{}, err
	}

	err = r.verifySecret(ctx, certificate)
	if err != nil {
		log.Error(err, "Failed to verify secret the Certificate")
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}

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
				r.removeStatusCondition(cert, apiv1.CertificateConditionIssuing)
			}
		}
	}

	err := r.Status().Update(ctx, cert)
	if err != nil {
		return err
	}

	return nil
}

func (r *CertificateReconciler) getUpdatedCertificate(ctx context.Context, req ctrl.Request) (*apiv1.Certificate, error) {
	certificate := &apiv1.Certificate{}
	err := r.Get(ctx, req.NamespacedName, certificate)
	if err != nil {
		return nil, err
	}
	return certificate, nil
}

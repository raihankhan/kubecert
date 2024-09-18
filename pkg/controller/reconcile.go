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
	apiv1 "github.com/raihankhan/kubecert/api/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
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

	// get the certificate object first
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

	// ensure finalizer for the certificate object
	// remove the finalizer if object is on deletion
	err = r.ensureFinalizer(ctx, certificate)
	if err != nil {
		log.Error(err, "Failed to ensure finalizers")
		return reconcile.Result{}, err
	}

	if certificate.DeletionTimestamp != nil {
		log.Info("Aborting Reconcile as object is on deletion")
		return reconcile.Result{}, nil
	}

	// update certificate status
	err = r.updateCertificateStatus(ctx, certificate)
	if err != nil {
		log.Error(err, "Failed to update the Certificate Status")
		return reconcile.Result{}, err
	}

	// create using specs in certificate object
	// if created, make sure they are synced
	err = r.ensureSecret(ctx, certificate)
	if err != nil {
		log.Error(err, "Failed to ensure secret the Certificate")
		return reconcile.Result{}, err
	}

	// verify secret to have both certificate and private key
	// also decode the certificate to check expiry
	err = r.verifySecret(ctx, certificate)
	if err != nil {
		log.Error(err, "Failed to verify secret for the Certificate")
		return reconcile.Result{}, err
	}

	return reconcile.Result{}, nil
}

func (r *CertificateReconciler) getUpdatedCertificate(ctx context.Context, req ctrl.Request) (*apiv1.Certificate, error) {
	certificate := &apiv1.Certificate{}
	err := r.Get(ctx, req.NamespacedName, certificate)
	if err != nil {
		return nil, err
	}
	return certificate, nil
}

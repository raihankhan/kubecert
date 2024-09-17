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

package v1

import (
	"github.com/prometheus/common/model"
	v12 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	validationutils "k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"
	ctrl "sigs.k8s.io/controller-runtime"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
	"time"
)

// log is for logging in this package.
var certificatelog = logf.Log.WithName("certificate-resource")

// SetupWebhookWithManager will setup the manager to manage the webhooks
func (c *Certificate) SetupWebhookWithManager(mgr ctrl.Manager) error {
	return ctrl.NewWebhookManagedBy(mgr).
		For(c).
		Complete()
}

// TODO(user): EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!

// +kubebuilder:webhook:path=/mutate-certs-k8c-io-v1-certificate,mutating=true,failurePolicy=fail,sideEffects=None,groups=certs.k8c.io,resources=certificates,verbs=create;update,versions=v1,name=mcertificate.kb.io,admissionReviewVersions=v1

var _ webhook.Defaulter = &Certificate{}

// Default implements webhook.Defaulter so a webhook will be registered for the type
func (c *Certificate) Default() {
	certificatelog.Info("default", "name", c.Name)

	c.Labels = c.UpdateWithDefaultLabels(c.Labels)

	if c.Spec.SecretRef == nil {
		c.Spec.SecretRef = &v12.LocalObjectReference{
			Name: c.GetSecretName(),
		}
	}

	if c.Spec.SecretTemplate == nil {
		c.Spec.SecretTemplate = &CertificateSecretTemplate{}
	}

	c.Spec.SecretTemplate.Labels = c.UpdateWithDefaultSecretLabels(c.Spec.SecretTemplate.Labels)

	defaultDuration := model.Duration(time.Hour * 24 * 90)
	if c.Spec.Duration == nil {
		c.Spec.Duration = &defaultDuration
	}

	if c.Spec.PrivateKey == nil {
		c.Spec.PrivateKey = &CertificatePrivateKey{}
	}
	if c.Spec.PrivateKey.Algorithm == "" {
		c.Spec.PrivateKey.Algorithm = RSAKeyAlgorithm
	}
	if c.Spec.PrivateKey.Algorithm == RSAKeyAlgorithm {
		if c.Spec.PrivateKey.Size == 0 {
			c.Spec.PrivateKey.Size = 2048
		}
	}
	if c.Spec.PrivateKey.Algorithm == ECDSAKeyAlgorithm {
		if c.Spec.PrivateKey.Size == 0 {
			c.Spec.PrivateKey.Size = 256
		}
	}
	if c.Spec.Usages == nil {
		c.Spec.Usages = []KeyUsage{
			"digital signature",
			"key encipherment",
		}
	}
}

// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
// NOTE: The 'path' attribute must follow a specific pattern and should not be modified directly here.
// Modifying the path for an invalid path can cause API server errors; failing to locate the webhook.
// +kubebuilder:webhook:path=/validate-certs-k8c-io-v1-certificate,mutating=false,failurePolicy=fail,sideEffects=None,groups=certs.k8c.io,resources=certificates,verbs=create;update,versions=v1,name=vcertificate.kb.io,admissionReviewVersions=v1

var _ webhook.Validator = &Certificate{}

// ValidateCreate implements webhook.Validator so a webhook will be registered for the type
func (c *Certificate) ValidateCreate() (admission.Warnings, error) {
	certificatelog.Info("validate create", "name", c.Name)

	return nil, c.validateCertificate()
}

// ValidateUpdate implements webhook.Validator so a webhook will be registered for the type
func (c *Certificate) ValidateUpdate(old runtime.Object) (admission.Warnings, error) {
	certificatelog.Info("validate update", "name", c.Name)

	return nil, c.validateCertificate()
}

// ValidateDelete implements webhook.Validator so a webhook will be registered for the type
func (c *Certificate) ValidateDelete() (admission.Warnings, error) {
	certificatelog.Info("validate delete", "name", c.Name)

	// TODO(user): fill in your validation logic upon object deletion.
	return nil, nil
}

func (c *Certificate) validateCertificate() error {
	var allErrs field.ErrorList
	if err := c.validateCertificateName(); err != nil {
		allErrs = append(allErrs, err)
	}
	if err := c.validateCertificateSpec(); err != nil {
		allErrs = append(allErrs, err)
	}
	if len(allErrs) == 0 {
		return nil
	}

	return apierrors.NewInvalid(
		schema.GroupKind{Group: "certs.k8s.io", Kind: "Certificates"},
		c.Name, allErrs)
}

func (c *Certificate) validateCertificateName() *field.Error {
	if len(c.ObjectMeta.Name) > validationutils.DNS1035LabelMaxLength-11 {
		return field.Invalid(field.NewPath("metadata").Child("name"), c.Name, "must be no more than 52 characters")
	}
	return nil
}

func (c *Certificate) validateCertificateSpec() *field.Error {
	_, err := model.ParseDuration(c.Spec.Duration.String())
	if err != nil {
		return field.Invalid(field.NewPath("spec").Child("duration"), c.Name, error.Error(err))
	}
	if len(c.ObjectMeta.Name) > validationutils.DNS1035LabelMaxLength-11 {
		return field.Invalid(field.NewPath("metadata").Child("name"), c.Name, "must be no more than 52 characters")
	}
	return nil
}

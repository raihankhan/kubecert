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
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// Certificate is the Schema for the certificates API
type Certificate struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CertificateSpec   `json:"spec,omitempty"`
	Status CertificateStatus `json:"status,omitempty"`
}

// CertificateSpec defines the desired state of Certificate.
// A valid Certificate requires at least one of a CommonName, LiteralSubject, DNSName, or URI to be valid.
type CertificateSpec struct {
	// Requested set of X509 certificate subject attributes.
	// The common name attribute is specified separately in the `commonName` field.
	// Cannot be set if the `literalSubject` field is set.
	// +optional
	Subject *Subject `json:"subject,omitempty"`

	// Requested common name X509 certificate subject attribute.
	// +optional
	CommonName string `json:"commonName,omitempty"`

	// Requested 'duration' (i.e. lifetime) of the Certificate.
	// If unset, this defaults to 90 days.
	// Minimum accepted duration is 1 hour.
	// Value must be in units "ms", "s", "m", "h", "d", "w", "y"
	// +optional
	// +kubebuilder:validation:XIntOrString
	Duration *model.Duration `json:"duration,omitempty"`

	// Requested DNS subject alternative names.
	// +optional
	DNSNames []string `json:"dnsNames,omitempty"`

	// Requested IP address subject alternative names.
	// +optional
	IPAddresses []string `json:"ipAddresses,omitempty"`

	// Requested URI subject alternative names.
	// +optional
	URIs []string `json:"uris,omitempty"`

	// Requested email subject alternative names.
	// +optional
	EmailAddresses []string `json:"emailAddresses,omitempty"`

	// Name of the Secret resource that will be automatically created and
	// managed by this Certificate resource. It will be populated with a
	// private key and certificate, signed by itself. The Secret
	// resource lives in the same namespace as the Certificate resource.
	SecretRef *v1.LocalObjectReference `json:"secretRef,omitempty"`

	// Defines annotations and labels to be copied to the Certificate's Secret.
	// Labels and annotations on the Secret will be changed as they appear on the
	// SecretTemplate when added or removed.
	// +optional
	SecretTemplate *CertificateSecretTemplate `json:"secretTemplate,omitempty"`

	// Requested key usages and extended key usages.
	// These usages are used to set the `usages` field on the created X509 certificate.
	// If unset, defaults to `digital signature` and `key encipherment`.
	// +optional
	Usages []KeyUsage `json:"usages,omitempty"`

	// Private key options. These include the key algorithm and size, the used
	// encoding and the rotation policy.
	// +optional
	PrivateKey *CertificatePrivateKey `json:"privateKey,omitempty"`
}

// Subject Full X509 name specification
type Subject struct {
	// Organizations to be used on the Certificate.
	// +optional
	Organizations []string `json:"organizations,omitempty"`
	// Countries to be used on the Certificate.
	// +optional
	Countries []string `json:"countries,omitempty"`
	// Organizational Units to be used on the Certificate.
	// +optional
	OrganizationalUnits []string `json:"organizationalUnits,omitempty"`
	// Cities to be used on the Certificate.
	// +optional
	Localities []string `json:"localities,omitempty"`
	// State/Provinces to be used on the Certificate.
	// +optional
	Provinces []string `json:"provinces,omitempty"`
	// Street addresses to be used on the Certificate.
	// +optional
	StreetAddresses []string `json:"streetAddresses,omitempty"`
	// Postal codes to be used on the Certificate.
	// +optional
	PostalCodes []string `json:"postalCodes,omitempty"`
}

// CertificateSecretTemplate defines the default labels and annotations
// to be copied to the Kubernetes Secret resource named in `CertificateSpec.secretName`.
type CertificateSecretTemplate struct {
	// Annotations is a key value map to be copied to the target Kubernetes Secret.
	// +optional
	Annotations map[string]string `json:"annotations,omitempty"`

	// Labels is a key value map to be copied to the target Kubernetes Secret.
	// +optional
	Labels map[string]string `json:"labels,omitempty"`
}

// CertificatePrivateKey contains configuration options for private keys
// used by the Certificate controller.
// These include the key algorithm and size, the used encoding and the
// rotation policy.
type CertificatePrivateKey struct {
	// RotationPolicy controls how private keys should be regenerated when a
	// re-issuance is being processed.
	//
	// If set to `Never`, a private key will only be generated if one does not
	// already exist in the target `spec.secretName`. If one does exists but it
	// does not have the correct algorithm or size, a warning will be raised
	// to await user intervention.
	// If set to `Always`, a private key matching the specified requirements
	// will be generated whenever a re-issuance occurs.
	// Default is `Never` for backward compatibility.
	// +optional
	RotationPolicy PrivateKeyRotationPolicy `json:"rotationPolicy,omitempty"`

	// The private key cryptography standards (PKCS) encoding for this
	// certificate's private key to be encoded in.
	//
	// If provided, allowed values are `PKCS1` and `PKCS8` standing for PKCS#1
	// and PKCS#8, respectively.
	// Defaults to `PKCS1` if not specified.
	// +optional
	Encoding PrivateKeyEncoding `json:"encoding,omitempty"`

	// Algorithm is the private key algorithm of the corresponding private key
	// for this certificate.
	//
	// If provided, allowed values are either `RSA`, `ECDSA` or `Ed25519`.
	// If `algorithm` is specified and `size` is not provided,
	// key size of 2048 will be used for `RSA` key algorithm and
	// key size of 256 will be used for `ECDSA` key algorithm.
	// key size is ignored when using the `Ed25519` key algorithm.
	// +optional
	Algorithm PrivateKeyAlgorithm `json:"algorithm,omitempty"`

	// Size is the key bit size of the corresponding private key for this certificate.
	//
	// If `algorithm` is set to `RSA`, valid values are `2048`, `4096` or `8192`,
	// and will default to `2048` if not specified.
	// If `algorithm` is set to `ECDSA`, valid values are `256`, `384` or `521`,
	// and will default to `256` if not specified.
	// If `algorithm` is set to
	//, Size is ignored.
	// No other values are allowed.
	// +optional
	Size int `json:"size,omitempty"`
}

// KeyUsage specifies valid usage contexts for keys.
// +kubebuilder:validation:Enum="digital signature";"content commitment";"key encipherment";"key agreement";"data encipherment";"cert sign";"crl sign";"encipher only";"decipher only";"any";"server auth";"client auth";"code signing";"email protection";"ipsec end system";"ipsec tunnel";"ipsec user";"timestamping";"ocsp signing";"microsoft sgc";"netscape sgc"
type KeyUsage string

const (
	UsageDigitalSignature  KeyUsage = "digital signature"
	UsageContentCommitment KeyUsage = "content commitment"
	UsageKeyEncipherment   KeyUsage = "key encipherment"
	UsageKeyAgreement      KeyUsage = "key agreement"
	UsageDataEncipherment  KeyUsage = "data encipherment"
	UsageCertSign          KeyUsage = "cert sign"
	UsageCRLSign           KeyUsage = "crl sign"
	UsageEncipherOnly      KeyUsage = "encipher only"
	UsageDecipherOnly      KeyUsage = "decipher only"
	UsageAny               KeyUsage = "any"
	UsageServerAuth        KeyUsage = "server auth"
	UsageClientAuth        KeyUsage = "client auth"
	UsageCodeSigning       KeyUsage = "code signing"
	UsageEmailProtection   KeyUsage = "email protection"
	UsageIPsecEndSystem    KeyUsage = "ipsec end system"
	UsageIPsecTunnel       KeyUsage = "ipsec tunnel"
	UsageIPsecUser         KeyUsage = "ipsec user"
	UsageTimestamping      KeyUsage = "timestamping"
	UsageOCSPSigning       KeyUsage = "ocsp signing"
	UsageMicrosoftSGC      KeyUsage = "microsoft sgc"
	UsageNetscapeSGC       KeyUsage = "netscape sgc"
)

// Denotes how private keys should be generated or sourced when a Certificate
// is being issued.
// +kubebuilder:validation:Enum=Never;Always
type PrivateKeyRotationPolicy string

var (
	// RotationPolicyNever means a private key will only be generated if one
	// does not already exist in the target `spec.secretName`.
	// If one does exists but it does not have the correct algorithm or size,
	// a warning will be raised to await user intervention.
	RotationPolicyNever PrivateKeyRotationPolicy = "Never"

	// RotationPolicyAlways means a private key matching the specified
	// requirements will be generated whenever a re-issuance occurs.
	RotationPolicyAlways PrivateKeyRotationPolicy = "Always"
)

// +kubebuilder:validation:Enum=RSA;ECDSA;Ed25519
type PrivateKeyAlgorithm string

const (
	// RSA private key algorithm.
	RSAKeyAlgorithm PrivateKeyAlgorithm = "RSA"

	// ECDSA private key algorithm.
	ECDSAKeyAlgorithm PrivateKeyAlgorithm = "ECDSA"

	// Ed25519 private key algorithm.
	Ed25519KeyAlgorithm PrivateKeyAlgorithm = "Ed25519"
)

// +kubebuilder:validation:Enum=PKCS1;PKCS8
type PrivateKeyEncoding string

const (
	// PKCS1 private key encoding.
	// PKCS1 produces a PEM block that contains the private key algorithm
	// in the header and the private key in the body. A key that uses this
	// can be recognised by its `BEGIN RSA PRIVATE KEY` or `BEGIN EC PRIVATE KEY` header.
	// NOTE: This encoding is not supported for Ed25519 keys. Attempting to use
	// this encoding with an Ed25519 key will be ignored and default to PKCS8.
	PKCS1 PrivateKeyEncoding = "PKCS1"

	// PKCS8 private key encoding.
	// PKCS8 produces a PEM block with a static header and both the private
	// key algorithm and the private key in the body. A key that uses this
	// encoding can be recognised by its `BEGIN PRIVATE KEY` header.
	PKCS8 PrivateKeyEncoding = "PKCS8"
)

// CertificateStatus defines the observed state of Certificate
type CertificateStatus struct {
	// List of status conditions to indicate the status of certificates.
	// Known condition types are `Ready` and `Issuing`.
	// +listType=map
	// +listMapKey=type
	// +optional
	Conditions []CertificateCondition `json:"conditions,omitempty"`
	// The expiration time of the certificate stored in the secret named
	// by this resource in `spec.secretName`.
	// +optional
	NotAfter *metav1.Time `json:"notAfter,omitempty"`
}

// CertificateCondition contains condition information for an Certificate.
type CertificateCondition struct {
	// Type of the condition, known values are (`Ready`, `Issuing`).
	Type CertificateConditionType `json:"type"`

	// Status of the condition, one of (`True`, `False`, `Unknown`).
	Status metav1.ConditionStatus `json:"status"`

	// LastTransitionTime is the timestamp corresponding to the last status
	// change of this condition.
	// +optional
	LastTransitionTime *metav1.Time `json:"lastTransitionTime,omitempty"`

	// Message is a description of the details of the last
	// transition, complementing reason.
	// +optional
	Message string `json:"message,omitempty"`

	// If set, this represents the .metadata.generation that the condition was
	// set based upon.
	// For instance, if .metadata.generation is currently 12, but the
	// .status.condition[x].observedGeneration is 9, the condition is out of date
	// with respect to the current state of the Certificate.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// ConditionStatus represents a condition's status.
// +kubebuilder:validation:Enum=True;False;Unknown
type ConditionStatus string

// These are valid condition statuses. "ConditionTrue" means a resource is in
// the condition; "ConditionFalse" means a resource is not in the condition;
// "ConditionUnknown" means kubernetes can't decide if a resource is in the
// condition or not.
const (
	// ConditionTrue represents the fact that a given condition is true
	ConditionTrue ConditionStatus = "True"

	// ConditionFalse represents the fact that a given condition is false
	ConditionFalse ConditionStatus = "False"

	// ConditionUnknown represents the fact that a given condition is unknown
	ConditionUnknown ConditionStatus = "Unknown"
)

// CertificateConditionType represents a Certificate condition value.
// +kubebuilder:validation:Enum=Ready;Issuing
type CertificateConditionType string

const (
	// CertificateConditionReady indicates that a certificate is ready for use.
	// This is defined as:
	// - The target secret exists
	// - The target secret contains a certificate that has not expired
	// - The target secret contains a private key valid for the certificate
	// - The commonName and dnsNames attributes match those specified on the Certificate
	CertificateConditionReady CertificateConditionType = "Ready"

	// CertificateConditionIssuing - A condition added to Certificate resources when an issuance is required.
	CertificateConditionIssuing CertificateConditionType = "Issuing"
)

// +kubebuilder:object:root=true

// CertificateList contains a list of Certificate
type CertificateList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Certificate `json:"items"`
}

func init() {
	SchemeBuilder.Register(&Certificate{}, &CertificateList{})
}

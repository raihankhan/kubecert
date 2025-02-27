{{/*
Expand the name of the chart.
*/}}
{{- define "kubecert-controller.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "kubecert-controller.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "kubecert-controller.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "kubecert-controller.labels" -}}
helm.sh/chart: {{ include "kubecert-controller.chart" . }}
{{ include "kubecert-controller.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "kubecert-controller.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kubecert-controller.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "kubecert-controller.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "kubecert-controller.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Prepare certs
*/}}
{{- define "kubecert-controller.prepare-certs" -}}
{{- if not ._caCrt }}
{{- $caCrt := "" }}
{{- $serverCrt := "" }}
{{- $serverKey := "" }}
{{- if .Values.webhook.servingCerts.generate }}
{{- $ca := genCA "ca" 3650 }}
{{- $cn := include "kubecert-controller.fullname" . -}}
{{- $altName1 := printf "%s.%s" $cn .Release.Namespace }}
{{- $altName2 := printf "%s.%s.svc" $cn .Release.Namespace }}
{{- $server := genSignedCert $cn nil (list $altName1 $altName2) 3650 $ca }}
{{- $caCrt =  b64enc $ca.Cert }}
{{- $serverCrt = b64enc $server.Cert }}
{{- $serverKey = b64enc $server.Key }}
{{- else }}
{{- $caCrt = required "Required when webhook.servingCerts.generate is false" .Values.webhook.servingCerts.caCrt }}
{{- $serverCrt = required "Required when apiserver.servingCerts.generate is false" .Values.webhook.servingCerts.serverCrt }}
{{- $serverKey = required "Required when apiserver.servingCerts.generate is false" .Values.webhook.servingCerts.serverKey }}
{{- end }}
{{- end }}
{{- end }}


{{- define "cerebro.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "cerebro.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "cerebro.serviceAccountName" -}}
{{- if .Values.cerebroService.serviceAccount.create -}}
{{- if .Values.cerebroService.serviceAccount.name -}}
{{- .Values.cerebroService.serviceAccount.name -}}
{{- else -}}
{{- printf "%s-sa" (include "cerebro.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- else -}}
{{- default "default" .Values.cerebroService.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "cerebro.componentName" -}}
{{- $root := index . 0 -}}
{{- $component := index . 1 -}}
{{- printf "%s-%s" (include "cerebro.fullname" $root) $component | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "cerebro.labels" -}}
{{- $root := . -}}
app.kubernetes.io/name: {{ include "cerebro.name" $root }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "cerebro.selectorLabels" -}}
app.kubernetes.io/name: {{ include "cerebro.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "cerebro.configMapName" -}}
{{- printf "%s-config" (include "cerebro.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "tresor.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "tresor.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else if contains (include "tresor.name" .) .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "tresor.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "tresor.selectorLabels" -}}
app.kubernetes.io/name: {{ include "tresor.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "tresor.labels" -}}
{{ include "tresor.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{- define "tresor.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "tresor.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "tresor.stateKind" -}}
{{- (.Values.config.state | default dict).kind | default "" -}}
{{- end -}}

{{/* The service's configuration as rendered: the chart's listen, sqlite's path, the TLS secret's files. */}}
{{- define "tresor.config" -}}
{{- $cfg := deepCopy .Values.config -}}
{{- $_ := set $cfg "listen" "0.0.0.0:8080" -}}
{{- $state := $cfg.state | default dict -}}
{{- if and (eq (include "tresor.stateKind" .) "sqlite") (not $state.path) -}}
{{- $_ := set $state "path" "/var/lib/tresor/tresor.db" -}}
{{- $_ := set $cfg "state" $state -}}
{{- end -}}
{{- if .Values.tlsSecret -}}
{{- $_ := set $cfg "tls" (dict "cert" "/var/run/tresor/tls/tls.crt" "key" "/var/run/tresor/tls/tls.key") -}}
{{- end -}}
{{- toYaml $cfg -}}
{{- end -}}

{{- define "tresor.replicas" -}}
{{- if eq (include "tresor.stateKind" .) "sqlite" -}}1{{- else -}}{{ .Values.replicas }}{{- end -}}
{{- end -}}

{{/* state.password_ref's Secret, when it is a ref+k8s://<namespace>/<secret>/<key>: "namespace secret". */}}
{{- define "tresor.passwordSecret" -}}
{{- $ref := ((.Values.config.state | default dict).password_ref | default "") -}}
{{- if hasPrefix "ref+k8s://" $ref -}}
{{- $parts := splitList "/" (trimPrefix "ref+k8s://" $ref) -}}
{{- if eq (len $parts) 3 -}}{{ index $parts 0 }} {{ index $parts 1 }}{{- end -}}
{{- end -}}
{{- end -}}

{{/* Whether the pod talks to the Kubernetes API: the store, ref+k8s, a password from a Secret. */}}
{{- define "tresor.usesAPI" -}}
{{- $k8s := ((.Values.config.material | default dict).k8s | default dict).allow -}}
{{- if or (eq (include "tresor.stateKind" .) "kubernetes") $k8s (include "tresor.passwordSecret" .) -}}true{{- end -}}
{{- end -}}

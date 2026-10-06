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
{{- $name := .Values.serviceAccount.name | default "" -}}
{{- if .Values.serviceAccount.create -}}
{{- $name = default (include "tresor.fullname" .) $name -}}
{{- end -}}
{{- if or (not $name) (eq $name "default") -}}
{{- fail "serviceAccount.name: the service needs a ServiceAccount of its own - not the namespace's default, which every pod gets" -}}
{{- end -}}
{{- if not (regexMatch "^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$" $name) -}}
{{- fail "serviceAccount.name is a DNS subdomain" -}}
{{- end -}}
{{- $name -}}
{{- end -}}

{{- define "tresor.stateKind" -}}
{{- (.Values.config.state | default dict).kind | default "" -}}
{{- end -}}

{{/* The service's configuration as rendered: the chart's listen, sqlite's path, the TLS secret's files. */}}
{{- define "tresor.config" -}}
{{- $cfg := deepCopy .Values.config -}}
{{- $_ := set $cfg "listen" ":8080" -}}
{{- $state := $cfg.state | default dict -}}
{{- if and (eq (include "tresor.stateKind" .) "sqlite") (not $state.path) -}}
{{- $_ := set $state "path" "/var/lib/tresor/tresor.db" -}}
{{- $_ := set $cfg "state" $state -}}
{{- end -}}
{{- if .Values.tlsSecret -}}
{{- $_ := set $cfg "tls" (dict "cert" "/var/run/tresor/tls/tls.crt" "key" "/var/run/tresor/tls/tls.key") -}}
{{- else if not $cfg.tls -}}
{{- $_ := set $cfg "tls" (dict "offload" true) -}}
{{- end -}}
{{- $vault := $cfg.vault | default dict -}}
{{- $auth := $vault.auth | default dict -}}
{{- if and .Values.vaultToken.enabled (has $auth.method (list "kubernetes" "jwt")) (not $auth.jwt_file) -}}
{{- $_ := set $auth "jwt_file" "/var/run/tresor/vault-token/token" -}}
{{- $_ := set $vault "auth" $auth -}}
{{- $_ := set $cfg "vault" $vault -}}
{{- end -}}
{{- /* named vault sources (spec 008) with a vault: of their own log in with the same token */ -}}
{{- if .Values.vaultToken.enabled -}}
{{- range (($cfg.material | default dict).sources | default list) -}}
{{- $sauth := ((.vault | default dict).auth | default dict) -}}
{{- if and (eq (.kind | default "") "vault") .vault (has $sauth.method (list "kubernetes" "jwt")) (not $sauth.jwt_file) -}}
{{- $_ := set $sauth "jwt_file" "/var/run/tresor/vault-token/token" -}}
{{- $_ := set .vault "auth" $sauth -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if and .Values.localKEK.secretName (not $cfg.keys) -}}
{{- $_ := set $cfg "keys" (dict "kind" "local" "key_file" (printf "/var/run/tresor/kek/%s" .Values.localKEK.key)) -}}
{{- end -}}
{{- /* a previous local KEK (spec 011): read only, until rewrap has moved every data key */ -}}
{{- if and .Values.localKEK.previousSecretName $cfg.keys (not $cfg.keys.previous) -}}
{{- $keys := deepCopy $cfg.keys -}}
{{- $_ := set $keys "previous" (list (dict "kind" "local" "key_file" (printf "/var/run/tresor/kek-previous/%s" (.Values.localKEK.previousKey | default .Values.localKEK.key)))) -}}
{{- $_ := set $cfg "keys" $keys -}}
{{- end -}}
{{- toYaml $cfg -}}
{{- end -}}

{{/* What the service would refuse, or what would not run, refused at the render. */}}
{{- define "tresor.validate" -}}
{{- $kind := include "tresor.stateKind" . -}}
{{- if not (has $kind (list "memory" "sqlite" "postgres" "sqlserver" "kubernetes")) -}}
{{- fail "config.state.kind is memory, sqlite, postgres, sqlserver or kubernetes" -}}
{{- end -}}
{{- if not .Values.config.issuers -}}
{{- fail "config.issuers: at least one issuer is required" -}}
{{- end -}}
{{- $state := .Values.config.state | default dict -}}
{{- if and $state.namespace (ne $state.namespace .Release.Namespace) -}}
{{- fail "config.state.namespace: the chart's RBAC and admission policy are the release's namespace - leave it unset" -}}
{{- end -}}
{{- if and (eq $kind "sqlite") $state.path (not (hasPrefix "/var/lib/tresor/" $state.path)) -}}
{{- fail "config.state.path: under /var/lib/tresor/, the volume (the root filesystem is read-only)" -}}
{{- end -}}
{{- $keys := .Values.config.keys | default dict -}}
{{- if and (ne $kind "memory") (not $keys) (not .Values.localKEK.secretName) -}}
{{- fail "a KEK is required: localKEK.secretName, or config.keys (azurekeyvault, vault)" -}}
{{- end -}}
{{- $vault := .Values.config.vault | default dict -}}
{{- $auth := $vault.auth | default dict -}}
{{- if and (or (eq ($keys.kind | default "") "vault") $auth.method) (not $vault.address) -}}
{{- fail "config.vault.address is required (a vault KEK, config.vault.auth)" -}}
{{- end -}}
{{- /* the logins the chart's token serves: the top-level vault's, and named sources' own (spec 008) */ -}}
{{- $tokenLogin := has ($auth.method | default "") (list "kubernetes" "jwt") -}}
{{- range (((.Values.config.material | default dict).sources | default list)) -}}
{{- if and (eq (.kind | default "") "vault") .vault -}}
{{- $sauth := (.vault.auth | default dict) -}}
{{- if not .vault.address -}}
{{- fail (printf "config.material.sources[%s].vault.address is required" .name) -}}
{{- end -}}
{{- if has ($sauth.method | default "") (list "kubernetes" "jwt") -}}
{{- $tokenLogin = true -}}
{{- end -}}
{{- if and (eq ($sauth.method | default "") "jwt") (not $sauth.jwt_file) (not $.Values.vaultToken.enabled) -}}
{{- fail (printf "config.material.sources[%s].vault.auth.method jwt: vaultToken.enabled (or its jwt_file)" .name) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if and .Values.vaultToken.enabled $auth.jwt_file -}}
{{- fail "vaultToken: config.vault.auth.jwt_file is set - the chart's token would not be read; unset one" -}}
{{- end -}}
{{- if and (eq ($auth.method | default "") "jwt") (not $auth.jwt_file) (not .Values.vaultToken.enabled) -}}
{{- fail "config.vault.auth.method jwt: vaultToken.enabled (or config.vault.auth.jwt_file)" -}}
{{- end -}}
{{- if and .Values.vaultToken.enabled (not $tokenLogin) -}}
{{- fail "vaultToken: for a Vault login by kubernetes or jwt (config.vault.auth, or a named source's)" -}}
{{- end -}}
{{- if and (hasPrefix "/var/run/tresor/kek/" ($keys.key_file | default "")) (not .Values.localKEK.secretName) -}}
{{- fail "config.keys.key_file is under the chart's KEK volume: localKEK.secretName names its Secret" -}}
{{- end -}}
{{- range (((.Values.config.material | default dict).k8s | default dict).allow | default list) -}}
{{- if not .namespace -}}
{{- fail "config.material.k8s.allow: every entry names a namespace" -}}
{{- end -}}
{{- if eq .namespace $.Release.Namespace -}}
{{- fail "config.material.k8s.allow names the service's own namespace: its credentials are there (the service refuses it)" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/* One replica on sqlite (one writer) and memory (each pod's own, lost at its end). */}}
{{- define "tresor.replicas" -}}
{{- if has (include "tresor.stateKind" .) (list "sqlite" "memory") -}}1{{- else -}}{{ .Values.replicas }}{{- end -}}
{{- end -}}

{{/* state.password_ref's Secret, when it is a ref+k8s://<namespace>/<secret>/<key>: "namespace secret". */}}
{{- define "tresor.passwordSecret" -}}
{{- $ref := ((.Values.config.state | default dict).password_ref | default "") -}}
{{- if hasPrefix "ref+k8s://" $ref -}}
{{- $parts := splitList "/" (trimPrefix "ref+k8s://" $ref) -}}
{{- if eq (len $parts) 3 -}}{{ index $parts 0 }} {{ index $parts 1 }}{{- end -}}
{{- end -}}
{{- end -}}

{{/* Whether the pod needs its ServiceAccount token: the store, ref+k8s, a password from a Secret (the Kubernetes
API), or Vault's kubernetes login with no token of its own (vaultToken). */}}
{{- define "tresor.usesAPI" -}}
{{- $k8s := ((.Values.config.material | default dict).k8s | default dict).allow -}}
{{- $auth := ((.Values.config.vault | default dict).auth | default dict) -}}
{{- $vaultPod := and (eq ($auth.method | default "") "kubernetes") (not $auth.jwt_file) (not .Values.vaultToken.enabled) -}}
{{- if not .Values.vaultToken.enabled -}}
{{- range (((.Values.config.material | default dict).sources | default list)) -}}
{{- $sauth := ((.vault | default dict).auth | default dict) -}}
{{- if and (eq (.kind | default "") "vault") (eq ($sauth.method | default "") "kubernetes") (not $sauth.jwt_file) -}}
{{- $vaultPod = true -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if or (eq (include "tresor.stateKind" .) "kubernetes") $k8s (include "tresor.passwordSecret" .) $vaultPod -}}true{{- end -}}
{{- end -}}

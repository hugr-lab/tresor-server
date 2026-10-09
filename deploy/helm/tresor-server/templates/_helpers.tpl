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
{{- if and .Values.localKEK.previousSecretName $keys.previous -}}
{{- $named := false -}}
{{- range $keys.previous -}}{{- if hasPrefix "/var/run/tresor/kek-previous/" (.key_file | default "") -}}{{- $named = true -}}{{- end -}}{{- end -}}
{{- if not $named -}}
{{- fail "localKEK.previousSecretName is mounted at /var/run/tresor/kek-previous/, but config.keys.previous names no file there" -}}
{{- end -}}
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

{{/* The pod's parts the service and the maintenance jobs share (spec 019): one ServiceAccount, configuration,
volumes and environment - a job acts as the service. Each is rendered at column 0, for nindent. */}}
{{- define "tresor.podSecurity" -}}
serviceAccountName: {{ include "tresor.serviceAccountName" . }}
automountServiceAccountToken: {{ include "tresor.usesAPI" . | eq "true" }}
{{- with .Values.imagePullSecrets }}
imagePullSecrets: {{- toYaml . | nindent 2 }}
{{- end }}
securityContext: {{- toYaml .Values.podSecurityContext | nindent 2 }}
{{- end -}}

{{- define "tresor.env" -}}
{{- with .Values.env }}
env: {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.envFrom }}
envFrom: {{- toYaml . | nindent 2 }}
{{- end }}
{{- end -}}

{{- define "tresor.volumeMounts" -}}
{{- $kind := include "tresor.stateKind" . -}}
volumeMounts:
  - {name: config, mountPath: /etc/tresor, readOnly: true}
  - {name: tmp, mountPath: /tmp}
  {{- if .Values.localKEK.secretName }}
  - {name: kek, mountPath: /var/run/tresor/kek, readOnly: true}
  {{- end }}
  {{- if .Values.localKEK.previousSecretName }}
  - {name: kek-previous, mountPath: /var/run/tresor/kek-previous, readOnly: true}
  {{- end }}
  {{- if .Values.tlsSecret }}
  - {name: tls, mountPath: /var/run/tresor/tls, readOnly: true}
  {{- end }}
  {{- if .Values.exchangeToken.enabled }}
  - {name: idp-token, mountPath: /var/run/tresor/idp-token, readOnly: true}
  {{- end }}
  {{- if .Values.vaultToken.enabled }}
  - {name: vault-token, mountPath: /var/run/tresor/vault-token, readOnly: true}
  {{- end }}
  {{- if eq $kind "sqlite" }}
  - {name: data, mountPath: /var/lib/tresor}
  {{- end }}
  {{- with .Values.extraVolumeMounts }}{{ toYaml . | nindent 2 }}{{ end }}
{{- end -}}

{{- define "tresor.volumes" -}}
{{- $kind := include "tresor.stateKind" . -}}
volumes:
  - name: config
    configMap: {name: {{ include "tresor.fullname" . }}}
  - name: tmp
    emptyDir: {}
  {{- if .Values.localKEK.secretName }}
  - name: kek
    secret:
      secretName: {{ .Values.localKEK.secretName }}
      items: [{key: {{ .Values.localKEK.key | quote }}, path: {{ .Values.localKEK.key | quote }}}]
      defaultMode: 0400   # the pod's user reads it as its owner group (fsGroup)
  {{- end }}
  {{- if .Values.localKEK.previousSecretName }}
  {{- $pk := .Values.localKEK.previousKey | default .Values.localKEK.key }}
  - name: kek-previous
    secret:
      secretName: {{ .Values.localKEK.previousSecretName }}
      items: [{key: {{ $pk | quote }}, path: {{ $pk | quote }}}]
      defaultMode: 0400
  {{- end }}
  {{- if .Values.tlsSecret }}
  - name: tls
    secret: {secretName: {{ .Values.tlsSecret }}, defaultMode: 0400}
  {{- end }}
  {{- if .Values.exchangeToken.enabled }}
  - name: idp-token
    projected:
      sources:
        - serviceAccountToken:
            path: token
            audience: {{ required "exchangeToken.audience: the identity provider's" .Values.exchangeToken.audience | quote }}
            expirationSeconds: {{ .Values.exchangeToken.expirationSeconds }}
  {{- end }}
  {{- if .Values.vaultToken.enabled }}
  - name: vault-token
    projected:
      sources:
        - serviceAccountToken:
            path: token
            audience: {{ required "vaultToken.audience: the Vault role's" .Values.vaultToken.audience | quote }}
            expirationSeconds: {{ .Values.vaultToken.expirationSeconds }}
  {{- end }}
  {{- if eq $kind "sqlite" }}
  - name: data
    persistentVolumeClaim: {claimName: {{ include "tresor.fullname" . }}}
  {{- end }}
  {{- with .Values.extraVolumes }}{{ toYaml . | nindent 2 }}{{ end }}
{{- end -}}

{{- define "tresor.scheduling" -}}
{{- with .Values.nodeSelector }}
nodeSelector: {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.tolerations }}
tolerations: {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.affinity }}
affinity: {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.topologySpreadConstraints }}
topologySpreadConstraints: {{- toYaml . | nindent 2 }}
{{- end }}
{{- end -}}

{{/* A maintenance job's spec (spec 019): one command, the service's pod - its identity, configuration and
volumes - with no port, no probe, no retry. Not the service's selector labels: the Service never routes to it. */}}
{{- define "tresor.maintenanceJob" -}}
{{- $ := .root -}}
spec:
  backoffLimit: 0
  activeDeadlineSeconds: {{ $.Values.maintenance.activeDeadlineSeconds }}
  ttlSecondsAfterFinished: 604800
  template:
    metadata:
      labels:
        app.kubernetes.io/instance: {{ $.Release.Name }}
        app.kubernetes.io/component: maintenance
        tresor.hugr-lab.io/command: {{ .name }}
        {{- if $.Values.workloadIdentity.enabled }}
        azure.workload.identity/use: "true"
        {{- end }}
      annotations:
        checksum/config: {{ include "tresor.config" $ | sha256sum }}
    spec:
      restartPolicy: Never
      {{- include "tresor.podSecurity" $ | trim | nindent 6 }}
      containers:
        - name: tresor-server
          image: "{{ $.Values.image.repository }}:{{ $.Values.image.tag | default $.Chart.AppVersion }}"
          imagePullPolicy: {{ $.Values.image.pullPolicy }}
          args: {{ concat .args (list "-config" (.config | default "/etc/tresor/server.yaml")) | toJson }}
          {{- with include "tresor.env" $ | trim }}{{ . | nindent 10 }}{{ end }}
          securityContext: {{- toYaml $.Values.securityContext | nindent 12 }}
          resources: {{- toYaml ($.Values.maintenance.resources | default $.Values.resources) | nindent 12 }}
          {{- include "tresor.volumeMounts" $ | trim | nindent 10 }}
      {{- include "tresor.volumes" $ | trim | nindent 6 }}
      {{- with include "tresor.scheduling" $ | trim }}{{ . | nindent 6 }}{{ end }}
{{- end -}}

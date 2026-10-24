{{- define "llm-proxy.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "llm-proxy.fullname" -}}
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

{{- define "llm-proxy.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "llm-proxy.selectorLabels" -}}
app.kubernetes.io/name: {{ include "llm-proxy.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "llm-proxy.labels" -}}
helm.sh/chart: {{ include "llm-proxy.chart" . }}
{{ include "llm-proxy.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "llm-proxy.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "llm-proxy.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "llm-proxy.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end }}

{{/* The Secret the chart writes for secret.env. Every key becomes an environment variable. */}}
{{- define "llm-proxy.secretName" -}}
{{- include "llm-proxy.fullname" . }}
{{- end }}

{{/*
The Secret that holds the Redis URL. Apart from secret.env, because it is
mounted as a file, not exported as a variable.
*/}}
{{- define "llm-proxy.redisSecretName" -}}
{{- if .Values.sharedStore.existingSecret }}
{{- .Values.sharedStore.existingSecret }}
{{- else }}
{{- printf "%s-redis" (include "llm-proxy.fullname" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "llm-proxy.redisMountDir" -}}
/var/run/llm-proxy/redis
{{- end }}

{{/*
The config file. From `configFile` verbatim, or rendered from `config` with
version, listen, admin and (with sharedStore) auth.store filled in.
*/}}
{{- define "llm-proxy.configFile" -}}
{{- if .Values.configFile }}
{{- .Values.configFile }}
{{- else }}
{{- if not .Values.config }}
{{- fail "set config (the llm-proxy --config file, as YAML) or configFile" }}
{{- end }}
{{- $cfg := deepCopy .Values.config }}
{{- if not (hasKey $cfg "version") }}
{{- $_ := set $cfg "version" 1 }}
{{- end }}
{{- if not (hasKey $cfg "listen") }}
{{- $_ := set $cfg "listen" (printf "0.0.0.0:%d" (int .Values.ports.http)) }}
{{- end }}
{{- if not (hasKey $cfg "admin") }}
{{- $_ := set $cfg "admin" (printf "0.0.0.0:%d" (int .Values.ports.admin)) }}
{{- end }}
{{- if .Values.sharedStore.enabled }}
{{- $auth := get $cfg "auth" }}
{{- if not $auth }}
{{- fail "sharedStore.enabled needs an `auth` block in config: auth.store is part of auth" }}
{{- end }}
{{- if hasKey $auth "store" }}
{{- fail "sharedStore.enabled sets config.auth.store; remove auth.store from config" }}
{{- end }}
{{- $shared := dict "url_file" (printf "%s/%s" (include "llm-proxy.redisMountDir" .) .Values.sharedStore.key) "namespace" (default (include "llm-proxy.fullname" .) .Values.sharedStore.namespace) }}
{{- $_ := set $auth "store" (dict "shared" $shared) }}
{{- end }}
{{- toYaml $cfg }}
{{- end }}
{{- end }}

{{/*
Whether to pass --service-node (see `serviceNode` in values.yaml).
*/}}
{{- define "llm-proxy.passNodeId" -}}
{{- if eq .Values.serviceNode "always" -}}
true
{{- else if eq .Values.serviceNode "auto" -}}
{{- if or .Values.sharedStore.enabled (gt (int .Values.replicaCount) 1) -}}
true
{{- end }}
{{- else if ne .Values.serviceNode "never" -}}
{{- fail (printf "serviceNode must be auto, always or never, not %q" .Values.serviceNode) }}
{{- end }}
{{- end }}

{{- define "llm-proxy.terminationGracePeriodSeconds" -}}
{{- $floor := add (int .Values.preStopSleepSeconds) (int .Values.drain.timeSeconds) }}
{{- if kindIs "invalid" .Values.terminationGracePeriodSeconds }}
{{- add $floor 15 }}
{{- else if lt (int .Values.terminationGracePeriodSeconds) (int $floor) }}
{{- fail (printf "terminationGracePeriodSeconds (%d) must be at least preStopSleepSeconds + drain.timeSeconds (%d): the kubelet would kill streams the drain still allows" (int .Values.terminationGracePeriodSeconds) (int $floor)) }}
{{- else }}
{{- int .Values.terminationGracePeriodSeconds }}
{{- end }}
{{- end }}

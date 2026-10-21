{{- define "rk.name" -}}
{{- .Release.Name | trunc 50 | trimSuffix "-" -}}
{{- end -}}

{{- define "rk.labels" -}}
app.kubernetes.io/name: reality-kernel
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "rk.selector" -}}
app.kubernetes.io/name: reality-kernel
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "rk.image" -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end -}}

{{/* The policy file: profiles, namespace rules, extra policy. */}}
{{- define "rk.policy" -}}
{{ .Values.profiles }}
{{- range $ns, $r := .Values.namespaces }}

[kubernetes.namespaces.{{ $ns }}]
{{- with $r.default }}
default = {{ . | quote }}
{{- end }}
{{- with $r.allowed }}
allowed = [{{ range $i, $p := . }}{{ if $i }}, {{ end }}{{ $p | quote }}{{ end }}]
{{- end }}
{{- end }}
{{ .Values.extraPolicy }}
{{- end -}}

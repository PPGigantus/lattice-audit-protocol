{{- define "lap-gateway.name" -}}
lap-gateway
{{- end -}}

{{- define "lap-gateway.labels" -}}
app.kubernetes.io/name: {{ include "lap-gateway.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

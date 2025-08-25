FROM golang:1.22-alpine AS builder
WORKDIR /app
RUN apk update && apk upgrade --no-cache
COPY . .
RUN go mod init fhirgate-plugin || true
RUN go mod tidy
RUN go build -o fhirgate-plugin main.go

FROM kong:3.9.1
USER root
RUN mkdir -p /kong/go-plugins
COPY --from=builder /app/fhirgate-plugin /kong/go-plugins/fhirgate-plugin
RUN chmod +x /kong/go-plugins/fhirgate-plugin
ENV KONG_GO_PLUGINS_DIR=/kong/go-plugins
ENV KONG_PLUGINS=bundled,fhirgate-plugin
COPY kong.yaml /kong.yaml
COPY kong.yaml /kong/declarative/kong.yaml
ENV KONG_DECLARATIVE_CONFIG=/kong.yaml
ENV KONG_DATABASE=off
ENV KONG_LOG_LEVEL=info
USER kong

# Pluginserver config
ENV KONG_PLUGINSERVER_NAMES=fhirgate-plugin
ENV KONG_PLUGINSERVER_FHIRGATE_PLUGIN_START_CMD=/kong/go-plugins/fhirgate-plugin
ENV KONG_PLUGINSERVER_FHIRGATE_PLUGIN_QUERY_CMD="/kong/go-plugins/fhirgate-plugin -dump"

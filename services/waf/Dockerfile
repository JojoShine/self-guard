FROM golang:1.27.3-alpine AS build
RUN apk add --no-cache gcc musl-dev pcre2-dev=10.49-r0
WORKDIR /src
COPY services/waf/go.mod services/waf/*.go ./
COPY services/waf/testdata ./testdata
RUN go test -tags pcre2 ./... && CGO_ENABLED=1 go build -trimpath -tags pcre2 -o /waf .
FROM alpine:3.24.3 AS runtime
ARG SOURCE_REVISION
LABEL org.opencontainers.image.source="https://github.com/JojoShine/self-guard" org.opencontainers.image.revision=$SOURCE_REVISION org.opencontainers.image.licenses="LicenseRef-SelfGuard-Internal"
RUN apk add --no-cache ca-certificates pcre2=10.49-r0 && adduser -D -u 10001 waf && mkdir /state && chown waf:waf /state
COPY --from=build /waf /waf
USER waf
EXPOSE 8081
ENTRYPOINT ["/waf"]

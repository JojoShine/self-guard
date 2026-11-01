FROM golang:1.27.3-alpine AS build
WORKDIR /src
COPY go.mod *.go ./
RUN CGO_ENABLED=0 go build -o /agent .
FROM alpine:3.24
RUN apk add --no-cache ca-certificates
COPY --from=build /agent /usr/local/bin/agent
ENV AGENT_STATE_DIR=/var/lib/selfguard
VOLUME /var/lib/selfguard
ENTRYPOINT ["agent"]

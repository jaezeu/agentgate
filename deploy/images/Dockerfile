# syntax=docker/dockerfile:1.7
FROM golang:1.24.13-alpine3.23@sha256:8bee1901f1e530bfb4a7850aa7a479d17ae3a18beb6e09064ed54cfd245b7191 AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY cmd ./cmd
COPY internal ./internal
COPY policies ./policies

ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG TERRAFORM_VERSION=1.15.6
RUN CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build -trimpath -ldflags="-s -w" -o /out/agentgate ./cmd/agentgate && \
    CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build -trimpath -ldflags="-s -w" -o /out/agent-sim ./cmd/agent-sim && \
    CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build -trimpath -ldflags="-s -w" -o /out/orchestrator-stub ./cmd/orchestrator-stub
RUN case "${TARGETARCH}" in \
      amd64) terraform_sha256="a7150d3b0e1b5c466ad42e8c499954a3c54645f8b56b385fa025d34f7e88faa9" ;; \
      arm64) terraform_sha256="404c9cfa43728d31005f6e7a848b8a7cc701320067d9d87d8850031a5beb37b0" ;; \
      *) echo "unsupported Terraform architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac && \
    wget -q -O /tmp/terraform.zip \
      "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_${TARGETARCH}.zip" && \
    echo "${terraform_sha256}  /tmp/terraform.zip" | sha256sum -c - && \
    unzip -q /tmp/terraform.zip -d /out && \
    chmod 0755 /out/terraform && \
    rm /tmp/terraform.zip

FROM gcr.io/distroless/static-debian13:nonroot@sha256:f7f8f729987ad0fdf6b05eeeae94b26e6a0f613bdf46feea7fc40f7bd72953e6

COPY --from=build --chown=65532:65532 /out/agentgate /usr/local/bin/agentgate
COPY --from=build --chown=65532:65532 /out/agent-sim /usr/local/bin/agent-sim
COPY --from=build --chown=65532:65532 /out/orchestrator-stub /usr/local/bin/orchestrator-stub
COPY --from=build --chown=65532:65532 /out/terraform /usr/local/bin/terraform

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/agentgate"]

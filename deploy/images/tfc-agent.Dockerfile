# syntax=docker/dockerfile:1.7
FROM --platform=linux/amd64 public.ecr.aws/aws-cli/aws-cli:2.36.1@sha256:e492f7fa148e6cd31ca40ff584b222b7b5fd5554c952d3855d47f220b7fbd0bc AS aws-cli
FROM --platform=linux/amd64 registry.k8s.io/kubectl:v1.36.1@sha256:4247b6241dbcb173a6cc76297b9ada8867e0518ab97cd4abb26123b7965c2730 AS kubectl

FROM --platform=linux/amd64 hashicorp/tfc-agent:1.29.0@sha256:d53f16c18643e645eae1a6677396ccba5466e2251625e7b08171e7662fad12d8

USER root
COPY --from=aws-cli /usr/local/aws-cli /usr/local/aws-cli
COPY --from=aws-cli /usr/local/bin/aws /usr/local/bin/aws
COPY --from=kubectl /bin/kubectl /usr/local/bin/kubectl
RUN chmod 0755 /usr/local/bin/kubectl

USER tfc-agent

FROM alpine:3.21

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

LABEL maintainer="Signet Team" \
  org.label-schema.name="Signet MCP" \
  org.label-schema.vendor="Signet" \
  org.label-schema.schema-version="1.0" \
  org.label-schema.version="${VERSION}"

LABEL org.opencontainers.image.source=https://github.com/go-signet/signet-mcp
LABEL org.opencontainers.image.description="Official MCP server for Signet — OAuth diagnostics and flow-testing tools over streamable HTTP"
LABEL org.opencontainers.image.licenses=MIT
LABEL org.opencontainers.image.version="${VERSION}"

RUN apk add --no-cache ca-certificates wget && \
  rm -rf /var/cache/apk/* && \
  adduser -D -u 1000 signet && \
  mkdir -p /app && \
  chown -R signet:signet /app

COPY release/${TARGETOS}/${TARGETARCH}/signet-mcp /bin/signet-mcp

USER signet

WORKDIR /app

# Expose default HTTP transport port
EXPOSE 8090

# Health check against the unauthenticated liveness endpoint
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8090/healthz || exit 1

# The remote image serves streamable HTTP by default; bind all interfaces so
# the port is reachable through Docker's port mapping.
ENV SIGNET_MCP_TRANSPORT=http \
  SIGNET_MCP_ADDR=:8090

CMD ["/bin/signet-mcp"]

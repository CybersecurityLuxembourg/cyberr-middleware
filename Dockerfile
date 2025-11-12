FROM node:20-alpine
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=8002

# Accept proxy as build arg
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY

# Install CA certificates for HTTPS and DNS utilities for debugging
RUN apk add --no-cache ca-certificates

COPY package.json package-lock.json ./
RUN set -ex && \
    npm --version && \
    node --version && \
    npm ci --omit=dev --loglevel=verbose && \
    ls -la node_modules/ && \
    test -d node_modules/dotenv || (echo "ERROR: dotenv not installed" && exit 1)
COPY server.js ./
EXPOSE 8002
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s CMD wget -qO- http://127.0.0.1:8002/healthz || exit 1
CMD ["node", "server.js"]
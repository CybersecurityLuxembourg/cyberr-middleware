# syntax=docker/dockerfile:1
FROM node:20-alpine
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=8002
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev || npm i --omit=dev
COPY server.js ./
EXPOSE 8002
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s CMD wget -qO- http://127.0.0.1:8002/healthz || exit 1
CMD ["node", "server.js"]
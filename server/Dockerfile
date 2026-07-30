# Vigil DFIR — server image
# Pure-JS deps (winevtx has no native build) + Node's built-in node:sqlite (needs
# Node >=22.5), so a slim Alpine base is still enough — no native toolchain required.
FROM node:22-alpine

WORKDIR /app

# Install deps first (better layer caching). npm ci uses the committed lockfile.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

# App source (node_modules, data/, .git excluded via .dockerignore)
COPY . .

# Cases + rules + detections persist under /data (mount a volume here)
# --max-old-space-size caps the V8 heap so a huge log can't exhaust RAM and hard-crash
# the container; past the detection/cache caps the server streams from disk instead.
ENV NODE_ENV=production \
    PORT=8742 \
    EVTX_DATA=/data \
    NODE_OPTIONS=--max-old-space-size=3072

EXPOSE 8742
VOLUME ["/data"]

# Liveness: the app answers /api/meta as soon as it's up
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- "http://localhost:8742/api/meta" >/dev/null 2>&1 || exit 1

CMD ["node", "server.mjs"]

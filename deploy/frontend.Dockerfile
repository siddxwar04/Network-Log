# The web interface: the built pages served by nginx, which also passes every /api request
# on to the backend container, so the browser talks to one address only.
#
# Built in two stages: Node builds the pages (type check, then Vite, which writes no source
# maps); the final image is nginx with the built files and one config file, and no Node,
# no node_modules and no source.
#
# Built by deploy/compose.yaml from the repository root.

ARG NODE_IMAGE=node:24-slim
ARG NGINX_IMAGE=nginxinc/nginx-unprivileged:stable-alpine

FROM ${NODE_IMAGE} AS build
WORKDIR /src
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend/ ./
RUN npm run build \
    && if find dist -name '*.map' | grep -q .; then echo "source maps found in dist" >&2; exit 1; fi

# This image runs nginx as an unprivileged user (uid 101) and listens on 8080.
FROM ${NGINX_IMAGE}
COPY deploy/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /src/dist /usr/share/nginx/html
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=5s --start-period=10s --retries=5 \
    CMD ["wget", "-q", "-O", "/dev/null", "http://127.0.0.1:8080/healthz"]

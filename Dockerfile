# Build stage: compile the workspace, then prune to production dependencies.
FROM node:22-alpine AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.base.json tsconfig.json ./
COPY packages ./packages
COPY apps ./apps
# `npm run build` also builds the editor, which `tmac serve` needs.
RUN npm ci && npm run build && npm run bundle:editor && npm prune --omit=dev

FROM node:22-alpine
LABEL org.opencontainers.image.title="tmac" \
      org.opencontainers.image.description="Threat models as code" \
      org.opencontainers.image.source="https://github.com/sheltowt/threat_model" \
      org.opencontainers.image.licenses="Apache-2.0"

# Diagrams render through WASM Graphviz, so there is no system graphviz to install
# and no version of it to drift. That is the whole reason for @viz-js/viz.
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/packages ./packages
COPY --from=build /app/apps ./apps
COPY --from=build /app/package.json ./package.json

RUN addgroup -S tmac && adduser -S tmac -G tmac && chown -R tmac:tmac /app
USER tmac
WORKDIR /work

ENTRYPOINT ["node", "/app/apps/cli/dist/index.js"]
CMD ["--help"]

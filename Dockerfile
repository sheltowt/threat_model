# Build stage: compile the workspace, then prune to production dependencies.
FROM node:22-alpine AS build
WORKDIR /app

# Manifests first, so a dependency install is cached across source-only changes.
COPY package.json package-lock.json ./
COPY packages/core/package.json ./packages/core/
COPY packages/rules/package.json ./packages/rules/
COPY packages/render/package.json ./packages/render/
COPY packages/report/package.json ./packages/report/
COPY packages/importers/package.json ./packages/importers/
COPY apps/cli/package.json ./apps/cli/
COPY apps/web/package.json ./apps/web/
RUN npm ci

COPY tsconfig.base.json tsconfig.json ./
# `scripts/` holds the data generator, which `npm run build` runs first. Leaving it
# out is how this image stayed broken from the moment the generator was added: the
# build only fails when somebody actually builds it.
COPY scripts ./scripts
# The editor imports the worked example at build time, so it and the CLI share one
# copy rather than keeping two that drift. Without this the web build cannot resolve
# it and the whole image fails.
COPY examples ./examples
COPY packages ./packages
COPY apps ./apps

# `npm run build` also builds the editor, which `tmac serve` needs.
RUN npm run build && npm run bundle:editor && npm prune --omit=dev

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

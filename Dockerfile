FROM node:24-bookworm AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY tsconfig.json ./
COPY packages packages
COPY apps apps
COPY scripts scripts
RUN npm run build && npm prune --omit=dev
FROM node:24-bookworm-slim
ENV NODE_ENV=production HOST=0.0.0.0
WORKDIR /app
COPY --from=build --chown=node:node /app/dist dist
COPY --from=build --chown=node:node /app/node_modules node_modules
COPY --chown=node:node package.json ./
USER node
EXPOSE 3000
CMD ["node","dist/apps/api/main.js"]

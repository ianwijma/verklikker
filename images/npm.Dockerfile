FROM node:24-bookworm-slim
RUN mkdir /work && chown node:node /work
USER node
WORKDIR /work
ENV npm_config_cache=/tmp/npm-cache
CMD ["node"]

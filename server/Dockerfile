# syntax=docker/dockerfile:1.7
FROM node:20-bookworm-slim
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --include=dev && npm cache clean --force
COPY --chown=1000:1000 *.ts ./
ENV NODE_ENV=production PORT=8081
USER 1000:1000
EXPOSE 8081
CMD ["./node_modules/.bin/ts-node", "./index.ts"]

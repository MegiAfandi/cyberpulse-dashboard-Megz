FROM node:24-bookworm-slim

WORKDIR /app
COPY package.json ./
COPY server.mjs ./
COPY public ./public
COPY tests ./tests

# No third-party dependencies. Fail the build if regression checks fail.
RUN npm test

ENV NODE_ENV=production
ENV HOST=0.0.0.0
ENV PORT=8080
EXPOSE 8080

USER node
CMD ["node", "server.mjs"]

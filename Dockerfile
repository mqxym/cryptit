FROM node:22-slim AS runner

WORKDIR /usr/src/app

COPY package*.json ./
RUN npm ci --omit=dev

COPY dist ./dist

ENV NODE_ENV=production

ENTRYPOINT ["node", "dist/cryptit.cli.js"]
CMD []
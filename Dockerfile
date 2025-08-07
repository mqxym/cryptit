FROM oven/bun:latest AS runner

WORKDIR /app

COPY package*.json ./
COPY bun.lock ./

RUN bun install --production

COPY packages/ ./packages

RUN bun build --compile --external=argon2-browser --outfile=cryptit packages/node-runtime/src/cli.ts

ENTRYPOINT ["/app/cryptit"]
CMD []
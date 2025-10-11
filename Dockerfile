FROM oven/bun:1.3.0-alpine AS builder

WORKDIR /app

COPY package*.json ./
COPY bun.lock* ./

RUN bun install

COPY packages/ ./packages

RUN bun build --compile --outfile=/app/cryptit packages/node-runtime/src/cli.ts


FROM alpine:3.22 AS runner

RUN apk add --no-cache ca-certificates libstdc++ libgcc

WORKDIR /app

RUN addgroup -S app && adduser -S -G app appuser

COPY --from=builder /app/cryptit /app/cryptit

RUN chmod +x /app/cryptit && chown -R appuser:app /app

USER appuser

ENTRYPOINT ["/app/cryptit"]
CMD []
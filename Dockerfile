FROM debian:bookworm-slim AS builder
RUN apt-get update && apt-get install -y --no-install-recommends nasm binutils && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY blog.asm .
RUN nasm -f elf64 blog.asm -o blog.o && ld blog.o -o blog && strip blog

FROM alpine:3.19
RUN apk add --no-cache curl
RUN mkdir -p /data
COPY --from=builder /build/blog /blog
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/ || exit 1
ENTRYPOINT ["/blog"]

# web-asm

A blogging platform written in pure x86-64 assembly. No libc, no libraries, just syscalls.

## Features

- **HTTP server** — Socket creation, request parsing, response generation
- **Flat-file database** — Fixed-size records with hash-indexed storage
- **Bearer token auth** — Constant-time comparison, no brute-force surface
- **TLS-ready** — Designed to run behind reverse proxy (Caddy/nginx)
- **Tiny footprint** — 18KB compiled binary, 84KB memory usage

## Build

```bash
nasm -f elf64 blog.asm -o blog.o
ld blog.o -o blog
```

## Run

```bash
BLOG_TOKEN=your-secret-token-here ./blog
```

Then visit `http://localhost:8080`

Admin page: `http://localhost:8080/admin?token=your-secret-token-here`

## Production Deployment

Run behind a reverse proxy for HTTPS:

```bash
# Using Caddy
caddy reverse-proxy --from yourdomain.com --to localhost:8080
```

Or create a systemd service:

```ini
[Unit]
Description=Assembly Blog
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/blog
Environment="BLOG_TOKEN=your-token-here"
ExecStart=/opt/blog/blog
Restart=always

[Install]
WantedBy=multi-user.target
```

## Database Format

`blog.dat` structure:
- **Header** (8 bytes): Post count
- **Hash index** (2,048 bytes): 256 buckets × 8-byte offsets
- **Records** (4,096 bytes each):
  - Next pointer (8 bytes)
  - Timestamp (8 bytes)
  - Title (256 bytes)
  - Body (3,824 bytes)

## API

**Read (public):**
```bash
curl http://localhost:8080
```

**Post (authenticated):**
```bash
curl -H "Authorization: Bearer <token>" \
  -X POST -d "title=Hello&body=World" \
  http://localhost:8080/post
```

## License

MIT

# web-asm

A blog engine written in pure x86-64 Linux assembly. No libc, no libraries, only syscalls.

## Features

- **HTTP server** — Socket creation, request parsing, response generation
- **Flat-file database** — Fixed-size records with hash-indexed storage
- **Admin dashboard** — Create, edit, delete posts and update bio from the browser
- **Bearer token auth** — Constant-time comparison, no brute-force surface
- **Fork-per-request** — Process isolation with XSS escaping and security headers
- **Configurable name** — Blog name set via `BLOG_NAME` env var
- **Tiny footprint** — ~18KB compiled binary

## Local Development (macOS)

Native build requires Linux x86-64. On macOS, use Docker Desktop:

```bash
docker build --platform linux/amd64 -t blog-dev .
docker run --rm --platform linux/amd64 -p 8080:8080 \
  -e BLOG_TOKEN=dev -e BLOG_NAME="My Blog" \
  -v $(pwd)/data:/data blog-dev
```

- Blog: http://localhost:8080
- Admin: http://localhost:8080/admin?token=dev

## Native Build (Linux only)

```bash
nasm -f elf64 blog.asm -o blog.o && ld blog.o -o blog
BLOG_TOKEN=secret BLOG_NAME="My Blog" ./blog
```

## Environment Variables

| Variable     | Required | Description                              |
|--------------|----------|------------------------------------------|
| `BLOG_TOKEN` | Yes      | Auth token for admin/posting             |
| `BLOG_NAME`  | No       | Blog name in title/header (default: "Assembly Blog") |

## Routes

| Method | Path           | Auth   | Description              |
|--------|----------------|--------|--------------------------|
| GET    | /              | No     | Public blog              |
| GET    | /admin?token=  | Token  | Admin dashboard          |
| GET    | /bio           | No     | Plain text bio           |
| POST   | /post          | Bearer | Create post              |
| POST   | /edit-post     | Form   | Edit existing post       |
| POST   | /delete-post   | Form   | Delete post              |
| POST   | /bio           | Bearer | Update bio (API)         |
| POST   | /update-bio    | Form   | Update bio (form)        |

## Deployment (Kamal)

Copy the example config files and fill in your values:

```bash
cp config/deploy.yml.example config/deploy.yml
cp .kamal/secrets.example .kamal/secrets
# Edit both files with your server IP, Docker Hub username, tokens
kamal setup
```

## Database Format

`/data/blog.dat` structure:
- **Header** (8 bytes): Post count
- **Hash index** (2,048 bytes): 256 buckets x 8-byte offsets
- **Records** (4,096 bytes each): next pointer + timestamp + title + body

Bio stored separately in `/data/bio.txt`.

## License

MIT

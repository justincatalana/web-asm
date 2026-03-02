# Assembly Blog Engine

A blog engine written in pure x86-64 Linux assembly. No libc, no libraries, only syscalls.

## Architecture

- **Single file**: `blog.asm` contains everything — HTTP server, router, HTML templates, database engine
- **Database**: Flat binary file (`/data/blog.dat`) with fixed-size 4096-byte records and a 256-bucket hash index
- **Auth**: Single bearer token via `BLOG_TOKEN` env var, constant-time comparison
- **Blog name**: Configurable via `BLOG_NAME` env var (defaults to "Assembly Blog")
- **Process model**: Fork-per-request with SIGCHLD auto-reap
- **Security**: XSS escaping, security headers, socket timeouts, file locking

## Routes

| Method | Path           | Auth     | Description            |
|--------|----------------|----------|------------------------|
| GET    | /              | No       | Public blog            |
| GET    | /admin?token=  | Token    | Admin dashboard        |
| GET    | /bio           | No       | Plain text bio         |
| POST   | /post          | Bearer   | Create new post        |
| POST   | /edit-post     | Form     | Edit existing post     |
| POST   | /delete-post   | Form     | Delete post (zeroes title) |
| POST   | /bio           | Bearer   | Update bio (API)       |
| POST   | /update-bio    | Form     | Update bio (form)      |

## Local Development (macOS)

Native build requires Linux. Use Docker Desktop:

```bash
docker build --platform linux/amd64 -t blog-dev .
docker run --rm --platform linux/amd64 -p 8080:8080 \
  -e BLOG_TOKEN=dev -e BLOG_NAME="My Blog" \
  -v $(pwd)/data:/data blog-dev
```

Visit http://localhost:8080 and http://localhost:8080/admin?token=dev

## Build (Linux only)

```bash
nasm -f elf64 blog.asm -o blog.o && ld blog.o -o blog
```

## Deployment

Uses Kamal for Docker-based deployment. Copy the example files and fill in your values:

```bash
cp config/deploy.yml.example config/deploy.yml
cp .kamal/secrets.example .kamal/secrets
```

## Database Format

- Header: 8 bytes (post count)
- Hash index: 256 x 8 bytes (bucket offsets)
- Records: 4096 bytes each (next ptr + timestamp + title + body)
- Bio: separate `/data/bio.txt` plain text file

## Key Constraints

- Binary is x86-64 Linux ELF — must target `linux/amd64`
- No libc — all I/O is raw syscalls
- Response buffer is 64KB (`RESP_SIZE 65536`) — limits total page size
- Max 1024 posts (`MAX_POSTS`)
- Titles max 255 bytes, bodies max 3823 bytes

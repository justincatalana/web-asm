; blog.asm - A blog engine in x86-64 Linux assembly
; "Database": flat binary file with fixed-size records + hash index
; Auth: Bearer token from BLOG_TOKEN env var (no brute-force surface)
; HTTPS: Designed to run behind Caddy reverse proxy for auto-TLS
; No libc. No libraries. Only syscalls and regret.
;
; Build:  nasm -f elf64 blog.asm -o blog.o && ld blog.o -o blog
;
; Run (dev):
;   BLOG_TOKEN=my-secret-token-here ./blog
;
; Run (prod with HTTPS via Caddy):
;   ./blog &
;   caddy reverse-proxy --from yourdomain.com --to localhost:8080
;
; Docker:
;   docker run --rm -it --platform linux/amd64 -p 9090:8080 \
;     -e BLOG_TOKEN=my-secret-token-here \
;     -v $(pwd):/src ubuntu:24.04 bash
;
; Read blog:  curl http://localhost:8080
; Admin page: http://localhost:8080/admin?token=my-secret-token-here
; Post (API): curl -H "Authorization: Bearer my-secret-token-here" \
;               -X POST -d "title=Hello&body=World" http://localhost:8080/post
;
; Auth model:
;   - Anyone can read the blog (GET /)
;   - POST /post requires either:
;     (a) Authorization: Bearer <token> header, OR
;     (b) Hidden "token" field in form body (set automatically by /admin page)
;   - /admin?token=<token> shows the posting form only if token matches
;   - Token is a single long secret, no usernames, no passwords, no brute force
;   - Token comparison is constant-time to prevent timing side-channels
;
; Database format (blog.dat):
;   Header:      8 bytes - number of posts (uint64)
;   Hash index:  256 * 8 bytes = 2048 bytes - bucket array (offsets into records)
;   Records:     each record is 4096 bytes:
;                  - 8 bytes: next pointer (for hash chain, 0 = end)
;                  - 8 bytes: timestamp (unix epoch)
;                  - 256 bytes: title (null-terminated)
;                  - 3824 bytes: body (null-terminated)

%define RECORD_SIZE     4096
%define TITLE_OFF       16
%define BODY_OFF        272
%define TITLE_MAX       255
%define BODY_MAX        3823
%define HEADER_SIZE     8
%define INDEX_BUCKETS   256
%define INDEX_SIZE      (INDEX_BUCKETS * 8)
%define DATA_START      (HEADER_SIZE + INDEX_SIZE)
%define MAX_POSTS       1024
%define LISTEN_PORT     0x901F          ; htons(8080)
%define BUF_SIZE        8192
%define RESP_SIZE       65536
%define TOKEN_MAX       256

; syscall numbers
%define SYS_READ        0
%define SYS_WRITE       1
%define SYS_OPEN        2
%define SYS_CLOSE       3
%define SYS_LSEEK       8
%define SYS_SOCKET      41
%define SYS_ACCEPT      43
%define SYS_BIND        49
%define SYS_LISTEN      50
%define SYS_SETSOCKOPT  54
%define SYS_CLOCK_GETTIME 228

; open flags
%define O_RDONLY        0
%define O_WRONLY        1
%define O_RDWR          2
%define O_CREAT         64
%define O_TRUNC         512

section .data
    db_path:     db "/data/blog.dat", 0
    bio_path:    db "/data/bio.txt", 0

    default_bio:
        db 'Served by hand-crafted x86-64 assembly. '
        db 'Database: flat binary file with hash-chained records. '
        db 'No libc. No libraries. Only syscalls.'
    default_bio_len equ $ - default_bio

    env_token:   db "BLOG_TOKEN=", 0
    env_token_len equ $ - env_token - 1

    sockaddr:
        dw 2                    ; AF_INET
        dw LISTEN_PORT
        dd 0x00000000           ; 0.0.0.0 (INADDR_ANY - bind to all interfaces)
        dq 0

    ; Strings for header/URL parsing
    str_bearer:
        db 'Authorization: Bearer ', 0
    str_bearer_len equ $ - str_bearer - 1

    str_get_admin:
        db 'GET /admin', 0
    str_get_admin_len equ $ - str_get_admin - 1

    str_token_eq:
        db 'token=', 0
    str_token_eq_len equ $ - str_token_eq - 1

    str_get_bio:
        db 'GET /bio', 0
    str_get_bio_len equ $ - str_get_bio - 1

    str_post_bio:
        db 'POST /bio', 0
    str_post_bio_len equ $ - str_post_bio - 1

    str_content_length:
        db 'Content-Length: ', 0
    str_content_length_len equ $ - str_content_length - 1

    ; ---- HTML TEMPLATES ----

    html_head:
        db '<!DOCTYPE html><html><head><meta charset="utf-8">'
        db '<title>Justin Catalana</title>'
        db '<style>'
        db 'body{background:#f8f8f8;color:#333;font-family:monospace;'
        db 'max-width:700px;margin:40px auto;padding:0 20px;}'
        db 'h1{color:#2a7fc1;text-shadow:0 0 8px #66b3ff;}'
        db 'h2{color:#00aa55;}'
        db '.post{border:1px solid #ddd;padding:15px;margin:15px 0;'
        db 'background:#fff;box-shadow:0 1px 3px rgba(0,0,0,0.05);}'
        db '.post h3{color:#2a7fc1;margin:0 0 5px 0;}'
        db '.post .ts{color:#888;font-size:0.8em;}'
        db '.post .body{margin-top:10px;white-space:pre-wrap;color:#555;}'
        db 'form{background:#fff;border:1px solid #ddd;padding:20px;margin:20px 0;}'
        db 'input,textarea{width:100%;background:#fff;color:#333;'
        db 'border:1px solid #ccc;padding:8px;margin:5px 0 15px 0;'
        db 'font-family:monospace;box-sizing:border-box;}'
        db 'button{background:#66b3ff;color:#fff;border:none;padding:10px 20px;'
        db 'cursor:pointer;font-family:monospace;font-weight:bold;}'
        db 'button:hover{background:#4da3ff;}'
        db '.hdr{border-bottom:1px solid #ddd;padding-bottom:10px;margin-bottom:20px;}'
        db '.foot{color:#888;margin-top:40px;border-top:1px solid #eee;'
        db 'padding-top:10px;font-size:0.8em;}'
        db '</style></head><body>'
        db '<div class="hdr"><h1>Justin Catalana</h1>'
    html_head_len equ $ - html_head

    html_bio_open:
        db '<p style="color:#777;">'
    html_bio_open_len equ $ - html_bio_open

    html_bio_close:
        db '</p></div>'
    html_bio_close_len equ $ - html_bio_close

    ; Form: split around the token value so we can inject it
    html_form_pre:
        db '<h2>> NEW POST</h2>'
        db '<form method="POST" action="/post">'
        db '<input type="hidden" name="token" value="'
    html_form_pre_len equ $ - html_form_pre

    html_form_post:
        db '">'
        db '<label>TITLE:</label>'
        db '<input type="text" name="title" maxlength="255" required>'
        db '<label>BODY:</label>'
        db '<textarea name="body" rows="8" maxlength="3800" required></textarea>'
        db '<button type="submit">WRITE TO DISK</button>'
        db '</form>'
    html_form_post_len equ $ - html_form_post

    html_post_open:
        db '<div class="post"><h3>'
    html_post_open_len equ $ - html_post_open

    html_title_close:
        db '</h3><div class="ts">epoch: '
    html_title_close_len equ $ - html_title_close

    html_ts_close:
        db '</div><div class="body">'
    html_ts_close_len equ $ - html_ts_close

    html_post_close:
        db '</div></div>'
    html_post_close_len equ $ - html_post_close

    html_tail:
        db '<div class="foot">Justin Catalana // '
        db 'served by x86-64 assembly // '
        db '<a href="https://github.com/justincatalana/web-asm" style="color:#66b3ff;">source</a> // '
        db 'records: '
    html_tail_len equ $ - html_tail

    html_end:
        db ' posts on disk</div></body></html>'
    html_end_len equ $ - html_end

    html_no_posts:
        db '<p style="color:#666;">[no posts yet. the void stares back.]</p>'
    html_no_posts_len equ $ - html_no_posts

    ; ---- HTTP RESPONSES ----

    http_200:
        db 'HTTP/1.1 200 OK', 13, 10
        db 'Content-Type: text/html; charset=utf-8', 13, 10
        db 'Connection: close', 13, 10
        db 'Content-Length: '
    http_200_len equ $ - http_200

    http_302:
        db 'HTTP/1.1 302 Found', 13, 10
        db 'Location: /', 13, 10
        db 'Content-Length: 0', 13, 10
        db 13, 10
    http_302_len equ $ - http_302

    http_401:
        db 'HTTP/1.1 401 Unauthorized', 13, 10
        db 'Content-Type: text/html; charset=utf-8', 13, 10
        db 'Connection: close', 13, 10
        db 'Content-Length: 120', 13, 10
        db 13, 10
        db '<html><body style="background:#0a0a0a;color:#ff4444;'
        db 'font-family:monospace;padding:40px;">'
        db '<h1>401 UNAUTHORIZED</h1></body></html>'
    http_401_len equ $ - http_401

    http_403:
        db 'HTTP/1.1 403 Forbidden', 13, 10
        db 'Content-Type: text/html; charset=utf-8', 13, 10
        db 'Connection: close', 13, 10
        db 'Content-Length: 117', 13, 10
        db 13, 10
        db '<html><body style="background:#0a0a0a;color:#ff4444;'
        db 'font-family:monospace;padding:40px;">'
        db '<h1>403 ACCESS DENIED</h1></body></html>'
    http_403_len equ $ - http_403

    http_503:
        db 'HTTP/1.1 503 Service Unavailable', 13, 10
        db 'Content-Type: text/plain', 13, 10
        db 'Content-Length: 30', 13, 10
        db 13, 10
        db 'NO AUTH TOKEN CONFIGURED', 13, 10, 13, 10
    http_503_len equ $ - http_503

    http_200_plain:
        db 'HTTP/1.1 200 OK', 13, 10
        db 'Content-Type: text/plain; charset=utf-8', 13, 10
        db 'Connection: close', 13, 10
        db 13, 10
    http_200_plain_len equ $ - http_200_plain

    http_200_bio_updated:
        db 'HTTP/1.1 200 OK', 13, 10
        db 'Content-Type: text/plain; charset=utf-8', 13, 10
        db 'Connection: close', 13, 10
        db 'Content-Length: 11', 13, 10
        db 13, 10
        db 'Bio updated'
    http_200_bio_updated_len equ $ - http_200_bio_updated

    http_403_plain:
        db 'HTTP/1.1 403 Forbidden', 13, 10
        db 'Content-Type: text/plain; charset=utf-8', 13, 10
        db 'Connection: close', 13, 10
        db 'Content-Length: 13', 13, 10
        db 13, 10
        db '403 Forbidden'
    http_403_plain_len equ $ - http_403_plain

    crlf: db 13, 10, 13, 10
    crlf_len equ $ - crlf

    startup_msg:
        db 10, '  === Justin Catalana Blog Engine ===', 10
        db '  Pure x86-64 assembly', 10
        db '  Database: blog.dat (binary flat file + hash index)', 10
        db '  Listening on http://localhost:8080', 10
        db '  Auth: Bearer token via BLOG_TOKEN env var', 10
        db '  Admin: /admin?token=<your-token>', 10, 10
    startup_msg_len equ $ - startup_msg

    auth_ok_msg:
        db '  [AUTH] Token loaded from BLOG_TOKEN', 10
    auth_ok_msg_len equ $ - auth_ok_msg

    auth_fail_msg:
        db '  [AUTH] WARNING: BLOG_TOKEN not set! Posting disabled.', 10
    auth_fail_msg_len equ $ - auth_fail_msg

section .bss
    server_fd       resq 1
    db_fd           resq 1
    post_count      resq 1
    read_buf        resb BUF_SIZE
    resp_buf        resb RESP_SIZE
    record_buf      resb RECORD_SIZE
    num_buf         resb 32
    decode_tmp      resb 8
    client_addr     resb 16
    client_len      resq 1
    timespec        resq 2
    dec_title       resb 256
    dec_body        resb 3824
    auth_token      resb TOKEN_MAX
    auth_token_len  resq 1
    auth_enabled    resb 1
    envp_save       resq 1
    bio_buffer      resb 512
    bio_length      resq 1

section .text
    global _start

;; ============================================================
;; ENTRY POINT
;; ============================================================
_start:
    ; Stack on entry: [rsp]=argc, [rsp+8..]=argv, NULL, envp...
    mov rdi, [rsp]              ; argc
    lea rsi, [rsp + 8]          ; argv
    lea rax, [rsi + rdi*8 + 8]  ; envp = past argv + null
    mov [rel envp_save], rax

    ; Startup message
    mov rax, SYS_WRITE
    mov rdi, 1
    lea rsi, [rel startup_msg]
    mov rdx, startup_msg_len
    syscall

    call load_token
    call db_init

    ; Create socket
    mov rax, SYS_SOCKET
    mov rdi, 2
    mov rsi, 1
    xor edx, edx
    syscall
    mov [rel server_fd], rax

    ; SO_REUSEADDR
    mov rax, SYS_SETSOCKOPT
    mov rdi, [rel server_fd]
    mov rsi, 1
    mov rdx, 2
    push qword 1
    mov r10, rsp
    mov r8, 4
    syscall
    pop rax

    ; Bind
    mov rax, SYS_BIND
    mov rdi, [rel server_fd]
    lea rsi, [rel sockaddr]
    mov rdx, 16
    syscall

    ; Listen
    mov rax, SYS_LISTEN
    mov rdi, [rel server_fd]
    mov rsi, 128
    syscall

;; ============================================================
;; MAIN ACCEPT LOOP
;; ============================================================
.accept_loop:
    mov rax, SYS_ACCEPT
    mov rdi, [rel server_fd]
    lea rsi, [rel client_addr]
    lea rdx, [rel client_len]
    mov qword [rdx], 16
    syscall

    test rax, rax
    js .accept_loop

    push rax                    ; client fd

    ; Read request
    mov rax, SYS_READ
    pop rdi
    push rdi
    lea rsi, [rel read_buf]
    mov rdx, BUF_SIZE - 1
    syscall

    test rax, rax
    jle .close_client
    lea rdi, [rel read_buf]
    mov byte [rdi + rax], 0

    ; Route: POST, GET /admin, GET /bio, or public
    cmp byte [rdi], 'P'
    je .check_post_routes

    ; Check GET /bio
    call check_get_bio_route
    test eax, eax
    jnz .handle_get_bio

    call check_admin_route
    test eax, eax
    jnz .route_admin

    ; Public blog (no form)
    mov edi, 0
    call render_blog
    jmp .send_response

.handle_get_bio:
    call load_bio               ; rax = bio ptr, rcx = bio len
    mov r13, rax
    mov r14, rcx

    pop r15                     ; client fd
    mov rax, SYS_WRITE
    mov rdi, r15
    lea rsi, [rel http_200_plain]
    mov rdx, http_200_plain_len
    syscall

    mov rax, SYS_WRITE
    mov rdi, r15
    mov rsi, r13
    mov rdx, r14
    syscall

    mov rax, SYS_CLOSE
    mov rdi, r15
    syscall
    jmp .accept_loop

.check_post_routes:
    ; Check POST /bio
    call check_post_bio_route
    test eax, eax
    jnz .handle_post_bio
    jmp .route_post

.handle_post_bio:
    ; Require auth
    cmp byte [rel auth_enabled], 1
    jne .bio_403

    lea rdi, [rel read_buf]
    call check_post_auth
    test eax, eax
    jz .bio_403

    ; Find Content-Length
    lea rdi, [rel read_buf]
    call find_content_length
    test rax, rax
    jle .close_client
    cmp rax, 500
    ja .close_client
    mov r14, rax                ; content length

    ; Find body
    lea rdi, [rel read_buf]
    call find_body
    test rax, rax
    jz .close_client
    mov r13, rax                ; body pointer

    ; Save bio
    mov rsi, r13
    mov rdx, r14
    call save_bio
    test rax, rax
    js .close_client

    ; Send success
    pop r15                     ; client fd
    mov rax, SYS_WRITE
    mov rdi, r15
    lea rsi, [rel http_200_bio_updated]
    mov rdx, http_200_bio_updated_len
    syscall

    mov rax, SYS_CLOSE
    mov rdi, r15
    syscall
    jmp .accept_loop

.bio_403:
    mov rax, SYS_WRITE
    pop rdi
    push rdi
    lea rsi, [rel http_403_plain]
    mov rdx, http_403_plain_len
    syscall
    jmp .close_client

.route_admin:
    lea rdi, [rel read_buf]
    call check_query_token
    test eax, eax
    jz .send_403

    ; Valid token: render with form
    mov edi, 1
    call render_blog
    jmp .send_response

.route_post:
    cmp byte [rel auth_enabled], 1
    jne .send_503

    lea rdi, [rel read_buf]
    call check_post_auth
    test eax, eax
    jz .send_401

    call handle_post_request

    mov rax, SYS_WRITE
    pop rdi
    push rdi
    lea rsi, [rel http_302]
    mov rdx, http_302_len
    syscall
    jmp .close_client

.send_401:
    mov rax, SYS_WRITE
    pop rdi
    push rdi
    lea rsi, [rel http_401]
    mov rdx, http_401_len
    syscall
    jmp .close_client

.send_403:
    mov rax, SYS_WRITE
    pop rdi
    push rdi
    lea rsi, [rel http_403]
    mov rdx, http_403_len
    syscall
    jmp .close_client

.send_503:
    mov rax, SYS_WRITE
    pop rdi
    push rdi
    lea rsi, [rel http_503]
    mov rdx, http_503_len
    syscall
    jmp .close_client

.send_response:
    mov r14, rax                ; html length
    pop r15                     ; client fd

    mov rax, SYS_WRITE
    mov rdi, r15
    lea rsi, [rel http_200]
    mov rdx, http_200_len
    syscall

    mov rdi, r14
    call uint_to_str
    mov rsi, rax
    mov rdx, rcx
    mov rax, SYS_WRITE
    mov rdi, r15
    syscall

    mov rax, SYS_WRITE
    mov rdi, r15
    lea rsi, [rel crlf]
    mov rdx, crlf_len
    syscall

    mov rax, SYS_WRITE
    mov rdi, r15
    lea rsi, [rel resp_buf]
    mov rdx, r14
    syscall

    mov rax, SYS_CLOSE
    mov rdi, r15
    syscall
    jmp .accept_loop

.close_client:
    mov rax, SYS_CLOSE
    pop rdi
    syscall
    jmp .accept_loop

;; ============================================================
;; LOAD TOKEN FROM ENVIRONMENT
;; ============================================================
load_token:
    push rbx
    push r12

    mov byte [rel auth_enabled], 0

    lea rdi, [rel env_token]
    mov rsi, env_token_len
    call find_env_var
    test rax, rax
    jz .tok_fail

    ; Copy token
    mov rsi, rax
    lea rdi, [rel auth_token]
    mov [rel auth_token_len], rcx
    push rcx
    rep movsb
    mov byte [rdi], 0
    pop rcx

    mov byte [rel auth_enabled], 1

    mov rax, SYS_WRITE
    mov rdi, 1
    lea rsi, [rel auth_ok_msg]
    mov rdx, auth_ok_msg_len
    syscall

    pop r12
    pop rbx
    ret

.tok_fail:
    mov rax, SYS_WRITE
    mov rdi, 1
    lea rsi, [rel auth_fail_msg]
    mov rdx, auth_fail_msg_len
    syscall

    pop r12
    pop rbx
    ret

;; ============================================================
;; FIND_ENV_VAR - search envp for a prefix
;; rdi = prefix, rsi = prefix length
;; Returns: rax = ptr to value, rcx = value length, or rax=0
;; ============================================================
find_env_var:
    push rbx
    push r12
    push r13
    mov r12, rdi
    mov r13, rsi
    mov rbx, [rel envp_save]

.fev_loop:
    mov rdi, [rbx]
    test rdi, rdi
    jz .fev_notfound

    mov rsi, r12
    mov rcx, r13
    push rdi
.fev_cmp:
    test rcx, rcx
    jz .fev_match
    cmpsb
    jne .fev_next
    dec rcx
    jmp .fev_cmp

.fev_next:
    pop rdi
    add rbx, 8
    jmp .fev_loop

.fev_match:
    pop rax
    mov rax, rdi

    xor ecx, ecx
.fev_vlen:
    cmp byte [rax + rcx], 0
    je .fev_done
    inc rcx
    jmp .fev_vlen

.fev_done:
    pop r13
    pop r12
    pop rbx
    ret

.fev_notfound:
    xor eax, eax
    xor ecx, ecx
    pop r13
    pop r12
    pop rbx
    ret

;; ============================================================
;; CHECK_ADMIN_ROUTE - does request start with "GET /admin"?
;; Returns: eax = 1 yes, 0 no
;; ============================================================
check_admin_route:
    lea rdi, [rel read_buf]
    lea rsi, [rel str_get_admin]
    mov rcx, str_get_admin_len
.car_cmp:
    test rcx, rcx
    jz .car_yes
    cmpsb
    jne .car_no
    dec rcx
    jmp .car_cmp
.car_yes:
    mov eax, 1
    ret
.car_no:
    xor eax, eax
    ret

;; ============================================================
;; CHECK_QUERY_TOKEN - find token= in URL query string
;; rdi = request buffer
;; Returns: eax = 1 if matches, 0 if not
;; ============================================================
check_query_token:
    push rbx
    push r12

    mov r12, rdi

    ; Find '?' in request line
.cqt_find_q:
    cmp byte [r12], 0
    je .cqt_fail
    cmp byte [r12], '?'
    je .cqt_found_q
    cmp byte [r12], 13
    je .cqt_fail
    cmp byte [r12], 10
    je .cqt_fail
    inc r12
    jmp .cqt_find_q

.cqt_found_q:
    inc r12

    mov rdi, r12
    lea rsi, [rel str_token_eq]
    call find_param_in_str
    test rax, rax
    jz .cqt_fail

    ; rax=value ptr, rcx=length
    mov rdi, rax
    mov rsi, rcx
    call compare_token
    test eax, eax
    jz .cqt_fail

    mov eax, 1
    pop r12
    pop rbx
    ret

.cqt_fail:
    xor eax, eax
    pop r12
    pop rbx
    ret

;; ============================================================
;; CHECK_POST_AUTH - Bearer header OR form token field
;; rdi = request buffer
;; Returns: eax = 1 authorized, 0 not
;; ============================================================
check_post_auth:
    push rbx
    push r12
    push r13

    mov r12, rdi

    ; Try Authorization: Bearer <token>
    mov r13, r12
.cpa_search_bearer:
    cmp byte [r13], 0
    je .cpa_try_form

    push r13
    mov rdi, r13
    lea rsi, [rel str_bearer]
    mov rcx, str_bearer_len
.cpa_bcmp:
    test rcx, rcx
    jz .cpa_bearer_found
    cmpsb
    jne .cpa_bnext
    dec rcx
    jmp .cpa_bcmp

.cpa_bnext:
    pop r13
    inc r13
    jmp .cpa_search_bearer

.cpa_bearer_found:
    pop r13
    ; rdi = past "Authorization: Bearer "
    mov rax, rdi
    xor ecx, ecx
.cpa_blen:
    movzx edx, byte [rax + rcx]
    test dl, dl
    jz .cpa_bcheck
    cmp dl, 13
    je .cpa_bcheck
    cmp dl, 10
    je .cpa_bcheck
    cmp dl, ' '
    je .cpa_bcheck
    inc rcx
    jmp .cpa_blen

.cpa_bcheck:
    mov rdi, rax
    mov rsi, rcx
    call compare_token
    test eax, eax
    jnz .cpa_success

.cpa_try_form:
    ; Find HTTP body, then token= in form data
    mov rdi, r12
    call find_body
    test rax, rax
    jz .cpa_fail

    mov rdi, rax
    lea rsi, [rel str_token_eq]
    call find_param_in_str
    test rax, rax
    jz .cpa_fail

    mov rdi, rax
    mov rsi, rcx
    call compare_token
    test eax, eax
    jz .cpa_fail

.cpa_success:
    mov eax, 1
    pop r13
    pop r12
    pop rbx
    ret

.cpa_fail:
    xor eax, eax
    pop r13
    pop r12
    pop rbx
    ret

;; ============================================================
;; COMPARE_TOKEN - constant-time comparison
;; rdi = candidate, rsi = candidate length
;; Returns: eax = 1 match, 0 no match
;; ============================================================
compare_token:
    push rbx
    push r12
    push r13

    mov r12, rdi
    mov r13, rsi

    mov rax, [rel auth_token_len]
    xor ebx, ebx               ; difference accumulator

    ; If lengths differ, mark as different but still compare
    cmp r13, rax
    je .ct_same_len
    or ebx, 1
.ct_same_len:

    ; Compare min(candidate_len, token_len) bytes
    mov rcx, r13
    cmp rcx, rax
    jbe .ct_use_len
    mov rcx, rax
.ct_use_len:

    test rcx, rcx
    jz .ct_done

    lea rdi, [rel auth_token]
    xor edx, edx
.ct_loop:
    cmp rdx, rcx
    jge .ct_done
    movzx eax, byte [r12 + rdx]
    xor al, byte [rdi + rdx]
    or bl, al
    inc rdx
    jmp .ct_loop

.ct_done:
    test ebx, ebx
    setz al
    movzx eax, al

    pop r13
    pop r12
    pop rbx
    ret

;; ============================================================
;; DATABASE INIT
;; ============================================================
db_init:
    mov rax, SYS_OPEN
    lea rdi, [rel db_path]
    mov rsi, O_RDWR
    mov rdx, 0644o
    syscall

    test rax, rax
    jns .db_opened

    mov rax, SYS_OPEN
    lea rdi, [rel db_path]
    mov rsi, O_RDWR | O_CREAT | O_TRUNC
    mov rdx, 0644o
    syscall

.db_opened:
    mov [rel db_fd], rax

    mov rax, SYS_LSEEK
    mov rdi, [rel db_fd]
    xor esi, esi
    xor edx, edx
    syscall

    mov rax, SYS_READ
    mov rdi, [rel db_fd]
    lea rsi, [rel post_count]
    mov rdx, 8
    syscall

    cmp rax, 8
    je .db_done

    mov qword [rel post_count], 0

    mov rax, SYS_LSEEK
    mov rdi, [rel db_fd]
    xor esi, esi
    xor edx, edx
    syscall

    mov rax, SYS_WRITE
    mov rdi, [rel db_fd]
    lea rsi, [rel post_count]
    mov rdx, 8
    syscall

    lea rdi, [rel record_buf]
    mov rcx, INDEX_SIZE
    xor al, al
    rep stosb

    mov rax, SYS_WRITE
    mov rdi, [rel db_fd]
    lea rsi, [rel record_buf]
    mov rdx, INDEX_SIZE
    syscall

.db_done:
    ret

;; ============================================================
;; HANDLE POST
;; ============================================================
handle_post_request:
    push rbx
    push r12
    push r13
    push r14
    push r15

    lea rdi, [rel read_buf]
    call find_body
    test rax, rax
    jz .post_done
    mov r12, rax

    ; Parse title=
    mov rdi, r12
    lea rsi, [rel .str_title]
    call find_param_in_str
    test rax, rax
    jz .post_done

    mov rsi, rax
    mov rdx, rcx
    lea rdi, [rel dec_title]
    mov rcx, TITLE_MAX
    call url_decode

    ; Parse body=
    mov rdi, r12
    lea rsi, [rel .str_body]
    call find_param_in_str
    test rax, rax
    jz .post_done

    mov rsi, rax
    mov rdx, rcx
    lea rdi, [rel dec_body]
    mov rcx, BODY_MAX
    call url_decode

    ; Zero out record buffer
    lea rdi, [rel record_buf]
    mov rcx, RECORD_SIZE
    xor al, al
    rep stosb

    ; Timestamp
    mov rax, SYS_CLOCK_GETTIME
    xor edi, edi
    lea rsi, [rel timespec]
    syscall
    mov rax, [rel timespec]
    mov [rel record_buf + 8], rax

    ; Copy title and body into record
    lea rdi, [rel record_buf + TITLE_OFF]
    lea rsi, [rel dec_title]
    mov rcx, TITLE_MAX
    call copy_str

    lea rdi, [rel record_buf + BODY_OFF]
    lea rsi, [rel dec_body]
    mov rcx, BODY_MAX
    call copy_str

    ; Calculate file offset for new record
    mov rax, [rel post_count]
    imul rax, RECORD_SIZE
    add rax, DATA_START
    mov r13, rax

    ; Write record to file
    mov rax, SYS_LSEEK
    mov rdi, [rel db_fd]
    mov rsi, r13
    xor edx, edx
    syscall

    mov rax, SYS_WRITE
    mov rdi, [rel db_fd]
    lea rsi, [rel record_buf]
    mov rdx, RECORD_SIZE
    syscall

    ; Update hash index
    lea rdi, [rel dec_title]
    call djb2_hash
    and eax, (INDEX_BUCKETS - 1)
    mov r14d, eax

    mov eax, r14d
    shl rax, 3
    add rax, HEADER_SIZE
    mov r15, rax

    ; Read old bucket head
    mov rax, SYS_LSEEK
    mov rdi, [rel db_fd]
    mov rsi, r15
    xor edx, edx
    syscall

    sub rsp, 8
    mov rax, SYS_READ
    mov rdi, [rel db_fd]
    mov rsi, rsp
    mov rdx, 8
    syscall
    pop rbx                     ; old head

    ; Write old head as our record's next pointer
    mov rax, SYS_LSEEK
    mov rdi, [rel db_fd]
    mov rsi, r13
    xor edx, edx
    syscall

    mov [rel record_buf], rbx
    mov rax, SYS_WRITE
    mov rdi, [rel db_fd]
    lea rsi, [rel record_buf]
    mov rdx, 8
    syscall

    ; Point bucket to our record
    mov rax, SYS_LSEEK
    mov rdi, [rel db_fd]
    mov rsi, r15
    xor edx, edx
    syscall

    push r13
    mov rax, SYS_WRITE
    mov rdi, [rel db_fd]
    mov rsi, rsp
    mov rdx, 8
    syscall
    pop rax

    ; Increment post count
    inc qword [rel post_count]
    mov rax, SYS_LSEEK
    mov rdi, [rel db_fd]
    xor esi, esi
    xor edx, edx
    syscall

    mov rax, SYS_WRITE
    mov rdi, [rel db_fd]
    lea rsi, [rel post_count]
    mov rdx, 8
    syscall

.post_done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

.str_title: db 'title=', 0
.str_body:  db 'body=', 0

;; ============================================================
;; RENDER BLOG
;; edi = 1 show form (admin), 0 public
;; Returns: rax = HTML length in resp_buf
;; ============================================================
render_blog:
    push rbx
    push r12
    push r13
    push r14
    push r15

    mov ebx, edi
    lea r12, [rel resp_buf]

    lea rsi, [rel html_head]
    mov rcx, html_head_len
    call append_to_resp

    ; Dynamic bio
    lea rsi, [rel html_bio_open]
    mov rcx, html_bio_open_len
    call append_to_resp

    call load_bio               ; rax = bio ptr, rcx = bio len
    mov rsi, rax
    call append_to_resp

    lea rsi, [rel html_bio_close]
    mov rcx, html_bio_close_len
    call append_to_resp

    ; Form only if admin
    test ebx, ebx
    jz .skip_form

    lea rsi, [rel html_form_pre]
    mov rcx, html_form_pre_len
    call append_to_resp

    ; Inject token value
    lea rsi, [rel auth_token]
    mov rcx, [rel auth_token_len]
    call append_to_resp

    lea rsi, [rel html_form_post]
    mov rcx, html_form_post_len
    call append_to_resp

.skip_form:
    mov r13, [rel post_count]
    test r13, r13
    jnz .has_posts

    lea rsi, [rel html_no_posts]
    mov rcx, html_no_posts_len
    call append_to_resp
    jmp .render_tail

.has_posts:
    mov r14, r13
    dec r14

.render_loop:
    mov rax, r14
    imul rax, RECORD_SIZE
    add rax, DATA_START

    push rax
    mov rax, SYS_LSEEK
    mov rdi, [rel db_fd]
    pop rsi
    xor edx, edx
    syscall

    mov rax, SYS_READ
    mov rdi, [rel db_fd]
    lea rsi, [rel record_buf]
    mov rdx, RECORD_SIZE
    syscall

    lea rsi, [rel html_post_open]
    mov rcx, html_post_open_len
    call append_to_resp

    lea rsi, [rel record_buf + TITLE_OFF]
    call strlen_safe
    call append_to_resp

    lea rsi, [rel html_title_close]
    mov rcx, html_title_close_len
    call append_to_resp

    mov rdi, [rel record_buf + 8]
    call uint_to_str
    mov rsi, rax
    call append_to_resp

    lea rsi, [rel html_ts_close]
    mov rcx, html_ts_close_len
    call append_to_resp

    lea rsi, [rel record_buf + BODY_OFF]
    call strlen_safe
    call append_to_resp

    lea rsi, [rel html_post_close]
    mov rcx, html_post_close_len
    call append_to_resp

    dec r14
    test r14, r14
    jns .render_loop

.render_tail:
    lea rsi, [rel html_tail]
    mov rcx, html_tail_len
    call append_to_resp

    mov rdi, [rel post_count]
    call uint_to_str
    mov rsi, rax
    call append_to_resp

    lea rsi, [rel html_end]
    mov rcx, html_end_len
    call append_to_resp

    lea rax, [rel resp_buf]
    sub r12, rax
    mov rax, r12

    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    ret

;; ============================================================
;; CHECK_GET_BIO_ROUTE - does request start with "GET /bio"?
;; Returns: eax = 1 yes, 0 no
;; ============================================================
check_get_bio_route:
    lea rdi, [rel read_buf]
    lea rsi, [rel str_get_bio]
    mov rcx, str_get_bio_len
.cgbr_cmp:
    test rcx, rcx
    jz .cgbr_yes
    cmpsb
    jne .cgbr_no
    dec rcx
    jmp .cgbr_cmp
.cgbr_yes:
    mov eax, 1
    ret
.cgbr_no:
    xor eax, eax
    ret

;; ============================================================
;; CHECK_POST_BIO_ROUTE - does request start with "POST /bio"?
;; Returns: eax = 1 yes, 0 no
;; ============================================================
check_post_bio_route:
    lea rdi, [rel read_buf]
    lea rsi, [rel str_post_bio]
    mov rcx, str_post_bio_len
.cpbr_cmp:
    test rcx, rcx
    jz .cpbr_yes
    cmpsb
    jne .cpbr_no
    dec rcx
    jmp .cpbr_cmp
.cpbr_yes:
    mov eax, 1
    ret
.cpbr_no:
    xor eax, eax
    ret

;; ============================================================
;; LOAD_BIO - Read bio from /data/bio.txt or use default
;; Returns: rax = bio text pointer, rcx = bio length
;; ============================================================
load_bio:
    push rbx
    push r12

    ; Open /data/bio.txt
    mov rax, SYS_OPEN
    lea rdi, [rel bio_path]
    xor esi, esi                ; O_RDONLY
    xor edx, edx
    syscall
    test rax, rax
    js .lb_default              ; File doesn't exist

    mov r12, rax                ; save fd

    ; Read file
    mov rax, SYS_READ
    mov rdi, r12
    lea rsi, [rel bio_buffer]
    mov rdx, 500
    syscall

    test rax, rax
    jle .lb_close_default       ; Read failed or empty

    mov rbx, rax                ; save length
    mov [rel bio_length], rax

    ; Close file
    mov rax, SYS_CLOSE
    mov rdi, r12
    syscall

    ; Return bio buffer
    lea rax, [rel bio_buffer]
    mov rcx, rbx
    pop r12
    pop rbx
    ret

.lb_close_default:
    mov rax, SYS_CLOSE
    mov rdi, r12
    syscall

.lb_default:
    lea rax, [rel default_bio]
    mov rcx, default_bio_len
    pop r12
    pop rbx
    ret

;; ============================================================
;; SAVE_BIO - Write bio to /data/bio.txt
;; rsi = bio text pointer, rdx = bio length
;; Returns: rax = 0 on success, -1 on error
;; ============================================================
save_bio:
    push rbx
    push r12
    push r13

    mov r12, rsi                ; bio text pointer
    mov r13, rdx                ; bio length

    ; Open/create file (O_WRONLY | O_CREAT | O_TRUNC = 1|64|512 = 577)
    mov rax, SYS_OPEN
    lea rdi, [rel bio_path]
    mov esi, 577
    mov rdx, 0644o
    syscall
    test rax, rax
    js .sb_error

    mov rbx, rax                ; save fd

    ; Write bio
    mov rax, SYS_WRITE
    mov rdi, rbx
    mov rsi, r12
    mov rdx, r13
    syscall

    ; Close file
    mov rax, SYS_CLOSE
    mov rdi, rbx
    syscall

    xor eax, eax                ; success
    pop r13
    pop r12
    pop rbx
    ret

.sb_error:
    mov rax, -1
    pop r13
    pop r12
    pop rbx
    ret

;; ============================================================
;; FIND_CONTENT_LENGTH - parse Content-Length header value
;; rdi = request buffer
;; Returns: rax = content length as integer, 0 if not found
;; ============================================================
find_content_length:
    push rbx
    push r12
    mov r12, rdi

.fcl_search:
    cmp byte [r12], 0
    je .fcl_notfound

    mov rdi, r12
    lea rsi, [rel str_content_length]
    mov rcx, str_content_length_len
.fcl_cmp:
    test rcx, rcx
    jz .fcl_found
    cmpsb
    jne .fcl_next
    dec rcx
    jmp .fcl_cmp

.fcl_next:
    inc r12
    jmp .fcl_search

.fcl_found:
    ; rdi points past "Content-Length: " - parse decimal number
    xor rax, rax
    mov rbx, 10
.fcl_parse:
    movzx ecx, byte [rdi]
    cmp cl, '0'
    jb .fcl_done
    cmp cl, '9'
    ja .fcl_done
    imul rax, rbx
    sub cl, '0'
    movzx ecx, cl
    add rax, rcx
    inc rdi
    jmp .fcl_parse

.fcl_done:
    pop r12
    pop rbx
    ret

.fcl_notfound:
    xor eax, eax
    pop r12
    pop rbx
    ret

;; ============================================================
;; UTILITIES
;; ============================================================

append_to_resp:
    lea rax, [rel resp_buf]
    add rax, RESP_SIZE - 256
    cmp r12, rax
    jae .skip_append
    mov rdi, r12
    rep movsb
    mov r12, rdi
.skip_append:
    ret

strlen_safe:
    push rdi
    mov rdi, rsi
    xor rcx, rcx
.sl_loop:
    cmp byte [rdi + rcx], 0
    je .sl_done
    inc rcx
    cmp rcx, 4000
    jb .sl_loop
.sl_done:
    pop rdi
    ret

uint_to_str:
    push rbx
    push r12

    lea r12, [rel num_buf]
    mov qword [r12], 0
    mov qword [r12+8], 0
    mov qword [r12+16], 0
    mov qword [r12+24], 0

    mov rax, rdi
    mov rbx, 10
    lea r8, [rel num_buf + 30]

    test rax, rax
    jnz .uts_loop
    mov byte [r8], '0'
    mov rax, r8
    mov rcx, 1
    pop r12
    pop rbx
    ret

.uts_loop:
    test rax, rax
    jz .uts_done
    xor edx, edx
    div rbx
    add dl, '0'
    mov byte [r8], dl
    dec r8
    jmp .uts_loop

.uts_done:
    inc r8
    mov rax, r8
    lea rcx, [rel num_buf + 31]
    sub rcx, r8
    pop r12
    pop rbx
    ret

find_body:
    push rbx
.fb_loop:
    cmp byte [rdi], 0
    je .fb_notfound
    cmp byte [rdi], 13
    jne .fb_next
    cmp byte [rdi+1], 10
    jne .fb_next
    cmp byte [rdi+2], 13
    jne .fb_next
    cmp byte [rdi+3], 10
    jne .fb_next
    lea rax, [rdi+4]
    pop rbx
    ret
.fb_next:
    inc rdi
    jmp .fb_loop
.fb_notfound:
    xor eax, eax
    pop rbx
    ret

find_param_in_str:
    push rbx
    push r12
    push r13
    mov r12, rdi
    mov r13, rsi

    mov rbx, r13
    xor ecx, ecx
.fpis_plen:
    cmp byte [rbx + rcx], 0
    je .fpis_search
    inc rcx
    jmp .fpis_plen

.fpis_search:
    mov r8, rcx
    mov rdi, r12

.fpis_outer:
    cmp byte [rdi], 0
    je .fpis_notfound

    xor ecx, ecx
.fpis_match:
    cmp rcx, r8
    je .fpis_found
    movzx eax, byte [rdi + rcx]
    cmp al, byte [rbx + rcx]
    jne .fpis_skip
    inc rcx
    jmp .fpis_match

.fpis_skip:
    inc rdi
    jmp .fpis_outer

.fpis_found:
    lea rax, [rdi + r8]
    xor ecx, ecx
.fpis_vlen:
    movzx edx, byte [rax + rcx]
    test dl, dl
    jz .fpis_vdone
    cmp dl, '&'
    je .fpis_vdone
    cmp dl, ' '
    je .fpis_vdone
    cmp dl, 13
    je .fpis_vdone
    cmp dl, 10
    je .fpis_vdone
    inc rcx
    jmp .fpis_vlen
.fpis_vdone:
    pop r13
    pop r12
    pop rbx
    ret

.fpis_notfound:
    xor eax, eax
    xor ecx, ecx
    pop r13
    pop r12
    pop rbx
    ret

url_decode:
    push rbx
    push r12
    push r13
    mov r12, rdx
    mov r13, rcx
    xor ecx, ecx
    xor ebx, ebx

.ud_loop:
    cmp rcx, r12
    jge .ud_done
    cmp rbx, r13
    jge .ud_done

    movzx eax, byte [rsi + rcx]

    cmp al, '+'
    jne .ud_not_plus
    mov byte [rdi + rbx], ' '
    inc rcx
    inc rbx
    jmp .ud_loop

.ud_not_plus:
    cmp al, '%'
    jne .ud_literal
    lea rax, [rcx + 2]
    cmp rax, r12
    jg .ud_literal

    inc rcx
    movzx eax, byte [rsi + rcx]
    call hex_digit
    shl al, 4
    mov r8b, al
    inc rcx
    movzx eax, byte [rsi + rcx]
    call hex_digit
    or al, r8b
    mov byte [rdi + rbx], al
    inc rcx
    inc rbx
    jmp .ud_loop

.ud_literal:
    mov byte [rdi + rbx], al
    inc rcx
    inc rbx
    jmp .ud_loop

.ud_done:
    mov byte [rdi + rbx], 0
    pop r13
    pop r12
    pop rbx
    ret

hex_digit:
    cmp al, '9'
    jle .hd_num
    cmp al, 'F'
    jle .hd_upper
    sub al, 'a'
    add al, 10
    ret
.hd_upper:
    sub al, 'A'
    add al, 10
    ret
.hd_num:
    sub al, '0'
    ret

djb2_hash:
    mov eax, 5381
.dh_loop:
    movzx ecx, byte [rdi]
    test cl, cl
    jz .dh_done
    imul eax, 33
    add eax, ecx
    inc rdi
    jmp .dh_loop
.dh_done:
    ret

copy_str:
.cs_loop:
    test rcx, rcx
    jz .cs_done
    lodsb
    test al, al
    jz .cs_done
    stosb
    dec rcx
    jmp .cs_loop
.cs_done:
    mov byte [rdi], 0
    ret

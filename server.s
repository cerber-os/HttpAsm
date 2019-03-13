;; server.s
;; Basic HTTP server written in x86_64 assembly
;;

segment .text
  global _start

;; exit_success
exit_success:
  mov rax, SYS_EXIT
  mov rdi, 0
  syscall
  ret

;; exit_error
exit_error:
  mov rax, SYS_EXIT
  mov rdi, 1
  syscall
  ret

;; strlen
;; returns string length
strlen:
  mov rcx, 0
  .len:
    cmp byte[rdi+rcx], 0
    je .end
    add rcx, 1
    jmp .len
  .end:
  mov rax, rcx
  ret

;; strncmp
;; compares two strings at max n bits; return 0 if equal
strncmp:
  mov rcx, 0
  mov rax, 0
  .lp:
    cmp rcx, rdx
    je .end
    movzx r8, byte[rdi+rcx]
    movzx r9, byte[rsi+rcx]
    cmp r8, r9
    jnz .bad_end
    add rcx, 1
    jmp .lp
  .bad_end:
    mov rax, 1
  .end:
    ret

;; abort
;; stops program with optional error message
abort:
  cmp rdi, 0
  je .exit
    call strlen
    mov r8, rax

    mov rax, SYS_WRITE
    mov rsi, rdi
    mov rdi, 1
    mov rdx, r8
    syscall
  .exit:
    call exit_error
    ret

;; open_socket
open_socket:
  mov rax, SYS_SOCKET
  mov rdi, 2
  xor rsi, 1
  xor rdx, rdx
  syscall

  cmp rax, 0
  jge .exit
    mov rdi, socket_open_error
    call abort
  .exit:
    ret

;; bind_socket
bind_socket:
  mov rax, SYS_BIND
  mov rsi, SOCKADDR_STRUCT
  mov rdx, SOCKADDR_STRUCT_LENGTH
  syscall

  cmp rax, 0
  jge .exit
    mov rdi, socket_bind_error
    call abort
  .exit:
    ret

;; listen_socket
listen_socket:
  mov rax, SYS_LISTEN
  mov rsi, 5          ;; Max number of clients in queue
  syscall
  ret

;; accept_socket
accept_socket:
  mov rax, SYS_ACCEPT
  xor rsi, rsi
  xor rdx, rdx
  syscall

  cmp rax, 0
  jge .exit
    mov rdi, socket_accept_error
    call abort
  .exit:
    ret

;; shutdown_socket
shutdown_socket:
  mov rax, SYS_SHUTDOWN
  mov rsi, 1
  syscall
  ret

;; close_socket
close_socket:
  mov rax, SYS_CLOSE
  syscall
  ret

;; read
read:
  mov rax, SYS_READ
  syscall
  ret

;; write_str
write_str:
  mov r8, rdi
  mov rdi, rsi
  call strlen

  mov rdx, rax
  mov rax, SYS_WRITE
  mov rdi, r8
  syscall
  ret

;; open_file
open_file:
  mov rax, SYS_OPEN
  xor rsi, rsi
  xor rdx, rdx
  syscall

  cmp rax, 0
  jge .exit
    mov rdi, file_open_error
    call abort
  .exit:
    ret

;; file_exists
file_exists:
  mov rax, SYS_OPEN
  mov rsi, 1
  xor rdx, rdx
  syscall

  cmp rax, 0
  jl .exit
    mov rdi, rax
    mov rax, SYS_CLOSE
    syscall
    mov rax, 1
  .exit:
    ret

;; HTTP server logic

;; http_reponse
var_fd_client       equ -8
var_file_name       equ -16
var_error_code      equ -24
var_file_buffer     equ -152      ;; Buffer of size 128 bytes
http_response:
  enter 152, 0
    mov qword[rbp+var_fd_client], rdi
    mov qword[rbp+var_file_name], rsi
    mov qword[rbp+var_error_code], rdx

    mov rdi, rsi
    call open_file
    mov r15, rax

    ;; Send http header
    cmp qword[rbp+var_error_code], 200
    je .http_200
    cmp qword[rbp+var_error_code], 400
    je .http_400
    cmp qword[rbp+var_error_code], 403
    je .http_403
    cmp qword[rbp+var_error_code], 404
    je .http_404
    cmp qword[rbp+var_error_code], 413
    je .http_413
    .http_other:
      mov rdi, http_header_error
      call abort
    .http_200:
      mov rdi, qword[rbp+var_fd_client]
      mov rsi, http_header_200
      call write_str
      jmp .header
    .http_400:
      mov rdi, qword[rbp+var_fd_client]
      mov rsi, http_header_400
      call write_str
      jmp .header
    .http_403:
      mov rdi, qword[rbp+var_fd_client]
      mov rsi, http_header_403
      call write_str
      jmp .header
    .http_404:
      mov rdi, qword[rbp+var_fd_client]
      mov rsi, http_header_404
      call write_str
      jmp .header
    .http_413:
      mov rdi, qword[rbp+var_fd_client]
      mov rsi, http_header_413
      call write_str
      jmp .header

    .header:
      mov rdi, qword[rbp+var_fd_client]
      mov rsi, http_header_main
      call write_str
    .lp:
      mov rdi, r15
      lea rsi, [rbp+var_file_buffer]
      mov rdx, 127
      call read

      cmp rax, 0
      je .exit

      ;; Add null at the end of buffer
      mov byte[rbp+var_file_buffer+rax], 0

      ;; Send http body
      mov rdi, [rbp+var_fd_client]
      lea rsi, [rbp+var_file_buffer]
      call write_str
    jmp .lp

  .exit:
    leave
    ret


;; http_process
var_client          equ -8
var_request_buffer  equ -520
http_process:
  enter 520, 0
  mov qword[rbp+var_client], rdi

  ;; Read request
  mov rdi, qword[rbp+var_client]
  lea rsi, [rbp+var_request_buffer]
  mov rdx, 519
  call read

  ;; Check if max length was exceeded
  cmp rax, 519
  jae .error_req_too_large
  ;; Append null at the end of buffer
  mov byte[rbp+var_request_buffer+rax], 0

  ;; Check if it's GET request - we support only it
  cmp dword[rbp+var_request_buffer], "GET "
  jne .error_bad_request

  ;; Extract requested resource name
    lea rdi, [rbp+var_request_buffer+5]
    cmp byte[rdi], "/"
    .lp:
      cmp byte[rdi], 0
      je .end
      cmp byte[rdi], " "
      je .end
      inc rdi
      jmp .lp
    .end:
      mov byte[rdi], 0  ;; End buffer at the end of file name
  ;; End of extract

  ;; Check if requested file exists
  lea rdi, [rbp+var_request_buffer+5]
  call file_exists
  cmp rax, -13
  je .error_file_denied
  cmp rax, 0
  jl .error_file_not_found

  mov rdi, qword[rbp+var_client]
  lea rsi, [rbp+var_request_buffer+5]
  mov rdx, 200
  call http_response

  jmp .exit
  .error_req_too_large:
    mov rdi, qword[rbp+var_client]
    mov rsi, error_req_too_large
    mov rdx, 413
    call http_response
    jmp .exit
  .error_bad_request:
    mov rdi, qword[rbp+var_client]
    mov rsi, http_bad_request
    mov rdx, 400
    call http_response
    jmp .exit
  .error_file_denied:
    mov rdi, qword[rbp+var_client]
    mov rsi, http_access_denied
    mov rdx, 403
    call http_response
    jmp .exit
  .error_file_not_found:
    mov rdi, qword[rbp+var_client]
    mov rsi, http_not_found
    mov rdx, 404
    call http_response
    jmp .exit
  .exit:
    leave
    ret

;; _start
;; program entry point
var_fd        equ   -8
var_client_fd equ   -16
_start:
  mov rbp, rsp
  sub rsp, 16

  call open_socket
  mov qword[rbp+var_fd], rax

  mov rdi, qword[rbp+var_fd]
  call bind_socket

  .main_loop:
    mov rdi, qword[rbp+var_fd]
    call listen_socket

    mov rdi, qword[rbp+var_fd]
    call accept_socket
    mov qword[rbp+var_client_fd], rax

    ;; Here goes communication with client
    mov rdi, qword[rbp+var_client_fd]
    call http_process

    mov rdi, qword[rbp+var_client_fd]
    call shutdown_socket
    mov rdi, qword[rbp+var_client_fd]
    call close_socket

    jmp .main_loop

  mov rdi, qword[rbp+var_client_fd]
  call close_socket
  call exit_success


;; Data section
segment .data
  SYS_READ      equ 0
  SYS_WRITE     equ 1
  SYS_OPEN      equ 2
  SYS_CLOSE     equ 3
  SYS_SOCKET    equ 41
  SYS_ACCEPT    equ 43
  SYS_SHUTDOWN  equ 48
  SYS_BIND      equ 49
  SYS_LISTEN    equ 50
  SYS_EXIT      equ 60

  LISTEN_PORT equ 36895   ;; Have to be converted to big endian

  struc SOCKADDR_T
    family: resw  1
    port:   resw  1
    addr:   resd  1
  endstruc

  SOCKADDR_STRUCT:
    istruc SOCKADDR_T
        at family, dw  2
        at port,   dw  LISTEN_PORT
        at addr,   dd  0
    iend
  SOCKADDR_STRUCT_LENGTH: equ 16

  socket_open_error:    db  "Error: Cannot open socket", 0Ah, 0
  socket_bind_error:    db  "Error: Cannot bind to socket", 0Ah, 0
  socket_accept_error:  db  "Error: Cannot accept connection", 0Ah, 0
  file_open_error:      db  "Error: Unable to open requested file", 0Ah, 0
  http_header_error:    db  "Error: Not implemented header requested", 0Ah, 0

  http_bad_request:     db  "html/400.html", 0
  http_access_denied    db  "html/403.html", 0
  http_not_found        db  "html/404.html", 0
  error_req_too_large:  db  "html/413.html", 0
  http_header_200:      db  "HTTP/1.0 200 OK", 0
  http_header_400:      db  "HTTP/1.0 400 Bad Request", 0
  http_header_403:      db  "HTTP/1.0 403 Forbidden", 0
  http_header_404:      db  "HTTP/1.0 404 Not found", 0
  http_header_413:      db  "HTTP/1.0 413 Request Entity Too Large", 0
  http_header_main:     db  0Ah, "Server: HttpAsm/1.0", 0Ah, "Connection: close", 0Ah, 0Ah, 0

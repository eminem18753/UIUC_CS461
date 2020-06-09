address:
	.string "/bin//sh"
.global _main
.section .text

_main:

push	%ebp
mov	%esp,%ebp

lea address,%ebx
mov $0,%ecx
mov $0,%edx
mov $11,%eax
int $0x80

leave
ret

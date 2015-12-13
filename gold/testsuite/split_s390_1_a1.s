# split_s390_1_a1.s: s390 specific, adjustment failure

	.text

	.global	fn1
	.type	fn1,@function
fn1:
	.cfi_startproc
	stm	%r13, %r15, 0x34(%r15)
	.cfi_offset	%r13, -0x2c
	.cfi_offset	%r14, -0x28
	.cfi_offset	%r15, -0x24
	ahi	%r15, -0x60
	.cfi_adjust_cfa_offset	0x60
	basr	%r13, %r0
.L1:
	l	%r1, .L2-.L1(%r13)
	bas	%r14, 0(%r13, %r1)
	l	%r1, .L3-.L1(%r13)
	bas	%r14, 0(%r13, %r1)
	lm	%r13, %r15, 0x94(%r15)
	.cfi_restore	%r13
	.cfi_restore	%r14
	.cfi_restore	%r15
	.cfi_adjust_cfa_offset	-0x60
	br	%r14
	.align	4
.L2:
	.long	__morestack-.L1
.L3:
	.long	fn2-.L1
	.cfi_endproc
	.size	fn1,. - fn1

	.section	.note.GNU-stack,"",@progbits
	.section	.note.GNU-split-stack,"",@progbits

/// NB: This file is written in pure C to avoid heap allocations.
/// The stubs below cover every architecture dettrace runs on.

/// parsing vDSO symbols based on vDSO entry found from /proc/<pid>/maps
/// Note vDSO can be disabled by passing `vdso=0` kernel command line.
/// The vDSO entry is loaded by Linux kernel before app return from execve
/// Even statically linked app will have vDSO loaded (by Linux kernel).
///
/// vDSO is just a regular dynamic shared object (DSO), like any `.so` file
/// in Linux, with the exception it doesn't have external dependencies.
/// Typically it can be found at: /lib/modules/`uname -r`/vdso/vdso64.so
///
/// vDSO provides symbols like:
///     clock_gettime, time, gettimeofday, getcpu
/// more recent kernel also adds clock_getres
/// The symbols can be found in .dynsym section of the DSO
/// This file parse those symbols from .dynsym section, following the ELF
/// spec defined at:
/// https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.intro.html
///
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <fcntl.h>
#include <unistd.h>

#include <elf.h>
#include <errno.h>
#include <link.h> /* ElfW */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ptracer.hpp" /* BREAK_INSN */
#include "util.hpp"
#include "vdso.hpp"

/* link.h only has ElfW for types; the same for the ELF64_/ELF32_ macros. */
#define ELFW(type) _ElfW(ELF, __ELF_NATIVE_CLASS, type)

/* A system call number as the little-endian immediate of an instruction
   or a literal word. */
#define SYSNUM_LE32(n)                                                     \
  (unsigned char)((n)&0xff), (unsigned char)(((n) >> 8) & 0xff),           \
      (unsigned char)(((n) >> 16) & 0xff), (unsigned char)(((n) >> 24) & 0xff)

/*
 * Word written over the rest of a replaced vDSO function so that a call
 * into the original code traps, see execution::disableVdso: whole-word
 * fill of the architecture's breakpoint instruction.
 */
#if defined(__x86_64__) || defined(__i386__)
static const unsigned long vdsoPoison = (unsigned long)0xccccccccccccccccULL; /* int3 */
#elif defined(__s390x__)
static const unsigned long vdsoPoison = 0x0001000100010001UL; /* breakpoint */
#elif defined(__arm__)
/* The vDSO is either all ARM or all Thumb code, decided per symbol. */
static const unsigned long vdsoPoison = BREAK_INSN;
static const unsigned long vdsoPoisonThumb =
    THUMB_BREAK_INSN | (THUMB_BREAK_INSN << 16);
#elif defined(__sh__) || defined(__m68k__)
/* Two 16-bit breakpoints fill a word. */
static const unsigned long vdsoPoison = BREAK_INSN | (BREAK_INSN << 16);
#elif __SIZEOF_LONG__ == 8
static const unsigned long vdsoPoison = BREAK_INSN | (BREAK_INSN << 32);
#else
/* One 32-bit instruction is a whole word here. */
static const unsigned long vdsoPoison = BREAK_INSN;
#endif

/*
 * byte code for the new psudo vdso functions which do the actual syscalls.
 * NB: the byte code must be 8 bytes aligned
 */
// clang-format off
#if defined(__x86_64__)
// The x86_64 vDSO is also the one an x32 process gets, so the syscall
// numbers come from the headers: x32 marks every number it uses with
// __X32_SYSCALL_BIT.
#define X86_64_SYSCALL_STUB(nr)                                            \
  {                                                                        \
    0xb8, SYSNUM_LE32(nr),       /* mov $nr, %eax */                       \
    0x0f, 0x05,                  /* syscall */                             \
    0xc3,                        /* retq */                                \
    0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00 /* nopl 0x0(%rax,%rax,1) */ \
  }

static const unsigned char __vdso_time[] = X86_64_SYSCALL_STUB(SYS_time);

static const unsigned char __vdso_clock_gettime[] =
    X86_64_SYSCALL_STUB(SYS_clock_gettime);

// The generic vDSO's clock_getres reads the resolution from the vvar
// page, which disableVdso maps PROT_NONE, so it has to become a syscall
// too (clock_getres is not intercepted, its result is deterministic).
static const unsigned char __vdso_clock_getres[] =
    X86_64_SYSCALL_STUB(SYS_clock_getres);

static const unsigned char __vdso_gettimeofday[] =
    X86_64_SYSCALL_STUB(SYS_gettimeofday);

// returns 0 regardless
static const unsigned char __vdso_getcpu[] = {
    0x48, 0x85, 0xff                                   // test %rdi, %rdi
  , 0x74, 0x06                                         // je ..
  , 0xc7, 0x07, 0x00, 0x00, 0x00, 0x00                 // movl $0x0, (%rdi)
  , 0x48, 0x85, 0xf6                                   // test %rsi, %rsi
  , 0x74, 0x06                                         // je ..
  , 0xc7, 0x06, 0x00, 0x00, 0x00, 0x00                 // movl $0x0, (%rsi)
  , 0x31, 0xc0                                         // xor %eax, %eax
  , 0xc3                                               // retq
  , 0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00 };        // nopl 0x0(%rax)

// vDSO getrandom (added in kernel 6.11) produces random bytes without a
// syscall that could be intercepted, so make callers fall back to the
// (intercepted) getrandom syscall by returning -ENOSYS, as documented in
// the vgetrandom(3) man page.
static const unsigned char __vdso_getrandom[] = {
    0xb8, 0xda, 0xff, 0xff, 0xff                 // mov $-ENOSYS, %eax
  , 0xc3                                         // retq
  , 0x66, 0x90 };                                // nop
#elif defined(__i386__)
// cdecl: the arguments are on the stack, int $0x80 takes them in ebx and
// ecx (ebx is callee-saved). The 32-bit vDSO has both the 32-bit time_t
// entries and the *64 ones glibc uses since 2.34.
#define I386_SYSCALL_STUB_2ARGS(nr)                                        \
  {                                                                        \
    0x53,                        /* push %ebx */                           \
    0x8b, 0x5c, 0x24, 0x08,      /* mov 8(%esp), %ebx */                   \
    0x8b, 0x4c, 0x24, 0x0c,      /* mov 12(%esp), %ecx */                  \
    0xb8, SYSNUM_LE32(nr),       /* mov $nr, %eax */                       \
    0xcd, 0x80,                  /* int $0x80 */                           \
    0x5b,                        /* pop %ebx */                            \
    0xc3                         /* ret */                                 \
  }
static const unsigned char __vdso_clock_gettime[] =
    I386_SYSCALL_STUB_2ARGS(SYS_clock_gettime);
static const unsigned char __vdso_clock_gettime64[] =
    I386_SYSCALL_STUB_2ARGS(SYS_clock_gettime64);
static const unsigned char __vdso_gettimeofday[] =
    I386_SYSCALL_STUB_2ARGS(SYS_gettimeofday);
// See the x86_64 __vdso_clock_getres above.
static const unsigned char __vdso_clock_getres[] =
    I386_SYSCALL_STUB_2ARGS(SYS_clock_getres);
static const unsigned char __vdso_clock_getres_time64[] =
    I386_SYSCALL_STUB_2ARGS(SYS_clock_getres_time64);
static const unsigned char __vdso_time[] = {
    0x53                                         // push %ebx
  , 0x8b, 0x5c, 0x24, 0x08                       // mov 8(%esp), %ebx
  , 0xb8, SYSNUM_LE32(SYS_time)                  // mov $SYS_time, %eax
  , 0xcd, 0x80                                   // int $0x80
  , 0x5b                                         // pop %ebx
  , 0xc3 };                                      // ret
// returns cpu 0, node 0, like the x86_64 __vdso_getcpu
static const unsigned char __vdso_getcpu[] = {
    0x8b, 0x44, 0x24, 0x04                       // mov 4(%esp), %eax
  , 0x85, 0xc0                                   // test %eax, %eax
  , 0x74, 0x06                                   // je ..
  , 0xc7, 0x00, 0x00, 0x00, 0x00, 0x00           // movl $0, (%eax)
  , 0x8b, 0x44, 0x24, 0x08                       // mov 8(%esp), %eax
  , 0x85, 0xc0                                   // test %eax, %eax
  , 0x74, 0x06                                   // je ..
  , 0xc7, 0x00, 0x00, 0x00, 0x00, 0x00           // movl $0, (%eax)
  , 0x31, 0xc0                                   // xor %eax, %eax
  , 0xc3 };                                      // ret
#elif defined(__arm__)
// r0 and r1 already hold the arguments, the number goes into r7. One
// encoding per instruction set: the kernel builds its vDSO as either ARM
// or Thumb code, the symbol's bit 0 tells which. ARM code loads r7 from
// a literal (movw needs ARMv6T2, and armv6 kernels are ARM code); Thumb
// vDSOs only exist on Thumb-2 kernels, so there a movw avoids depending
// on the 4-byte alignment a pc-relative literal load would need.
#define ARM_SYSCALL_STUB(nr)                                               \
  {                                                                        \
    0x04, 0x70, 0x9f, 0xe5,      /* ldr r7, [pc, #4] */                    \
    0x00, 0x00, 0x00, 0xef,      /* svc 0 */                               \
    0x1e, 0xff, 0x2f, 0xe1,      /* bx lr */                               \
    SYSNUM_LE32(nr)              /* .word nr */                            \
  }
/* Thumb-2 "movw r7, #nr" (encoding T3, imm16 = imm4:i:imm3:imm8). */
#define THUMB_MOVW_R7(nr)                                                  \
  (unsigned char)(0x40 | (((nr) >> 12) & 0xf)),                            \
      (unsigned char)(0xf2 | ((((nr) >> 11) & 1) << 2)),                   \
      (unsigned char)((nr)&0xff),                                          \
      (unsigned char)(0x07 | ((((nr) >> 8) & 7) << 4))
#define THUMB_SYSCALL_STUB(nr)                                             \
  {                                                                        \
    THUMB_MOVW_R7(nr),           /* movw r7, #nr */                        \
    0x00, 0xdf,                  /* svc 0 */                               \
    0x70, 0x47                   /* bx lr */                               \
  }
static const unsigned char __vdso_clock_gettime[] =
    ARM_SYSCALL_STUB(SYS_clock_gettime);
static const unsigned char __vdso_clock_gettime64[] =
    ARM_SYSCALL_STUB(SYS_clock_gettime64);
static const unsigned char __vdso_gettimeofday[] =
    ARM_SYSCALL_STUB(SYS_gettimeofday);
// See the x86_64 __vdso_clock_getres above.
static const unsigned char __vdso_clock_getres[] =
    ARM_SYSCALL_STUB(SYS_clock_getres);
static const unsigned char __vdso_clock_gettime_thumb[] =
    THUMB_SYSCALL_STUB(SYS_clock_gettime);
static const unsigned char __vdso_clock_gettime64_thumb[] =
    THUMB_SYSCALL_STUB(SYS_clock_gettime64);
static const unsigned char __vdso_gettimeofday_thumb[] =
    THUMB_SYSCALL_STUB(SYS_gettimeofday);
static const unsigned char __vdso_clock_getres_thumb[] =
    THUMB_SYSCALL_STUB(SYS_clock_getres);
#elif defined(__aarch64__)
static const unsigned char __kernel_clock_gettime[] = {
    0x28, 0x0e, 0x80, 0xd2                       // mov x8, #113 (SYS_clock_gettime)
  , 0x01, 0x00, 0x00, 0xd4                       // svc #0
  , 0xc0, 0x03, 0x5f, 0xd6                       // ret
  , 0x1f, 0x20, 0x03, 0xd5 };                    // nop

static const unsigned char __kernel_gettimeofday[] = {
    0x28, 0x15, 0x80, 0xd2                       // mov x8, #169 (SYS_gettimeofday)
  , 0x01, 0x00, 0x00, 0xd4                       // svc #0
  , 0xc0, 0x03, 0x5f, 0xd6                       // ret
  , 0x1f, 0x20, 0x03, 0xd5 };                    // nop

// See the x86_64 __vdso_clock_getres above.
static const unsigned char __kernel_clock_getres[] = {
    0x48, 0x0e, 0x80, 0xd2                       // mov x8, #114 (SYS_clock_getres)
  , 0x01, 0x00, 0x00, 0xd4                       // svc #0
  , 0xc0, 0x03, 0x5f, 0xd6                       // ret
  , 0x1f, 0x20, 0x03, 0xd5 };                    // nop

// See the x86_64 __vdso_getrandom above: force the fallback to the
// intercepted getrandom syscall.
static const unsigned char __kernel_getrandom[] = {
    0xa0, 0x04, 0x80, 0x92                       // mov x0, #-38 (-ENOSYS)
  , 0xc0, 0x03, 0x5f, 0xd6 };                    // ret
#elif defined(__riscv) && __riscv_xlen == 64
static const unsigned char __vdso_clock_gettime[] = {
    0x93, 0x08, 0x10, 0x07                       // li a7, 113 (SYS_clock_gettime)
  , 0x73, 0x00, 0x00, 0x00                       // ecall
  , 0x67, 0x80, 0x00, 0x00                       // ret
  , 0x13, 0x00, 0x00, 0x00 };                    // nop

static const unsigned char __vdso_gettimeofday[] = {
    0x93, 0x08, 0x90, 0x0a                       // li a7, 169 (SYS_gettimeofday)
  , 0x73, 0x00, 0x00, 0x00                       // ecall
  , 0x67, 0x80, 0x00, 0x00                       // ret
  , 0x13, 0x00, 0x00, 0x00 };                    // nop

// See the x86_64 __vdso_clock_getres above.
static const unsigned char __vdso_clock_getres[] = {
    0x93, 0x08, 0x20, 0x07                       // li a7, 114 (SYS_clock_getres)
  , 0x73, 0x00, 0x00, 0x00                       // ecall
  , 0x67, 0x80, 0x00, 0x00                       // ret
  , 0x13, 0x00, 0x00, 0x00 };                    // nop

// No __vdso_getcpu replacement: the kernel's own is just "li a7, 168;
// ecall; ret" (10 bytes with a compressed ret, __vdso_flush_icache
// follows right behind it), i.e. the getcpu syscall, which is
// intercepted and reports cpu 0, node 0.

// See the x86_64 __vdso_getrandom above: force the fallback to the
// intercepted getrandom syscall.
static const unsigned char __vdso_getrandom[] = {
    0x13, 0x05, 0xa0, 0xfd                       // li a0, -38 (-ENOSYS)
  , 0x67, 0x80, 0x00, 0x00 };                    // ret

// The hwprobe vDSO function reads cached hardware capabilities from the
// vvar pages which dettrace maps PROT_NONE, and the capabilities are
// nondeterministic across hosts anyway. Return -ENOSYS: callers fall
// back to the riscv_hwprobe syscall, which we also fail with -ENOSYS.
static const unsigned char __vdso_riscv_hwprobe[] = {
    0x13, 0x05, 0xa0, 0xfd                       // li a0, -38 (-ENOSYS)
  , 0x67, 0x80, 0x00, 0x00 };                    // ret
#elif defined(__hppa__)
// A syscall is a branch to the gateway page whose delay slot loads the
// number into r20; it comes back to the instruction behind the delay
// slot, which returns to the caller.
#define PARISC_LDI_R20(nr)                                                 \
  (0x34140000u | ((unsigned)(nr) << 1)) /* ldi nr, %r20 */
#define PARISC_BV_R2 0xe840c000u /* bv %r0(%r2) */

#define PARISC_SYSCALL_STUB(nr)                                            \
  {                                                                        \
    INSN32(SYSCALL_INSN), /* ble 0x100(%sr2,%r0) */                        \
        INSN32(PARISC_LDI_R20(nr)), /* ldi nr, %r20 (delay slot) */        \
        INSN32(PARISC_BV_R2), /* bv %r0(%r2) */                            \
        INSN32(PARISC_NOP_INSN) /* nop (delay slot) */                     \
  }

static const unsigned char __vdso_gettimeofday[] =
    PARISC_SYSCALL_STUB(SYS_gettimeofday);

static const unsigned char __vdso_clock_gettime[] =
    PARISC_SYSCALL_STUB(SYS_clock_gettime);

// glibc calls this one since 2.34, see the i386 stubs.
static const unsigned char __vdso_clock_gettime64[] =
    PARISC_SYSCALL_STUB(SYS_clock_gettime64);
#elif defined(__loongarch64)
// The syscall number goes into a7 from a 12-bit immediate, which fits
// every number of the generic table.
#define LA_ORI_A7(nr) (0x0380000bu | ((unsigned)(nr) << 10)) /* ori a7, zero, nr */
#define LA_SYSCALL 0x002b0000u /* syscall 0 */
#define LA_RET 0x4c000020u /* jr ra */
#define LA_NOP 0x03400000u /* andi zero, zero, 0 */
#define LA_ADDIW(rd, rj, imm)                                              \
  (0x02800000u | (((unsigned)(imm)&0xfffu) << 10) | ((unsigned)(rj) << 5) | \
   (unsigned)(rd)) /* addi.w rd, rj, imm */
#define LA_BEQZ(rj, insns)                                                 \
  (0x40000000u | (((unsigned)(insns)&0xffffu) << 10) |                     \
   ((unsigned)(rj) << 5)) /* beqz rj, insns instructions ahead */
#define LA_STW_0(rd, rj)                                                   \
  (0x29800000u | ((unsigned)(rj) << 5) | (unsigned)(rd)) /* st.w rd, rj, 0 */
#define LA_MOVE(rd, rj)                                                    \
  (0x00150000u | ((unsigned)(rj) << 5) | (unsigned)(rd)) /* or rd, rj, zero */
#define LA_ZERO 0
#define LA_A0 4
#define LA_A1 5

#define LA_SYSCALL_STUB(nr)                                                \
  {                                                                        \
    INSN32(LA_ORI_A7(nr)), /* ori a7, zero, nr */                          \
        INSN32(LA_SYSCALL), /* syscall 0 */                                \
        INSN32(LA_RET), /* jr ra */                                        \
        INSN32(LA_NOP) /* nop */                                           \
  }

static const unsigned char __vdso_clock_gettime[] =
    LA_SYSCALL_STUB(SYS_clock_gettime);

static const unsigned char __vdso_gettimeofday[] =
    LA_SYSCALL_STUB(SYS_gettimeofday);

// See the x86_64 __vdso_clock_getres above.
static const unsigned char __vdso_clock_getres[] =
    LA_SYSCALL_STUB(SYS_clock_getres);

// returns cpu 0, node 0, like the x86_64 __vdso_getcpu
static const unsigned char __vdso_getcpu[] = {
    INSN32(LA_BEQZ(LA_A0, 2)), // beqz a0, . + 8
    INSN32(LA_STW_0(LA_ZERO, LA_A0)), // st.w zero, a0, 0
    INSN32(LA_BEQZ(LA_A1, 2)), // beqz a1, . + 8
    INSN32(LA_STW_0(LA_ZERO, LA_A1)), // st.w zero, a1, 0
    INSN32(LA_MOVE(LA_A0, LA_ZERO)), // move a0, zero
    INSN32(LA_RET)}; // jr ra

// See the x86_64 __vdso_getrandom above: force the fallback to the
// intercepted getrandom syscall.
static const unsigned char __vdso_getrandom[] = {
    INSN32(LA_ADDIW(LA_A0, LA_ZERO, -ENOSYS)), // li.w a0, -38
    INSN32(LA_RET), // jr ra
    INSN32(LA_NOP), // nop
    INSN32(LA_NOP)}; // nop
#elif defined(__powerpc__)
// NB: the powerpc vDSO functions report errors through the cr0
// summary-overflow bit like system calls do, which the sc instruction
// sets up for us in the syscall-based stubs. The same instructions serve
// the 32-bit and the 64-bit vDSO, INSN32 puts their bytes in the
// target's order.
#define PPC_LI(r, v)                                                       \
  (0x38000000u | ((unsigned)(r) << 21) | ((unsigned)(v)&0xffffu)) /* li */
#define PPC_SC 0x44000002u /* sc */
#define PPC_BLR 0x4e800020u /* blr */
#define PPC_NOP 0x60000000u /* nop */
#define PPC_BEQ_8 0x41820008u /* beq . + 8 */
#define PPC_STW_0(r, b)                                                    \
  (0x90000000u | ((unsigned)(r) << 21) | ((unsigned)(b) << 16)) /* stw */
#define PPC_CRCLR_SO 0x4c631982u /* crclr so: success */
#define PPC_CRSET_SO 0x4c631a42u /* crset so: error */
#if defined(__powerpc64__)
#define PPC_CMPI_0(r) (0x2c200000u | ((unsigned)(r) << 16)) /* cmpdi r, 0 */
#else
/* cmpdi is a 64-bit instruction; on ppc32 a pointer is a word anyway. */
#define PPC_CMPI_0(r) (0x2c000000u | ((unsigned)(r) << 16)) /* cmpwi r, 0 */
#endif

#define PPC_SYSCALL_STUB(nr)                                               \
  {                                                                        \
    INSN32(PPC_LI(0, nr)), /* li r0, nr */                                 \
        INSN32(PPC_SC), /* sc */                                           \
        INSN32(PPC_BLR), /* blr */                                         \
        INSN32(PPC_NOP) /* nop */                                          \
  }

static const unsigned char __kernel_time[] = PPC_SYSCALL_STUB(SYS_time);

static const unsigned char __kernel_clock_gettime[] =
    PPC_SYSCALL_STUB(SYS_clock_gettime);

static const unsigned char __kernel_gettimeofday[] =
    PPC_SYSCALL_STUB(SYS_gettimeofday);

// See the x86_64 __vdso_clock_getres above.
static const unsigned char __kernel_clock_getres[] =
    PPC_SYSCALL_STUB(SYS_clock_getres);

#ifdef SYS_clock_gettime64
// The 32-bit vDSO also has the entries taking a 64-bit time_t, which is
// what glibc calls since 2.34.
static const unsigned char __kernel_clock_gettime64[] =
    PPC_SYSCALL_STUB(SYS_clock_gettime64);

static const unsigned char __kernel_clock_getres_time64[] =
    PPC_SYSCALL_STUB(SYS_clock_getres_time64);
#endif

// returns cpu 0, node 0, like the x86_64 __vdso_getcpu
static const unsigned char __kernel_getcpu[] = {
    INSN32(PPC_LI(9, 0)), // li r9, 0
    INSN32(PPC_CMPI_0(3)), // cmp r3, 0
    INSN32(PPC_BEQ_8), // beq . + 8
    INSN32(PPC_STW_0(9, 3)), // stw r9, 0(r3)
    INSN32(PPC_CMPI_0(4)), // cmp r4, 0
    INSN32(PPC_BEQ_8), // beq . + 8
    INSN32(PPC_STW_0(9, 4)), // stw r9, 0(r4)
    INSN32(PPC_LI(3, 0)), // li r3, 0
    INSN32(PPC_CRCLR_SO), // crclr so (success)
    INSN32(PPC_BLR)}; // blr

// See the x86_64 __vdso_getrandom above: force the fallback to the
// intercepted getrandom syscall. Error convention: positive errno with
// the cr0 summary-overflow bit set.
static const unsigned char __kernel_getrandom[] = {
    INSN32(PPC_LI(3, ENOSYS)), // li r3, 38 (ENOSYS)
    INSN32(PPC_CRSET_SO), // crset so (error)
    INSN32(PPC_BLR), // blr
    INSN32(PPC_NOP)}; // nop
#elif defined(__s390x__)
static const unsigned char __kernel_clock_gettime[] = {
    0xa7, 0x19, 0x01, 0x04                       // lghi %r1, 260 (SYS_clock_gettime)
  , 0x0a, 0x00                                   // svc 0
  , 0x07, 0xfe };                                // br %r14

static const unsigned char __kernel_gettimeofday[] = {
    0xa7, 0x19, 0x00, 0x4e                       // lghi %r1, 78 (SYS_gettimeofday)
  , 0x0a, 0x00                                   // svc 0
  , 0x07, 0xfe };                                // br %r14

// See the x86_64 __vdso_clock_getres above.
static const unsigned char __kernel_clock_getres[] = {
    0xa7, 0x19, 0x01, 0x05                       // lghi %r1, 261 (SYS_clock_getres)
  , 0x0a, 0x00                                   // svc 0
  , 0x07, 0xfe };                                // br %r14

// returns cpu 0, node 0, like the x86_64 __vdso_getcpu
static const unsigned char __kernel_getcpu[] = {
    0xa7, 0x09, 0x00, 0x00                       // lghi %r0, 0
  , 0xb9, 0x02, 0x00, 0x22                       // ltgr %r2, %r2
  , 0xa7, 0x84, 0x00, 0x04                       // jz . + 8
  , 0x50, 0x00, 0x20, 0x00                       // st %r0, 0(%r2)
  , 0xb9, 0x02, 0x00, 0x33                       // ltgr %r3, %r3
  , 0xa7, 0x84, 0x00, 0x04                       // jz . + 8
  , 0x50, 0x00, 0x30, 0x00                       // st %r0, 0(%r3)
  , 0xa7, 0x29, 0x00, 0x00                       // lghi %r2, 0
  , 0x07, 0xfe                                   // br %r14
  , 0x07, 0x07, 0x07, 0x07, 0x07, 0x07 };        // nopr (pad to 40 bytes)

// See the x86_64 __vdso_getrandom above: force the fallback to the
// intercepted getrandom syscall.
static const unsigned char __kernel_getrandom[] = {
    0xa7, 0x29, 0xff, 0xda                       // lghi %r2, -38 (-ENOSYS)
  , 0x07, 0xfe                                   // br %r14
  , 0x07, 0x07 };                                // nopr
#endif
// clang-format on

/*
std::ostream& operator<<(std::ostream& out, ProcMapEntry const& e) {
  out << std::hex << e.procMapBase << '-' << e.procMapBase + e.procMapSize
      << ' ';
  out << ((e.procMapPerms & ProcMapPermRead) ? 'r' : '-');
  out << ((e.procMapPerms & ProcMapPermWrite) ? 'w' : '-');
  out << ((e.procMapPerms & ProcMapPermExec) ? 'x' : '-');
  out << ((e.procMapPerms & ProcMapPermPrivate) ? 'p' : '-') << ' ';
  out << e.procMapOffset << ' ';
  out << (e.procMapDev >> 8) << ':' << (e.procMapDev & 0xffL) << ' ';
  out << e.procMapInode << "\t\t";
  out << e.procMapName;
  return out;
}
*/

/// parse a single (line of) /proc/<pid>maps.
static int parse_entry(char* line, struct ProcMapEntry* ep) {
  char *p, *q;

  p = line;

  ep->procMapBase = strtoull(p, &q, 16);
  ep->procMapSize = strtoull(1 + q, &p, 16) - ep->procMapBase;
  while (*p == ' ' || *p == '\t') ++p;

  ep->procMapPerms = 0;

  if (*p++ == 'r') ep->procMapPerms |= ProcMapPermRead;
  if (*p++ == 'w') ep->procMapPerms |= ProcMapPermWrite;
  if (*p++ == 'x') ep->procMapPerms |= ProcMapPermExec;
  if (*p++ == 'p') ep->procMapPerms |= ProcMapPermPrivate;

  while (*p == ' ' || *p == '\t') ++p;
  ep->procMapOffset = strtoul(p, &q, 16);
  while (*q == ' ' || *q == '\t') ++q;
  ep->procMapDev = strtoul(q, &p, 16) * 256;
  ep->procMapDev += strtoul(1 + p, &q, 16);
  while (*q == ' ' || *q == '\t') ++q;
  ep->procMapInode = strtoul(q, &p, 16);
  while (*p == ' ' || *p == '\t') ++p;
  strncpy(ep->procMapName, p, sizeof(ep->procMapName) - 1);
  return 0;
}

/// parse /proc/<pid>/maps
int proc_get_map_entries(pid_t pid, struct ProcMapEntry* ep, int size) {
  int fd = -1, res = 0;
  char mapsFile[32];

  snprintf(mapsFile, 32, "/proc/%u/maps", pid);
  fd = open(mapsFile, O_RDONLY);
  if (fd < 0) {
    perror("Failed to open /proc/self/maps");
    return 0;
  }

  unsigned long buffer_size = 0x100000;
  unsigned char* buffer = (unsigned char*)mmap(
      0, buffer_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1,
      0);
  if (buffer == MAP_FAILED) {
    sysError("unable to mmap buffer for proc maps");
  }

  unsigned long nr = 0;
  char *line = NULL, *text = (char*)buffer;

  while (1) {
    long nb = read(fd, buffer + nr, buffer_size - nr);
    if (nb < 0) {
      if (errno == EINTR) continue;
      goto out;
    } else if (nb == 0) {
      break;
    } else {
      nr += nb;
    }
  }
  close(fd);
  buffer[nr] = '\0';

  struct ProcMapEntry mapEntry;
  while (res < size && (line = strsep(&text, "\n")) != NULL) {
    if (parse_entry(line, &ep[res]) == 0) {
      ++res;
    }
  }

out:
  if (fd >= 0) close(fd);
  munmap(buffer, buffer_size);
  return res;
}

static const char* vdsoGetFuncNames(enum VDSOFunc func) {
  switch (func) {
  case VDSO_clock_gettime:
    return "__vdso_clock_gettime";
  case VDSO_getcpu:
    return "__vdso_getcpu";
  case VDSO_gettimeofday:
    return "__vdso_gettimeofday";
  case VDSO_time:
    return "__vdso_time";
  case VDSO_getrandom:
    return "__vdso_getrandom";
  case VDSO_riscv_hwprobe:
    return "__vdso_riscv_hwprobe";
  case VDSO_clock_getres:
    return "__vdso_clock_getres";
  case VDSO_clock_gettime64:
    return "__vdso_clock_gettime64";
  case VDSO_clock_getres_time64:
    return "__vdso_clock_getres_time64";
    // no default let the compiler do exhaustive check
  }
}

/// parse [vdso] and [vvar] from /proc/pid/maps.
/// returns 0 on success, -1 on failure.
/// caller to verify vdso/vvar have been updated.
int proc_get_vdso_vvar(
    pid_t pid, struct ProcMapEntry* vdso, struct ProcMapEntry* vvar) {
  const long buff_size = 2L << 20;
  char mapsFile[32];
  char* buff;
  snprintf(mapsFile, 32, "/proc/%d/maps", pid);

  buff = (char*)mmap(
      0, buff_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (buff == MAP_FAILED) {
    sysError("unable to mmap buffer for proc maps");
  }

  int fd = open(mapsFile, O_RDONLY);
  VERIFY(fd >= 0);

  unsigned long nr = 0;
  while (nr < buff_size - 1) {
    long nb = read(fd, buff + nr, buff_size - nr);
    if (nb < 0) {
      if (errno == EINTR) continue;
      break;
    } else if (nb == 0) {
      break;
    } else {
      nr += nb;
    }
  }
  buff[nr] = '\0';
  VERIFY(close(fd) == 0);

  // we cannot stat procfs.
  long file_size = nr;
  VERIFY(file_size >= 0);

  const long page_size = 4096;

  long off = file_size >= page_size ? file_size - page_size : 0;

  // s -> skip the first (likely partial) line.
  char* s = (char*)((unsigned char*)buff + off);
  while (s && *s && *s != '\n' && *s != '\0') ++s;
  while (s && *s == '\n' && *s != '\0') ++s;

  struct ProcMapEntry mapEntry;
  char* line;

  while ((line = strsep(&s, "\n")) != NULL) {
    if (parse_entry(line, &mapEntry) != 0) {
      return -1;
    }
    if (strcmp(mapEntry.procMapName, "[vdso]") == 0) {
      if (vdso) {
        memcpy(vdso, &mapEntry, sizeof(mapEntry));
      }
    } else if (strcmp(mapEntry.procMapName, "[vvar]") == 0) {
      if (vvar) {
        memcpy(vvar, &mapEntry, sizeof(mapEntry));
      }
    } else {
      continue;
    }
  }

  VERIFY(munmap(buff, buff_size) == 0);

  return 0;
}

/// get vdso symbols from vdso
/// returns number of vdso functions found.
int proc_get_vdso_symbols(
    struct ProcMapEntry* vdso_entry, struct VDSOSymbol* vdso, int size) {
  int res = 0;

  unsigned long base = vdso_entry->procMapBase;
  ElfW(Ehdr)* ehdr = (ElfW(Ehdr)*)base;
  ElfW(Shdr) * shbase = (ElfW(Shdr)*)(base + ehdr->e_shoff), *dynsym = NULL;
  const char* strtab = NULL;

  for (int i = 0; i < ehdr->e_shnum; i++) {
    ElfW(Shdr)* sh = &shbase[i];
    if (sh->sh_type == SHT_DYNSYM) {
      dynsym = sh;
    } else if (sh->sh_type == SHT_STRTAB && (sh->sh_flags & SHF_ALLOC)) {
      strtab = (const char*)(base + sh->sh_offset);
    }
  }

  if (!dynsym || !strtab) return res;

  for (int i = 0; i < dynsym->sh_size / dynsym->sh_entsize && res < size; i++) {
    ElfW(Sym)* sym =
        (ElfW(Sym)*)(base + dynsym->sh_offset + i * dynsym->sh_entsize);
    const char* name = (const char*)((unsigned long)strtab + sym->st_name);
    if (ELFW(ST_BIND)(sym->st_info) == STB_GLOBAL &&
        ELFW(ST_TYPE)(sym->st_info) == STT_FUNC) {
      VERIFY(sym->st_shndx < ehdr->e_shnum);
      unsigned long alignment = sym->st_shndx < ehdr->e_shnum
                                    ? shbase[sym->st_shndx].sh_addralign
                                    : 16;
#if defined(__x86_64__)
      if (strcmp("__vdso_clock_gettime", name) == 0) {
        vdso[res].func = VDSO_clock_gettime;
        vdso[res].code_size = sizeof(__vdso_clock_gettime);
        vdso[res].code = (const unsigned char*)__vdso_clock_gettime;
      } else if (strcmp("__vdso_getcpu", name) == 0) {
        vdso[res].func = VDSO_getcpu;
        vdso[res].code_size = sizeof(__vdso_getcpu);
        vdso[res].code = (const unsigned char*)__vdso_getcpu;
      } else if (strcmp("__vdso_gettimeofday", name) == 0) {
        vdso[res].func = VDSO_gettimeofday;
        vdso[res].code_size = sizeof(__vdso_gettimeofday);
        vdso[res].code = (const unsigned char*)__vdso_gettimeofday;
      } else if (strcmp("__vdso_time", name) == 0) {
        vdso[res].func = VDSO_time;
        vdso[res].code_size = sizeof(__vdso_time);
        vdso[res].code = (const unsigned char*)__vdso_time;
      } else if (strcmp("__vdso_clock_getres", name) == 0) {
        vdso[res].func = VDSO_clock_getres;
        vdso[res].code_size = sizeof(__vdso_clock_getres);
        vdso[res].code = (const unsigned char*)__vdso_clock_getres;
      } else if (strcmp("__vdso_getrandom", name) == 0) {
        vdso[res].func = VDSO_getrandom;
        vdso[res].code_size = sizeof(__vdso_getrandom);
        vdso[res].code = (const unsigned char*)__vdso_getrandom;
      } else {
        continue;
      }
#elif defined(__i386__)
      if (strcmp("__vdso_clock_gettime", name) == 0) {
        vdso[res].func = VDSO_clock_gettime;
        vdso[res].code_size = sizeof(__vdso_clock_gettime);
        vdso[res].code = (const unsigned char*)__vdso_clock_gettime;
      } else if (strcmp("__vdso_clock_gettime64", name) == 0) {
        vdso[res].func = VDSO_clock_gettime64;
        vdso[res].code_size = sizeof(__vdso_clock_gettime64);
        vdso[res].code = (const unsigned char*)__vdso_clock_gettime64;
      } else if (strcmp("__vdso_getcpu", name) == 0) {
        vdso[res].func = VDSO_getcpu;
        vdso[res].code_size = sizeof(__vdso_getcpu);
        vdso[res].code = (const unsigned char*)__vdso_getcpu;
      } else if (strcmp("__vdso_gettimeofday", name) == 0) {
        vdso[res].func = VDSO_gettimeofday;
        vdso[res].code_size = sizeof(__vdso_gettimeofday);
        vdso[res].code = (const unsigned char*)__vdso_gettimeofday;
      } else if (strcmp("__vdso_time", name) == 0) {
        vdso[res].func = VDSO_time;
        vdso[res].code_size = sizeof(__vdso_time);
        vdso[res].code = (const unsigned char*)__vdso_time;
      } else if (strcmp("__vdso_clock_getres", name) == 0) {
        vdso[res].func = VDSO_clock_getres;
        vdso[res].code_size = sizeof(__vdso_clock_getres);
        vdso[res].code = (const unsigned char*)__vdso_clock_getres;
      } else if (strcmp("__vdso_clock_getres_time64", name) == 0) {
        vdso[res].func = VDSO_clock_getres_time64;
        vdso[res].code_size = sizeof(__vdso_clock_getres_time64);
        vdso[res].code = (const unsigned char*)__vdso_clock_getres_time64;
      } else {
        continue;
      }
#elif defined(__arm__)
      /* Bit 0 of a function symbol's value marks Thumb code. */
      const int thumb = sym->st_value & 1;
      if (strcmp("__vdso_clock_gettime", name) == 0) {
        vdso[res].func = VDSO_clock_gettime;
        vdso[res].code_size = thumb ? sizeof(__vdso_clock_gettime_thumb)
                                    : sizeof(__vdso_clock_gettime);
        vdso[res].code = thumb ? __vdso_clock_gettime_thumb
                               : __vdso_clock_gettime;
      } else if (strcmp("__vdso_clock_gettime64", name) == 0) {
        vdso[res].func = VDSO_clock_gettime64;
        vdso[res].code_size = thumb ? sizeof(__vdso_clock_gettime64_thumb)
                                    : sizeof(__vdso_clock_gettime64);
        vdso[res].code = thumb ? __vdso_clock_gettime64_thumb
                               : __vdso_clock_gettime64;
      } else if (strcmp("__vdso_gettimeofday", name) == 0) {
        vdso[res].func = VDSO_gettimeofday;
        vdso[res].code_size = thumb ? sizeof(__vdso_gettimeofday_thumb)
                                    : sizeof(__vdso_gettimeofday);
        vdso[res].code = thumb ? __vdso_gettimeofday_thumb
                               : __vdso_gettimeofday;
      } else if (strcmp("__vdso_clock_getres", name) == 0) {
        vdso[res].func = VDSO_clock_getres;
        vdso[res].code_size = thumb ? sizeof(__vdso_clock_getres_thumb)
                                    : sizeof(__vdso_clock_getres);
        vdso[res].code = thumb ? __vdso_clock_getres_thumb
                               : __vdso_clock_getres;
      } else {
        continue;
      }
      vdso[res].poison = thumb ? vdsoPoisonThumb : vdsoPoison;
#elif defined(__aarch64__)
      if (strcmp("__kernel_clock_gettime", name) == 0) {
        vdso[res].func = VDSO_clock_gettime;
        vdso[res].code_size = sizeof(__kernel_clock_gettime);
        vdso[res].code = (const unsigned char*)__kernel_clock_gettime;
      } else if (strcmp("__kernel_gettimeofday", name) == 0) {
        vdso[res].func = VDSO_gettimeofday;
        vdso[res].code_size = sizeof(__kernel_gettimeofday);
        vdso[res].code = (const unsigned char*)__kernel_gettimeofday;
      } else if (strcmp("__kernel_clock_getres", name) == 0) {
        vdso[res].func = VDSO_clock_getres;
        vdso[res].code_size = sizeof(__kernel_clock_getres);
        vdso[res].code = (const unsigned char*)__kernel_clock_getres;
      } else if (strcmp("__kernel_getrandom", name) == 0) {
        vdso[res].func = VDSO_getrandom;
        vdso[res].code_size = sizeof(__kernel_getrandom);
        vdso[res].code = (const unsigned char*)__kernel_getrandom;
      } else {
        continue;
      }
#elif defined(__riscv) && __riscv_xlen == 64
      if (strcmp("__vdso_clock_gettime", name) == 0) {
        vdso[res].func = VDSO_clock_gettime;
        vdso[res].code_size = sizeof(__vdso_clock_gettime);
        vdso[res].code = (const unsigned char*)__vdso_clock_gettime;
      } else if (strcmp("__vdso_gettimeofday", name) == 0) {
        vdso[res].func = VDSO_gettimeofday;
        vdso[res].code_size = sizeof(__vdso_gettimeofday);
        vdso[res].code = (const unsigned char*)__vdso_gettimeofday;
      } else if (strcmp("__vdso_clock_getres", name) == 0) {
        vdso[res].func = VDSO_clock_getres;
        vdso[res].code_size = sizeof(__vdso_clock_getres);
        vdso[res].code = (const unsigned char*)__vdso_clock_getres;
      } else if (strcmp("__vdso_getrandom", name) == 0) {
        vdso[res].func = VDSO_getrandom;
        vdso[res].code_size = sizeof(__vdso_getrandom);
        vdso[res].code = (const unsigned char*)__vdso_getrandom;
      } else if (strcmp("__vdso_riscv_hwprobe", name) == 0) {
        vdso[res].func = VDSO_riscv_hwprobe;
        vdso[res].code_size = sizeof(__vdso_riscv_hwprobe);
        vdso[res].code = (const unsigned char*)__vdso_riscv_hwprobe;
      } else {
        continue;
      }
#elif defined(__hppa__)
      // NB: the two trampolines the parisc vDSO exports besides these,
      // __kernel_sigtramp_rt32 and __kernel_restart_syscall32, are not
      // matched and so are left alone.
      if (strcmp("__vdso_clock_gettime", name) == 0) {
        vdso[res].func = VDSO_clock_gettime;
        vdso[res].code_size = sizeof(__vdso_clock_gettime);
        vdso[res].code = (const unsigned char*)__vdso_clock_gettime;
      } else if (strcmp("__vdso_clock_gettime64", name) == 0) {
        vdso[res].func = VDSO_clock_gettime64;
        vdso[res].code_size = sizeof(__vdso_clock_gettime64);
        vdso[res].code = (const unsigned char*)__vdso_clock_gettime64;
      } else if (strcmp("__vdso_gettimeofday", name) == 0) {
        vdso[res].func = VDSO_gettimeofday;
        vdso[res].code_size = sizeof(__vdso_gettimeofday);
        vdso[res].code = (const unsigned char*)__vdso_gettimeofday;
      } else {
        continue;
      }
#elif defined(__loongarch64)
      if (strcmp("__vdso_clock_gettime", name) == 0) {
        vdso[res].func = VDSO_clock_gettime;
        vdso[res].code_size = sizeof(__vdso_clock_gettime);
        vdso[res].code = (const unsigned char*)__vdso_clock_gettime;
      } else if (strcmp("__vdso_gettimeofday", name) == 0) {
        vdso[res].func = VDSO_gettimeofday;
        vdso[res].code_size = sizeof(__vdso_gettimeofday);
        vdso[res].code = (const unsigned char*)__vdso_gettimeofday;
      } else if (strcmp("__vdso_clock_getres", name) == 0) {
        vdso[res].func = VDSO_clock_getres;
        vdso[res].code_size = sizeof(__vdso_clock_getres);
        vdso[res].code = (const unsigned char*)__vdso_clock_getres;
      } else if (strcmp("__vdso_getcpu", name) == 0) {
        vdso[res].func = VDSO_getcpu;
        vdso[res].code_size = sizeof(__vdso_getcpu);
        vdso[res].code = (const unsigned char*)__vdso_getcpu;
      } else if (strcmp("__vdso_getrandom", name) == 0) {
        vdso[res].func = VDSO_getrandom;
        vdso[res].code_size = sizeof(__vdso_getrandom);
        vdso[res].code = (const unsigned char*)__vdso_getrandom;
      } else {
        continue;
      }
#elif defined(__powerpc__)
      if (strcmp("__kernel_time", name) == 0) {
        vdso[res].func = VDSO_time;
        vdso[res].code_size = sizeof(__kernel_time);
        vdso[res].code = (const unsigned char*)__kernel_time;
      } else if (strcmp("__kernel_clock_gettime", name) == 0) {
        vdso[res].func = VDSO_clock_gettime;
        vdso[res].code_size = sizeof(__kernel_clock_gettime);
        vdso[res].code = (const unsigned char*)__kernel_clock_gettime;
      } else if (strcmp("__kernel_gettimeofday", name) == 0) {
        vdso[res].func = VDSO_gettimeofday;
        vdso[res].code_size = sizeof(__kernel_gettimeofday);
        vdso[res].code = (const unsigned char*)__kernel_gettimeofday;
      } else if (strcmp("__kernel_getcpu", name) == 0) {
        vdso[res].func = VDSO_getcpu;
        vdso[res].code_size = sizeof(__kernel_getcpu);
        vdso[res].code = (const unsigned char*)__kernel_getcpu;
      } else if (strcmp("__kernel_clock_getres", name) == 0) {
        vdso[res].func = VDSO_clock_getres;
        vdso[res].code_size = sizeof(__kernel_clock_getres);
        vdso[res].code = (const unsigned char*)__kernel_clock_getres;
      } else if (strcmp("__kernel_getrandom", name) == 0) {
        vdso[res].func = VDSO_getrandom;
        vdso[res].code_size = sizeof(__kernel_getrandom);
        vdso[res].code = (const unsigned char*)__kernel_getrandom;
#ifdef SYS_clock_gettime64
      } else if (strcmp("__kernel_clock_gettime64", name) == 0) {
        vdso[res].func = VDSO_clock_gettime64;
        vdso[res].code_size = sizeof(__kernel_clock_gettime64);
        vdso[res].code = (const unsigned char*)__kernel_clock_gettime64;
      } else if (strcmp("__kernel_clock_getres_time64", name) == 0) {
        vdso[res].func = VDSO_clock_getres_time64;
        vdso[res].code_size = sizeof(__kernel_clock_getres_time64);
        vdso[res].code = (const unsigned char*)__kernel_clock_getres_time64;
#endif
      } else {
        continue;
      }
#elif defined(__s390x__)
      if (strcmp("__kernel_clock_gettime", name) == 0) {
        vdso[res].func = VDSO_clock_gettime;
        vdso[res].code_size = sizeof(__kernel_clock_gettime);
        vdso[res].code = (const unsigned char*)__kernel_clock_gettime;
      } else if (strcmp("__kernel_gettimeofday", name) == 0) {
        vdso[res].func = VDSO_gettimeofday;
        vdso[res].code_size = sizeof(__kernel_gettimeofday);
        vdso[res].code = (const unsigned char*)__kernel_gettimeofday;
      } else if (strcmp("__kernel_getcpu", name) == 0) {
        vdso[res].func = VDSO_getcpu;
        vdso[res].code_size = sizeof(__kernel_getcpu);
        vdso[res].code = (const unsigned char*)__kernel_getcpu;
      } else if (strcmp("__kernel_clock_getres", name) == 0) {
        vdso[res].func = VDSO_clock_getres;
        vdso[res].code_size = sizeof(__kernel_clock_getres);
        vdso[res].code = (const unsigned char*)__kernel_clock_getres;
      } else if (strcmp("__kernel_getrandom", name) == 0) {
        vdso[res].func = VDSO_getrandom;
        vdso[res].code_size = sizeof(__kernel_getrandom);
        vdso[res].code = (const unsigned char*)__kernel_getrandom;
      } else {
        continue;
      }
#endif
#if !defined(__arm__)
      vdso[res].poison = vdsoPoison;
#endif
      vdso[res].offset = sym->st_value & ~1UL; /* arm: strip the Thumb bit */
      vdso[res].size = sym->st_size;
      vdso[res].alignment = alignment;
      ++res;
    }
  }
  return res;
}

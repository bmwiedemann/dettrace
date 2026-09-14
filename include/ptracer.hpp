#ifndef PTRACER_H
#define PTRACER_H

#include <stdint.h>
#include <string.h>
#include <sys/ptrace.h>
#if defined(__x86_64__) || defined(__i386__)
#include <sys/reg.h> /* For constants ORIG_EAX, etc */
#endif
#include <sys/stat.h>
#include <sys/syscall.h> /* For SYS_write, etc */
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cstddef>
#include <experimental/optional>
#include <iostream>
#include <map>
#include <memory>
#include <set>
#include <tuple>

#include "traceePtr.hpp"
#include "util.hpp"

using namespace std;

const size_t wordSize = sizeof(long); /**< Size of a ptrace word: 8 bytes on
                                         64-bit, 4 on i386 and arm. */

/**
 * The bytes of one 32-bit instruction, in the order the processor reads
 * them: the machine code dettrace writes into a tracee (the post-execve
 * stub, the vDSO replacements) is byte data, so on a big-endian target
 * the most significant byte of the instruction word comes first.
 */
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define INSN32(w)                                                          \
  (unsigned char)(((unsigned long)(w) >> 24) & 0xff),                      \
      (unsigned char)(((unsigned long)(w) >> 16) & 0xff),                  \
      (unsigned char)(((unsigned long)(w) >> 8) & 0xff),                   \
      (unsigned char)((unsigned long)(w)&0xff)
#else
#define INSN32(w)                                                          \
  (unsigned char)((unsigned long)(w)&0xff),                                \
      (unsigned char)(((unsigned long)(w) >> 8) & 0xff),                   \
      (unsigned char)(((unsigned long)(w) >> 16) & 0xff),                  \
      (unsigned char)(((unsigned long)(w) >> 24) & 0xff)
#endif

/**
 * Architecture-independent accessors for the fields of
 * struct user_regs_struct, plus the size of the syscall instruction
 * ("syscall" on x86_64, "svc #0" on aarch64).
 */
#if defined(__x86_64__)
#define REG_SYSNUM(r) ((r).orig_rax)
#define REG_RETVAL(r) ((r).rax)
#define REG_ARG1(r) ((r).rdi)
#define REG_ARG2(r) ((r).rsi)
#define REG_ARG3(r) ((r).rdx)
#define REG_ARG4(r) ((r).r10)
#define REG_ARG5(r) ((r).r8)
#define REG_ARG6(r) ((r).r9)
#define REG_IP(r) ((r).rip)
#define REG_SP(r) ((r).rsp)
const size_t syscallInsnSize = 2;
#elif defined(__aarch64__)
// The syscall number lives in x8. Note that for changing which system
// call actually executes, NT_ARM_SYSTEM_CALL must be written as well,
// see ptracer::changeSystemCall.
#define REG_SYSNUM(r) ((r).regs[8])
#define REG_RETVAL(r) ((r).regs[0])
#define REG_ARG1(r) ((r).regs[0])
#define REG_ARG2(r) ((r).regs[1])
#define REG_ARG3(r) ((r).regs[2])
#define REG_ARG4(r) ((r).regs[3])
#define REG_ARG5(r) ((r).regs[4])
#define REG_ARG6(r) ((r).regs[5])
#define REG_IP(r) ((r).pc)
#define REG_SP(r) ((r).sp)
const size_t syscallInsnSize = 4;
/* Machine code of one breakpoint and one syscall instruction, used for
   the stub injected after execve, see execution::handleExecEvent. The
   breakpoint traps with the pc still pointing at itself. */
#define BREAK_INSN 0xd4200000UL /* brk #0 */
#define SYSCALL_INSN 0xd4000001UL /* svc #0 */
#elif defined(__powerpc__)
/* Both the 32-bit and the 64-bit powerpc ABIs, big and little endian:
   they share one syscall table and one register layout, the 32-bit one
   simply has 32-bit registers. powerpc has no struct user_regs_struct,
   ptrace uses struct pt_regs (pulled in via sys/user.h). */
#define user_regs_struct pt_regs
#define REG_SYSNUM(r) ((r).gpr[0])
#define REG_RETVAL(r) ((r).gpr[3])
#define REG_ARG1(r) ((r).gpr[3])
#define REG_ARG2(r) ((r).gpr[4])
#define REG_ARG3(r) ((r).gpr[5])
#define REG_ARG4(r) ((r).gpr[6])
#define REG_ARG5(r) ((r).gpr[7])
#define REG_ARG6(r) ((r).gpr[8])
#define REG_IP(r) ((r).nip)
#define REG_SP(r) ((r).gpr[1])
/* At the seccomp-trace stop the kernel has preset gpr[3] (the return
   register) to -ENOSYS; the original first argument is kept in
   orig_gpr3. */
#define REG_ORIG_ARG1(r) ((r).orig_gpr3)
const size_t syscallInsnSize = 4;
#define BREAK_INSN 0x7fe00008UL /* trap */
#define SYSCALL_INSN 0x44000002UL /* sc */
/* The kernel reports syscall errors by setting the summary-overflow bit
   of cr0 and storing the positive errno in r3, see regsReturnValue. */
#define PPC_CR0_SO 0x10000000UL
#elif defined(__s390x__)
/* glibc's sys/user.h calls the register struct _user_regs_struct on
   s390; the kernel uapi header provides the user_regs_struct our macros
   below expect (with psw, gprs and orig_gpr2). */
#include <asm/ptrace.h>
/* Syscall arguments live in gprs[2..7] and gprs[2] also receives the
   return value; the kernel takes the first argument from orig_gpr2,
   where it preserves it at entry (see ptracer::arg1, writeArg1). At a
   syscall stop gprs[2] doubles as the number of the system call to
   execute (see ptracer::changeSystemCall), which is otherwise not part
   of the register set. REG_SYSNUM refers to r1, which is what a freshly
   executed "svc 0" instruction uses. */
#define REG_SYSNUM(r) ((r).gprs[1])
#define REG_RETVAL(r) ((r).gprs[2])
#define REG_ARG1(r) ((r).gprs[2])
#define REG_ARG2(r) ((r).gprs[3])
#define REG_ARG3(r) ((r).gprs[4])
#define REG_ARG4(r) ((r).gprs[5])
#define REG_ARG5(r) ((r).gprs[6])
#define REG_ARG6(r) ((r).gprs[7])
#define REG_IP(r) ((r).psw.addr)
#define REG_SP(r) ((r).gprs[15])
/* gprs[2] is the return register and holds the syscall number at the
   seccomp-trace stop; orig_gpr2 keeps the original first argument. */
#define REG_ORIG_ARG1(r) ((r).orig_gpr2)
const size_t syscallInsnSize = 2;
#elif defined(__riscv) && __riscv_xlen == 64
/* glibc's sys/user.h does not define user_regs_struct on riscv, the
   kernel uapi header does. */
#include <asm/ptrace.h>
#define REG_SYSNUM(r) ((r).a7)
#define REG_RETVAL(r) ((r).a0)
#define REG_ARG1(r) ((r).a0)
#define REG_ARG2(r) ((r).a1)
#define REG_ARG3(r) ((r).a2)
#define REG_ARG4(r) ((r).a3)
#define REG_ARG5(r) ((r).a4)
#define REG_ARG6(r) ((r).a5)
#define REG_IP(r) ((r).pc)
#define REG_SP(r) ((r).sp)
const size_t syscallInsnSize = 4;
#define BREAK_INSN 0x00100073UL /* ebreak */
#define SYSCALL_INSN 0x00000073UL /* ecall */
#elif defined(__loongarch64)
/* glibc's sys/user.h defines struct user_regs_struct here, the kernel's
   user_pt_regs: the 32 general registers, the saved first argument and
   the two control registers ptrace exposes. a0..a5 (r4..r9) are the
   arguments, a7 (r11) the syscall number, a0 the return value. */
#define REG_SYSNUM(r) ((r).regs[11])
#define REG_RETVAL(r) ((r).regs[4])
#define REG_ARG1(r) ((r).regs[4])
#define REG_ARG2(r) ((r).regs[5])
#define REG_ARG3(r) ((r).regs[6])
#define REG_ARG4(r) ((r).regs[7])
#define REG_ARG5(r) ((r).regs[8])
#define REG_ARG6(r) ((r).regs[9])
#define REG_IP(r) ((r).csr_era)
#define REG_SP(r) ((r).regs[3])
/* do_syscall() presets a0, which is also the return register, to -ENOSYS
   before the trace stop and keeps the first argument in orig_a0, exactly
   like powerpc does. It also advances the pc past the syscall
   instruction there, so rewinding by one instruction replays the call. */
#define REG_ORIG_ARG1(r) ((r).orig_a0)
const size_t syscallInsnSize = 4;
/* break 4 is BRK_USERBP, what debuggers use: do_bp() leaves the pc on
   the instruction and raises SIGTRAP for every code it does not claim
   for kprobes, kgdb or BUG(). */
#define BREAK_INSN 0x002a0004UL /* break 4 */
#define SYSCALL_INSN 0x002b0000UL /* syscall 0 */
#elif defined(__i386__)
/* 32-bit x86: the arguments are in ebx, ecx, edx, esi, edi, ebp, the
   number in eax (orig_eax at a stop), the result in eax; "int $0x80",
   "sysenter" and "syscall" are all 2 bytes and the kernel leaves the pc
   behind the int $0x80 of the vDSO's __kernel_vsyscall for the latter
   two, so replaying by re-executing the 2 bytes before the pc works for
   every entry path. */
#define REG_SYSNUM(r) ((r).orig_eax)
#define REG_RETVAL(r) ((r).eax)
#define REG_ARG1(r) ((r).ebx)
#define REG_ARG2(r) ((r).ecx)
#define REG_ARG3(r) ((r).edx)
#define REG_ARG4(r) ((r).esi)
#define REG_ARG5(r) ((r).edi)
#define REG_ARG6(r) ((r).ebp)
#define REG_IP(r) ((r).eip)
#define REG_SP(r) ((r).esp)
const size_t syscallInsnSize = 2;
#elif defined(__arm__)
/* glibc's sys/user.h calls the register struct user_regs on arm, with
   the 18 words of the kernel's struct pt_regs: r0-r15, cpsr, orig_r0.
   EABI passes the syscall number in r7, the arguments in r0-r5 and the
   result in r0; the kernel keeps the first argument in orig_r0. */
#define user_regs_struct user_regs
#define REG_SYSNUM(r) ((r).uregs[7])
#define REG_RETVAL(r) ((r).uregs[0])
#define REG_ARG1(r) ((r).uregs[0])
#define REG_ARG2(r) ((r).uregs[1])
#define REG_ARG3(r) ((r).uregs[2])
#define REG_ARG4(r) ((r).uregs[3])
#define REG_ARG5(r) ((r).uregs[4])
#define REG_ARG6(r) ((r).uregs[5])
#define REG_IP(r) ((r).uregs[15])
#define REG_SP(r) ((r).uregs[13])
#define REG_CPSR(r) ((r).uregs[16])
#define REG_ORIG_ARG1(r) ((r).uregs[17])
/* User code is ARM or Thumb per the cpsr T bit, and glibc for armv7 is
   Thumb-2, so the syscall instruction is "svc 0" as 4 or 2 bytes, see
   ptracer::syscallInsnLength. */
#define ARM_CPSR_THUMB 0x20UL
const size_t syscallInsnSize = 4;
/* The kernel's software breakpoints (what gdb uses): the undefined
   instructions the arm and the arm64 compat undef handlers turn into a
   SIGTRAP with the pc still on them. bkpt itself needs debug hardware
   support on 32-bit kernels. */
#define BREAK_INSN 0xe7f001f0UL /* udf #0x10 */
#define SYSCALL_INSN 0xef000000UL /* svc 0 */
#define THUMB_BREAK_INSN 0xde01U /* udf #1 */
#define THUMB_SYSCALL_INSN 0xdf00U /* svc 0 */
/* Changes the system call the kernel executes at the current stop, r7
   only matters for a re-executed svc (compare NT_ARM_SYSTEM_CALL on
   aarch64). glibc's sys/ptrace.h has it, the kernel accepts it for
   native and for arm64 compat tracees alike. */
#ifndef PTRACE_SET_SYSCALL
#define PTRACE_SET_SYSCALL 23
#endif
#else
#error "dettrace only supports x86_64, i386, x32, aarch64, arm, powerpc, riscv64, loongarch64 and s390x"
#endif

/* The general purpose registers named by the x86 instructions dettrace
   emulates (rdtsc, rdtscp, cpuid), see execution::handleSignal. */
#if defined(__x86_64__)
#define REG_AX(r) ((r).rax)
#define REG_BX(r) ((r).rbx)
#define REG_CX(r) ((r).rcx)
#define REG_DX(r) ((r).rdx)
#elif defined(__i386__)
#define REG_AX(r) ((r).eax)
#define REG_BX(r) ((r).ebx)
#define REG_CX(r) ((r).ecx)
#define REG_DX(r) ((r).edx)
#endif

/* The value of the first system-call argument at syscall entry. On most
   architectures this is REG_ARG1, but ppc and s390 preset that register
   to -ENOSYS at the seccomp-trace stop and keep the argument in a
   separate orig register. */
#ifndef REG_ORIG_ARG1
#define REG_ORIG_ARG1(r) REG_ARG1(r)
#endif

/**
 * Machine code of a breakpoint; syscall; breakpoint stub, injected at
 * the entry point after execve to run system calls inside the tracee,
 * see execution::handleExecEvent. The offsets describe where the pc
 * points relative to the stub start: after the first breakpoint trap
 * (firstTrapOff), where the syscall instruction is (syscallOff) and
 * after the trailing breakpoint trap (endOff). x86 and s390x advance
 * the pc past a trapping breakpoint, the others do not. arm has two
 * instruction sets, syscallStubFor picks the one the tracee runs in.
 */
struct SyscallStub {
  const unsigned char* code;
  size_t size;
  unsigned long firstTrapOff;
  unsigned long syscallOff;
  unsigned long endOff;
};

#if defined(__x86_64__)
static const unsigned char syscallStubCode[] = {0xcc, 0x0f, 0x05, 0xcc};
static const SyscallStub syscallStub = {syscallStubCode, 4, 1, 1, 4};
#elif defined(__i386__)
static const unsigned char syscallStubCode[] = {0xcc, 0xcd, 0x80, 0xcc};
static const SyscallStub syscallStub = {syscallStubCode, 4, 1, 1, 4};
#elif defined(__aarch64__)
static const unsigned char syscallStubCode[] = {0x00, 0x00, 0x20, 0xd4,
                                                0x01, 0x00, 0x00, 0xd4,
                                                0x00, 0x00, 0x20, 0xd4};
static const SyscallStub syscallStub = {syscallStubCode, 12, 0, 4, 8};
#elif defined(__arm__)
static const unsigned char armSyscallStubCode[] = {0xf0, 0x01, 0xf0, 0xe7,
                                                   0x00, 0x00, 0x00, 0xef,
                                                   0xf0, 0x01, 0xf0, 0xe7};
static const SyscallStub armSyscallStub = {armSyscallStubCode, 12, 0, 4, 8};
static const unsigned char thumbSyscallStubCode[] = {0x01, 0xde, 0x00,
                                                     0xdf, 0x01, 0xde};
static const SyscallStub thumbSyscallStub = {thumbSyscallStubCode, 6, 0, 2,
                                             4};
#elif defined(__powerpc__)
static const unsigned char syscallStubCode[] = {
    INSN32(BREAK_INSN), INSN32(SYSCALL_INSN), INSN32(BREAK_INSN)};
static const SyscallStub syscallStub = {syscallStubCode, 12, 0, 4, 8};
#elif defined(__riscv) && __riscv_xlen == 64
static const unsigned char syscallStubCode[] = {0x73, 0x00, 0x10, 0x00,
                                                0x73, 0x00, 0x00, 0x00,
                                                0x73, 0x00, 0x10, 0x00};
static const SyscallStub syscallStub = {syscallStubCode, 12, 0, 4, 8};
#elif defined(__loongarch64)
static const unsigned char syscallStubCode[] = {
    INSN32(BREAK_INSN), INSN32(SYSCALL_INSN), INSN32(BREAK_INSN)};
static const SyscallStub syscallStub = {syscallStubCode, 12, 0, 4, 8};
#elif defined(__s390x__)
/* 0x0001 is the s390 breakpoint instruction, the kernel turns the
   resulting operation exception into a SIGTRAP. */
static const unsigned char syscallStubCode[] = {0x00, 0x01, 0x0a,
                                                0x00, 0x00, 0x01};
static const SyscallStub syscallStub = {syscallStubCode, 6, 2, 2, 6};
#endif

/* Room for the largest stub, 12 bytes, in words of the smallest size. */
const size_t maxSyscallStubWords = 3;

/**
 * The stub to inject into a tracee stopped with the given registers.
 */
static inline const SyscallStub& syscallStubFor(
    const struct user_regs_struct& r) {
#if defined(__arm__)
  return (REG_CPSR(r) & ARM_CPSR_THUMB) ? thumbSyscallStub : armSyscallStub;
#else
  (void)r;
  return syscallStub;
#endif
}

/**
 * Return value of the current/last system call in the usual Linux
 * convention (negative errno on error), and its setter. On most
 * architectures this is simply the REG_RETVAL register; powerpc uses
 * the cr0 summary-overflow bit plus a positive errno instead.
 */
static inline long regsReturnValue(const struct user_regs_struct& r) {
#if defined(__powerpc__)
  return (r.ccr & PPC_CR0_SO) ? -(long)r.gpr[3] : (long)r.gpr[3];
#else
  return (long)REG_RETVAL(r);
#endif
}

/**
 * Whether a raw system call return value is -errno. Not simply "negative":
 * on 32-bit architectures mmap hands out addresses above 2 GiB, which
 * are negative as a long.
 */
static inline bool syscallFailed(long ret) {
  return (unsigned long)ret >= (unsigned long)-4095;
}

static inline void regsSetReturnValue(struct user_regs_struct& r, long val) {
#if defined(__powerpc__)
  if (val < 0) {
    r.gpr[3] = -val;
    r.ccr |= PPC_CR0_SO;
  } else {
    r.gpr[3] = val;
    r.ccr &= ~PPC_CR0_SO;
  }
#else
  REG_RETVAL(r) = val;
#endif
}

/**
 * ptrace event enum.
 * Types of events we expect returned from getNextEvent(), I wish we had ADTs.
 */
enum class ptraceEvent {
  syscall, /**< Post system call execution event. */
  nonEventExit, /** Process/thread has exited. */
  eventExit, /**< Process/thread has exited. */
  signal, /**< Received signal. */
  exec, /**< Execve event. */
  clone, /**< Clone event. */
  fork, /**< fork event. */
  vfork, /** fork event. */
  terminatedBySignal, /**< Tracee terminated by signal. */
  seccomp,
};

/**
 * State of SysCall enum.
 * Ptrace does not keep track for us if this is a pre or a post event. Instead
 * we must track this ourselves.
 */
enum class syscallState {
  pre, /**< pre-hook state*/
  post /**< post-hook state*/
};

/**
 * ptracer.
 * Class wrapping the functionality of the system call ptrace.
 */
class ptracer {
public:
  /**
   * counter to keep track read vm events;
   */
  uint32_t readVmCalls = 0;

  /**
   * counter to keep track write vm events;
   */
  uint32_t writeVmCalls = 0;

  /**
   * counter for peeks, peeks only called through: readTraceeCString.
   */
  uint32_t ptracePeeks = 0;

  /**
   * Map of real inodes to virtual inodes.
   */
  map<ino_t, ino_t> real2VirtualMap;

  /**
   * Constructor.
   * Create a ptracer. The child must have called PTRACE_TRACEME and then
   *stopped itself like so: raise(SIGSTOP); execvp(traceeCommand[0],
   *traceeCommand);
   *
   * Else this will block forever. Set up options for our tracer.
   * @param pid process pid
   */
  ptracer(pid_t pid);

  /**
   * Retrieves value for arg1: rdi register.
   * @return rdi register value
   */
  uint64_t arg1();

  /**
   * Retrieves value for arg2: rsi register.
   * @return rsi register value
   */
  uint64_t arg2();

  /**
   * Retrieves value for arg3: rdx register.
   * @return rdx register value
   */
  uint64_t arg3();

  /**
   * Retrieves value for arg4: r10 register.
   * RCX, along with R11, is used by the syscall instruction, being immediately
   * destroyed by it. Thus these registers are not only not saved after syscall,
   * but they can't even be used for parameter passing. Thus R10 was chosen to
   * replace unusable RCX to pass fourth parameter. per:
   * https://stackoverflow.com/questions/21322100/linux-x64-why-does-r10-come-before-r8-and-r9-in-syscalls
   *
   * @return r10 register value
   */
  uint64_t arg4();

  /**
   * Retrieves value for arg5: r8 register.
   * @return r8 register value
   */
  uint64_t arg5();

  /**
   * Retrieves value for arg6: r9 register.
   * @return r9 register value
   */
  uint64_t arg6();

  /**
   * Retrieves register struct.
   * @return x86 register struct
   */
  struct user_regs_struct getRegs();

  /**
   * Set regs to the values given by passed struct.
   * @param newValues struct of new register values
   */
  void setRegs(struct user_regs_struct newValues);
  /**
   * Retrieves value for Rip register.
   * @return Rip register value
   */
  traceePtr<void> getRip();

  /**
   * Retrieves value for Rsp register.
   * @return Rsp register value
   */
  traceePtr<void> getRsp();

  /**
   * Retrieves value for Rax register.
   * @return Rax register value
   */
  traceePtr<void> getRax();

  /**
   * Change system call.
   * Writing to rax register, be careful!
   * @param val value to write to eax for new system call
   */
  void changeSystemCall(uint64_t val);

  /**
   * Write  value to Arg1: rdi register.
   * @param val new rdi register value
   */
  void writeArg1(uint64_t val);

  /**
   * Write  value to Arg2: rsi register.
   * @param val new rsi register value
   */
  void writeArg2(uint64_t val);

  /**
   * Write  value to Arg3: rdx register.
   * @param val new rdx register value
   */
  void writeArg3(uint64_t val);

  /**
   * Write  value to Arg4: r10 register.
   * @param val new r10 register value
   */
  void writeArg4(uint64_t val);

  /**
   * Write  value to Arg5: r8 register.
   * @param val new r8 register value
   */
  void writeArg5(uint64_t val);

  /**
   * Write  value to Arg6: r9 register.
   * @param val new r9 register value
   */
  void writeArg6(uint64_t val);

  /**
   * Write  value to ip register.
   * @param val new ip register value
   */
  void writeIp(uint64_t val);

  /**
   * Size in bytes of the syscall instruction the tracee stopped behind,
   * to rewind the pc onto it for a replay. A constant everywhere but on
   * arm, where Thumb code has a 2 byte svc.
   */
  size_t syscallInsnLength() const;

#if defined(__x86_64__) || defined(__i386__)
  /**
   * Write  value to rax (eax) register. Use setReturnRegister() to set a
   * system call's return value; on some architectures that is not just
   * a register write.
   * @param val new rax register value
   */
  void writeRax(uint64_t val);

  /**
   * Write value to rbx register.
   * @param val new rbx register value
   */
  void writeRbx(uint64_t val);

  /**
   * Write  value to rdx register.
   * @param val new rdx register value
   */
  void writeRdx(uint64_t val);

  /**
   * Write  value to rcx register.
   * @param val new rcx register value
   */
  void writeRcx(uint64_t val);
#endif

  /**
   * Cache the current register values as the system call arguments, to
   * be returned by arg1()..arg6() until the next call. Must be invoked
   * at the syscall-entry (seccomp) stop, where all argument registers
   * still hold the values the tracee passed.
   */
  void captureSyscallArgs();

  /**
   * Copy the cached system call arguments out to / in from per-tracee
   * storage. The ptracer keeps a single shared copy, so execution
   * persists it into the current tracee's state after capturing and
   * restores it before running the post-hook, keeping the arguments
   * correct across scheduler switches.
   */
  void saveSyscallArgs(uint64_t out[6]) const;
  void restoreSyscallArgs(const uint64_t in[6]);

#if defined(__s390x__)
  /**
   * Override the syscall number decoded by updateState, used by execution
   * to restore a tracee's (possibly changed) number at its post stop.
   */
  void setSystemCallNumber(long val) { currentSyscall = val; }
#endif

  /**
   * Write the cached system call arguments back into the tracee's
   * argument registers. Needed before replaying a system call on
   * architectures where the return value has overwritten the first
   * argument register (x0/a0/r3), so the replayed call sees its
   * original arguments again.
   */
  void writeSyscallArgsToRegs();

  /**
   * Read the registers of an arbitrary tracee into regs.
   * Uses PTRACE_GETREGS where available and PTRACE_GETREGSET elsewhere.
   */
  static void readRegisters(pid_t pid, struct user_regs_struct& regs);

  /**
   * Write regs into the registers of an arbitrary tracee.
   */
  static void writeRegisters(pid_t pid, struct user_regs_struct& regs);

#if defined(__aarch64__)
  /**
   * Set the system call the kernel executes for the current syscall stop.
   * Everywhere else this is part of the register set (orig_rax, gpr[0],
   * a7, gprs[2] on s390x); on aarch64 it must be written separately
   * through the NT_ARM_SYSTEM_CALL regset.
   */
  static void writeSyscallNumber(pid_t pid, long val);
#endif
  /**
   * All system call return an argument through their rax register.
   * Set state here.
   * @param retVal return value
   */
  void setReturnRegister(uint64_t retVal);

  /**
   * Get results of system calls, we cast register value into int to avoid
   * issues with sign.
   * @return Return value
   */
  int getReturnValue();

  /**
   * Get system call number.
   * During pre system call event.
   * @return System call number
   */
  uint64_t getSystemCallNumber();

  /**
   * Wrapper around PTRACE_GETEVENTMSG for our current tracee.
   * @return Event message
   */
  static uint64_t getEventMessage(pid_t traceePid);

  /**
   * Compare status returned from waitpid to ptrace event.
   * @param status
   * @param event
   * @return
   */
  inline static bool isPtraceEvent(int status, enum __ptrace_eventcodes event) {
    return (status >> 8) == (SIGTRAP | (event << 8));
  }

  /**
   * Re-read the current tracee's registers into the cache after they were
   * written behind its back (e.g. cancelSystemCall's restore), without
   * touching the cached syscall arguments or number.
   */
  void refreshRegisters();

  /**
   * Update registers to the state of the passed pid. This is now the new pid.
   * @param newPid new pid number
   */
  void updateState(pid_t newPid);

  /**
   * Return the pid for the current process we have stopped in an event.
   * @return pid
   */
  pid_t getPid();

  /**
   * Set the correct tracing options for a child we plan to trace. This should
   * be called per child and only once! This must be called when child is
   * stopped waiting on ptrace.
   * @param pid process id
   */
  static void setOptions(pid_t pid);

  /*
   * Ptrace wrapper with error checking, use this instead of raw ptrace.
   * @param request
   * @param pid
   * @param addr
   * @param data
   * @return On success, PTRACE_PEEK* requests return the requested data, while
   * other requests return zero. On error, all requests return -1, and errno is
   * set appropriately. Since the value returned by a successful PTRACE_PEEK*
   * request may be -1, the caller must clear errno before the call, and then
   * check it afterward to determine whether or not an error occurred.
   */
  static long doPtrace(
      enum __ptrace_request request, pid_t pid, void *addr, void *data);

  /**
   * Read a type T from the tracee at source address. Be careful when reading
   * record types which may further contain other pointers! You will have to
   * fetch the other pointers yourself.
   * @param sourceAddress memory address of the type T in tracee memory to read.
   * @param traceePid Pid of the tracee
   * @return the data of type T at the memory address in tracee address space
   */
  template <typename T>
  T readFromTracee(traceePtr<T> sourceAddress, pid_t traceePid) {
    readVmCalls++;
    T myData;
    doWithCheck(
        readVmTraceeRaw(sourceAddress, &myData, sizeof(T), traceePid),
        "readFromTracee: Unable to read bytes at address.");
    return myData;
  }

  /**
   * Read the C-string from the tracee's memory.
   * Notice we keep reading until we hit a null.
   * Undefined behavior will happen if the location is not actually a C-string.
   * @param readAddress address of CString to be read from (in tracee address
   * space)
   * @param traceePid the pid of the tracee
   * @return cpp string version of readAddress.
   */
  string readTraceeCString(traceePtr<char> readAddress, pid_t traceePid);

  /**
   * Write a value to tracee.
   * @param writeAddress memory address in trace memory to write to.
   * @param valueToCopy value of type T to be written in tracee memory
   * @param traceePid the pid of the tracee
   */
  template <typename T>
  void writeToTracee(
      traceePtr<T> writeAddress, T valueToCopy, pid_t traceePid) {
    writeVmCalls++;
    writeVmTraceeRaw(
        &valueToCopy, traceePtr<T>(writeAddress), sizeof(T), traceePid);

    return;
  }

private:
  pid_t traceePid; /**< The pid of the tracee.  */

  struct user_regs_struct regs; /**< Registers struct defined in sys.   */
  /**
   * System call arguments captured at syscall entry. On x86_64 the
   * argument registers survive into the post-hook, but on most other
   * architectures the first argument register aliases the return-value
   * register (x0/a0/r3), so it is overwritten by the time the post-hook
   * runs. We therefore cache all arguments at the seccomp (entry) stop
   * and serve arg1()..arg6() from the cache; writeArgN() keeps the cache
   * in sync so the argument-rewriting logic still reads back what it
   * wrote.
   */
  uint64_t syscallArgs[6] = {0, 0, 0, 0, 0, 0};
#if defined(__s390x__)
  /**
   * Number of the system call at the current stop. Decoded from the svc
   * instruction by updateState (see decodeSyscallNumber) and overridden
   * by changeSystemCall; execution persists it per tracee across the
   * pre/post stops like syscallArgs.
   */
  long currentSyscall = 0;
  long decodeSyscallNumber();
#endif
};

#endif

extern "C" {
#include <stdint.h>
#include <string.h>
#include <elf.h>
#include <sys/ptrace.h>
#if defined(__x86_64__) || defined(__i386__)
#include <sys/reg.h> /* For constants ORIG_EAX, etc */
#endif
#include <sys/syscall.h> /* For SYS_write, etc */
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/vfs.h>
#include <sys/wait.h>
}
#include <algorithm>
#include <cstddef>
#include <experimental/optional>
#include <iostream>
#include <memory>
#include <set>
#include <tuple>

#include "dettraceSystemCall.hpp"
#include "ptracer.hpp"

using namespace std;

ptracer::ptracer(pid_t pid) {
  traceePid = pid;

  int startingStatus;
  if (-1 == waitpid(pid, &startingStatus, 0)) {
    throw runtime_error(
        "Unable to start first process: " + string{strerror(errno)});
  }
}

uint64_t ptracer::arg1() { return syscallArgs[0]; }
uint64_t ptracer::arg2() { return syscallArgs[1]; }
uint64_t ptracer::arg3() { return syscallArgs[2]; }
uint64_t ptracer::arg4() { return syscallArgs[3]; }
uint64_t ptracer::arg5() { return syscallArgs[4]; }
uint64_t ptracer::arg6() { return syscallArgs[5]; }

void ptracer::captureSyscallArgs() {
  // At the syscall-entry stop every argument register still holds the
  // value the tracee passed (on s390 the first argument is in gprs[2]
  // which is not yet clobbered here). Go through unsigned long: i386's
  // struct user_regs_struct has signed fields, and a pointer or ioctl
  // request with the top bit set must not be sign-extended to 64 bits.
  syscallArgs[0] = (unsigned long)REG_ORIG_ARG1(regs);
  syscallArgs[1] = (unsigned long)REG_ARG2(regs);
  syscallArgs[2] = (unsigned long)REG_ARG3(regs);
  syscallArgs[3] = (unsigned long)REG_ARG4(regs);
  syscallArgs[4] = (unsigned long)REG_ARG5(regs);
  syscallArgs[5] = (unsigned long)REG_ARG6(regs);
}

#if defined(__riscv)
void ptracer::captureSyscallArgsFromProc() {
  // "nr arg1 .. arg6 sp pc", the arguments as syscall_get_arguments()
  // reports them, which is orig_a0 for the first one.
  string path = "/proc/" + to_string(traceePid) + "/syscall";
  FILE* f = fopen(path.c_str(), "r");
  if (f == nullptr) {
    runtimeError("Unable to open " + path + ": " + string{strerror(errno)});
  }
  long nr;
  unsigned long args[6];
  int n = fscanf(
      f, "%ld %lx %lx %lx %lx %lx %lx", &nr, &args[0], &args[1], &args[2],
      &args[3], &args[4], &args[5]);
  fclose(f);
  if (n != 7 || nr != (long)getSystemCallNumber()) {
    runtimeError(
        path + " does not show the tracee inside system call " +
        to_string(getSystemCallNumber()));
  }
  for (int i = 0; i < 6; i++) syscallArgs[i] = args[i];
}
#endif

void ptracer::saveSyscallArgs(uint64_t out[6]) const {
  for (int i = 0; i < 6; i++) out[i] = syscallArgs[i];
}

void ptracer::restoreSyscallArgs(const uint64_t in[6]) {
  for (int i = 0; i < 6; i++) syscallArgs[i] = in[i];
}

void ptracer::writeSyscallArgsToRegs() {
  // Only used at the exit stop right before re-executing the syscall
  // instruction, so on s390 gprs[2] must hold the first argument the
  // tracee will pass again, not the syscall number (see writeArg1).
  REG_ORIG_ARG1(regs) = syscallArgs[0];
  REG_ARG1(regs) = syscallArgs[0];
  REG_ARG2(regs) = syscallArgs[1];
  REG_ARG3(regs) = syscallArgs[2];
  REG_ARG4(regs) = syscallArgs[3];
  REG_ARG5(regs) = syscallArgs[4];
  REG_ARG6(regs) = syscallArgs[5];
  writeRegisters(traceePid, regs);
}
struct user_regs_struct ptracer::getRegs() {
  return regs;
}

void ptracer::setRegs(struct user_regs_struct newValues) {
  regs = newValues;
  writeRegisters(traceePid, regs);
  // A wholesale register restore (e.g. popping the state saved before an
  // injected system call) must also refresh the cached syscall arguments,
  // otherwise a subsequent replaySystemCall would write the stale
  // arguments of the injected call back over the restored registers.
  captureSyscallArgs();
  return;
}

void ptracer::readRegisters(pid_t pid, struct user_regs_struct& regs) {
#if defined(__m68k__)
  // m68k has no regsets. PTRACE_GETREGS fills the 19 words the kernel
  // keeps, which is all of the struct but its trailing format/vector
  // word, so clear it rather than leave that one undefined.
  memset(&regs, 0, sizeof(regs));
  doPtrace(PTRACE_GETREGS, pid, nullptr, &regs);
#elif defined(__x86_64__) || defined(__i386__)
  doPtrace(PTRACE_GETREGS, pid, nullptr, &regs);
#else
  struct iovec iov = {&regs, sizeof(regs)};
  doPtrace(
      (enum __ptrace_request)PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &iov);
#endif
}

void ptracer::writeRegisters(pid_t pid, struct user_regs_struct& regs) {
#if defined(__x86_64__) || defined(__i386__) || defined(__m68k__)
  doPtrace(PTRACE_SETREGS, pid, nullptr, &regs);
#else
  struct iovec iov = {&regs, sizeof(regs)};
  doPtrace(
      (enum __ptrace_request)PTRACE_SETREGSET, pid, (void*)NT_PRSTATUS, &iov);
#endif
}

#if defined(__aarch64__)
void ptracer::writeSyscallNumber(pid_t pid, long val) {
  int sysnum = (int)val;
  struct iovec iov = {&sysnum, sizeof(sysnum)};
  doPtrace(
      (enum __ptrace_request)PTRACE_SETREGSET, pid,
      (void*)(long)NT_ARM_SYSTEM_CALL, &iov);
}
#endif

traceePtr<void> ptracer::getRip() {
  return traceePtr<void>((void*)regsGetIp(regs));
}
traceePtr<void> ptracer::getRsp() {
  return traceePtr<void>((void*)REG_SP(regs));
}

traceePtr<void> ptracer::getRax() {
  return traceePtr<void>((void*)regsReturnValue(regs));
}

uint64_t ptracer::getEventMessage(pid_t traceePid) {
  long event;
  doPtrace(PTRACE_GETEVENTMSG, traceePid, nullptr, &event);

  return event;
}

int ptracer::getReturnValue() { return (int)regsReturnValue(regs); }

uint64_t ptracer::getSystemCallNumber() {
#if defined(__s390x__)
  return currentSyscall;
#else
  return (unsigned long)REG_SYSNUM(regs);
#endif
}

#if defined(__s390x__)
long ptracer::decodeSyscallNumber() {
  // The NT_S390_SYSTEM_CALL regset is not readable at the seccomp-trace
  // stop (it returned garbage there). glibc uses both encodings of the
  // svc instruction: "svc N" carries the number as its immediate, "svc 0"
  // takes it from r1. The pc points right behind the 2-byte svc at every
  // syscall stop, so decode it; fall back to r1 elsewhere.
  uint16_t insn = readFromTracee(
      traceePtr<uint16_t>((uint16_t*)(regsGetIp(regs) - 2)), traceePid);
  if ((insn & 0xff00) == 0x0a00 && (insn & 0x00ff) != 0) {
    return insn & 0x00ff;
  }
  return (long)REG_SYSNUM(regs);
}
#endif

void ptracer::setReturnRegister(uint64_t retVal) {
  regsSetReturnValue(regs, (long)retVal);
  writeRegisters(traceePid, regs);
}

void ptracer::refreshRegisters() { readRegisters(traceePid, regs); }

void ptracer::updateState(pid_t newPid) {
  traceePid = newPid;
  readRegisters(traceePid, regs);
#if defined(__s390x__)
  currentSyscall = decodeSyscallNumber();
#endif
#if defined(__riscv)
  // At a system call entry the kernel has already replaced a0 with
  // -ENOSYS (do_trap_ecall_u keeps the first argument in orig_a0, which
  // no regset exposes, and passes that to the handler), so ask what it
  // will pass and show a0 as the tracee loaded it, like every other
  // architecture does at this stop. The register snapshots a pre-hook
  // saves and restores around an injected call then carry the argument
  // as well. Writing a0 back here is ignored, see writeArg1.
  struct __ptrace_syscall_info info;
  atSyscallEntry = false;
  doPtrace(
      (enum __ptrace_request)PTRACE_GET_SYSCALL_INFO, traceePid,
      (void*)sizeof(info), &info);
  if (info.op == PTRACE_SYSCALL_INFO_ENTRY ||
      info.op == PTRACE_SYSCALL_INFO_SECCOMP) {
    regs.a0 = info.entry.args[0];
    atSyscallEntry = true;
  }
#endif

  return;
}

pid_t ptracer::getPid() { return traceePid; }

void ptracer::setOptions(pid_t pid) {
  doPtrace(PTRACE_SETOPTIONS, pid, NULL, (void*)
	   (PTRACE_O_EXITKILL | // If Tracer exits. Send SIGKIll signal to all tracees.
	    PTRACE_O_TRACECLONE | // enroll child of tracee when clone is called.
	    // We don't really need to catch execves, but we get a spurious signal 5
	    // from ptrace if we don't.
	    PTRACE_O_TRACEEXEC |
	    PTRACE_O_TRACEFORK |
	    PTRACE_O_TRACEVFORK |
	    // Stop tracee right as it is about to exit. This is needed as we cannot
	    // assume WIFEXITED will work, see man ptrace 2.
	    PTRACE_O_TRACEEXIT |
	    PTRACE_O_TRACESYSGOOD |
	    PTRACE_O_TRACESECCOMP |
      PTRACE_O_TRACEEXEC
	    ));
  return;
}

string ptracer::readTraceeCString(
    traceePtr<char> readAddress, pid_t traceePid) {
  string r;
  bool done = false;

  // Read long-sized chunks of memory at at time.
  while (!done) {
    long result =
        doPtrace(PTRACE_PEEKDATA, traceePid, readAddress.ptr, nullptr);
    ptracePeeks++;
    const char *p = (const char *)&result;
    const size_t bytesRead = strnlen(p, wordSize);
    if (wordSize != bytesRead) {
      done = true;
    }

    for (unsigned i = 0; i < bytesRead; i++) {
      r += p[i];
    }

    // Notice this doesn't change readAddress outside this function -> pass by
    // value.
    readAddress.ptr += bytesRead;
  }

  return r;
}

long ptracer::doPtrace(
    enum __ptrace_request request, pid_t pid, void *addr, void *data) {
  /*
    Return Value
    On success, PTRACE_PEEK* requests return the requested data, while other
    requests return zero. On error, all requests return -1, and errno is set
    appropriately. Since the value returned by a successful PTRACE_PEEK* request
    may be -1, the caller must clear errno before the call, and then check it
    afterward to determine whether or not an error occurred.
    -- ptrace manpage
  */

  errno = 0;
  const long val = ptrace(request, pid, addr, data);

  if (PTRACE_PEEKTEXT == request || PTRACE_PEEKDATA == request ||
      PTRACE_PEEKUSER == request) {
    if (0 != errno) {
      runtimeError(
          "Ptrace_peek* failed with error: " + string{strerror(errno)});
    }
  } else if (-1 == val) {
    runtimeError(
        "Ptrace failed with error: " + string{strerror(errno)} + " on thread " +
        to_string(pid) + " with request " + to_string(request) + "\n");
  }
  return val;
}

void ptracer::changeSystemCall(uint64_t val) {
#if defined(__x86_64__) || defined(__i386__) || defined(__m68k__)
  // Two registers to write: the kernel reads the number of the call to
  // execute from the one it saved at entry (orig_rax, orig_d0), while a
  // trap executed afresh -- which is what a replay does -- takes it from
  // the plain register the tracee loaded (rax, d0). On m68k the kernel
  // overwrites orig_d0 from d0 on the way in, and restarts an
  // interrupted call by copying orig_d0 back into d0 before rewinding.
  REG_SYSNUM(regs) = val;
  REG_RETVAL(regs) = val;
#elif defined(__s390x__)
  // At a syscall stop the kernel takes the number of the system call to
  // execute from gprs[2]: __poke_user (arch/s390/kernel/ptrace.c) rewrites
  // the low 16 bits of int_code from every write of that register while
  // PIF_SYSCALL is set. So the number has to go there; r1 as well, so that
  // a replayed "svc 0" (which reads its number from r1) picks it up when
  // the instruction is re-executed. The NT_S390_SYSTEM_CALL regset is not
  // consulted at syscall stops, only at signal stops for restart handling.
  regs.gprs[1] = val;
  regs.gprs[2] = val;
#else
  REG_SYSNUM(regs) = val;
#endif
  writeRegisters(traceePid, regs);
#if defined(__aarch64__)
  // Writing x8 does not change which system call the kernel executes for
  // the current syscall stop, that takes a dedicated regset write.
  writeSyscallNumber(traceePid, (long)val);
#endif
#if defined(__arm__)
  // Like aarch64, arm takes the number of the system call to execute
  // from the tracer through a dedicated request; r7 is only read by a
  // re-executed svc. The sentinels of syscallCompat.hpp must not reach
  // the kernel here: a 32-bit kernel masks the number with 0xfffff, which
  // turns them into ARM-private numbers it answers with SIGILL. Hand it a
  // number that is simply not a syscall instead (above the table, below
  // the private range), which native and arm64-compat kernels alike turn
  // into -ENOSYS; r7 keeps the sentinel so the post-hook still dispatches
  // on it.
  long kernelNr = isSentinelSyscall((long)val) ? 0xeffff : (long)val;
  doPtrace(
      (enum __ptrace_request)PTRACE_SET_SYSCALL, traceePid, nullptr,
      (void*)kernelNr);
#endif
#if defined(__s390x__)
  currentSyscall = (long)val;
#endif
  return;
}

void ptracer::writeArg1(uint64_t val) {
#if defined(__s390x__)
  // The kernel passes the first argument to the handler from orig_gpr2.
  // Leave gprs[2] alone: at the entry stop it carries the syscall number,
  // and writing it would make the low 16 bits of the argument the number
  // of the system call that executes (see changeSystemCall).
  regs.orig_gpr2 = val;
#else
#if defined(__riscv)
  // The handler gets its first argument from orig_a0, which a tracer can
  // only write from Linux 6.15 on (PTRACE_SET_SYSCALL_INFO); a0 written
  // at the entry stop does not reach the call. Note it, so that the call
  // is skipped and executed again from these registers instead, see
  // takeArg1RewrittenAtEntry. At an exit stop the write is fine: the
  // only reason to write it there is a replay, which traps afresh.
  if (atSyscallEntry && val != syscallArgs[0]) {
    arg1RewrittenAtEntry = true;
  }
#endif
  REG_ORIG_ARG1(regs) = val;
  REG_ARG1(regs) = val;
#endif
  syscallArgs[0] = val;
  writeRegisters(traceePid, regs);
}

bool ptracer::takeArg1RewrittenAtEntry() {
#if defined(__riscv)
  bool rewritten = arg1RewrittenAtEntry;
  arg1RewrittenAtEntry = false;
  return rewritten;
#else
  return false;
#endif
}

void ptracer::writeArg2(uint64_t val) {
  REG_ARG2(regs) = val;
  syscallArgs[1] = val;
  writeRegisters(traceePid, regs);
}
void ptracer::writeArg3(uint64_t val) {
  REG_ARG3(regs) = val;
  syscallArgs[2] = val;
  writeRegisters(traceePid, regs);
}

void ptracer::writeArg4(uint64_t val) {
  REG_ARG4(regs) = val;
  syscallArgs[3] = val;
  writeRegisters(traceePid, regs);
}

void ptracer::writeArg5(uint64_t val) {
  REG_ARG5(regs) = val;
  syscallArgs[4] = val;
  writeRegisters(traceePid, regs);
}

void ptracer::writeArg6(uint64_t val) {
  REG_ARG6(regs) = val;
  syscallArgs[5] = val;
  writeRegisters(traceePid, regs);
}

void ptracer::writeIp(uint64_t val) {
  regsSetIp(regs, (unsigned long)val);
  writeRegisters(traceePid, regs);
}

void ptracer::rewindToSyscall() {
#if defined(__hppa__)
  // parisc enters the kernel by branching to the gateway page, so the
  // instruction queue at a syscall stop does not point into user code at
  // all and the address to come back to is the one the branch left in
  // r31. Winding that back over the branch and its delay slot is how the
  // kernel restarts an interrupted system call itself, see
  // check_syscallno_in_delay_branch() in arch/parisc/kernel/signal.c.
  // NB: the delay slot usually loads the syscall number, so the replayed
  // call is the one the tracee originally made -- changing the number
  // and replaying does not work here, the same limitation s390x has with
  // the number in the svc instruction.
  regs.gr[31] -= syscallInsnSize;
  writeRegisters(traceePid, regs);
#else
  writeIp(regsGetIp(regs) - syscallInsnLength());
#endif
}

size_t ptracer::syscallInsnLength() const {
#if defined(__arm__)
  return (REG_CPSR(regs) & ARM_CPSR_THUMB) ? 2 : 4;
#else
  return syscallInsnSize;
#endif
}

#if defined(__x86_64__) || defined(__i386__)
void ptracer::writeRax(uint64_t val) {
  REG_RETVAL(regs) = val;
  writeRegisters(traceePid, regs);
}

void ptracer::writeRbx(uint64_t val) {
  REG_BX(regs) = val;
  writeRegisters(traceePid, regs);
}

void ptracer::writeRdx(uint64_t val) {
  REG_DX(regs) = val;
  writeRegisters(traceePid, regs);
}

void ptracer::writeRcx(uint64_t val) {
  REG_CX(regs) = val;
  writeRegisters(traceePid, regs);
}
#endif

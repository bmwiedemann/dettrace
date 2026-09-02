extern "C" {
#include <stdint.h>
#include <string.h>
#include <elf.h>
#include <sys/ptrace.h>
#if defined(__x86_64__)
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
  // which is not yet clobbered here).
  syscallArgs[0] = REG_ORIG_ARG1(regs);
  syscallArgs[1] = REG_ARG2(regs);
  syscallArgs[2] = REG_ARG3(regs);
  syscallArgs[3] = REG_ARG4(regs);
  syscallArgs[4] = REG_ARG5(regs);
  syscallArgs[5] = REG_ARG6(regs);
}

void ptracer::saveSyscallArgs(uint64_t out[6]) const {
  for (int i = 0; i < 6; i++) out[i] = syscallArgs[i];
}

void ptracer::restoreSyscallArgs(const uint64_t in[6]) {
  for (int i = 0; i < 6; i++) syscallArgs[i] = in[i];
}

void ptracer::writeSyscallArgsToRegs() {
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
  return;
}

void ptracer::readRegisters(pid_t pid, struct user_regs_struct& regs) {
#if defined(__x86_64__)
  doPtrace(PTRACE_GETREGS, pid, nullptr, &regs);
#else
  struct iovec iov = {&regs, sizeof(regs)};
  doPtrace((enum __ptrace_request)PTRACE_GETREGSET, pid, (void*)NT_PRSTATUS, &iov);
#endif
}

void ptracer::writeRegisters(pid_t pid, struct user_regs_struct& regs) {
#if defined(__x86_64__)
  doPtrace(PTRACE_SETREGS, pid, nullptr, &regs);
#else
  struct iovec iov = {&regs, sizeof(regs)};
  doPtrace((enum __ptrace_request)PTRACE_SETREGSET, pid, (void*)NT_PRSTATUS, &iov);
#endif
}

#if defined(__aarch64__) || defined(__s390x__)
void ptracer::writeSyscallNumber(pid_t pid, long val) {
#if defined(__aarch64__)
  const int regset = NT_ARM_SYSTEM_CALL;
#else
  const int regset = NT_S390_SYSTEM_CALL;
#endif
  int sysnum = (int)val;
  struct iovec iov = {&sysnum, sizeof(sysnum)};
  doPtrace(
      (enum __ptrace_request)PTRACE_SETREGSET, pid, (void*)(long)regset, &iov);
}
#endif

traceePtr<void> ptracer::getRip() { return traceePtr<void>((void *)REG_IP(regs)); }
traceePtr<void> ptracer::getRsp() { return traceePtr<void>((void *)REG_SP(regs)); }

traceePtr<void> ptracer::getRax() { return traceePtr<void>((void *)regsReturnValue(regs)); }

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
  return REG_SYSNUM(regs);
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
      traceePtr<uint16_t>((uint16_t*)(REG_IP(regs) - 2)), traceePid);
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

void ptracer::updateState(pid_t newPid) {
  traceePid = newPid;
  readRegisters(traceePid, regs);
#if defined(__s390x__)
  currentSyscall = decodeSyscallNumber();
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
    int64_t result =
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
#if defined(__x86_64__)
  regs.orig_rax = val;
  regs.rax = val;
#else
  REG_SYSNUM(regs) = val;
#endif
  writeRegisters(traceePid, regs);
#if defined(__aarch64__) || defined(__s390x__)
  // Writing the syscall number register does not change which system call
  // the kernel executes for the current syscall stop here, that takes a
  // dedicated regset write.
  writeSyscallNumber(traceePid, (long)val);
#endif
#if defined(__s390x__)
  currentSyscall = (long)val;
#endif
  return;
}

void ptracer::writeArg1(uint64_t val) {
  REG_ORIG_ARG1(regs) = val;
  REG_ARG1(regs) = val;
  syscallArgs[0] = val;
  writeRegisters(traceePid, regs);
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
  REG_IP(regs) = val;
  writeRegisters(traceePid, regs);
}

#if defined(__x86_64__)
void ptracer::writeRax(uint64_t val) {
  REG_RETVAL(regs) = val;
  writeRegisters(traceePid, regs);
}

void ptracer::writeRbx(uint64_t val) {
  regs.rbx = val;
  writeRegisters(traceePid, regs);
}

void ptracer::writeRdx(uint64_t val) {
  regs.rdx = val;
  writeRegisters(traceePid, regs);
}

void ptracer::writeRcx(uint64_t val) {
  regs.rcx = val;
  writeRegisters(traceePid, regs);
}
#endif

// Regression test: the CPU number a tracee sees must be 0 regardless of where
// it runs. glibc >= 2.35 answers sched_getcpu() from its rseq area without
// any syscall or vDSO call, which leaked the real CPU number, and the getcpu
// syscall it falls back to had no seccomp rule at all, which aborted dettrace.
#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
  printf("sched_getcpu() = %d\n", sched_getcpu());

  unsigned int cpu = 12345, node = 12345;
  long rc = syscall(SYS_getcpu, &cpu, &node, NULL);
  printf("getcpu() = %ld, cpu %u, node %u\n", rc, cpu, node);

#ifdef SYS_rseq
  // Registering an rseq area must fail, otherwise glibc uses it again.
  errno = 0;
  rc = syscall(SYS_rseq, NULL, 0, 0, 0);
  printf("rseq() = %ld, errno %d\n", rc, errno);
#endif
  return 0;
}

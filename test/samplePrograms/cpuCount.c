// Regression test: sched_getaffinity had no interception at all -- it was
// listed as noIntercept under a comment claiming dettrace set the affinity
// itself, which it never did. So the guest read the host's CPU mask, and
// glibc answers get_nprocs(), and with it nproc, sysconf(_SC_NPROCESSORS_ONLN),
// OpenMP and std::thread::hardware_concurrency(), from exactly that call.
//
// The return value mattered as much as the mask: the kernel returns
// min(cpusetsize, cpumask_size()), and cpumask_size() follows the host's
// nr_cpu_ids, so even a pinned mask leaked the host's CPU count. Same for the
// EINVAL the kernel raises for a cpusetsize below its own cpumask size.
//
// std::thread::hardware_concurrency() is not tested directly: libstdc++
// implements it as exactly sysconf(_SC_NPROCESSORS_ONLN), so it would add a
// C++ build for no extra coverage. Same for OpenMP and -fopenmp.
#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <unistd.h>

int main(void) {
  printf("_SC_NPROCESSORS_ONLN = %ld\n", sysconf(_SC_NPROCESSORS_ONLN));
  printf("_SC_NPROCESSORS_CONF = %ld\n", sysconf(_SC_NPROCESSORS_CONF));
  printf("get_nprocs() = %d\n", get_nprocs());
  printf("get_nprocs_conf() = %d\n", get_nprocs_conf());

  // Raw syscall with a full cpu_set_t, the way glibc asks.
  cpu_set_t set;
  CPU_ZERO(&set);
  long rc = syscall(SYS_sched_getaffinity, 0, sizeof(set), &set);
  printf(
      "sched_getaffinity(%zu) = %ld, CPU_COUNT = %d, CPU_ISSET(0) = %d\n",
      sizeof(set), rc, CPU_COUNT(&set), CPU_ISSET(0, &set) ? 1 : 0);

  // ... and with the smallest mask the kernel accepts, where the EINVAL
  // threshold used to depend on the host.
  unsigned long word = 0;
  rc = syscall(SYS_sched_getaffinity, 0, sizeof(word), &word);
  printf("sched_getaffinity(%zu) = %ld, mask = 0x%lx\n", sizeof(word), rc, word);

  // Too small for any kernel: must be EINVAL everywhere.
  unsigned int half = 0;
  errno = 0;
  rc = syscall(SYS_sched_getaffinity, 0, sizeof(half), &half);
  printf("sched_getaffinity(%zu) = %ld, errno = %d\n", sizeof(half), rc, errno);

  CPU_ZERO(&set);
  CPU_SET(0, &set);
  printf("sched_setaffinity(cpu0) = %d\n", sched_setaffinity(0, sizeof(set), &set));

  CPU_ZERO(&set);
  CPU_SET(1, &set);
  errno = 0;
  int sr = sched_setaffinity(0, sizeof(set), &set);
  printf("sched_setaffinity(cpu1) = %d, errno = %d\n", sr, errno);

  printf("sched_getcpu() = %d\n", sched_getcpu());
  return 0;
}

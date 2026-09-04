// Regression test: clock_getres must work. dettrace maps the vvar page the
// vDSO reads its data from as PROT_NONE, and the generic vDSO's
// clock_getres reads the resolution from there, so every caller (Python,
// the JVM, the GHC runtime) died with SIGSEGV.
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <time.h>

static void show(const char* name, clockid_t id, int portable) {
  struct timespec res;
  memset(&res, 0xff, sizeof(res));
  int rc = clock_getres(id, &res);
  printf(
      "%s%s: rc %d res %lld.%09ld\n", portable ? "" : "NONPORTABLE ", name, rc,
      (long long)res.tv_sec, (long)res.tv_nsec);
}

int main(void) {
  show("CLOCK_REALTIME", CLOCK_REALTIME, 1);
  show("CLOCK_MONOTONIC", CLOCK_MONOTONIC, 1);
  show("CLOCK_MONOTONIC_RAW", CLOCK_MONOTONIC_RAW, 1);
  show("CLOCK_BOOTTIME", CLOCK_BOOTTIME, 1);
  show("CLOCK_PROCESS_CPUTIME_ID", CLOCK_PROCESS_CPUTIME_ID, 1);
  show("CLOCK_THREAD_CPUTIME_ID", CLOCK_THREAD_CPUTIME_ID, 1);
  // The coarse clocks report the timer tick, which depends on the kernel.
  show("CLOCK_REALTIME_COARSE", CLOCK_REALTIME_COARSE, 0);
  show("CLOCK_MONOTONIC_COARSE", CLOCK_MONOTONIC_COARSE, 0);
  return 0;
}

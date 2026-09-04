// Regression test: the kernel's timer_t is an int, and glibc passes the
// address of an int local to timer_create. dettrace wrote its virtual timer
// id there as a 64-bit value, so four bytes past the timer id were
// clobbered (and on big-endian the tracee read zero as its timer id).
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

int main(void) {
  struct {
    int id;
    unsigned int guard;
  } box;
  box.id = -1;
  box.guard = 0x5a5a5a5au;

  struct sigevent sev;
  memset(&sev, 0, sizeof(sev));
  sev.sigev_notify = SIGEV_NONE;

  long rc = syscall(SYS_timer_create, CLOCK_REALTIME, &sev, &box.id);
  printf("timer_create returned %ld\n", rc);
  printf("timer id %d\n", box.id);
  printf("word behind the timer id intact: %d\n", box.guard == 0x5a5a5a5au);

  // The same through libc, which hands out its own opaque timer_t.
  timer_t tid;
  if (timer_create(CLOCK_REALTIME, &sev, &tid) != 0) {
    perror("timer_create");
    return 1;
  }
  struct itimerspec spec;
  memset(&spec, 0, sizeof(spec));
  spec.it_value.tv_sec = 60;
  if (timer_settime(tid, 0, &spec, NULL) != 0) {
    perror("timer_settime");
    return 1;
  }
  printf("libc timer_create and timer_settime succeeded\n");
  return 0;
}

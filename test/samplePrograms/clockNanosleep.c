// Regression test: clock_nanosleep must not wait. It used to be routed to the
// nanosleep hook, which rewrites the request at arg1; for clock_nanosleep
// that is the clock id, so CLOCK_REALTIME slept for real and CLOCK_MONOTONIC
// failed with EINVAL. glibc implements nanosleep, sleep and usleep through
// clock_nanosleep since 2.31. Four real sleeps would exceed the test timeout.
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

int main(void) {
  struct timespec req = {5, 0};
  struct timespec rem = {-1, -1};

  int rc = clock_nanosleep(CLOCK_MONOTONIC, 0, &req, &rem);
  printf("clock_nanosleep(MONOTONIC, 5s) = %d\n", rc);
  rc = clock_nanosleep(CLOCK_REALTIME, 0, &req, NULL);
  printf("clock_nanosleep(REALTIME, 5s) = %d\n", rc);

  struct timespec abs;
  if (clock_gettime(CLOCK_REALTIME, &abs) != 0) {
    perror("clock_gettime");
    return 1;
  }
  abs.tv_sec += 3600;
  rc = clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &abs, NULL);
  printf("clock_nanosleep(REALTIME, +1h absolute) = %d\n", rc);

  rc = nanosleep(&req, NULL);
  printf("nanosleep(5s) = %d\n", rc);
  rc = (int)sleep(5);
  printf("sleep(5) = %d\n", rc);
  return 0;
}

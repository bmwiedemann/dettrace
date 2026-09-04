// Regression test for ppoll, which is what glibc's poll() is on aarch64 and
// riscv64. dettrace zeroed the timeout without ever reading it and replayed
// every zero return without a budget, so a probe with a zero timeout and a
// bounded wait both spun until the test timeout killed them.
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void) {
  int fds[2];
  if (pipe(fds) != 0) {
    perror("pipe");
    return 1;
  }
  struct pollfd pfd = {fds[0], POLLIN, 0};
  struct timespec zero = {0, 0};
  struct timespec ms = {0, 100 * 1000 * 1000};

  int rc = ppoll(&pfd, 1, &zero, NULL);
  printf("ppoll(empty pipe, 0s) = %d\n", rc);

  rc = ppoll(&pfd, 1, &ms, NULL);
  printf("ppoll(empty pipe, 100ms) = %d\n", rc);

  if (write(fds[1], "x", 1) != 1) {
    perror("write");
    return 1;
  }
  pfd.revents = 0;
  rc = ppoll(&pfd, 1, NULL, NULL);
  printf("ppoll(ready pipe, no timeout) = %d, POLLIN %d\n", rc, (pfd.revents & POLLIN) != 0);

  // The timeout struct of the caller must come back untouched.
  printf("caller timeout intact: %d\n", ms.tv_sec == 0 && ms.tv_nsec == 100 * 1000 * 1000);
  return 0;
}

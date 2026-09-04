// Regression test for pselect6, which is what glibc's select() is on every
// 64-bit architecture since 2.32 and the only form on aarch64 and riscv64.
// dettrace used to pass it through unchanged, so a tracee blocking in it
// never returned to the tracer and the process that was to wake it up was
// never scheduled: the last case below deadlocked.
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
  int fds[2];
  if (pipe(fds) != 0) {
    perror("pipe");
    return 1;
  }
  fd_set rd;
  struct timespec zero = {0, 0};
  struct timespec ms = {0, 100 * 1000 * 1000};

  FD_ZERO(&rd);
  FD_SET(fds[0], &rd);
  int rc = pselect(fds[0] + 1, &rd, NULL, NULL, &zero, NULL);
  printf("pselect(empty pipe, 0s) = %d, readable %d\n", rc, FD_ISSET(fds[0], &rd) != 0);

  FD_ZERO(&rd);
  FD_SET(fds[0], &rd);
  rc = pselect(fds[0] + 1, &rd, NULL, NULL, &ms, NULL);
  printf("pselect(empty pipe, 100ms) = %d\n", rc);

  if (write(fds[1], "x", 1) != 1) {
    perror("write");
    return 1;
  }
  FD_ZERO(&rd);
  FD_SET(fds[0], &rd);
  rc = pselect(fds[0] + 1, &rd, NULL, NULL, NULL, NULL);
  printf("pselect(ready pipe, no timeout) = %d, readable %d\n", rc, FD_ISSET(fds[0], &rd) != 0);
  char c;
  if (read(fds[0], &c, 1) != 1) {
    perror("read");
    return 1;
  }

  // Now block with no timeout on a pipe only the child will feed.
  fflush(NULL);
  pid_t child = fork();
  if (child == -1) {
    perror("fork");
    return 1;
  }
  if (child == 0) {
    if (write(fds[1], "y", 1) != 1) {
      _exit(1);
    }
    _exit(0);
  }

  FD_ZERO(&rd);
  FD_SET(fds[0], &rd);
  rc = pselect(fds[0] + 1, &rd, NULL, NULL, NULL, NULL);
  printf("pselect(pipe fed by child, no timeout) = %d\n", rc);
  int status;
  if (waitpid(child, &status, 0) != child) {
    perror("waitpid");
    return 1;
  }
  printf("child exited with %d\n", WEXITSTATUS(status));
  return 0;
}

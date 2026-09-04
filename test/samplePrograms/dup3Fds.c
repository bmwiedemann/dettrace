// Regression test for dup3, which is glibc's dup2() on aarch64 and riscv64.
// dettrace let it through without a handler, so the file descriptor
// bookkeeping of dup2 never happened. dettrace forces timerfds and pipes
// non-blocking behind the tracee's back and emulates the blocking read for
// the descriptors it knows about, so reading from a duplicate it did not
// know about returned EAGAIN instead of the data.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/timerfd.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
  int fds[2];
  if (pipe(fds) != 0) {
    perror("pipe");
    return 1;
  }

  int copy = dup3(fds[0], 9, 0);
  printf("dup3(pipe read end, 9) = %d\n", copy);

  int rc = dup3(fds[0], fds[0], 0);
  printf("dup3(fd, fd) = %d %s\n", rc, rc < 0 ? strerror(errno) : "");

  int cloexec = dup3(fds[0], 10, O_CLOEXEC);
  printf(
      "dup3(.., O_CLOEXEC) = %d, FD_CLOEXEC set: %d\n", cloexec,
      (fcntl(cloexec, F_GETFD) & FD_CLOEXEC) != 0);

  fflush(NULL);
  pid_t child = fork();
  if (child == -1) {
    perror("fork");
    return 1;
  }
  if (child == 0) {
    if (write(fds[1], "hello", 5) != 5) {
      _exit(1);
    }
    _exit(0);
  }

  char buf[6];
  memset(buf, 0, sizeof(buf));
  ssize_t n = read(copy, buf, 5);
  printf(
      "read from the pipe duplicate: %zd \"%s\"\n", n,
      n > 0 ? buf : strerror(errno));
  int status;
  if (waitpid(child, &status, 0) != child) {
    perror("waitpid");
    return 1;
  }
  printf("child exited with %d\n", WEXITSTATUS(status));

  // A timerfd duplicate must keep behaving like a timerfd: dettrace opens
  // it non-blocking and answers the read from its own timer model.
  int tfd = timerfd_create(CLOCK_MONOTONIC, 0);
  if (tfd < 0) {
    perror("timerfd_create");
    return 1;
  }
  struct itimerspec it;
  memset(&it, 0, sizeof(it));
  it.it_interval.tv_nsec = 100000000UL;
  it.it_value.tv_nsec = 100000000UL;
  if (timerfd_settime(tfd, 0, &it, NULL) != 0) {
    perror("timerfd_settime");
    return 1;
  }
  int tcopy = dup3(tfd, 11, 0);
  printf("dup3(timerfd, 11) = %d\n", tcopy);
  unsigned long expired = 0;
  n = read(tcopy, &expired, sizeof(expired));
  if (n != (ssize_t)sizeof(expired)) {
    printf(
        "read from the timerfd duplicate failed: %zd %s\n", n, strerror(errno));
    return 1;
  }
  printf("read from the timerfd duplicate: expired %lu\n", expired);
  return 0;
}

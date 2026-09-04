// Regression test: poll() must not pick up a timeout left behind by an
// earlier system call. dettrace's poll hook shares its saved-argument slot
// with prlimit64 (setrlimit), wait4 and others; it used to take the stale
// value as the timeout, so a zero-timeout probe after setrlimit was
// replayed with an enormous retry budget and never returned.
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

int main(void) {
  int fds[2];
  if (pipe(fds) == -1) {
    perror("pipe");
    return 1;
  }

  struct rlimit rl;
  if (getrlimit(RLIMIT_CORE, &rl) == -1 || setrlimit(RLIMIT_CORE, &rl) == -1) {
    perror("rlimit");
    return 1;
  }

  struct pollfd pfd = {fds[0], POLLIN, 0};
  int rc = poll(&pfd, 1, 0);
  printf("poll(timeout 0) on empty pipe: %d\n", rc);

  if (write(fds[1], "x", 1) != 1) {
    perror("write");
    return 1;
  }
  rc = poll(&pfd, 1, -1);
  printf("poll(timeout -1) on ready pipe: %d\n", rc);
  return 0;
}

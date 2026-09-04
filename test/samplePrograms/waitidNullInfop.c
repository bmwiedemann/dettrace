// Regression test: a blocking waitid() with infop == NULL must report the
// exited child instead of running into ECHILD. dettrace turns the call into
// a WNOHANG poll and, with no siginfo to inspect, used to treat the 0 return
// of the call that reaped the child as "nothing yet" and replay it.
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
  pid_t child = fork();
  if (child == -1) {
    perror("fork");
    return 1;
  }
  if (child == 0) {
    _exit(3);
  }

  int rc = waitid(P_ALL, 0, NULL, WEXITED);
  printf("waitid(NULL infop): %d %s\n", rc, rc == 0 ? "ok" : strerror(errno));

  // Now the child really is gone.
  rc = waitid(P_ALL, 0, NULL, WEXITED);
  printf("second waitid: %d %s\n", rc, rc == 0 ? "ok" : strerror(errno));
  return 0;
}

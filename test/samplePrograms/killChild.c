// A tracee may signal its own child; only process-group and broadcast
// kills are refused (see kill.c). The child blocks in a pipe read that
// nothing ever writes, and the parent terminates it with SIGTERM.
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
  int fds[2];
  if (pipe(fds) == -1) {
    perror("pipe");
    return 1;
  }
  pid_t child = fork();
  if (child == -1) {
    perror("fork");
    return 1;
  }
  if (child == 0) {
    char c;
    close(fds[1]);
    if (read(fds[0], &c, 1) != 1) {
      _exit(2);
    }
    _exit(0);
  }
  close(fds[0]);

  int rc = kill(child, SIGTERM);
  printf("kill(child, SIGTERM) returned %d%s%s\n", rc, rc ? ": " : "",
         rc ? strerror(errno) : "");

  int status;
  if (waitpid(child, &status, 0) != child) {
    perror("waitpid");
    return 1;
  }
  if (WIFSIGNALED(status)) {
    printf("child terminated by signal %d\n", WTERMSIG(status));
  } else {
    printf("child exited with status %d\n", WEXITSTATUS(status));
  }

  rc = kill(1, SIGTERM);
  printf("kill(1, SIGTERM) returned %d%s%s\n", rc, rc ? ": " : "",
         rc ? strerror(errno) : "");
  return 0;
}

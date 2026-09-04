// Regression test: accept4 on a non-blocking socket with nothing pending must
// return EAGAIN to the tracee. dettrace borrows one state flag for "this call
// has a timeout", poll set it and never cleared it, and accept4's post-hook
// then replayed the EAGAIN that ends an accept loop until a connection
// arrived.
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int main(void) {
  const char* path = "accept4-testsock";
  unlink(path);

  int s = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
  if (s < 0) {
    perror("socket");
    return 1;
  }
  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
  if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
    perror("bind");
    return 1;
  }
  if (listen(s, 1) != 0) {
    perror("listen");
    return 1;
  }

  struct pollfd pfd = {s, POLLIN, 0};
  printf("poll(listening socket, 10ms) = %d\n", poll(&pfd, 1, 10));

  int c = accept4(s, NULL, NULL, SOCK_NONBLOCK);
  printf("accept4(nothing pending) = %d %s\n", c, c < 0 ? strerror(errno) : "");

  if (close(s) != 0) {
    perror("close");
    return 1;
  }
  unlink(path);
  return 0;
}

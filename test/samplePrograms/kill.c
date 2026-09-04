#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <stdlib.h>
#include <sys/types.h>
#include <signal.h>
#include <assert.h>

int main(int argc, char** argv) {

  assert(2 == argc);
  char* endptr = NULL;
  int signum = (int) strtol(argv[1], &endptr, 10);
  assert(endptr != argv[1] && signum != 0 && "invalid argument");
  
  // A process-group kill would reach dettrace itself (and the shell that
  // started it); dettrace must refuse it instead of letting it through or
  // aborting.
  int rc = kill(0/*my process group, i.e., me*/, signum);
  fprintf(stderr, "kill(0, signal) returned %d: %s\n", rc,
          rc == 0 ? "ok" : strerror(errno));
  
  return 0;
}

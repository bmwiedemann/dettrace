// Regression test: uname(2) has always been synthesized -- it reported an
// empty nodename, and gethostname(2) with it, since glibc answers that from
// uname and there is no gethostname syscall. /proc/sys/kernel/hostname was
// the host's, though, so the two disagreed and the real machine name leaked
// into anything that captured it, which for a build is most of the
// interesting output. dettrace now creates a UTS namespace and sets the name
// there, so all of them agree.
//
// Values are bracketed so an empty one is still visible.
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/utsname.h>

static void catBracketed(const char* path) {
  char buf[256] = {0};
  FILE* f = fopen(path, "r");
  if (f == NULL) {
    printf("%s = <could not open>\n", path);
    return;
  }
  if (fgets(buf, sizeof(buf), f) == NULL) {
    buf[0] = '\0';
  }
  fclose(f);
  // proc_dostring appends a newline that is not part of the value.
  size_t n = strlen(buf);
  if (n > 0 && buf[n - 1] == '\n') {
    buf[n - 1] = '\0';
  }
  printf("%s = [%s]\n", path, buf);
}

int main(void) {
  char host[256] = {0};
  char domain[256] = {0};

  printf("gethostname() = %d, [%s]\n", gethostname(host, sizeof(host)), host);
  printf(
      "getdomainname() = %d, [%s]\n", getdomainname(domain, sizeof(domain)),
      domain);

  struct utsname buf;
  if (uname(&buf) == -1) {
    printf("uname failed\n");
    return 1;
  }
  printf("uname nodename = [%s]\n", buf.nodename);
  printf("uname domainname = [%s]\n", buf.domainname);

  catBracketed("/proc/sys/kernel/hostname");
  catBracketed("/proc/sys/kernel/domainname");
  return 0;
}

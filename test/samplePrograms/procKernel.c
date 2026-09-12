// Regression test: /proc/version and /proc/sys/kernel/{ostype,osrelease,
// version} were the host's, so they contradicted the "Linux 4.0 #1" that
// uname(2) has always reported, and pinned the guest's output to whichever
// kernel happened to build it. /proc/sys/kernel/random/boot_id was a fresh
// UUID per boot of the host, and /proc/uptime and /proc/loadavg were live
// even though sysinfo(2) already synthesized both.
//
// Unlike the sysctls, these three are read-only and a fresh UTS namespace
// inherits them, so they have to be mounted over rather than set.
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>

static void catBracketed(const char* path) {
  char buf[512] = {0};
  FILE* f = fopen(path, "r");
  if (f == NULL) {
    printf("%s = <could not open>\n", path);
    return;
  }
  if (fgets(buf, sizeof(buf), f) == NULL) {
    buf[0] = '\0';
  }
  fclose(f);
  size_t n = strlen(buf);
  if (n > 0 && buf[n - 1] == '\n') {
    buf[n - 1] = '\0';
  }
  printf("%s = [%s]\n", path, buf);
}

int main(void) {
  catBracketed("/proc/sys/kernel/ostype");
  catBracketed("/proc/sys/kernel/osrelease");
  catBracketed("/proc/sys/kernel/version");
  catBracketed("/proc/version");
  catBracketed("/proc/sys/kernel/random/boot_id");
  catBracketed("/proc/uptime");
  catBracketed("/proc/loadavg");

  // The whole point is that these agree with uname(2).
  struct utsname buf;
  if (uname(&buf) == -1) {
    printf("uname failed\n");
    return 1;
  }
  printf("uname release matches osrelease: %d\n", strcmp(buf.release, "4.0") == 0);
  printf("uname version matches version: %d\n", strcmp(buf.version, "#1") == 0);
  return 0;
}

// Regression test: dettrace used to refuse every open under
// /sys/devices/system/cpu, which was how it kept the host's cpuN directories
// from the guest. But the readers that matter -- glibc's CPU count, hwloc,
// lscpu -- open that directory and then read relative to the fd, so the
// refusal was not something they fell back from: lscpu stopped at "failed to
// determine number of CPUs" and produced nothing. dettrace now mounts its own
// single-CPU tree there, so the directory opens and describes the canonical
// machine.
//
// Read through a directory fd on purpose, the way lscpu does; an absolute
// path would not have exercised the bug.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/sysinfo.h>
#include <unistd.h>

static void showAt(int dirfd, const char* name) {
  int fd = openat(dirfd, name, O_RDONLY);
  if (fd < 0) {
    printf("%s: open failed (%s)\n", name, strerror(errno));
    return;
  }

  char buf[128];
  ssize_t nb = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  if (nb < 0) {
    printf("%s: read failed (%s)\n", name, strerror(errno));
    return;
  }

  // These are one short line each; show it with the newline made visible so
  // that an empty value (offline, on a machine with no offline CPU) is not
  // indistinguishable from a missing one.
  buf[nb] = '\0';
  if (nb > 0 && buf[nb - 1] == '\n') {
    buf[nb - 1] = '\0';
  }
  printf("%s: \"%s\"\n", name, buf);
}

int main(void) {
  int dirfd = open("/sys/devices/system/cpu", O_RDONLY | O_DIRECTORY);
  if (dirfd < 0) {
    printf("open(/sys/devices/system/cpu) failed (%s)\n", strerror(errno));
    return 1;
  }

  showAt(dirfd, "possible");
  showAt(dirfd, "present");
  showAt(dirfd, "online");
  showAt(dirfd, "offline");
  showAt(dirfd, "kernel_max");
  showAt(dirfd, "cpu0/topology/core_id");
  showAt(dirfd, "cpu0/topology/physical_package_id");
  showAt(dirfd, "cpu0/topology/thread_siblings");
  close(dirfd);

  // The neighbouring trees have no override of their own, so they stay
  // refused, and no spelling of a path may be a way around that. /sys/bus/cpu
  // exists on every machine that has the tree this test is gated on, so an
  // ENOENT here really is dettrace refusing rather than the host not having
  // it -- which is not true of the NUMA nodes, hence this one as the oracle.
  static const char* escapes[] = {
      "/sys/devices/system/cpu/../../../bus/cpu/devices",
      "//sys/bus/cpu/devices",
      "/sys/devices/system/./cpu/../../../bus/cpu/devices",
      "/sys/devices/system/cpu/../node/node0/cpulist",
  };
  for (size_t i = 0; i < sizeof(escapes) / sizeof(escapes[0]); i++) {
    int leak = open(escapes[i], O_RDONLY);
    printf("refused %s: %s\n", escapes[i], leak < 0 ? "yes" : "NO, OPENED");
    if (leak >= 0) {
      close(leak);
    }
  }

  // ... while a ".." that stays inside our own tree still resolves. Refusing
  // this would hide nothing and is how a blunter guard fails.
  showAt(AT_FDCWD, "/sys/devices/system/cpu/cpu0/../possible");

  // Whichever way this glibc counts -- the cpuN directories, or possible and
  // online -- the answer has to be the canonical one.
  printf("get_nprocs_conf() = %d\n", get_nprocs_conf());
  return 0;
}

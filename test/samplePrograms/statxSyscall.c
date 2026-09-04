// Regression test for the statx handler. dettrace used to dispatch statx to
// the stat handlers, which take the buffer from the second argument: for
// statx that is the pathname, so a struct stat was written over the path and
// the real inode, device and timestamps reached the tracee unvirtualized.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
#if !defined(SYS_statx) || !defined(STATX_BASIC_STATS)
  printf("statx is not available here\n");
  return 0;
#else
  // A writable buffer, so that overwriting it is visible instead of fatal.
  char path[64];
  strcpy(path, "statx-testfile");
  unlink(path);

  int fd = open(path, O_CREAT | O_WRONLY | O_TRUNC, 0644);
  if (fd < 0) {
    perror("open");
    return 1;
  }
  if (write(fd, "hello", 5) != 5) {
    perror("write");
    return 1;
  }
  if (close(fd) != 0) {
    perror("close");
    return 1;
  }

  struct statx stx;
  memset(&stx, 0xff, sizeof(stx));
  long rc = syscall(SYS_statx, AT_FDCWD, path, 0, STATX_BASIC_STATS, &stx);
  printf("statx returned %ld\n", rc);
  printf("path after statx: %s\n", path);
  printf(
      "size %llu nlink %u blksize %u blocks %llu\n",
      (unsigned long long)stx.stx_size, (unsigned)stx.stx_nlink,
      (unsigned)stx.stx_blksize, (unsigned long long)stx.stx_blocks);
  printf(
      "dev %u:%u mode 0%o uid %u gid %u\n", (unsigned)stx.stx_dev_major,
      (unsigned)stx.stx_dev_minor, (unsigned)(stx.stx_mode & 07777),
      stx.stx_uid, stx.stx_gid);
  printf(
      "atime %lld ctime %lld mtime %lld.%09u\n", (long long)stx.stx_atime.tv_sec,
      (long long)stx.stx_ctime.tv_sec, (long long)stx.stx_mtime.tv_sec,
      (unsigned)stx.stx_mtime.tv_nsec);
  // The virtual inodes are handed out from a small counter; how many the
  // dynamic loader used up before us depends on the libc.
  printf("NONPORTABLE ino %llu\n", (unsigned long long)stx.stx_ino);
  printf("ino is virtualized: %d\n", stx.stx_ino < 1000);

  // The same file through fstat must agree with statx.
  fd = open(path, O_RDONLY);
  if (fd < 0) {
    perror("reopen");
    return 1;
  }
  struct stat st;
  if (fstat(fd, &st) != 0) {
    perror("fstat");
    return 1;
  }
  printf("fstat agrees with statx: %d\n", st.st_ino == stx.stx_ino);
  if (close(fd) != 0) {
    perror("close");
    return 1;
  }
  unlink(path);
  return 0;
#endif
}

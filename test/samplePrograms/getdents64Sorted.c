// Regression test: dettrace returns directory entries in a deterministic
// order. The entry store was typed for the getdents layout for both
// flavours, so for getdents64 the sort key started at d_type instead of
// d_name and the entries came back grouped by file type (and in the
// kernel's own order on filesystems that report DT_UNKNOWN).
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define BUF_SIZE 8192

struct linux_dirent64 {
  ino64_t d_ino;
  off64_t d_off;
  unsigned short d_reclen;
  unsigned char d_type;
  char d_name[];
};

static const char* dirName = "dents-testdir";
// Mixed file types on purpose: sorting by type first would interleave them
// differently than sorting by name.
static const char* files[] = {"a.txt", "c.txt", "e.txt"};
static const char* dirs[] = {"b.dir", "d.dir", "f.dir"};

static void cleanup(void) {
  char path[128];
  for (unsigned i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
    snprintf(path, sizeof(path), "%s/%s", dirName, files[i]);
    unlink(path);
  }
  for (unsigned i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
    snprintf(path, sizeof(path), "%s/%s", dirName, dirs[i]);
    rmdir(path);
  }
  rmdir(dirName);
}

int main(void) {
  char path[128];
  cleanup();
  if (mkdir(dirName, 0755) != 0) {
    perror("mkdir");
    return 1;
  }
  for (unsigned i = 0; i < sizeof(files) / sizeof(files[0]); i++) {
    snprintf(path, sizeof(path), "%s/%s", dirName, files[i]);
    int fd = open(path, O_CREAT | O_WRONLY, 0644);
    if (fd < 0) {
      perror("open");
      return 1;
    }
    if (close(fd) != 0) {
      perror("close");
      return 1;
    }
  }
  for (unsigned i = 0; i < sizeof(dirs) / sizeof(dirs[0]); i++) {
    snprintf(path, sizeof(path), "%s/%s", dirName, dirs[i]);
    if (mkdir(path, 0755) != 0) {
      perror("mkdir");
      return 1;
    }
  }

  int fd = open(dirName, O_RDONLY | O_DIRECTORY);
  if (fd < 0) {
    perror("open dir");
    return 1;
  }
  char buf[BUF_SIZE];
  for (;;) {
    long nread = syscall(SYS_getdents64, fd, buf, BUF_SIZE);
    if (nread == -1) {
      perror("getdents64");
      return 1;
    }
    if (nread == 0) {
      break;
    }
    for (long pos = 0; pos < nread;) {
      struct linux_dirent64* d = (struct linux_dirent64*)(buf + pos);
      printf("%s\n", d->d_name);
      pos += d->d_reclen;
    }
  }
  if (close(fd) != 0) {
    perror("close");
    return 1;
  }
  cleanup();
  return 0;
}

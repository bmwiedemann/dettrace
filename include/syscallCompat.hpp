#ifndef SYSCALL_COMPAT_H
#define SYSCALL_COMPAT_H

#include <sys/syscall.h>

/**
 * Legacy system calls that do not exist on newer architectures like
 * aarch64 or riscv64. Define the missing ones to unique impossible
 * numbers so that the architecture-independent code (the syscall
 * dispatch switches and the handler classes) still compiles.
 *
 * A tracee can never invoke them: the kernel of such an architecture
 * does not know these numbers. seccomp::intercept/noIntercept skip
 * them when installing filter rules.
 *
 * dettrace itself however may set one of them with
 * ptracer::changeSystemCall (e.g. SYS_pause in sendTraceeSignalNow or
 * SYS_time in replaceSystemCallWithNoop). The kernel then treats the
 * unknown number as sys_ni_syscall: nothing executes and the tracee
 * sees -ENOSYS, while the post-hook still dispatches on the sentinel
 * number and overwrites the return value. That preserves the x86_64
 * semantics of hijacking the call, so these mechanisms keep working.
 */
#define SYSCALL_SENTINEL(n) (-10000 - (n))

static inline bool isSentinelSyscall(long num) {
  return num <= SYSCALL_SENTINEL(0) && num > SYSCALL_SENTINEL(1000);
}

#ifndef SYS_access
#define SYS_access SYSCALL_SENTINEL(1)
#endif
#ifndef SYS_alarm
#define SYS_alarm SYSCALL_SENTINEL(2)
#endif
#ifndef SYS_arch_prctl
#define SYS_arch_prctl SYSCALL_SENTINEL(3)
#endif
#ifndef SYS_chmod
#define SYS_chmod SYSCALL_SENTINEL(4)
#endif
#ifndef SYS_chown
#define SYS_chown SYSCALL_SENTINEL(5)
#endif
#ifndef SYS_creat
#define SYS_creat SYSCALL_SENTINEL(6)
#endif
#ifndef SYS_dup2
#define SYS_dup2 SYSCALL_SENTINEL(7)
#endif
#ifndef SYS_epoll_create
#define SYS_epoll_create SYSCALL_SENTINEL(8)
#endif
#ifndef SYS_epoll_wait
#define SYS_epoll_wait SYSCALL_SENTINEL(9)
#endif
#ifndef SYS_fork
#define SYS_fork SYSCALL_SENTINEL(10)
#endif
#ifndef SYS_futimesat
#define SYS_futimesat SYSCALL_SENTINEL(11)
#endif
#ifndef SYS_getdents
#define SYS_getdents SYSCALL_SENTINEL(12)
#endif
#ifndef SYS_getpgrp
#define SYS_getpgrp SYSCALL_SENTINEL(13)
#endif
#ifndef SYS_inotify_init
#define SYS_inotify_init SYSCALL_SENTINEL(14)
#endif
#ifndef SYS_lchown
#define SYS_lchown SYSCALL_SENTINEL(15)
#endif
#ifndef SYS_link
#define SYS_link SYSCALL_SENTINEL(16)
#endif
#ifndef SYS_lstat
#define SYS_lstat SYSCALL_SENTINEL(17)
#endif
#ifndef SYS_mkdir
#define SYS_mkdir SYSCALL_SENTINEL(18)
#endif
#ifndef SYS_mknod
#define SYS_mknod SYSCALL_SENTINEL(19)
#endif
#ifndef SYS_open
#define SYS_open SYSCALL_SENTINEL(20)
#endif
#ifndef SYS_pause
#define SYS_pause SYSCALL_SENTINEL(21)
#endif
#ifndef SYS_pipe
#define SYS_pipe SYSCALL_SENTINEL(22)
#endif
#ifndef SYS_poll
#define SYS_poll SYSCALL_SENTINEL(23)
#endif
#ifndef SYS_readlink
#define SYS_readlink SYSCALL_SENTINEL(24)
#endif
#ifndef SYS_rename
#define SYS_rename SYSCALL_SENTINEL(25)
#endif
#ifndef SYS_rmdir
#define SYS_rmdir SYSCALL_SENTINEL(26)
#endif
#ifndef SYS_select
#define SYS_select SYSCALL_SENTINEL(27)
#endif
#ifndef SYS_stat
#define SYS_stat SYSCALL_SENTINEL(28)
#endif
#ifndef SYS_symlink
#define SYS_symlink SYSCALL_SENTINEL(29)
#endif
#ifndef SYS_time
#define SYS_time SYSCALL_SENTINEL(30)
#endif
#ifndef SYS_unlink
#define SYS_unlink SYSCALL_SENTINEL(31)
#endif
#ifndef SYS_utime
#define SYS_utime SYSCALL_SENTINEL(32)
#endif
#ifndef SYS_utimes
#define SYS_utimes SYSCALL_SENTINEL(33)
#endif
#ifndef SYS_vfork
#define SYS_vfork SYSCALL_SENTINEL(34)
#endif
#ifndef SYS_renameat
#define SYS_renameat SYSCALL_SENTINEL(35)
#endif
#ifndef SYS_accept
#define SYS_accept SYSCALL_SENTINEL(36)
#endif

#endif

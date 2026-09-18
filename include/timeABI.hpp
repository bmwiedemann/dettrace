#ifndef TIME_ABI_H
#define TIME_ABI_H

/*
 * The time ABI dettrace itself is built with, forced before any libc
 * header is read.
 *
 * dettrace hands the tracee its own struct timespec, struct timeval,
 * struct itimerval, struct utimbuf, struct rusage, struct stat64 and bare
 * time_t values, so those have to be the structures the system calls it
 * emulates actually take. Where the system call ABI is 32-bit (i586, arm,
 * powerpc, hppa) the legacy calls take the kernel's 32-bit time_t forms,
 * which is what glibc hands out exactly while __USE_TIME_BITS64 is off.
 * Ask for _TIME_BITS=64, as Debian's build flags do by default on those
 * architectures since the 64-bit time transition, and every one of them
 * grows -- a timespec and a timeval from 8 to 16 bytes, a struct stat64 by
 * 8 -- and dettrace writes past the end of the tracee's buffers on every
 * gettimeofday, every legacy clock_gettime and every stat. The *_time64
 * calls are a separate matter and go through struct __kernel_timespec in
 * src/dettraceSystemCall.cpp. Traced programs are free to use either time
 * ABI; only dettrace's own structures have to match the kernel's.
 *
 * This pins the time ABI the way the Makefile's -D_FILE_OFFSET_BITS=64
 * pins the file offset one, but it cannot itself be a -D: a distribution
 * passes its flags in EXTRA_CXXFLAGS, i.e. after $(DEFINES), and the last
 * -D of a macro wins. A -include file is processed after all -D and -U
 * options wherever it stands on the command line (documented for GCC, and
 * the same in clang), so the #undef here beats any -D_TIME_BITS=64.
 *
 * <bits/timesize.h> is the one header that gives __TIMESIZE without
 * evaluating _TIME_BITS: <features.h> pulls in <features-time64.h>, where
 * _TIME_BITS=32 is a hard #error once __TIMESIZE > 32 -- which is every
 * 64-bit architecture, and x32, which is ILP32 but has 64-bit time
 * throughout. It includes only <bits/wordsize.h>, defines nothing but
 * __TIMESIZE, has no feature test side effects and repeats that
 * definition identically when <features.h> includes it later.
 *
 * __TIMESIZE == 32 covers every architecture on which syscallCompat.hpp
 * defines DETTRACE_32BIT_SYSCALL_ABI, and a few older 32-bit ports that
 * use the generic system call table, for which it is equally right. An
 * architecture with a 32-bit system call ABI but 64-bit default time
 * would be left unpinned; there is none today, and the static assertions
 * in include/syscallCompat.hpp would stop such a build with an
 * explanation rather than let it corrupt the tracee.
 *
 * A libc that does not ship the header has nothing to pin: <bits/timesize.h>
 * arrived with glibc 2.31, and _TIME_BITS itself only later, so an older
 * one -- the Ubuntu 18.04 of this project's own Dockerfile among them --
 * has no 64-bit time to be switched into. Include it only if it is there,
 * rather than failing every translation unit over a header whose absence
 * answers the question by itself.
 */
#if defined(__has_include)
#if __has_include(<bits/timesize.h>)
#include <bits/timesize.h>
#endif
#endif

#if defined(__TIMESIZE) && __TIMESIZE == 32
#undef _TIME_BITS
#define _TIME_BITS 32
#endif

#endif

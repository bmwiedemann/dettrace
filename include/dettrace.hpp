#ifndef DETTRACE_H
#define DETTRACE_H

#include <time.h>

extern "C" {

struct SyscallState {
  bool noop;
};

typedef long (*SysEnter)(
    void* data,
    struct SyscallState* s,
    int pid,
    int tid,
    int syscallno,
    unsigned long arg0,
    unsigned long arg1,
    unsigned long arg2,
    unsigned long arg3,
    unsigned long arg4,
    unsigned long arg5);

typedef long (*SysExit)(
    void* data,
    struct SyscallState* s,
    int pid,
    int tid,
    int syscallno,
    unsigned long retval,
    unsigned long arg0,
    unsigned long arg1,
    unsigned long arg2,
    unsigned long arg3,
    unsigned long arg4,
    unsigned long arg5);

/* The canonical virtual hardware platform presented to the guest. Every
 * window onto it -- the CPUID tables in execution.cpp, the files under
 * root/proc, uname(2), sched_getaffinity(2) -- has to be derived from these
 * so that they cannot drift apart and contradict each other. */
/* One CPU: this is what the CPUID tables already report (leaf 0xB says one
 * logical processor) and what getcpu/sched_getcpu already answer. Must stay
 * below 64, since the affinity mask below is a single word. */
#define DETTRACE_NR_CPUS 1
/* Bits 0..DETTRACE_NR_CPUS-1: the affinity mask of the canonical machine.
 * Written as a shifted-down all-ones word so that it stays defined at
 * DETTRACE_NR_CPUS == 64, where 1UL << 64 would not be. */
#define DETTRACE_CPU_MASK_WORD0 (~0UL >> (64 - DETTRACE_NR_CPUS))
#define DETTRACE_HOSTNAME "reproducible"
/* uname(2) has always reported an empty domain name; a stock Linux box says
 * "(none)". Keep the empty string so the two stay consistent. */
#define DETTRACE_DOMAINNAME ""
#define DETTRACE_UTS_SYSNAME "Linux"
#define DETTRACE_UTS_RELEASE "4.0"
#define DETTRACE_UTS_VERSION "#1"

/// Represents a mount. These parameters are passed directly to mount(2).
typedef struct {
  const char* source;
  const char* target;
  const char* fstype;
  unsigned long flags;
  const void* data;
  /// When set, a mount(2) failure is logged and skipped instead of being
  /// fatal. Used for the /proc and /etc overrides, whose targets do not
  /// exist on every kernel; never for user-specified -v volumes.
  bool optional;
  /// When set, the bind is remounted read-only. Our overrides of files that
  /// a real kernel does not let anyone write -- everything under /proc --
  /// need this: the bind exposes the file in dettrace's own install tree, so
  /// a guest that writes it would corrupt the canonical data for every later
  /// run on the machine instead of getting the EACCES it expects.
  bool readonly;
} Mount;

/**
 * Options for Dettrace.
 */
typedef struct {
  // Name of the program.
  const char* program;

  // List of arguments. The first argument should be a pointer to the program
  // name. As expected by execvpe, this needs to be a NULL terminated array.
  char* const* argv;

  // The environment variables. As expected by execvpe, this needs to be a NULL
  // terminated array.
  char* const* envs;

  // Working directory to chdir() into before the execvpe().
  const char* workdir;

  // stdio file descriptors.
  int stdin;
  int stdout;
  int stderr;

  // Flags to use to when clone()ing.
  int clone_ns_flags;

  // The timeout in seconds before the tracee is killed. Set to 0 for no
  // timeout (i.e., indefinite).
  unsigned int timeout;

  // Callback function to run before each time a syscall is made. If NULL, the
  // callback is not executed.
  SysEnter sys_enter;

  // Callback function to run after each time a syscall is made. If NULL, the
  // callback is not executed.
  SysExit sys_exit;

  // Pointer to some data that will be passed to each sys_enter and sys_exit
  // call.
  void* user_data;

  // The beginning of time we will use.
  time_t epoch;

  // The number of microseconds to increment the clock.
  unsigned long clock_step;

  // The seed to use for /dev/[u]random and other random-related system calls.
  unsigned short prng_seed;

  // Whether or not to allow networking.
  bool allow_network;

  // Whether or not ASLR should be on or off.
  bool with_aslr;

  bool convert_uids;

  // NULL terminated array of mounts.
  Mount* const* mounts;

  // Directory to chroot into.
  const char* chroot_dir;

  // Mount our own deterministic /dev/[u]random fifo pipes.
  bool with_devrand_overrides;

  // When false, the guest is not being shown the canonical machine, so the
  // syscall-level half of it -- the affinity emulation and the single-CPU
  // pin -- stands down as well. Cleared by --real-proc, and also when there
  // is no mount namespace to apply the file overrides in, since a guest told
  // it has one CPU while nproc still counts the host's off the host's
  // /proc/stat cannot pin the threads it decided to spawn.
  bool with_proc_overrides;

  // When false (--real-proc only), stop hiding the sysfs trees that describe
  // the host's CPU topology. Unlike the above this does not need a mount
  // namespace, so it stays on in --in-docker, where it was on before.
  bool hide_host_topology;

  // Logging options
  int debug_level;
  bool use_color;
  bool print_statistics;
  const char* log_file;
} TraceOptions;

/**
 * Spawns the tracee process. If no mount options are provided, we assume that
 * the container has already been created and we are chrooted.
 *
 * If the return value is -1, an error has occured attempting to spawn
 * the process. Otherwise, the pid of the child is returned.
 */
pid_t dettrace(const TraceOptions* options);

} // extern "C"

#endif // DETTRACE_H

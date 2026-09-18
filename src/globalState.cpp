#include "globalState.hpp"

globalState::globalState(
    logger& log,
    ValueMapper<DevIno, ino_t, DevInoHash> inodeMap,
    ModTimeMap mtimeMap,
    bool kernelPre4_12,
    unsigned prngSeed,
    logical_clock::time_point epoch,
    bool allow_network,
    bool with_proc_overrides,
    bool hide_host_topology,
    bool sysfs_cpu_overridden)
    : log(log),
      inodeMap{inodeMap},
      mtimeMap{mtimeMap},
      kernelPre4_12{kernelPre4_12},
      prng(prngSeed),
      epoch(epoch),
      allow_network(allow_network),
      with_proc_overrides(with_proc_overrides),
      hide_host_topology(hide_host_topology),
      sysfs_cpu_overridden(sysfs_cpu_overridden) {
  allow_trapCPUID = true;
}

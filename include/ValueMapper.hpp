#ifndef VALUE_MAPPER_H
#define VALUE_MAPPER_H

#include <sys/types.h>
#include <unordered_map>
#include "logger.hpp"

using namespace std;

/**
 * Identity of a file on the host: an inode number is only unique within
 * one filesystem, so the maps are keyed on (device, inode). Otherwise the
 * root of a tmpfs and a directory on the root filesystem with the same
 * inode number got the same virtual inode, and e.g. rm refused to remove
 * a directory because it looked like "/".
 */
struct DevIno {
  dev_t dev;
  ino_t ino;
  bool operator==(const DevIno& o) const {
    return dev == o.dev && ino == o.ino;
  }
};
struct DevInoHash {
  size_t operator()(const DevIno& k) const {
    return std::hash<uint64_t>()((uint64_t)k.ino) ^
           (std::hash<uint64_t>()((uint64_t)k.dev) * 0x9E3779B97F4A7C15ULL);
  }
};
inline string to_string(const DevIno& k) {
  return to_string(k.dev) + ":" + to_string(k.ino);
}

/**
 * Simple wrapper around std::map for virtualizing values like inodes.
 * Template parameter Virtual must be an integral type.
 */
template <typename Real, typename Virtual, typename Hash = std::hash<Real>>
class ValueMapper {
protected:
  /**
   * I would ideally like to type alias real values to virtual values from int
   * and have the compiler enforce them through type errors. But it seems like
   * C++ doesn't support that unless I use phantom types and wrapper classes...
   */

  unordered_map<Real, Virtual, Hash>
      realToVirtualValue; /**< A mapping from Real to Virtual. */
  Virtual freshValue; /**< Next available Virtual value to be added to map. */
  logger& myLogger; /**< A logger. */
  const string
      mappingName; /**< String name of this map, useful for debugging. */

public:
  /**
   * Constructor.
   * Takes in logger for writing data, name of the mapping, and a starting
   * virtual value.
   * @param logr initialized logger to write data to.
   * @param name string name of this mapping, useful for debugging.
   * @param startingValue initial Virtual value to start with.
   */
  ValueMapper(logger& logr, string name, Virtual startingValue)
      : myLogger(logr), mappingName(name) {
    freshValue = startingValue;
  }

  /**
   * Given a real value, add it to our mapping tables and map it to a fresh new
   * virtual value.
   * @param realValue: realValue to add.
   * @return the mapped virtual value.
   */
  Virtual addRealValue(Real realValue) {
    // it is nondet whether this realValue (typically an inode) has been seen
    // before, so we need to print either way to keep log message IDs
    // deterministic
    if (realToVirtualValue.find(realValue) != realToVirtualValue.end()) {
      myLogger.writeToLog(Importance::extra, "Overwriting old value in map.\n");
    } else {
      myLogger.writeToLog(Importance::extra, "Allocating new value in map.\n");
    }

    myLogger.writeToLog(
        Importance::info, mappingName + ": New virtual value added: " +
                              to_string(freshValue) + "\n");
    myLogger.writeToLog(
        Importance::extra,
        "  (Real value was: " + to_string(realValue) + ")\n");

    Virtual vValue = freshValue++;
    realToVirtualValue[realValue] = vValue;
    return vValue;
  }

  /**
   * Get the virtual value from the real value.
   * Throws error if real value does not exist.
   * @param realValue real value of process.
   * @return virtual value that is mapped to the real one.
   */
  Virtual getVirtualValue(Real realValue) {
    if (realToVirtualValue.find(realValue) != realToVirtualValue.end()) {
      Virtual virtValue = realToVirtualValue.at(realValue);
      myLogger.writeToLog(
          Importance::info, mappingName + " fetched virtual value: " +
                                to_string(virtValue) + "\n");
      myLogger.writeToLog(
          Importance::extra,
          "  (Real value was: " + to_string(realValue) + ")\n");

      return virtValue;
    }
    throw runtime_error(
        "dettrace runtime exception: " + mappingName + ": getVirtualValue(" +
        to_string(realValue) + ") does not exist\n");
  }

  /**
   * Check if real value is already in map for real values.
   * @param realValue: real value to check for.
   * @return True if real value exists, otherwise False.
   */
  bool realValueExists(Real realValue) {
    bool keyExists =
        realToVirtualValue.find(realValue) != realToVirtualValue.end();
    myLogger.writeToLog(
        Importance::extra, mappingName + "realValueExists(" +
                               to_string(realValue) +
                               ") = " + to_string(keyExists) + "\n");
    return keyExists;
  }
};

#endif

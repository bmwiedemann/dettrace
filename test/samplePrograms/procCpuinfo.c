// Regression test: /proc/cpuinfo used to be the host's. The CPUID instruction
// is masked, but nothing stopped a SIMD feature probe or a per-core bucketing
// scheme from reading the real vendor, model name, flags and core count
// straight out of /proc, so those escaped the container entirely.
//
// The values below have to stay in step with the CPUID tables in
// src/execution.cpp; root/proc/cpuinfo.x86_64 is derived from them.
#include <stdio.h>
#include <string.h>

// Echo "key = value" for the keys worth pinning, normalising away the tabs
// the kernel pads its keys with so the expected output holds no whitespace
// surprises. The key sets differ per architecture, hence the mixed bag.
static const char* interesting[] = {
    "vendor_id",   "cpu family", "model name", "stepping",     "cpu MHz",
    "cache size",  "cpuid level", "flags",     "bogomips",     "clflush size",
    "Features",    "CPU part",   "cpu",        "isa",          NULL};

static void trim(char* s) {
  size_t n = strlen(s);
  while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\n')) {
    s[--n] = '\0';
  }
}

int main(void) {
  FILE* f = fopen("/proc/cpuinfo", "r");
  if (f == NULL) {
    printf("could not open /proc/cpuinfo\n");
    return 1;
  }

  char line[4096];
  int processors = 0;
  while (fgets(line, sizeof(line), f) != NULL) {
    // s390x prints "processor 0: version = .." as well as "# processors : 1";
    // only the per-CPU blocks start with "processor" at column 0.
    if (strncmp(line, "processor", strlen("processor")) == 0) {
      processors++;
    }

    char* colon = strchr(line, ':');
    if (colon == NULL) {
      continue;
    }
    *colon = '\0';
    char* value = colon + 1;
    while (*value == ' ' || *value == '\t') {
      value++;
    }
    trim(line);
    trim(value);

    for (int i = 0; interesting[i] != NULL; i++) {
      if (strcmp(line, interesting[i]) == 0) {
        // NONPORTABLE: the key set and the values are architecture specific,
        // so only the processor count below is diffed across arches. The
        // harness still requires these to be identical between two runs.
        printf("NONPORTABLE %s = %s\n", line, value);
        break;
      }
    }
  }
  fclose(f);

  printf("processor entries: %d\n", processors);
  return 0;
}

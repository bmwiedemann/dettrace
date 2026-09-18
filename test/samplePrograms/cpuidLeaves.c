// Regression test: a cpuid leaf the canonical machine does not describe used
// to abort the tracer with "CPUID unsupported %eax = ...". Leaf 0x40000000 is
// not a hypothetical one to ask for: our own leaf 1 sets the hypervisor bit,
// so anything looking for a hypervisor vendor asks for it, and lscpu does --
// it could not run under dettrace at all.
//
// The two leaves one past the end of each table are here for the second half
// of that bug: the case ranges used the entry count rather than the highest
// leaf, so 0x0e and 0x8000000b were answered out of bounds.
#include <cpuid.h>
#include <stdio.h>

static void show(unsigned leaf) {
  unsigned eax = 0, ebx = 0, ecx = 0, edx = 0;
  // __cpuid, not __get_cpuid: the latter refuses a leaf above the maximum the
  // CPU reports, which is exactly what this test is about.
  __cpuid(leaf, eax, ebx, ecx, edx);
  printf("cpuid(0x%08x) = %08x %08x %08x %08x\n", leaf, eax, ebx, ecx, edx);
}

int main(void) {
  show(0x00000000); // highest basic leaf
  show(0x0000000d); // highest basic leaf we describe
  show(0x0000000e); // one past it
  show(0x40000000); // hypervisor vendor id
  show(0x80000000); // highest extended leaf
  show(0x8000000a); // highest extended leaf we describe
  show(0x8000000b); // one past it
  show(0xdeadbeef); // nothing at all
  return 0;
}

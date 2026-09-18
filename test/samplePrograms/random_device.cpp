#include <iostream>
#include <random>

int main() {

  std::uniform_int_distribution<int> d(0, 1000000);

  std::random_device rd1; // without any ctor args, appears to use RDRND

  // Marked NONPORTABLE for the same reason getRandom.c marks its bytes: the
  // values are deterministic for a given libc, but libc draws a
  // version-dependent number of times before main() -- glibc 2.44 makes two
  // getrandom calls where the recorded stream had one, which shifts every
  // value by one position without making anything less deterministic. What
  // has to hold everywhere is that two runs agree, which the harness checks
  // by running the program twice.
  std::cout << "NONPORTABLE values:";
  int first = -1;
  bool varies = false;
  for (int n = 0; n < 10; ++n) {
    const int value = d(rd1);
    if (n == 0) {
      first = value;
    } else if (value != first) {
      varies = true;
    }
    std::cout << ' ' << value;
  }
  std::cout << std::endl;

  // The portable half, which is what the harness compares against the
  // expectation. Asserting that the values are within the distribution would
  // assert nothing -- the library guarantees that whatever bytes it is fed --
  // whereas ten identical ones would mean our getrandom() answered with a
  // constant, which is deterministic but not random and would otherwise pass
  // every check here.
  std::cout << "10 values, not all identical: " << (varies ? "yes" : "no")
            << std::endl;

  return 0;
}

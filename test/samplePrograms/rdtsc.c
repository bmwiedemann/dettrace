#include <stdio.h>
#include <x86intrin.h>

int main()
{
    unsigned long long int i;

    i = __rdtsc();
    printf("NONPORTABLE RDTSC: %llu ticks\n", i);
    unsigned long long int j = __rdtsc();
    printf("NONPORTABLE RDTSC: %llu ticks\n", j);
    // The values differ between machines, the step between two reads must
    // not (and the harness needs at least one portable line).
    printf("RDTSC advanced by %llu ticks\n", j - i);
}

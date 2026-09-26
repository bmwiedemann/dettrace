# Building and testing dettrace

## Build dependencies

dettrace is C++14 built with clang and needs libseccomp. The test suites
additionally build small C and C++ programs with gcc and run a few common
Linux utilities under dettrace.

Debian, Ubuntu:

    sudo apt install clang make pkg-config libseccomp-dev \
        gcc g++ python3 gawk procps less util-linux

openSUSE:

    sudo zypper install clang make pkgconf-pkg-config libseccomp-devel \
        gcc gcc-c++ python3-base gawk procps less util-linux linux-glibc-devel

Optional: `clang-format` and `clang-tidy` (Debian: `clang-format clang-tidy`,
openSUSE: `clang-tools`, already pulled in by `clang`). When clang-tidy is
installed the build runs it on every source file, which is slow on small
machines; `make CLANG_TIDY=none build` skips it.

## Building

    make build

produces `bin/dettrace`. It expects `root/` next to `bin/`, see README.md.

## Running the tests

    make -C test/unitTests build && make -C test/unitTests run
    make -C test/samplePrograms build
    MAKEFLAGS= make --keep-going -C test/samplePrograms run < /dev/null

On a slow machine give the sample programs more than their default 5 s
each with `make TEST_TIMEOUT=30s ...` on the last command.

(`make test` also checks the formatting first, which needs the clang-format
version the sources were formatted with.)

## Testing on a machine without the toolchain

dettrace needs a real kernel: user, PID and mount namespaces, ptrace and
seccomp. Emulators such as qemu-user cannot provide those, so a foreign
architecture is best tested on real hardware, for instance a single-board
computer. The distribution there does not have to match: a rootless podman
container of an openSUSE Tumbleweed image works on an Ubuntu host, no root
needed on the host. Clone the repository into your home directory and run:

    podman run -d --name dettrace-tw --network host --privileged \
        --userns=keep-id --security-opt label=disable --security-opt unmask=all \
        -v "$HOME:$HOME" -w "$HOME/git/dettrace" \
        registry.opensuse.org/opensuse/tumbleweed sleep infinity
    podman exec -u 0 dettrace-tw zypper -n install clang make pkgconf-pkg-config \
        libseccomp-devel gcc gcc-c++ python3-base gawk procps less util-linux \
        linux-glibc-devel
    podman exec -it dettrace-tw bash

Then build and test inside the container as above. What the options are for:

- `--privileged --security-opt unmask=all`: the tracee's own user and mount
  namespaces, and the `/proc` mount dettrace makes inside them, need the
  container's `/proc` not to be masked and no seccomp profile in the way.
- `--userns=keep-id`: files in the mounted home keep your uid; installing
  packages then needs `-u 0`, which is root inside the container only.
- `--network host`: rootless networking needs `/dev/net/tun`, which some
  vendor kernels lack.

distrobox would set the same options, but its current Tumbleweed images
fail its setup step (`/etc/zypp/zypp.conf` moved to `/usr/etc`), so this uses
podman directly.

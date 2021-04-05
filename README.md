# eBPF

[![PkgGoDev](https://pkg.go.dev/badge/github.com/DataDog/ebpf)](https://pkg.go.dev/github.com/DataDog/ebpf)

NOTE: This is a fork from [cilium/ebpf](https://github.com/cilium/ebpf) that adds a declarative manager on top to manage the lifecycle of eBPF objects.

## Current status

Work is underway to convert this library to wrap the upstream library, rather than forking.

## Requirements

* A version of Go that is [supported by
  upstream](https://golang.org/doc/devel/release.html#policy)
* Linux 4.4+

## Useful resources

* [eBPF.io](https://ebpf.io) (recommended)
* [Cilium eBPF documentation](https://docs.cilium.io/en/latest/bpf/#bpf-guide)
  (recommended)
* [Linux documentation on
  BPF](https://www.kernel.org/doc/html/latest/networking/filter.html)
* [eBPF features by Linux
  version](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md)

## Regenerating Testdata

Run `make` in the root of this repository to rebuild testdata in all
subpackages. This requires Docker, as it relies on a standardized build
environment to keep the build output stable.

The toolchain image build files are kept in [testdata/docker/](testdata/docker/).

## License

MIT

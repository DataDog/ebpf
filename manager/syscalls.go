package manager

import (
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"

	"github.com/DataDog/ebpf"
	"github.com/DataDog/ebpf/internal"
)

// perfEventOpenWithProbe - Kernel API with e12f03d ("perf/core: Implement the 'perf_kprobe' PMU") allows
// creating [k,u]probe with perf_event_open, which makes it easier to clean up
// the [k,u]probe. This function tries to create pfd with the perf_kprobe PMU.
func perfEventOpenWithProbe(name string, offset, pid int, sectionPrefix string, referenceCounterOffset uint64) (int, error) {
	var err error
	attr := unix.PerfEventAttr{
		Ext2: uint64(offset), // config2 here is kprobe_addr or probe_offset
	}
	attr.Size = uint32(unsafe.Sizeof(attr))

	attr.Type, _ = FindPMUType(sectionPrefix)
	//if err != nil {
	//	return 0, errors.Wrapf(err, "couldn't find PMU type for %s", sectionPrefix)
	//}

	var returnBit uint32
	returnBit, _ = FindRetProbeBit(sectionPrefix)
	//if err != nil {
	//	return 0, errors.Wrapf(err, "couldn't find retprobe bit for %s", sectionPrefix)
	//}
	if returnBit > 0 {
		attr.Config = 1 << returnBit
	}
	if referenceCounterOffset > 0 {
		attr.Config |= referenceCounterOffset << 32
	}

	namePtr, err := syscall.BytePtrFromString(name)
	if err != nil {
		return 0, errors.Wrapf(err, "couldn't create pointer to string %s", name)
	}
	// config1 here is kprobe_func or uprobe_path
	attr.Ext1 = uint64(uintptr(unsafe.Pointer(namePtr)))

	// PID filter is only possible for uprobe events.
	if pid < 0 {
		pid = -1
	}
	// perf_event_open API doesn't allow both pid and cpu to be -1.
	// So only set it to -1 when PID is not -1.
	// Tracing events do not do CPU filtering in any cases.
	var cpu int
	if pid != -1 {
		cpu = -1
	}

	efd, err := unix.PerfEventOpen(&attr, pid, cpu, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if efd < 0 {
		return 0, errors.Wrap(err, "perf_event_open error")
	}
	return efd, nil
}

func perfEventOpenTracingEvent(probeID int) (int, error) {
	attr := unix.PerfEventAttr{
		Type:        unix.PERF_TYPE_TRACEPOINT,
		Sample_type: unix.PERF_SAMPLE_RAW,
		Sample:      1,
		Wakeup:      1,
		Config:      uint64(probeID),
	}
	attr.Size = uint32(unsafe.Sizeof(attr))

	efd, err := unix.PerfEventOpen(&attr, -1, 0, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if efd < 0 {
		return 0, errors.Wrap(err, "perf_event_open error")
	}
	return efd, nil
}

func ioctlPerfEventEnable(perfEventOpenFD int, progFD int) error {
	if _, _, err := unix.Syscall(unix.SYS_IOCTL, uintptr(perfEventOpenFD), unix.PERF_EVENT_IOC_SET_BPF, uintptr(progFD)); err != 0 {
		return errors.Wrap(err, "error attaching bpf program to perf event")
	}
	if _, _, err := unix.Syscall(unix.SYS_IOCTL, uintptr(perfEventOpenFD), unix.PERF_EVENT_IOC_ENABLE, 0); err != 0 {
		return errors.Wrap(err, "error enabling perf event")
	}
	return nil
}

type bpfProgAttachAttr struct {
	targetFD    uint32
	attachBpfFD uint32
	attachType  uint32
	attachFlags uint32
}

const (
	_ProgAttach = 8
	_ProgDetach = 9
)

func bpfProgAttach(progFd int, targetFd int, attachType ebpf.AttachType) (int, error) {
	attr := bpfProgAttachAttr{
		targetFD:    uint32(targetFd),
		attachBpfFD: uint32(progFd),
		attachType:  uint32(attachType),
	}
	ptr, err := internal.BPF(_ProgAttach, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	if err != nil {
		return -1, errors.Wrapf(err, "can't attach program id %d to target fd %d", progFd, targetFd)
	}
	return int(ptr), nil
}

func bpfProgDetach(progFd int, targetFd int, attachType ebpf.AttachType) (int, error) {
	attr := bpfProgAttachAttr{
		targetFD:    uint32(targetFd),
		attachBpfFD: uint32(progFd),
		attachType:  uint32(attachType),
	}
	ptr, err := internal.BPF(_ProgDetach, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	if err != nil {
		return -1, errors.Wrapf(err, "can't detach program id %d to target fd %d", progFd, targetFd)
	}
	return int(ptr), nil
}

func sockAttach(sockFd int, progFd int) error {
	return syscall.SetsockoptInt(sockFd, syscall.SOL_SOCKET, unix.SO_ATTACH_BPF, progFd)
}

func sockDetach(sockFd int, progFd int) error {
	return syscall.SetsockoptInt(sockFd, syscall.SOL_SOCKET, unix.SO_DETACH_BPF, progFd)
}

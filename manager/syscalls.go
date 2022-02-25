package manager

// #include <stdlib.h>
import "C"

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"github.com/DataDog/ebpf"
	"github.com/DataDog/ebpf/internal"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

const perfUProbeRefCtrOffsetShift = 32

func parseUintFromFile(path, format string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return -1, err
	}
	defer f.Close()

	var ret int
	_, err = fmt.Fscanf(f, format, &ret)
	if err != nil {
		return -1, err
	}

	return ret, nil
}

func determineUProbePerfType() int {
	ret, _ := parseUintFromFile("/sys/bus/event_source/devices/uprobe/type", "%d\n")
	return ret
}

func determineKProbePerfType() int {
	ret, _ := parseUintFromFile("/sys/bus/event_source/devices/kprobe/type", "%d\n")
	return ret
}

func determineUProbeRetprobeBit() int {
	ret, _ := parseUintFromFile("/sys/bus/event_source/devices/uprobe/format/retprobe", "config:%d\n")
	return ret
}

func determineKProbeRetprobeBit() int {
	ret, _ := parseUintFromFile("/sys/bus/event_source/devices/kprobe/format/retprobe", "config:%d\n")
	return ret
}

func perfEventOpenProbe(progFd int, uprobe, retprobe bool, name string, offset uint64, pid int, refCtrOff int) (*internal.FD, error) {
	attr := unix.PerfEventAttr{}
	if uprobe {
		attr.Type = uint32(determineUProbePerfType())
	} else {
		attr.Type = uint32(determineKProbePerfType())
	}

	if retprobe {
		var bit int
		if uprobe {
			bit = determineUProbeRetprobeBit()
		} else {
			bit = determineKProbeRetprobeBit()
		}
		attr.Config |= 1 << uint(bit)
	}
	attr.Config |= uint64(refCtrOff) << perfUProbeRefCtrOffsetShift
	cs := unsafe.Pointer(C.CString(name))
	defer func() {
		C.free(cs)
	}()

	attr.Ext1 = uint64(uintptr(cs))
	attr.Ext2 = offset
	attr.Size = uint32(unsafe.Sizeof(attr))

	efd, err := unix.PerfEventOpen(&attr, -1, 0, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if efd < 0 {
		return nil, errors.Wrap(err, "perf_event_open error")
	}

	if _, _, err := unix.Syscall(unix.SYS_IOCTL, uintptr(efd), unix.PERF_EVENT_IOC_SET_BPF, uintptr(progFd)); err != 0 {
		return nil, errors.Wrap(err, "error attaching bpf program to perf event")
	}

	if _, _, err := unix.Syscall(unix.SYS_IOCTL, uintptr(efd), unix.PERF_EVENT_IOC_ENABLE, 0); err != 0 {
		return nil, errors.Wrap(err, "error enabling perf event")
	}

	return internal.NewFD(uint32(efd)), nil
}

func perfEventOpenTracepoint(id int, progFd int) (*internal.FD, error) {
	attr := unix.PerfEventAttr{
		Type:        unix.PERF_TYPE_TRACEPOINT,
		Sample_type: unix.PERF_SAMPLE_RAW,
		Sample:      1,
		Wakeup:      1,
		Config:      uint64(id),
	}
	attr.Size = uint32(unsafe.Sizeof(attr))

	efd, err := unix.PerfEventOpen(&attr, -1, 0, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if efd < 0 {
		return nil, errors.Wrap(err, "perf_event_open error")
	}

	if _, _, err := unix.Syscall(unix.SYS_IOCTL, uintptr(efd), unix.PERF_EVENT_IOC_SET_BPF, uintptr(progFd)); err != 0 {
		return nil, errors.Wrap(err, "error attaching bpf program to perf event")
	}

	if _, _, err := unix.Syscall(unix.SYS_IOCTL, uintptr(efd), unix.PERF_EVENT_IOC_ENABLE, 0); err != 0 {
		return nil, errors.Wrap(err, "error enabling perf event")
	}

	return internal.NewFD(uint32(efd)), nil
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

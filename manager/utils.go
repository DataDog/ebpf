package manager

import (
	"bytes"
	"debug/elf"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/DataDog/ebpf/manager/elfmap"
	"github.com/DataDog/gopsutil/process"
	"github.com/DataDog/gopsutil/process/so"
	"github.com/pkg/errors"
)

type state uint

const (
	reset state = iota
	initialized
	paused
	running

	// MaxEventNameLen - maximum length for a kprobe (or uprobe) event name
	// MAX_EVENT_NAME_LEN (linux/kernel/trace/trace.h)
	MaxEventNameLen    = 64
	MinFunctionNameLen = 10
)

// ConcatErrors - Concatenate 2 errors into one error.
func ConcatErrors(err1, err2 error) error {
	if err1 == nil {
		return err2
	}
	if err2 != nil {
		return errors.Wrap(err1, err2.Error())
	}
	return err1
}

// availableFilterFunctions - cache of the list of available kernel functions.
var availableFilterFunctions []string

func FindFilterFunction(funcName string) (string, error) {
	// Prepare matching pattern
	searchedName, err := regexp.Compile(funcName)
	if err != nil {
		return "", err
	}

	// Cache available filter functions if necessary
	if len(availableFilterFunctions) == 0 {
		funcs, err := ioutil.ReadFile("/sys/kernel/debug/tracing/available_filter_functions")
		if err != nil {
			return "", err
		}
		availableFilterFunctions = strings.Split(string(funcs), "\n")
		for i, name := range availableFilterFunctions {
			splittedName := strings.Split(name, " ")
			name = splittedName[0]
			splittedName = strings.Split(name, "\t")
			name = splittedName[0]
			availableFilterFunctions[i] = name
		}
		sort.Strings(availableFilterFunctions)
	}

	// Match function name
	var potentialMatches []string
	for _, f := range availableFilterFunctions {
		if searchedName.MatchString(f) {
			potentialMatches = append(potentialMatches, f)
		}
		if f == funcName {
			return f, nil
		}
	}
	if len(potentialMatches) > 0 {
		return potentialMatches[0], nil
	}
	return "", nil
}

// cache of the syscall prefix depending on kernel version
var syscallPrefix string

// GetSyscallFnName - Returns the kernel function of the provided syscall, after reading /proc/kallsyms to retrieve
// the list of symbols of the current kernel.
func GetSyscallFnName(name string) (string, error) {
	return GetSyscallFnNameWithSymFile(name, defaultSymFile)
}

// GetSyscallFnNameWithSymFile - Returns the kernel function of the provided syscall, after reading symFile to retrieve
// the list of symbols of the current kernel.
func GetSyscallFnNameWithSymFile(name string, symFile string) (string, error) {
	if symFile == "" {
		symFile = defaultSymFile
	}
	if syscallPrefix == "" {
		syscall, err := getSyscallName("open", symFile)
		if err != nil {
			return "", err
		}
		// copy to avoid memory leak due to go subslice
		// see: https://go101.org/article/memory-leaking.html
		var b strings.Builder
		b.WriteString(syscall)
		syscall = b.String()

		syscallPrefix = strings.TrimSuffix(syscall, "open")
	}

	return syscallPrefix + name, nil
}

const defaultSymFile = "/proc/kallsyms"

// Returns the qualified syscall named by going through '/proc/kallsyms' on the
// system on which its executed. It allows BPF programs that may have been compiled
// for older syscall functions to run on newer kernels
func getSyscallName(name string, symFile string) (string, error) {
	// Get kernel symbols
	syms, err := ioutil.ReadFile(symFile)
	if err != nil {
		return "", err
	}
	return getSyscallFnNameWithKallsyms(name, string(syms))
}

func getSyscallFnNameWithKallsyms(name string, kallsymsContent string) (string, error) {
	var arch string
	switch runtime.GOARCH {
	case "386":
		arch = "ia32"
	case "arm64":
		arch = "arm64"
	default:
		arch = "x64"
	}

	// We should search for new syscall function like "__x64__sys_open"
	// Note the start of word boundary. Should return exactly one string
	regexStr := `(\b__` + arch + `_[Ss]y[sS]_` + name + `\b)`
	fnRegex := regexp.MustCompile(regexStr)

	match := fnRegex.FindAllString(kallsymsContent, -1)
	if len(match) > 0 {
		return match[0], nil
	}

	// If nothing found, search for old syscall function to be sure
	regexStr = `(\b[Ss]y[sS]_` + name + `\b)`
	fnRegex = regexp.MustCompile(regexStr)
	match = fnRegex.FindAllString(kallsymsContent, -1)
	// If we get something like 'sys_open' or 'SyS_open', return
	// either (they have same addr) else, just return original string
	if len(match) > 0 {
		return match[0], nil
	}

	// check for '__' prefixed functions, like '__sys_open'
	regexStr = `(\b__[Ss]y[sS]_` + name + `\b)`
	fnRegex = regexp.MustCompile(regexStr)
	match = fnRegex.FindAllString(kallsymsContent, -1)
	// If we get something like '__sys_open' or '__SyS_open', return
	// either (they have same addr) else, just return original string
	if len(match) > 0 {
		return match[0], nil
	}

	return "", errors.New("could not find a valid syscall name")
}

var safeEventRegexp = regexp.MustCompile("[^a-zA-Z0-9]")

func GenerateEventName(probeType, funcName, UID string, attachPID int) (string, error) {
	// truncate the function name and UID name to reduce the length of the event
	attachPIDstr := strconv.Itoa(attachPID)
	maxFuncNameLen := (MaxEventNameLen - 3 /* _ */ - len(probeType) - len(UID) - len(attachPIDstr))
	if maxFuncNameLen < MinFunctionNameLen { /* let's garantee that we have a function name minimum of 10 chars (MinFunctionNameLen) of trow an error */
		dbgFullEventString := safeEventRegexp.ReplaceAllString(fmt.Sprintf("%s_%s_%s_%s", probeType, funcName, UID, attachPIDstr), "_")
		return "", errors.Errorf("event name is too long (kernel limit is %d (MAX_EVENT_NAME_LEN)): MinFunctionNameLen %d, len 3, probeType %d, funcName %d, UID %d, attachPIDstr %d ; full event string : '%s'", MaxEventNameLen, MinFunctionNameLen, len(probeType), len(funcName), len(UID), len(attachPIDstr), dbgFullEventString)
	}
	eventName := safeEventRegexp.ReplaceAllString(fmt.Sprintf("%s_%.*s_%s_%s", probeType, maxFuncNameLen, funcName, UID, attachPIDstr), "_")

	if len(eventName) > MaxEventNameLen {
		return "", errors.Errorf("event name too long (kernel limit MAX_EVENT_NAME_LEN is %d): '%s'", MaxEventNameLen, eventName)
	}
	return eventName, nil
}

// getKernelGeneratedEventName returns the pattern used by the kernel when a [k|u]probe is loaded without an event name.
// The library doesn't support loading a [k|u]probe with an address directly, so only one pattern applies here.
func getKernelGeneratedEventName(probeType, funcName string) string {
	return fmt.Sprintf("%s_%s_0", probeType, funcName)
}

// ReadKprobeEvents - Returns the content of kprobe_events
func ReadKprobeEvents() (string, error) {
	kprobeEvents, err := ioutil.ReadFile("/sys/kernel/debug/tracing/kprobe_events")
	if err != nil {
		return "", err
	}
	return string(kprobeEvents), nil
}

// EnableKprobeEvent - Writes a new kprobe in kprobe_events with the provided parameters. Call DisableKprobeEvent
// to remove the krpobe.
func EnableKprobeEvent(probeType, funcName, UID, maxactiveStr string, kprobeAttachPID int) (int, error) {
	// Generate event name
	eventName, err := GenerateEventName(probeType, funcName, UID, kprobeAttachPID)
	if err != nil {
		return -1, err
	}

	// Write line to kprobe_events
	kprobeEventsFileName := "/sys/kernel/debug/tracing/kprobe_events"
	f, err := os.OpenFile(kprobeEventsFileName, os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		return -1, errors.Wrap(err, "cannot open kprobe_events")
	}
	defer f.Close()
	cmd := fmt.Sprintf("%s%s:%s %s\n", probeType, maxactiveStr, eventName, funcName)
	if _, err = f.WriteString(cmd); err != nil && !os.IsExist(err) {
		return -1, errors.Wrapf(err, "cannot write %q to kprobe_events", cmd)
	}

	// Retrieve kprobe ID
	kprobeIDFile := fmt.Sprintf("/sys/kernel/debug/tracing/events/kprobes/%s/id", eventName)
	kprobeIDBytes, err := ioutil.ReadFile(kprobeIDFile)
	if err != nil {
		if os.IsNotExist(err) {
			return -1, ErrKprobeIDNotExist
		}
		return -1, errors.Wrap(err, "cannot read kprobe id")
	}
	kprobeID, err := strconv.Atoi(strings.TrimSpace(string(kprobeIDBytes)))
	if err != nil {
		return -1, errors.Wrap(err, "invalid kprobe id: %v")
	}
	return kprobeID, nil
}

// DisableKprobeEvent - Removes a kprobe from kprobe_events
func DisableKprobeEvent(probeType, funcName, UID string, kprobeAttachPID int) error {
	// Generate event name
	eventName, err := GenerateEventName(probeType, funcName, UID, kprobeAttachPID)
	if err != nil {
		return err
	}
	return disableKprobeEvent(eventName)
}

func disableKprobeEvent(eventName string) error {
	// Write line to kprobe_events
	kprobeEventsFileName := "/sys/kernel/debug/tracing/kprobe_events"
	f, err := os.OpenFile(kprobeEventsFileName, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return errors.Wrap(err, "cannot open kprobe_events")
	}
	defer f.Close()
	cmd := fmt.Sprintf("-:%s\n", eventName)
	if _, err = f.WriteString(cmd); err != nil {
		pathErr, ok := err.(*os.PathError)
		if ok && pathErr.Err == syscall.ENOENT {
			// This can happen when for example two modules
			// use the same elf object and both ratecall `Close()`.
			// The second will encounter the error as the
			// probe already has been cleared by the first.
			return nil
		} else {
			return errors.Wrapf(err, "cannot write %q to kprobe_events", cmd)
		}
	}
	return nil
}

// ReadUprobeEvents - Returns the content of uprobe_events
func ReadUprobeEvents() (string, error) {
	uprobeEvents, err := ioutil.ReadFile("/sys/kernel/debug/tracing/uprobe_events")
	if err != nil {
		return "", err
	}
	return string(uprobeEvents), nil
}

// EnableUprobeEvent - Writes a new Uprobe in uprobe_events with the provided parameters. Call DisableUprobeEvent
// to remove the krpobe.
func EnableUprobeEvent(probeType string, funcName, path, UID string, uprobeAttachPID int, offset uint64) (int, error) {
	// Generate event name
	eventName, err := GenerateEventName(probeType, funcName, UID, uprobeAttachPID)
	if err != nil {
		return -1, err
	}

	// Write line to uprobe_events, only eventName is tested to max MAX_EVENT_NAME_LEN (linux/kernel/trace/trace.h)
	uprobeEventsFileName := "/sys/kernel/debug/tracing/uprobe_events"
	f, err := os.OpenFile(uprobeEventsFileName, os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		return -1, errors.Wrap(err, "cannot open uprobe_events")
	}
	defer f.Close()

	cmd := fmt.Sprintf("%s:%s %s:%#x\n", probeType, eventName, path, offset)

	if _, err = f.WriteString(cmd); err != nil && !os.IsExist(err) {
		return -1, errors.Wrapf(err, "cannot write %q to uprobe_events", cmd)
	}

	// Retrieve Uprobe ID
	uprobeIdFile := fmt.Sprintf("/sys/kernel/debug/tracing/events/uprobes/%s/id", eventName)
	uprobeIdBytes, err := ioutil.ReadFile(uprobeIdFile)
	if err != nil {
		if os.IsNotExist(err) {
			return -1, ErrUprobeIDNotExist
		}
		return -1, errors.Wrap(err, "cannot read uprobe id")
	}
	uprobeId, err := strconv.Atoi(strings.TrimSpace(string(uprobeIdBytes)))
	if err != nil {
		return -1, errors.Wrap(err, "invalid uprobe id")
	}

	return uprobeId, nil
}

type memoryAccess int

const (
	Direct memoryAccess = iota
	Ptrace
)

type processMemory struct {
	memoryAccess memoryAccess
	pid          int
}

func newProcessMemory(targetPID int) *processMemory {
	p := &processMemory{
		pid: targetPID,
	}
	if targetPID == os.Getpid() {
		p.memoryAccess = Direct
	} else {
		p.memoryAccess = Ptrace
	} /* else { eRPC.Peek(addr, size) }  */
	return p
}

func (p *processMemory) PeekMemory(addr uintptr, size uint64) ([]byte, error) {
	mem := make([]byte, size)

	switch p.memoryAccess {
	case Direct:
		/* Ugly memcpy, but golang firendly */
		for i := uint64(0); i < size; i++ {
			var src *uint8 = (*uint8)(unsafe.Pointer(addr + uintptr(i)))
			mem[i] = *src
		}
		return mem, nil
	case Ptrace:
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		err := syscall.PtraceAttach(p.pid)
		if err != nil {
			return nil, errors.Wrapf(err, "ptrace attach")
		}
		_, err = syscall.Wait4(p.pid, nil, 0, nil)
		if err != nil {
			return nil, errors.Wrapf(err, "wait4")
		}
		copied, err := syscall.PtracePeekData(p.pid, addr, mem[:])
		if err != nil || copied != 8 {
			return nil, errors.Wrapf(err, "ptrace peek data")
		}
		err = syscall.PtraceDetach(p.pid)
		if err != nil {
			return nil, errors.Wrapf(err, "ptrace detach")
		}
		return mem, nil
		/* case eRPC: { return eRPC.Peek(p.pid, addr, size) } */
	}
	return nil, nil
}

func memELFFromProcMaps(pid int, path string) ([]byte, uintptr, error) {
	p, err := process.NewProcess(int32(pid))
	if err != nil {
		return nil, uintptr(0), err
	}
	procMaps, err := p.MemoryMaps(true)
	if err != nil {
		return nil, uintptr(0), err
	}
	b := make([]byte, 0)

	offset := int64(0)
	vBaseAddr := uintptr(0)
	for _, m := range *procMaps {
		if m.Path == path && m.Permission.Read {
			if offset == 0 {
				vBaseAddr = m.StartAddr
			}
			if uint64(offset) != m.Offset {
				if m.Offset > uint64(offset) {
					b = append(b, make([]byte, m.Offset-uint64(offset))...)
				}
				if uint64(offset) > m.Offset {
					b = b[:m.Offset] /* truncate */
					offset = int64(m.Offset)
				}
			}

			pMem := newProcessMemory(pid)
			size := int64(m.EndAddr - m.StartAddr)
			if size <= 0 {
				return nil, uintptr(0), fmt.Errorf("wrong mapping 0x%x 0x%x", m.EndAddr, m.StartAddr)
			}
			mem, err := pMem.PeekMemory(m.StartAddr, uint64(size))
			if err != nil {
				return nil, uintptr(0), errors.Wrapf(err, "process (%d) peek memory", pid)
			}

			b = append(b, mem...)
			offset += size
		}
	}
	return b, vBaseAddr, nil
}

// OpenAndListSymbolsFromPID - Opens an elf file matching path from memory (/proc/pid/maps)  and extracts all its symbols
func OpenAndListSymbolsFromPID(pid int, path string) (*elf.File, []elf.Symbol, error) {
	b, vBaseAddr, err := memELFFromProcMaps(pid, path)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "couldn't create elf from /proc/pid/maps %d %s", pid, path)
	}

	f, err := elfmap.OpenMapBytes(bytes.NewReader(b), vBaseAddr)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "couldn't open memory elf from /proc/pid/maps %d %s", pid, path)
	}
	defer f.Close()

	// Loop through all symbols
	syms, errSyms := f.Symbols()
	dynSyms, errDynSyms := f.DynamicSymbols()
	syms = append(syms, dynSyms...)

	if len(syms) == 0 {
		var err error
		if errSyms != nil {
			err = errors.Wrap(err, "failed to list symbols")
		}
		if errDynSyms != nil {
			err = errors.Wrap(err, "failed to list dynamic symbols")
		}
		if err != nil {
			return nil, nil, err
		}
		return nil, nil, errors.New("no symbols found")
	}
	return f.Elf, syms, nil
}

// OpenAndListSymbols - Opens an elf file and extracts all its symbols
func OpenAndListSymbols(path string) (*elf.File, []elf.Symbol, error) {
	// open elf file
	f, err := elf.Open(path)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "couldn't open elf file %s", path)
	}
	defer f.Close()

	// Loop through all symbols
	syms, errSyms := f.Symbols()
	dynSyms, errDynSyms := f.DynamicSymbols()
	syms = append(syms, dynSyms...)

	if len(syms) == 0 {
		var err error
		if errSyms != nil {
			err = errors.Wrap(err, "failed to list symbols")
		}
		if errDynSyms != nil {
			err = errors.Wrap(err, "failed to list dynamic symbols")
		}
		if err != nil {
			return nil, nil, err
		} else {
			return nil, nil, errors.New("no symbols found")
		}
	}
	return f, syms, nil
}

// SanitizeUprobeAddresses - sanitizes the addresses of the provided symbols
func SanitizeUprobeAddresses(f *elf.File, syms []elf.Symbol) {
	// If the binary is a non-PIE executable, addr must be a virtual address, otherwise it must be an offset relative to
	// the file load address. For executable (ET_EXEC) binaries and shared objects (ET_DYN), translate the virtual
	// address to physical address in the binary file.
	if f.Type == elf.ET_EXEC || f.Type == elf.ET_DYN {
		for i, sym := range syms {
			for _, prog := range f.Progs {
				if prog.Type == elf.PT_LOAD {
					if sym.Value >= prog.Vaddr && sym.Value < (prog.Vaddr+prog.Memsz) {
						syms[i].Value = sym.Value - prog.Vaddr + prog.Off
					}
				}
			}
		}
	}
}

// FindSymbolOffsets - Parses the provided file and returns the offsets of the symbols that match the provided pattern
func FindSymbolOffsets(path string, pattern *regexp.Regexp) ([]elf.Symbol, error) {
	var syms []elf.Symbol
	f, syms, err := OpenAndListSymbols(path)
	if err != nil {
		libRegex, err := regexp.Compile(path)
		if err != nil {
			return nil, err
		}
		libs := so.Find(libRegex)
		if len(libs) == 0 {
			return nil, fmt.Errorf("Can't find running process that have this lib %s loaded", path)
		}
		found := false
		for _, lib := range libs {
			for _, pidPath := range lib.PidsPath {
				pidStr := filepath.Base(pidPath)
				var pid int
				pid, err = strconv.Atoi(pidStr)
				if err != nil {
					continue
				}
				f, syms, err = OpenAndListSymbolsFromPID(pid, path)
				if err == nil {
					found = true
					goto found_syms
				}
			}
		}
		if !found {
			return nil, fmt.Errorf("Can't find/read memory of process for lib %s last error : %v", path, err)
		}
	}

found_syms:
	var matches []elf.Symbol
	for _, sym := range syms {
		if elf.ST_TYPE(sym.Info) == elf.STT_FUNC && pattern.MatchString(sym.Name) {
			matches = append(matches, sym)
		}
	}

	if len(matches) == 0 {
		return nil, ErrSymbolNotFound
	}

	SanitizeUprobeAddresses(f, matches)
	return matches, nil
}

// DisableUprobeEvent - Removes a uprobe from uprobe_events
func DisableUprobeEvent(probeType string, funcName string, UID string, uprobeAttachPID int) error {
	// Generate event name
	eventName, err := GenerateEventName(probeType, funcName, UID, uprobeAttachPID)
	if err != nil {
		return err
	}
	return disableUprobeEvent(eventName)
}

func disableUprobeEvent(eventName string) error {
	// Write uprobe_events line
	uprobeEventsFileName := "/sys/kernel/debug/tracing/uprobe_events"
	f, err := os.OpenFile(uprobeEventsFileName, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return errors.Wrapf(err, "cannot open uprobe_events")
	}
	defer f.Close()
	cmd := fmt.Sprintf("-:%s\n", eventName)
	if _, err = f.WriteString(cmd); err != nil {
		return errors.Wrapf(err, "cannot write %q to uprobe_events", cmd)
	}
	return nil
}

// GetTracepointID - Returns a tracepoint ID from its category and name
func GetTracepointID(category, name string) (int, error) {
	tracepointIDFile := fmt.Sprintf("/sys/kernel/debug/tracing/events/%s/%s/id", category, name)
	tracepointIDBytes, err := ioutil.ReadFile(tracepointIDFile)
	if err != nil {
		return -1, errors.Wrapf(err, "cannot read tracepoint id %q", tracepointIDFile)
	}
	tracepointID, err := strconv.Atoi(strings.TrimSpace(string(tracepointIDBytes)))
	if err != nil {
		return -1, errors.Wrap(err, "invalid tracepoint id")
	}
	return tracepointID, nil
}

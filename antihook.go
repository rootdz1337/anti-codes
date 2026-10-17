package main

import (
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

// ============================================================================
// Anti-Hook Detection Module
//
// Complements antipatch.go with focus on *hook infrastructure* rather than
// raw byte diffing. Detects:
//
//   1. Inline hooks (detours) at function entry points across ntdll, kernel32,
//      user32, ws2_32, wininet, winhttp, amsi, and advapi32
//   2. IAT hooks where an import slot points outside its owning module
//   3. EAT hooks where an export points outside its module's code range
//   4. "Hook stubs" — the JMP trampolines installed in the owning module
//   5. Suspicious memory protections (RWX pages hosting jumps)
//
// Produces a structured HookMap that callers can use to reason about which
// APIs are being observed. All operations are read-only.
// ============================================================================

// HookType classifies a detected interception.
type HookType string

const (
	HookInline HookType = "inline"
	HookIAT    HookType = "iat"
	HookEAT    HookType = "eat"
	HookStub   HookType = "stub"
	HookRWX    HookType = "rwx-page"
)

// Hook describes one intercepted function.
type Hook struct {
	Type        HookType
	Module      string   // owning module, e.g. "ntdll.dll"
	Function    string   // export name
	Address     uintptr  // runtime VA of the function entry
	SlotAddress uintptr  // for IAT/EAT: address of the slot
	Target      uintptr  // where the hook redirects to (0 if unknown)
	Bytes       []byte   // first N bytes at the entry
	Severity    PatchSeverity
	Detail      string
}

// HookMap is the full set of hooks detected in the current process.
type HookMap struct {
	Hooks       []Hook
	ByModule    map[string][]Hook
	Stubs       []Stub
	RWXPages    []RWXPage
}

// Stub describes a JMP trampoline: bytes at the hooked entry that jump to
// some destination (usually inside the EDR's own DLL).
type Stub struct {
	At   uintptr
	To   uintptr
	Kind string // "jmp-rel32", "jmp-rip", "push-ret", "jmp-rel8"
}

// RWXPage describes a memory region that is simultaneously writable and
// executable — where hook stubs typically live.
type RWXPage struct {
	Base  uintptr
	Size  uintptr
	Owner string
}

// AntiHook is the scanner.
type AntiHook struct {
	// Modules to scan. Order matters only for output.
	Modules []string

	// PrologueLen is how many bytes at each export entry are examined.
	PrologueLen int

	// MaxFunctions caps the exports scanned per module (defensive).
	MaxFunctions int

	mu sync.Mutex
}

// DefaultAntiHook returns a configuration that covers the modules most
// commonly hooked by EDR/AV products on Windows.
func DefaultAntiHook() *AntiHook {
	return &AntiHook{
		Modules: []string{
			"ntdll.dll",
			"kernel32.dll",
			"kernelbase.dll",
			"user32.dll",
			"advapi32.dll",
			"ws2_32.dll",
			"wininet.dll",
			"winhttp.dll",
			"amsi.dll",
			"crypt32.dll",
			"bcrypt.dll",
			"secur32.dll",
			"dnsapi.dll",
			"ole32.dll",
			"shell32.dll",
		},
		PrologueLen:  16,
		MaxFunctions: 4096,
	}
}

// ---------------------------------------------------------------------------
// Inline hook detection — scan every export's prologue for detour signatures
// ---------------------------------------------------------------------------

// ScanInline walks every export of every configured module and inspects the
// first PrologueLen bytes for known detour patterns.
func (ah *AntiHook) ScanInline() (*HookMap, error) {
	if runtime.GOOS != "windows" {
		return &HookMap{ByModule: map[string][]Hook{}}, nil
	}
	hm := &HookMap{
		ByModule: make(map[string][]Hook),
	}

	for _, modName := range ah.Modules {
		base, exports, err := enumerateExports(modName)
		if err != nil || base == 0 {
			continue
		}
		scanned := 0
		for _, exp := range exports {
			if scanned >= ah.MaxFunctions {
				break
			}
			scanned++
			addr := base + uintptr(exp.RVA)
			prologue := readLiveBytes(addr, ah.PrologueLen)
			if len(prologue) == 0 {
				continue
			}
			hook, ok := detectInlineHook(modName, exp.Name, addr, prologue)
			if !ok {
				continue
			}
			hm.Hooks = append(hm.Hooks, hook)
			hm.ByModule[modName] = append(hm.ByModule[modName], hook)
			if hook.Target != 0 {
				hm.Stubs = append(hm.Stubs, Stub{
					At:   addr,
					To:   hook.Target,
					Kind: hook.Detail,
				})
			}
		}
	}
	return hm, nil
}

// detectInlineHook inspects a prologue for detour signatures. Returns the
// Hook if found, plus a bool indicating whether a hook was detected.
func detectInlineHook(module, fn string, addr uintptr, prologue []byte) (Hook, bool) {
	if len(prologue) < 2 {
		return Hook{}, false
	}
	h := Hook{
		Type:     HookInline,
		Module:   module,
		Function: fn,
		Address:  addr,
		Bytes:    prologue,
	}

	// E9 rel32 — classic 5-byte detour.
	if prologue[0] == 0xE9 && len(prologue) >= 5 {
		rel := int32(binary.LittleEndian.Uint32(prologue[1:5]))
		h.Target = addr + 5 + uintptr(int64(rel))
		h.Severity = SevCritical
		h.Detail = "jmp-rel32"
		return h, true
	}
	// EB rel8 — 2-byte short jump (often to nearby stub).
	if prologue[0] == 0xEB && len(prologue) >= 2 {
		rel := int8(prologue[1])
		h.Target = addr + 2 + uintptr(int64(rel))
		h.Severity = SevSuspicious
		h.Detail = "jmp-rel8"
		return h, true
	}
	// FF 25 off32 — JMP [rip+off] (32-bit trampoline).
	if len(prologue) >= 6 && prologue[0] == 0xFF && prologue[1] == 0x25 {
		off := int32(binary.LittleEndian.Uint32(prologue[2:6]))
		slot := addr + 6 + uintptr(int64(off))
		target := *(*uintptr)(unsafe.Pointer(slot))
		h.Target = target
		h.Severity = SevCritical
		h.Detail = "jmp-rip"
		return h, true
	}
	// 48 FF 25 off32 — x64 JMP qword [rip+off] (x64 IAT-style).
	if len(prologue) >= 7 && prologue[0] == 0x48 && prologue[1] == 0xFF && prologue[2] == 0x25 {
		off := int32(binary.LittleEndian.Uint32(prologue[3:7]))
		slot := addr + 7 + uintptr(int64(off))
		target := *(*uintptr)(unsafe.Pointer(slot))
		h.Target = target
		h.Severity = SevCritical
		h.Detail = "jmp-qword-rip"
		return h, true
	}
	// 68 imm32 C3 — PUSH addr; RET thunk.
	if len(prologue) >= 6 && prologue[0] == 0x68 && prologue[5] == 0xC3 {
		imm := uintptr(binary.LittleEndian.Uint32(prologue[1:5]))
		h.Target = imm
		h.Severity = SevCritical
		h.Detail = "push-ret"
		return h, true
	}
	// 33 C0 C3 — xor eax,eax; ret — AMSI bypass pattern.
	if len(prologue) >= 3 && prologue[0] == 0x33 && prologue[1] == 0xC0 && prologue[2] == 0xC3 {
		h.Severity = SevCritical
		h.Detail = "force-return-zero"
		return h, true
	}
	// B8 imm32 C3 — mov eax, imm; ret — forced return value.
	if len(prologue) >= 6 && prologue[0] == 0xB8 && prologue[5] == 0xC3 {
		h.Severity = SevSuspicious
		h.Detail = "force-return-imm"
		return h, true
	}
	return Hook{}, false
}

// ---------------------------------------------------------------------------
// IAT hook detection
// ---------------------------------------------------------------------------

// ScanIAT walks the imports of the current executable and reports any slot
// whose resolved target falls outside the range of the module it should
// belong to.
func (ah *AntiHook) ScanIAT() ([]Hook, error) {
	if runtime.GOOS != "windows" {
		return nil, nil
	}
	selfPath, err := os.Executable()
	if err != nil {
		return nil, err
	}
	f, err := pe.Open(selfPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	imageBase := runtimeImageBase(selfPath)
	if imageBase == 0 {
		return nil, errors.New("could not resolve self image base")
	}

	imports, err := f.ImportedSymbols()
	if err != nil {
		return nil, err
	}

	// Get the IAT RVA and size.
	iatRVA, iatSize, err := importDirectory(f)
	if err != nil || iatRVA == 0 {
		return nil, err
	}

	ptrSize := uintptr(8)
	if f.Machine == pe.IMAGE_FILE_MACHINE_I386 {
		ptrSize = 4
	}

	// Resolve owning module ranges once.
	ranges := make(map[string]modRange)
	var hooks []Hook

	for idx, imp := range imports {
		parts := strings.SplitN(imp, ":", 2)
		if len(parts) != 2 {
			continue
		}
		dll := strings.ToLower(parts[0])
		fn := parts[1]

		r, ok := ranges[dll]
		if !ok {
			r = lookupModuleRange(dll)
			ranges[dll] = r
		}
		if r.Base == 0 || r.Size == 0 {
			continue
		}

		// Slot VA in our own image.
		off := uintptr(idx) * ptrSize
		if off >= uintptr(iatSize) {
			break
		}
		slot := imageBase + uintptr(iatRVA) + off
		current := *(*uintptr)(unsafe.Pointer(slot))
		if current == 0 {
			continue
		}

		// Is the current target inside the owning module?
		if current < r.Base || current >= r.Base+r.Size {
			hooks = append(hooks, Hook{
				Type:        HookIAT,
				Module:      dll,
				Function:    fn,
				SlotAddress: slot,
				Target:      current,
				Severity:    SevCritical,
				Detail: fmt.Sprintf("slot->%#x outside %s [%#x-%#x]",
					current, dll, r.Base, r.Base+r.Size),
			})
		}
	}
	return hooks, nil
}

// ---------------------------------------------------------------------------
// EAT hook detection
// ---------------------------------------------------------------------------

// ScanEAT walks the export address table of each module and flags any entry
// pointing outside the module's own code range. A common EDR persistence
// trick is to redirect a sensitive export (e.g. LdrLoadDll) to a hotpatch
// trampoline in another region.
func (ah *AntiHook) ScanEAT() ([]Hook, error) {
	if runtime.GOOS != "windows" {
		return nil, nil
	}
	var hooks []Hook
	for _, modName := range ah.Modules {
		base, exports, err := enumerateExports(modName)
		if err != nil || base == 0 {
			continue
		}
		r := lookupModuleRange(modName)
		if r.Base == 0 || r.Size == 0 {
			continue
		}
		scanned := 0
		for _, exp := range exports {
			if scanned >= ah.MaxFunctions {
				break
			}
			scanned++
			addr := base + uintptr(exp.RVA)
			if addr < r.Base || addr >= r.Base+r.Size {
				hooks = append(hooks, Hook{
					Type:     HookEAT,
					Module:   modName,
					Function: exp.Name,
					Address:  addr,
					Severity: SevCritical,
					Detail: fmt.Sprintf("export RVA resolves to %#x outside module range [%#x-%#x]",
						addr, r.Base, r.Base+r.Size),
				})
			}
		}
	}
	return hooks, nil
}

// ---------------------------------------------------------------------------
// RWX page discovery — where stub code typically lives
// ---------------------------------------------------------------------------

// ScanRWX walks the process's committed regions looking for pages that are
// simultaneously writable and executable, or that are not backed by a file
// (private committed). Such regions are where hook stubs and shellcode
// typically live.
func (ah *AntiHook) ScanRWX() ([]RWXPage, error) {
	if runtime.GOOS != "windows" {
		return nil, nil
	}
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getCurrentProcess := kernel32.NewProc("GetCurrentProcess")
	virtualQuery := kernel32.NewProc("VirtualQuery")

	hProc, _, _ := getCurrentProcess.Call()

	type memBasicInfo struct {
		BaseAddress       uintptr
		AllocationBase    uintptr
		AllocationProtect uint32
		PartitionId       uint16
		_                 uint16
		RegionSize        uintptr
		State             uint32
		Protect           uint32
		Type              uint32
		_                 uint32
	}

	var pages []RWXPage
	var addr uintptr
	for {
		var mbi memBasicInfo
		ret, _, _ := virtualQuery.Call(
			addr,
			uintptr(unsafe.Pointer(&mbi)),
			unsafe.Sizeof(mbi),
		)
		if ret == 0 || mbi.RegionSize == 0 {
			break
		}
		// MEM_COMMIT = 0x1000
		if mbi.State == 0x1000 {
			// PAGE_EXECUTE_READWRITE = 0x40, PAGE_EXECUTE_WRITECOPY = 0x80
			if mbi.Protect == 0x40 || mbi.Protect == 0x80 {
				pages = append(pages, RWXPage{
					Base: mbi.BaseAddress,
					Size: mbi.RegionSize,
				})
			}
		}
		next := mbi.BaseAddress + mbi.RegionSize
		if next <= addr {
			break
		}
		addr = next
	}
	return pages, nil
}

// ---------------------------------------------------------------------------
// Module / export enumeration helpers
// ---------------------------------------------------------------------------

// exportInfo mirrors pe.Symbol but avoids re-exporting the type.
type exportInfo struct {
	Name string
	RVA  uint32
}

// enumerateExports returns the runtime base and a list of exports for a
// loaded module.
func enumerateExports(modName string) (uintptr, []exportInfo, error) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getModuleHandle := kernel32.NewProc("GetModuleHandleW")
	getModuleFileName := kernel32.NewProc("GetModuleFileNameW")

	modPtr, err := syscall.UTF16PtrFromString(modName)
	if err != nil {
		return 0, nil, err
	}
	hMod, _, _ := getModuleHandle.Call(uintptr(unsafe.Pointer(modPtr)))
	if hMod == 0 {
		return 0, nil, fmt.Errorf("module %s not loaded", modName)
	}

	var buf [syscall.MAX_PATH]uint16
	n, _, _ := getModuleFileName.Call(hMod, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n == 0 {
		return 0, nil, fmt.Errorf("GetModuleFileNameW failed")
	}
	path := syscall.UTF16ToString(buf[:n])

	f, err := pe.Open(path)
	if err != nil {
		return 0, nil, err
	}
	defer f.Close()

	exports, err := f.Exports()
	if err != nil {
		return 0, nil, err
	}

	out := make([]exportInfo, 0, len(exports))
	for _, e := range exports {
		if e.Name == "" {
			continue
		}
		out = append(out, exportInfo{Name: e.Name, RVA: e.VirtualAddress})
	}
	return hMod, out, nil
}

// modRange caches the load range of a module.
type modRange struct {
	Base uintptr
	Size uintptr
}

// lookupModuleRange returns the base and size of a loaded module. Uses
// VirtualQuery to walk the module's committed regions and find its extent.
func lookupModuleRange(modName string) modRange {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getModuleHandle := kernel32.NewProc("GetModuleHandleW")
	modPtr, err := syscall.UTF16PtrFromString(modName)
	if err != nil {
		return modRange{}
	}
	hMod, _, _ := getModuleHandle.Call(uintptr(unsafe.Pointer(modPtr)))
	if hMod == 0 {
		return modRange{}
	}
	return imageExtent(hMod)
}

// imageExtent walks VirtualQuery from a module base to find its total span.
func imageExtent(base uintptr) modRange {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	virtualQuery := kernel32.NewProc("VirtualQuery")

	type memBasicInfo struct {
		BaseAddress       uintptr
		AllocationBase    uintptr
		AllocationProtect uint32
		PartitionId       uint16
		_                 uint16
		RegionSize        uintptr
		State             uint32
		Protect           uint32
		Type              uint32
		_                 uint32
	}

	var end uintptr
	addr := base
	for {
		var mbi memBasicInfo
		ret, _, _ := virtualQuery.Call(
			addr,
			uintptr(unsafe.Pointer(&mbi)),
			unsafe.Sizeof(mbi),
		)
		if ret == 0 || mbi.RegionSize == 0 {
			break
		}
		// Stop when we leave the module (different allocation base).
		if mbi.AllocationBase != base && end != 0 {
			break
		}
		end = mbi.BaseAddress + mbi.RegionSize
		next := end
		if next <= addr {
			break
		}
		addr = next
	}
	if end == 0 {
		return modRange{}
	}
	return modRange{Base: base, Size: end - base}
}

// runtimeImageBase returns the runtime load address of the current executable.
func runtimeImageBase(selfPath string) uintptr {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getModuleHandle := kernel32.NewProc("GetModuleHandleW")
	base := filepathBase(selfPath)
	ptr, _ := syscall.UTF16PtrFromString(base)
	if ptr == nil {
		return 0
	}
	hMod, _, _ := getModuleHandle.Call(uintptr(unsafe.Pointer(ptr)))
	return hMod
}

// importDirectory extracts the import directory RVA + size from a PE file.
func importDirectory(f *pe.File) (uint32, uint32, error) {
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if len(oh.DataDirectory) > 1 {
			return oh.DataDirectory[1].VirtualAddress, oh.DataDirectory[1].Size, nil
		}
	case *pe.OptionalHeader64:
		if len(oh.DataDirectory) > 1 {
			return oh.DataDirectory[1].VirtualAddress, oh.DataDirectory[1].Size, nil
		}
	}
	return 0, 0, errors.New("no import directory")
}

// filepathBase is a minimal filepath.Base.
func filepathBase(p string) string {
	i := strings.LastIndexAny(p, `\/`)
	if i < 0 {
		return p
	}
	return p[i+1:]
}

// ---------------------------------------------------------------------------
// Summary / reporting
// ---------------------------------------------------------------------------

// Summary returns a compact one-line description of the hook map.
func (hm *HookMap) Summary() string {
	if hm == nil || len(hm.Hooks) == 0 {
		return "no hooks detected"
	}
	counts := map[HookType]int{}
	for _, h := range hm.Hooks {
		counts[h.Type]++
	}
	parts := []string{}
	for _, t := range []HookType{HookInline, HookIAT, HookEAT, HookRWX} {
		if c := counts[t]; c > 0 {
			parts = append(parts, fmt.Sprintf("%s=%d", t, c))
		}
	}
	return fmt.Sprintf("%d hooks (%s)", len(hm.Hooks), strings.Join(parts, ", "))
}

// CriticalCount returns how many hooks are rated SevCritical.
func (hm *HookMap) CriticalCount() int {
	n := 0
	for _, h := range hm.Hooks {
		if h.Severity == SevCritical {
			n++
		}
	}
	return n
}

// HookedModules returns the set of modules with at least one hook.
func (hm *HookMap) HookedModules() []string {
	seen := make(map[string]struct{})
	var out []string
	for _, h := range hm.Hooks {
		if _, ok := seen[h.Module]; ok {
			continue
		}
		seen[h.Module] = struct{}{}
		out = append(out, h.Module)
	}
	return out
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

// Scan runs inline, IAT, EAT, and RWX detection and merges the results.
func (ah *AntiHook) Scan() (*HookMap, error) {
	hm, err := ah.ScanInline()
	if err != nil {
		hm = &HookMap{ByModule: map[string][]Hook{}}
	}

	iatHooks, _ := ah.ScanIAT()
	hm.Hooks = append(hm.Hooks, iatHooks...)
	for _, h := range iatHooks {
		hm.ByModule[h.Module] = append(hm.ByModule[h.Module], h)
	}

	eatHooks, _ := ah.ScanEAT()
	hm.Hooks = append(hm.Hooks, eatHooks...)
	for _, h := range eatHooks {
		hm.ByModule[h.Module] = append(hm.ByModule[h.Module], h)
	}

	rwxPages, _ := ah.ScanRWX()
	hm.RWXPages = rwxPages
	for _, p := range rwxPages {
		hm.Hooks = append(hm.Hooks, Hook{
			Type:     HookRWX,
			Address:  p.Base,
			Severity: SevSuspicious,
			Detail:   fmt.Sprintf("RWX region %#x-%#x", p.Base, p.Base+p.Size),
		})
	}
	return hm, nil
}

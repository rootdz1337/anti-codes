package main

import (
	"crypto/sha256"
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
// Anti-Patch / Integrity Verification Module
//
// EDR/AV/sandbox products patch the in-memory image of running processes:
//   - Inline hooks: overwrite function prologues with JMP to their own code
//   - IAT hooks:  rewrite Import Address Table entries to point at proxies
//   - EAT hooks:  rewrite Export Address Table entries
//   - PatchGuard-style: patch syscall stubs, AMSI buffer, ETW write
//
// This module:
//   1. Snapshots pristine code pages from the on-disk PE at startup
//   2. Re-hashes those pages on demand and diffs against the snapshot
//   3. Scans critical ntdll/kernel32 exports for inline-hook signatures
//   4. Reports which functions were patched, where, and with what bytes
//
// All operations are read-only. Nothing here unhooks or restores code.
// ============================================================================

// PatchReport describes the outcome of one integrity check.
type PatchReport struct {
	Region      string        // e.g. "ntdll!NtCreateThreadEx"
	Address     uintptr       // runtime VA where the anomaly was found
	OnDisk      []byte        // original bytes from the PE file
	InMemory    []byte        // bytes currently in the running image
	Delta       int           // byte-offset of first divergence (or -1)
	Kind        PatchKind     // InlineHook, IATHook, EATHook, ModifiedBytes
	Severity    PatchSeverity // Informational / Suspicious / Critical
	Description string
}

// PatchKind classifies the detected modification.
type PatchKind string

const (
	KindInlineHook  PatchKind = "inline-hook"
	KindIATHook     PatchKind = "iat-hook"
	KindEATHook     PatchKind = "eat-hook"
	KindModified    PatchKind = "modified-bytes"
	KindUnreadable  PatchKind = "unreadable"
)

// PatchSeverity ranks how alarming a finding is.
type PatchSeverity string

const (
	SevInfo     PatchSeverity = "info"
	SevSuspicious PatchSeverity = "suspicious"
	SevCritical PatchSeverity = "critical"
)

// AntiPatch holds configuration and the pristine snapshot cache.
type AntiPatch struct {
	// CriticalFunctions are "module!export" pairs whose pristine bytes are
	// snapshotted and re-verified. These are the functions EDRs most
	// commonly hook to observe process, memory, and network activity.
	CriticalFunctions []string

	// PrologueLen is how many bytes from the function entry are compared.
	// 16 is enough to catch a JMP (5 bytes) + padding + a few instructions.
	PrologueLen int

	mu       sync.Mutex
	snapshot map[string][]byte // "module!export" -> pristine bytes
	modules  map[string]*peModule
}

// peModule caches a parsed on-disk PE and its mapped image bytes.
type peModule struct {
	path   string
	file   *pe.File
	raw    []byte
	image  []byte // file laid out at its preferred ImageBase
	base   uintptr
	size   uintptr
}

// DefaultAntiPatch returns a configuration covering the most-hooked exports.
func DefaultAntiPatch() *AntiPatch {
	return &AntiPatch{
		CriticalFunctions: []string{
			// Process / thread creation — the first thing EDRs hook
			"ntdll.dll!NtCreateThreadEx",
			"ntdll.dll!NtCreateUserProcess",
			"ntdll.dll!NtOpenProcess",
			"ntdll.dll!NtAllocateVirtualMemory",
			"ntdll.dll!NtProtectVirtualMemory",
			"ntdll.dll!NtWriteVirtualMemory",
			"ntdll.dll!NtMapViewOfSection",
			// Execution / injection
			"ntdll.dll!NtQueueApcThread",
			"ntdll.dll!NtSetContextThread",
			"ntdll.dll!NtResumeThread",
			"ntdll.dll!NtSuspendThread",
			// AMSI / ETW — classic bypass targets
			"amsi.dll!AmsiScanBuffer",
			"amsi.dll!AmsiScanString",
			"ntdll.dll!EtwEventWrite",
			"ntdll.dll!EtwEventWriteFull",
			// Loader
			"ntdll.dll!LdrLoadDll",
			"ntdll.dll!LdrGetProcedureAddress",
			"kernel32.dll!LoadLibraryW",
			"kernel32.dll!GetProcAddress",
			"kernel32.dll!VirtualAlloc",
			"kernel32.dll!VirtualProtect",
			// Networking
			"ws2_32.dll!connect",
			"ws2_32.dll!send",
			"ws2_32.dll!recv",
			"wininet.dll!InternetOpenW",
			"winhttp.dll!WinHttpOpen",
		},
		PrologueLen: 16,
		snapshot:    make(map[string][]byte),
		modules:     make(map[string]*peModule),
	}
}

// ---------------------------------------------------------------------------
// Snapshot — capture pristine bytes from the on-disk PE at startup
// ---------------------------------------------------------------------------

// Snapshot reads the on-disk PE for each referenced module, maps it in the
// file's preferred layout, and stores the first PrologueLen bytes of each
// critical export. Must be called once, early, before EDR hooks are
// (re)applied or before any patch we care about happens.
func (ap *AntiPatch) Snapshot() error {
	if runtime.GOOS != "windows" {
		return nil // PE-only
	}
	ap.mu.Lock()
	defer ap.mu.Unlock()

	// Load each unique module once.
	needed := make(map[string]struct{})
	for _, fn := range ap.CriticalFunctions {
		mod := strings.SplitN(fn, "!", 2)[0]
		needed[strings.ToLower(mod)] = struct{}{}
	}
	for mod := range needed {
		if _, ok := ap.modules[mod]; ok {
			continue
		}
		pm, err := loadPeModule(mod)
		if err != nil {
			// Module may not be loaded (e.g. amsi.dll absent on Server Core).
			continue
		}
		ap.modules[mod] = pm
	}

	// Resolve each export's on-disk RVA and copy pristine bytes.
	for _, fn := range ap.CriticalFunctions {
		parts := strings.SplitN(fn, "!", 2)
		if len(parts) != 2 {
			continue
		}
		modKey := strings.ToLower(parts[0])
		pm, ok := ap.modules[modKey]
		if !ok {
			continue
		}
		exp, err := findExport(pm, parts[1])
		if err != nil || exp == nil {
			continue
		}
		rva := exp.VirtualAddress
		bytes, err := readImageBytes(pm, rva, uint32(ap.PrologueLen))
		if err != nil || len(bytes) == 0 {
			continue
		}
		key := modKey + "!" + parts[1]
		ap.snapshot[key] = bytes
	}
	return nil
}

// loadPeModule parses a loaded module's on-disk PE and lays it out at its
// preferred ImageBase so RVAs can be read without a live process handle.
func loadPeModule(modName string) (*peModule, error) {
	// Locate the module on disk via the loader (GetModuleFileNameW).
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getModuleHandle := kernel32.NewProc("GetModuleHandleW")
	getModuleFileName := kernel32.NewProc("GetModuleFileNameW")

	modPtr, err := syscall.UTF16PtrFromString(modName)
	if err != nil {
		return nil, err
	}
	hMod, _, _ := getModuleHandle.Call(uintptr(unsafe.Pointer(modPtr)))
	if hMod == 0 {
		// Not loaded in this process — try a default system path.
		path := `C:\Windows\System32\` + modName
		return parsePeFile(path)
	}

	var buf [syscall.MAX_PATH]uint16
	n, _, _ := getModuleFileName.Call(hMod, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if n == 0 {
		return nil, fmt.Errorf("GetModuleFileNameW failed for %s", modName)
	}
	path := syscall.UTF16ToString(buf[:n])
	return parsePeFile(path)
}

// parsePeFile reads a PE and materializes its image layout.
func parsePeFile(path string) (*peModule, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	f, err := pe.NewFile(strings.NewReader(string(raw)))
	if err != nil {
		return nil, err
	}
	// Determine image size from the optional header.
	var imageSize uintptr
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		imageSize = uintptr(oh.SizeOfImage)
	case *pe.OptionalHeader64:
		imageSize = uintptr(oh.SizeOfImage)
	default:
		return nil, errors.New("unknown optional header")
	}
	image := make([]byte, imageSize)
	for _, sec := range f.Sections {
		if sec.Offset == 0 || sec.Size == 0 {
			continue
		}
		start := int(sec.VirtualAddress)
		end := start + int(sec.Size)
		if end > len(image) {
			end = len(image)
		}
		copy(image[start:end], raw[sec.Offset:minInt(len(raw), int(sec.Offset)+int(sec.Size))])
	}
	return &peModule{path: path, file: f, raw: raw, image: image}, nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// findExport resolves an export name to its IMAGE_EXPORT_DIRECTORY entry.
func findExport(pm *peModule, name string) (*pe.Symbol, error) {
	if pm.file == nil {
		return nil, errors.New("nil pe file")
	}
	exports, err := pm.file.Exports()
	if err != nil {
		return nil, err
	}
	for _, e := range exports {
		if e.Name == name {
			return e, nil
		}
	}
	return nil, fmt.Errorf("export %q not found", name)
}

// readImageBytes copies n bytes from the materialized image at rva.
func readImageBytes(pm *peModule, rva uint32, n uint32) ([]byte, error) {
	start := int(rva)
	end := start + int(n)
	if start < 0 || end > len(pm.image) {
		return nil, fmt.Errorf("rva %#x out of bounds", rva)
	}
	out := make([]byte, n)
	copy(out, pm.image[start:end])
	return out, nil
}

// ---------------------------------------------------------------------------
// Live verification — compare running image bytes against the snapshot
// ---------------------------------------------------------------------------

// Verify re-reads each critical export from the live process and diffs
// against the snapshot taken at startup. Any divergence is a patch.
func (ap *AntiPatch) Verify() ([]PatchReport, error) {
	if runtime.GOOS != "windows" {
		return nil, nil
	}
	ap.mu.Lock()
	defer ap.mu.Unlock()

	var reports []PatchReport
	for key, pristine := range ap.snapshot {
		parts := strings.SplitN(key, "!", 2)
		if len(parts) != 2 {
			continue
		}
		modName := parts[0]
		expName := parts[1]

		liveAddr := resolveLiveExport(modName, expName)
		if liveAddr == 0 {
			continue // module unloaded or export missing
		}
		live := readLiveBytes(liveAddr, len(pristine))
		if live == nil {
			reports = append(reports, PatchReport{
				Region:      key,
				Kind:        KindUnreadable,
				Severity:    SevSuspicious,
				Description: "could not read live bytes (page unreadable or protected)",
			})
			continue
		}
		delta := firstDiff(pristine, live)
		if delta < 0 {
			continue // identical
		}

		kind, sev := classifyPatch(live, delta)
		reports = append(reports, PatchReport{
			Region:      key,
			Address:     liveAddr + uintptr(delta),
			OnDisk:      pristine,
			InMemory:    live,
			Delta:       delta,
			Kind:        kind,
			Severity:    sev,
			Description: describePatch(live, delta),
		})
	}
	return reports, nil
}

// resolveLiveExport returns the runtime VA of an export in the current
// process, or 0 if the module/export isn't loaded.
func resolveLiveExport(modName, expName string) uintptr {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getModuleHandle := kernel32.NewProc("GetModuleHandleW")
	getProcAddress := kernel32.NewProc("GetProcAddress")

	modPtr, err := syscall.UTF16PtrFromString(modName)
	if err != nil {
		return 0
	}
	hMod, _, _ := getModuleHandle.Call(uintptr(unsafe.Pointer(modPtr)))
	if hMod == 0 {
		return 0
	}
	namePtr, err := syscall.BytePtrFromString(expName)
	if err != nil {
		return 0
	}
	addr, _, _ := getProcAddress.Call(hMod, uintptr(unsafe.Pointer(namePtr)))
	return addr
}

// readLiveBytes copies n bytes from the running process using ReadProcessMemory
// on the current process handle — safe even for read-only or RX pages.
func readLiveBytes(addr uintptr, n int) []byte {
	if addr == 0 || n <= 0 {
		return nil
	}
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getCurrentProcess := kernel32.NewProc("GetCurrentProcess")
	readProcessMemory := kernel32.NewProc("ReadProcessMemory")

	hProc, _, _ := getCurrentProcess.Call()
	buf := make([]byte, n)
	var read uintptr
	ok, _, _ := readProcessMemory.Call(
		hProc,
		addr,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(n),
		uintptr(unsafe.Pointer(&read)),
	)
	if ok == 0 || read == 0 {
		return nil
	}
	return buf[:read]
}

// firstDiff returns the index of the first differing byte, or -1.
func firstDiff(a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	if len(a) != len(b) {
		return n
	}
	return -1
}

// classifyPatch inspects the modified prologue to guess the patch type.
// Known hook signatures:
//   E9 xx xx xx xx           JMP rel32 (classic detour)
//   FF 25 xx xx xx xx        JMP [rip+off] (trampoline)
//   48 FF 25 xx xx xx xx     JMP qword [rip+off] (x64 IAT-style)
//   68 xx xx xx xx C3        PUSH addr; RET (32-bit thunk)
//   EB xx                    JMP rel8
func classifyPatch(live []byte, delta int) (PatchKind, PatchSeverity) {
	if delta < 0 || delta+1 >= len(live) {
		return KindModified, SevSuspicious
	}
	b := live[delta:]
	switch {
	case b[0] == 0xE9:
		return KindInlineHook, SevCritical
	case len(b) >= 6 && b[0] == 0xFF && b[1] == 0x25:
		return KindInlineHook, SevCritical
	case len(b) >= 6 && b[0] == 0x48 && b[1] == 0xFF && b[2] == 0x25:
		return KindInlineHook, SevCritical
	case len(b) >= 5 && b[0] == 0x68 && b[4] == 0xC3:
		return KindInlineHook, SevCritical
	case b[0] == 0xEB:
		return KindInlineHook, SevSuspicious
	case len(b) >= 2 && b[0] == 0x33 && b[1] == 0xC0 && len(b) >= 3 && b[2] == 0xC3:
		// xor eax,eax; ret — a classic "make this function return 0" patch
		// (AMSI bypass pattern: AmsiScanBuffer -> 0 = CLEAN)
		return KindModified, SevCritical
	default:
		return KindModified, SevSuspicious
	}
}

// describePatch gives a short human-readable summary of what changed.
func describePatch(live []byte, delta int) string {
	if delta < 0 || delta+8 > len(live) {
		return "modified bytes (truncated)"
	}
	b := live[delta : delta+8]
	switch {
	case b[0] == 0xE9:
		rel := int32(binary.LittleEndian.Uint32(b[1:5]))
		return fmt.Sprintf("JMP rel32 -> +0x%x (detour)", int32(delta)+5+rel)
	case len(b) >= 6 && b[0] == 0xFF && b[1] == 0x25:
		return "JMP [rip+off] (trampoline)"
	case len(b) >= 6 && b[0] == 0x48 && b[1] == 0xFF && b[2] == 0x25:
		return "JMP qword [rip+off] (x64 trampoline)"
	case b[0] == 0x68 && b[4] == 0xC3:
		addr := binary.LittleEndian.Uint32(b[1:5])
		return fmt.Sprintf("PUSH %#x; RET (thunk)", addr)
	case b[0] == 0xEB:
		return fmt.Sprintf("JMP rel8 -> %+d", int8(b[1]))
	case b[0] == 0x33 && b[1] == 0xC0 && b[2] == 0xC3:
		return "xor eax,eax; ret (force return 0)"
	default:
		return fmt.Sprintf("modified prologue: % x", b[:minInt(8, len(b))])
	}
}

// ---------------------------------------------------------------------------
// IAT scan — detect hooks on the Import Address Table
// ---------------------------------------------------------------------------

// ScanIAT walks the IAT of the running executable and verifies each entry
// still resolves to the export it claims. Entries pointing outside the
// owning module's range are IAT hooks.
func (ap *AntiPatch) ScanIAT() ([]PatchReport, error) {
	if runtime.GOOS != "windows" {
		return nil, nil
	}
	selfPath, err := os.Executable()
	if err != nil {
		return nil, err
	}
	pm, err := parsePeFile(selfPath)
	if err != nil {
		return nil, err
	}
	// Determine the runtime base of our own image.
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getModuleHandle := kernel32.NewProc("GetModuleHandleW")
	namePtr, _ := syscall.UTF16PtrFromString(strings.ToLower(filepathBase(selfPath)))
	if namePtr == nil {
		namePtr, _ = syscall.UTF16PtrFromString(filepathBase(selfPath))
	}
	hMod, _, _ := getModuleHandle.Call(uintptr(unsafe.Pointer(namePtr)))
	if hMod == 0 {
		// Fall back to pe.ImageBase if GetModuleHandle fails.
		if oh, ok := pm.file.OptionalHeader.(*pe.OptionalHeader64); ok {
			hMod = uintptr(oh.ImageBase)
		}
	}

	var reports []PatchReport
	// Walk import descriptors.
	imports, err := pm.file.ImportedSymbols()
	if err != nil {
		return nil, err
	}
	// Build a set of "dll!func" -> expected module base.
	for _, imp := range imports {
		// imp is "dll:func" in debug/pe; split defensively.
		parts := strings.SplitN(imp, ":", 2)
		if len(parts) != 2 {
			continue
		}
		dll := strings.ToLower(parts[0])
		fn := parts[1]
		ownerBase := resolveLiveExport(dll, fn)
		if ownerBase == 0 {
			continue
		}
		// Find the IAT slot for this import in our own image.
		slot := findIATSlot(pm, hMod, dll, fn)
		if slot == 0 {
			continue
		}
		current := *(*uintptr)(unsafe.Pointer(slot))
		if current == 0 {
			continue
		}
		// Is the current target inside the owning module?
		modBase, modSize := moduleRange(dll)
		if modBase == 0 {
			continue
		}
		if current < modBase || current >= modBase+modSize {
			reports = append(reports, PatchReport{
				Region:      fmt.Sprintf("IAT:%s!%s", dll, fn),
				Address:     slot,
				Kind:        KindIATHook,
				Severity:    SevCritical,
				Description: fmt.Sprintf("IAT entry points to %#x outside %s [%#x-%#x]", current, dll, modBase, modBase+modSize),
			})
		}
	}
	return reports, nil
}

// findIATSlot locates the runtime VA of the IAT slot for dll!func in our
// own image. Requires walking the import directory manually.
func findIATSlot(pm *peModule, imageBase uintptr, dll, fn string) uintptr {
	if pm == nil || pm.file == nil {
		return 0
	}
	// Use ImportedSymbols + the IAT RVA exposed via the import directory.
	// debug/pe doesn't expose the raw IAT RVA, so we parse it ourselves.
	iatRVA, iatSize, err := importDirectoryRVA(pm)
	if err != nil || iatRVA == 0 {
		return 0
	}
	// Enumerate imports in order; the IAT is a parallel array.
	imports, _ := pm.file.ImportedSymbols()
	idx := 0
	for _, imp := range imports {
		parts := strings.SplitN(imp, ":", 2)
		if len(parts) != 2 {
			idx++
			continue
		}
		if strings.EqualFold(parts[0], dll) && parts[1] == fn {
			// Entry size is pointer-width.
			ptrSize := uintptr(8)
			if pm.file.Machine == pe.IMAGE_FILE_MACHINE_I386 {
				ptrSize = 4
			}
			if uintptr(idx)*ptrSize >= uintptr(iatSize) {
				return 0
			}
			return imageBase + uintptr(iatRVA) + uintptr(idx)*ptrSize
		}
		idx++
	}
	return 0
}

// importDirectoryRVA extracts the Import Directory RVA and size from the
// optional header's data directory.
func importDirectoryRVA(pm *peModule) (uint32, uint32, error) {
	switch oh := pm.file.OptionalHeader.(type) {
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

// moduleRange returns the load base and size of a loaded module.
func moduleRange(modName string) (uintptr, uintptr) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getModuleHandle := kernel32.NewProc("GetModuleHandleW")
	modPtr, err := syscall.UTF16PtrFromString(modName)
	if err != nil {
		return 0, 0
	}
	hMod, _, _ := getModuleHandle.Call(uintptr(unsafe.Pointer(modPtr)))
	if hMod == 0 {
		return 0, 0
	}
	// Use VirtualQuery to find the module's allocation range. For simplicity,
	// assume a 16 MiB ceiling — good enough for ntdll/kernel32/ws2_32.
	const ceiling = 16 << 20
	return hMod, ceiling
}

// filepathBase is a minimal filepath.Base to avoid importing path/filepath
// just for one call.
func filepathBase(p string) string {
	i := strings.LastIndexAny(p, `\/`)
	if i < 0 {
		return p
	}
	return p[i+1:]
}

// ---------------------------------------------------------------------------
// Summary helpers
// ---------------------------------------------------------------------------

// Summarize condenses a report list into a one-line status and a critical count.
func (ap *AntiPatch) Summarize(reports []PatchReport) (status string, critical int) {
	if len(reports) == 0 {
		return "clean", 0
	}
	for _, r := range reports {
		if r.Severity == SevCritical {
			critical++
		}
	}
	return fmt.Sprintf("%d anomalies (%d critical)", len(reports), critical), critical
}

// HashSelf returns the SHA-256 of the on-disk executable, useful as a
// baseline for external integrity checks.
func (ap *AntiPatch) HashSelf() ([]byte, error) {
	p, err := os.Executable()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	return sum[:], nil
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

// Audit runs Snapshot (if not already done), then Verify and ScanIAT, and
// returns the combined findings.
func (ap *AntiPatch) Audit() ([]PatchReport, error) {
	ap.mu.Lock()
	haveSnapshot := len(ap.snapshot) > 0
	ap.mu.Unlock()
	if !haveSnapshot {
		if err := ap.Snapshot(); err != nil {
			return nil, fmt.Errorf("snapshot: %w", err)
		}
	}
	var all []PatchReport
	if reps, err := ap.Verify(); err == nil {
		all = append(all, reps...)
	}
	if reps, err := ap.ScanIAT(); err == nil {
		all = append(all, reps...)
	}
	return all, nil
}

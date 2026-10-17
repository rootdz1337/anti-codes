package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// ============================================================================
// Anti-POMP (Proof of Monitoring Placement) Module
//
// POMP (pompom.exe) is Microsoft's EDR validation tool. It:
//   1. Drops known-bad artifacts (EICAR file, registry run key, scheduled task,
//      WMI subscription, named pipe, COM hijack, LSASS handle, etc.)
//   2. Waits for the EDR to emit detection telemetry for each
//   3. Reports per-test PASS/FAIL — a FAIL means the EDR was blind to it
//
// This module:
//   - Detects POMP binaries, config, and logs on disk
//   - Enumerates POMP's well-known test artifacts that may linger after a run
//   - Classifies host "certification state" based on which artifacts are present
//   - Fingerprints the EDR sensor via POMP's own output files
//
// All operations are read-only.
// ============================================================================

// POMPSignal enumerates what an artifact tells us about the host.
type POMPSignal string

const (
	SignalBinaryPresent  POMPSignal = "binary-present"     // pompom.exe on disk
	SignalLogPresent     POMPSignal = "log-present"        // POMP result log
	SignalConfigPresent  POMPSignal = "config-present"     // POMP config JSON
	SignalArtifactLinger POMPSignal = "artifact-lingering" // test artifact left behind
	SignalTaskPresent    POMPSignal = "scheduled-task"     // POMP task registered
	SignalPipePresent    POMPSignal = "named-pipe"         // POMP test pipe
	SignalRegKeyPresent  POMPSignal = "reg-run-key"        // POMP test run key
	SignalWMISubPresent  POMPSignal = "wmi-subscription"   // POMP test WMI sub
)

// POMPFinding is one piece of evidence.
type POMPFinding struct {
	Signal   POMPSignal
	Path     string // file path, registry path, pipe name, task path
	Detail   string
	Severity PatchSeverity
}

// CertificationState summarizes what the POMP artifacts imply about the host.
type CertificationState string

const (
	CertUnknown      CertificationState = "unknown"       // no evidence either way
	CertRecentlyRun  CertificationState = "recently-run"  // POMP ran very recently
	CertHistorically CertificationState = "historically"  // POMP has run in the past
	CertEDRBlind     CertificationState = "edr-blind"     // POMP logged FAILs
	CertEDRValidated CertificationState = "edr-validated" // POMP logged all PASS
)

// POMPReport is the module's output.
type POMPReport struct {
	State    CertificationState
	Findings []POMPFinding
	EDRName  string // best-effort; extracted from POMP log
	LastRun  time.Time
	Notes    string
}

// AntiPOMP holds configuration.
type AntiPOMP struct {
	// SearchPaths are directories where POMP binaries and artifacts are
	// typically dropped.
	SearchPaths []string

	// RunKeyPaths are the registry run-key locations POMP writes to.
	RunKeyPaths []string

	// PipeNames are the named pipes POMP creates during testing.
	PipeNames []string

	// TaskPaths are the scheduled task paths POMP registers.
	TaskPaths []string

	// WMISubscriptionNames are the WMI event subscription names POMP uses.
	WMISubscriptionNames []string

	// RecentThreshold is how recent a POMP log must be to count as
	// "recently-run". Defender's default re-validation cadence is weekly.
	RecentThreshold time.Duration

	mu sync.Mutex
}

// DefaultAntiPOMP returns a configuration matching POMP's public test schema.
func DefaultAntiPOMP() *AntiPOMP {
	return &AntiPOMP{
		SearchPaths: []string{
			// Standard POMP install locations
			`C:\Program Files\POMP\`,
			`C:\Program Files (x86)\POMP\`,
			`C:\ProgramData\POMP\`,
			`C:\ProgramData\Microsoft\POMP\`,
			`C:\POMP\`,
			`C:\Temp\POMP\`,
			// User-writable drop zones (POMP commonly run from these)
			`C:\Users\Public\`,
			filepath.Join(os.Getenv("TEMP")),
			filepath.Join(os.Getenv("USERPROFILE"), "Downloads"),
			filepath.Join(os.Getenv("USERPROFILE"), "Desktop"),
		},
		RunKeyPaths: []string{
			`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
			`HKLM\Software\Microsoft\Windows\CurrentVersion\Run`,
			`HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`,
			`HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`,
		},
		PipeNames: []string{
			// Documented POMP test pipe (named to be recognizable in ETW)
			`\\.\pipe\POMP-Test-Pipe`,
			`\\.\pipe\pompom`,
			`\\.\pipe\EDR-Validation`,
		},
		TaskPaths: []string{
			`\Microsoft\Windows\POMP\`,
			`\POMP\`,
			`\POMPTest\`,
		},
		WMISubscriptionNames: []string{
			"POMP_Test_Sub",
			"POMP_Validation",
			"POMP-Test",
		},
		RecentThreshold: 7 * 24 * time.Hour,
	}
}

// ---------------------------------------------------------------------------
// Filesystem detection — POMP binaries, configs, logs, artifact files
// ---------------------------------------------------------------------------

// scanFilesystem walks each SearchPath for POMP-related files. It returns
// findings for:
//   - pompom.exe / pomp.exe binaries
//   - *.json config files
//   - *.log / *.txt result logs
//   - EICAR / known test artifact files
func (ap *AntiPOMP) scanFilesystem() []POMPFinding {
	if runtime.GOOS != "windows" {
		return nil
	}
	var findings []POMPFinding
	seen := make(map[string]struct{})

	// Signature files we look for.
	binaryNames := map[string]bool{
		"pompom.exe":  true,
		"pomp.exe":    true,
		"pompom64.exe": true,
	}
	logExts := map[string]bool{".log": true, ".txt": true, ".json": true}

	// Known POMP test artifacts.
	artifactSignatures := map[string]string{
		"eicar.com":          "EICAR test file",
		"eicar.txt":          "EICAR test string",
		"pompom_eicar.com":   "POMP EICAR artifact",
		"pompom_eicar.txt":   "POMP EICAR artifact",
		"pomp_artifact.bin":  "POMP binary artifact",
		"pompom_artifact":    "POMP binary artifact",
	}

	for _, dir := range ap.SearchPaths {
		if dir == "" {
			continue
		}
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}
		_ = filepath.Walk(dir, func(path string, fi os.FileInfo, err error) error {
			if err != nil || fi == nil || fi.IsDir() {
				return nil
			}
			name := strings.ToLower(fi.Name())
			ext := strings.ToLower(filepath.Ext(name))

			// POMP binaries
			if binaryNames[name] {
				findings = append(findings, POMPFinding{
					Signal:   SignalBinaryPresent,
					Path:     path,
					Detail:   fmt.Sprintf("POMP binary (%s, %d bytes, mod %s)",
						name, fi.Size(), fi.ModTime().Format(time.RFC3339)),
					Severity: SevCritical,
				})
				return nil
			}

			// POMP logs / config (heuristic: "pomp" in name AND log-ish ext)
			if strings.Contains(name, "pomp") && logExts[ext] {
				sev := SevSuspicious
				if ext == ".log" {
					sev = SevCritical // completed run
				}
				findings = append(findings, POMPFinding{
					Signal:   SignalLogPresent,
					Path:     path,
					Detail:   fmt.Sprintf("POMP log/config (%s, mod %s)",
						name, fi.ModTime().Format(time.RFC3339)),
					Severity: sev,
				})
				return nil
			}

			// Known POMP test artifacts
			if detail, ok := artifactSignatures[name]; ok {
				key := path
				if _, dup := seen[key]; dup {
					return nil
				}
				seen[key] = struct{}{}
				findings = append(findings, POMPFinding{
					Signal:   SignalArtifactLinger,
					Path:     path,
					Detail:   fmt.Sprintf("%s (lingering, mod %s)", detail, fi.ModTime().Format(time.RFC3339)),
					Severity: SevSuspicious,
				})
			}
			return nil
		})
	}
	return findings
}

// ---------------------------------------------------------------------------
// Registry detection — POMP test run keys
// ---------------------------------------------------------------------------

// scanRegistry looks for POMP test run-key values. POMP writes a value named
// "POMP*" or pointing at the POMP binary; the value is usually removed by
// the tool but can linger if the run was interrupted or if the EDR
// quarantined the artifact before cleanup.
func (ap *AntiPOMP) scanRegistry() []POMPFinding {
	if runtime.GOOS != "windows" {
		return nil
	}
	var findings []POMPFinding
	advapi32 := syscall.NewLazyDLL("advapi32.dll")
	regOpenKeyEx := advapi32.NewProc("RegOpenKeyExW")
	regEnumValue := advapi32.NewProc("RegEnumValueW")
	regCloseKey := advapi32.NewProc("RegCloseKey")

	const (
		hklm       = 0x80000002
		hkcu       = 0x80000001
		keyRead    = 0x20019
	)

	for _, keyPath := range ap.RunKeyPaths {
		var root uintptr
		sub := keyPath
		switch {
		case strings.HasPrefix(strings.ToUpper(keyPath), "HKLM\\"):
			root = hklm
			sub = keyPath[5:]
		case strings.HasPrefix(strings.ToUpper(keyPath), "HKCU\\"):
			root = hkcu
			sub = keyPath[5:]
		default:
			continue
		}

		var hKey syscall.Handle
		subPtr, _ := syscall.UTF16PtrFromString(sub)
		ret, _, _ := regOpenKeyEx.Call(
			root,
			uintptr(unsafe.Pointer(subPtr)),
			0,
			keyRead,
			uintptr(unsafe.Pointer(&hKey)),
		)
		if ret != 0 {
			continue
		}

		var idx uint32
		for {
			var nameBuf [512]uint16
			var dataBuf [2048]uint16
			nameLen := uint32(len(nameBuf))
			dataLen := uint32(len(dataBuf) * 2)
			var valType uint32

			ret, _, _ := regEnumValue.Call(
				uintptr(hKey),
				uintptr(idx),
				uintptr(unsafe.Pointer(&nameBuf[0])),
				uintptr(unsafe.Pointer(&nameLen)),
				0,
				uintptr(unsafe.Pointer(&valType)),
				uintptr(unsafe.Pointer(&dataBuf[0])),
				uintptr(unsafe.Pointer(&dataLen)),
			)
			if ret == 259 { // ERROR_NO_MORE_ITEMS
				break
			}
			if ret != 0 {
				break
			}
			name := strings.ToLower(syscall.UTF16ToString(nameBuf[:nameLen]))
			val := strings.ToLower(syscall.UTF16ToString(dataBuf[:dataLen/2]))
			if strings.Contains(name, "pomp") || strings.Contains(val, "pomp") {
				findings = append(findings, POMPFinding{
					Signal:   SignalRegKeyPresent,
					Path:     keyPath + "\\" + name,
					Detail:   fmt.Sprintf("value=%q, data=%q", name, val),
					Severity: SevCritical,
				})
			}
			idx++
			if idx > 4096 {
				break
			}
		}
		regCloseKey.Call(uintptr(hKey))
	}
	return findings
}

// ---------------------------------------------------------------------------
// Named pipe detection — POMP test pipe
// ---------------------------------------------------------------------------

// scanNamedPipes checks whether any POMP test pipes currently exist. Uses
// CreateFileW against \\.\pipe\<name> with zero-access intent — opening a
// pipe in this mode does not disturb the server.
func (ap *AntiPOMP) scanNamedPipes() []POMPFinding {
	if runtime.GOOS != "windows" {
		return nil
	}
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	createFile := kernel32.NewProc("CreateFileW")
	closeHandle := kernel32.NewProc("CloseHandle")

	const (
		openExisting = 3
		fileFlagNone = 0
	)

	var findings []POMPFinding
	for _, pipe := range ap.PipeNames {
		ptr, _ := syscall.UTF16PtrFromString(pipe)
		h, _, _ := createFile.Call(
			uintptr(unsafe.Pointer(ptr)),
			0, // no access
			0, // no share
			0,
			openExisting,
			fileFlagNone,
			0,
		)
		// INVALID_HANDLE_VALUE = ^uintptr(0)
		if h != 0 && h != ^uintptr(0) {
			closeHandle.Call(h)
			findings = append(findings, POMPFinding{
				Signal:   SignalPipePresent,
				Path:     pipe,
				Detail:   "POMP test pipe currently listening",
				Severity: SevCritical,
			})
		}
	}
	return findings
}

// ---------------------------------------------------------------------------
// Scheduled task detection — POMP validation task
// ---------------------------------------------------------------------------

// scanScheduledTasks looks for POMP test scheduled tasks by walking the
// Tasks directory on disk (registry TaskCache also works, but disk walk is
// simpler and matches the same artifacts Sysinternals autoruns shows).
func (ap *AntiPOMP) scanScheduledTasks() []POMPFinding {
	if runtime.GOOS != "windows" {
		return nil
	}
	taskDir := `C:\Windows\System32\Tasks`
	if _, err := os.Stat(taskDir); err != nil {
		return nil
	}
	var findings []POMPFinding
	_ = filepath.Walk(taskDir, func(path string, fi os.FileInfo, err error) error {
		if err != nil || fi == nil || fi.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(taskDir, path)
		relLower := strings.ToLower(rel)
		for _, marker := range ap.TaskPaths {
			marker = strings.ToLower(strings.Trim(marker, `\`))
			if marker != "" && strings.Contains(relLower, marker) {
				findings = append(findings, POMPFinding{
					Signal:   SignalTaskPresent,
					Path:     path,
					Detail:   fmt.Sprintf("POMP scheduled task file (rel %s, mod %s)",
						rel, fi.ModTime().Format(time.RFC3339)),
					Severity: SevCritical,
				})
				break
			}
		}
		return nil
	})
	return findings
}

// ---------------------------------------------------------------------------
// POMP log parsing — extract verdicts and EDR name
// ---------------------------------------------------------------------------

// parsePOMPLog reads a POMP result log and extracts:
//   - per-test PASS/FAIL
//   - EDR product name (POMP logs it in the header)
//
// Supports the two common formats: plain text (pompom.txt) and JSON
// (pompom.json). Malformed input is silently ignored — this is observational.
func parsePOMPLog(path string) (pass, fail int, edrName string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, ""
	}
	text := string(data)

	// Extract EDR name from common header lines.
	for _, line := range strings.Split(text, "\n") {
		ll := strings.ToLower(line)
		if strings.Contains(ll, "product name") || strings.Contains(ll, "edr name") ||
			strings.Contains(ll, "antivirus") {
			if i := strings.IndexAny(line, ":="); i >= 0 {
				edrName = strings.TrimSpace(line[i+1:])
			}
		}
	}

	// Count PASS / FAIL tokens (case-insensitive, whole-word).
	words := strings.FieldsFunc(strings.ToLower(text), func(r rune) bool {
		return !(r >= 'a' && r <= 'z')
	})
	for _, w := range words {
		switch w {
		case "pass", "passed", "passeddetection":
			pass++
		case "fail", "failed", "faileddetection", "missed":
			fail++
		}
	}
	return pass, fail, edrName
}

// ---------------------------------------------------------------------------
// Or
// orchestration
// ---------------------------------------------------------------------------

// Scan runs the full POMP artifact pipeline and returns a report.
func (ap *AntiPOMP) Scan() *POMPReport {
	ap.mu.Lock()
	defer ap.mu.Unlock()

	rep := &POMPReport{
		State: CertUnknown,
	}

	// Collect findings from each detector.
	rep.Findings = append(rep.Findings, ap.scanFilesystem()...)
	rep.Findings = append(rep.Findings, ap.scanRegistry()...)
	rep.Findings = append(rep.Findings, ap.scanNamedPipes()...)
	rep.Findings = append(rep.Findings, ap.scanScheduledTasks()...)

	// Parse the freshest POMP log for verdicts and EDR name.
	var freshest time.Time
	var freshestPath string
	for _, f := range rep.Findings {
		if f.Signal != SignalLogPresent {
			continue
		}
		info, err := os.Stat(f.Path)
		if err != nil {
			continue
		}
		if info.ModTime().After(freshest) {
			freshest = info.ModTime()
			freshestPath = f.Path
		}
	}
	if freshestPath != "" {
		pass, fail, name := parsePOMPLog(freshestPath)
		rep.EDRName = name
		rep.LastRun = freshest
		if fail > 0 {
			rep.State = CertEDRBlind
			rep.Notes = fmt.Sprintf("%d PASS / %d FAIL — EDR missed telemetry", pass, fail)
		} else if pass > 0 {
			rep.State = CertEDRValidated
			rep.Notes = fmt.Sprintf("%d PASS / 0 FAIL — EDR validated", pass)
		}
	}

	// If no log, fall back to "recently-run" based on file mtimes.
	if rep.State == CertUnknown {
		for _, f := range rep.Findings {
			info, err := os.Stat(f.Path)
			if err != nil {
				continue
			}
			age := time.Since(info.ModTime())
			if age < ap.RecentThreshold {
				rep.State = CertRecentlyRun
				if rep.LastRun.IsZero() || info.ModTime().After(rep.LastRun) {
					rep.LastRun = info.ModTime()
				}
			} else {
				rep.State = CertHistorically
			}
		}
	}

	return rep
}

// ---------------------------------------------------------------------------
// Helpers for correlating with other anti-* modules
// ---------------------------------------------------------------------------

// EDRConfidence returns a 0–100 score combining POMP evidence. Higher means
// more certain the host has a live, *validated* EDR sensor.
func (ap *AntiPOMP) EDRConfidence(rep *POMPReport) int {
	if rep == nil {
		return 0
	}
	score := 0
	switch rep.State {
	case CertEDRValidated:
		score = 90
	case CertEDRBlind:
		score = 70 // EDR is present but misconfigured — still a sensor
	case CertRecentlyRun:
		score = 60
	case CertHistorically:
		score = 30
	}
	// Each additional signal adds a bit.
	for _, f := range rep.Findings {
		switch f.Severity {
		case SevCritical:
			score += 3
		case SevSuspicious:
			score += 1
		}
	}
	if score > 100 {
		score = 100
	}
	return score
}

// CrossReference joins POMP findings with the hook map from antihook.go and
// patch reports from antipatch.go to produce a composite verdict.
//
// The returned string is intentionally short — meant for operator logs,
// not automated decisions.
func (ap *AntiPOMP) CrossReference(pomp *POMPReport, hooks *HookMap, patches []PatchReport) string {
	var parts []string

	if pomp != nil && pomp.State != CertUnknown {
		parts = append(parts, fmt.Sprintf("pomp=%s", pomp.State))
	}
	if hooks != nil {
		if n := hooks.CriticalCount(); n > 0 {
			parts = append(parts, fmt.Sprintf("hooks=%d", n))
		}
	}
	if patches != nil {
		crit := 0
		for _, p := range patches {
			if p.Severity == SevCritical {
				crit++
			}
		}
		if crit > 0 {
			parts = append(parts, fmt.Sprintf("patches=%d", crit))
		}
	}
	if len(parts) == 0 {
		return "no EDR evidence"
	}
	return strings.Join(parts, " ")
}

// ErrPOMPNotInstalled is returned when no POMP artifacts are found at all.
var ErrPOMPNotInstalled = errors.New("no POMP artifacts found")

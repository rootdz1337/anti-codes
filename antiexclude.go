package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"unsafe"
)

// ============================================================================
// Anti-Exclusion Module
//
// AV/EDR products (Defender, CrowdStrike, SentinelOne, Carbon Black, etc.)
// maintain *exclusion lists* — paths, processes, extensions, and IPs that
// are skipped during scanning. An attacker who can read these lists learns:
//   - Which directories are safe to drop payloads into
//   - Which process names are ignored
//   - Which extensions bypass on-access scanning
//
// This module:
//   1. Enumerates exclusions from the registry and product configs
//   2. Detects whether the current process/path is already excluded
//   3. Flags suspicious exclusions (attacker-planted or admin-loosened)
//   4. Optionally recommends safe drop paths derived from the list
//
// All operations are read-only. Nothing here writes to AV config.
// ============================================================================

// ErrNoExclusions indicates the exclusion registry keys were empty or
// unreadable — common on locked-down hosts and hardened EDR deployments.
var ErrNoExclusions = errors.New("no exclusions found or access denied")

// ExclusionEntry describes one entry in an AV exclusion list.
type ExclusionEntry struct {
	Kind   ExclusionKind // Path, Process, Extension, IP
	Value  string        // The excluded value, normalized
	Source string        // Registry key or config file it came from
}

// ExclusionKind classifies the exclusion type.
type ExclusionKind string

const (
	ExclPath      ExclusionKind = "path"
	ExclProcess   ExclusionKind = "process"
	ExclExtension ExclusionKind = "extension"
	ExclIP        ExclusionKind = "ip"
)

// AntiExclude enumerates and reasons about AV exclusions.
type AntiExclude struct {
	// DefenderKeys are the registry paths where Defender stores exclusions.
	// These are per-machine and per-user; both are checked.
	DefenderKeys []string

	// ProductPaths lists config files/dirs for third-party EDRs that store
	// exclusions on disk (best-effort; formats vary by vendor).
	ProductPaths []string

	// MaxEntries caps enumeration to avoid pathological registry sizes.
	MaxEntries int
}

// DefaultAntiExclude returns a configuration covering Defender plus the
// most common third-party EDRs encountered in enterprise environments.
func DefaultAntiExclude() *AntiExclude {
	return &AntiExclude{
		DefenderKeys: []string{
			// Machine-wide exclusions (admin-set)
			`SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths`,
			`SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes`,
			`SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions`,
			`SOFTWARE\Microsoft\Windows Defender\Exclusions\IpAddresses`,
			// Policy-level exclusions (GPO/Intune pushed)
			`SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths`,
			`SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Processes`,
			`SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Extensions`,
			`SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\IpAddresses`,
		},
		ProductPaths: []string{
			// CrowdStrike Falcon — exclusion staging (often readable)
			`C:\ProgramData\CrowdStrike\`,
			// SentinelOne — local config cache
			`C:\ProgramData\SentinelOne\`,
			// Carbon Black — sensor config
			`C:\ProgramData\CarbonBlack\`,
			// Sophos — exclusion registry mirrored to disk
			`C:\ProgramData\Sophos\`,
			// Generic MDM/Intune cache
			`C:\ProgramData\Microsoft\IntuneManagementExtension\`,
		},
		MaxEntries: 4096,
	}
}

// ---------------------------------------------------------------------------
// Defender registry enumeration (read-only)
// ---------------------------------------------------------------------------

// regEnumKeyValues reads all values under a registry key via the Win32
// RegOpenKeyEx / RegEnumValue API. Read-only — never calls RegSetValue.
func regEnumKeyValues(root syscall.Handle, subkey string) (map[string]string, error) {
	var hKey syscall.Handle
	advapi32 := syscall.NewLazyDLL("advapi32.dll")
	regOpenKeyEx := advapi32.NewProc("RegOpenKeyExW")
	regEnumValue := advapi32.NewProc("RegEnumValueW")
	regCloseKey := advapi32.NewProc("RegCloseKey")

	subkeyPtr, err := syscall.UTF16PtrFromString(subkey)
	if err != nil {
		return nil, err
	}
	// KEY_READ = 0x20019
	const keyRead = 0x20019
	ret, _, _ := regOpenKeyEx.Call(
		uintptr(root),
		uintptr(unsafe.Pointer(subkeyPtr)),
		0,
		keyRead,
		uintptr(unsafe.Pointer(&hKey)),
	)
	if ret != 0 {
		return nil, fmt.Errorf("RegOpenKeyEx(%s): error %d", subkey, ret)
	}
	defer regCloseKey.Call(uintptr(hKey))

	values := make(map[string]string)
	var index uint32
	for {
		var nameBuf [512]uint16
		var dataBuf [2048]byte
		nameLen := uint32(len(nameBuf))
		dataLen := uint32(len(dataBuf))
		var valType uint32

		ret, _, _ := regEnumValue.Call(
			uintptr(hKey),
			uintptr(index),
			uintptr(unsafe.Pointer(&nameBuf[0])),
			uintptr(unsafe.Pointer(&nameLen)),
			0,
			uintptr(unsafe.Pointer(&valType)),
			uintptr(unsafe.Pointer(&dataBuf[0])),
			uintptr(unsafe.Pointer(&dataLen)),
		)
		// ERROR_NO_MORE_ITEMS = 259
		if ret == 259 {
			break
		}
		if ret != 0 {
			break
		}
		name := syscall.UTF16ToString(nameBuf[:nameLen])
		// REG_SZ = 1, REG_EXPAND_SZ = 2
		if valType == 1 || valType == 2 {
			val := syscall.UTF16ToString((*[1024]uint16)(unsafe.Pointer(&dataBuf[0]))[: dataLen/2])
			values[name] = val
		}
		index++
		if index > 4096 {
			break
		}
	}
	return values, nil
}

// EnumerateDefenderExclusions returns every Defender exclusion visible to
// the current user (machine + policy + user hives).
func (ax *AntiExclude) EnumerateDefenderExclusions() ([]ExclusionEntry, error) {
	if runtime.GOOS != "windows" {
		return nil, fmt.Errorf("defender exclusions only exist on windows")
	}

	// HKEY_LOCAL_MACHINE = 0x80000002
	const hklm = 0x80000002
	// HKEY_CURRENT_USER = 0x80000001
	const hkcu = 0x80000001

	var entries []ExclusionEntry
	seen := make(map[string]struct{})

	addEntries := func(kind ExclusionKind, values map[string]string, source string) {
		for name, val := range values {
			// Defender stores exclusions as named values where the name is
			// typically a GUID/random and the data is the actual path.
			// If the name looks like a path, prefer the name.
			value := val
			if value == "" {
				value = name
			}
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			key := string(kind) + "|" + strings.ToLower(value)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			entries = append(entries, ExclusionEntry{
				Kind:   kind,
				Value:  value,
				Source: source,
			})
		}
	}

	for _, key := range ax.DefenderKeys {
		kind := exclusionKindFromKey(key)
		if values, err := regEnumKeyValues(hklm, key); err == nil {
			addEntries(kind, values, "HKLM\\"+key)
		}
		if values, err := regEnumKeyValues(hkcu, key); err == nil {
			addEntries(kind, values, "HKCU\\"+key)
		}
	}

	if len(entries) == 0 {
		return nil, ErrNoExclusions
	}
	if len(entries) > ax.MaxEntries {
		entries = entries[:ax.MaxEntries]
	}
	return entries, nil
}

// exclusionKindFromKey maps a registry key path to its ExclusionKind.
func exclusionKindFromKey(key string) ExclusionKind {
	lk := strings.ToLower(key)
	switch {
	case strings.Contains(lk, `\paths`):
		return ExclPath
	case strings.Contains(lk, `\processes`):
		return ExclProcess
	case strings.Contains(lk, `\extensions`):
		return ExclExtension
	case strings.Contains(lk, `\ipaddresses`):
		return ExclIP
	}
	return ExclPath
}

// ---------------------------------------------------------------------------
// Third-party EDR exclusion discovery (best-effort, read-only)
// ---------------------------------------------------------------------------

// ScanProductPaths walks known EDR data directories looking for files that
// mention exclusion-related keywords. Formats vary wildly; this is a
// keyword-driven heuristic, not a parser.
func (ax *AntiExclude) ScanProductPaths() ([]ExclusionEntry, error) {
	if runtime.GOOS != "windows" {
		return nil, nil
	}
	keywords := []string{
		"exclusion", "exclude", "whitelist", "allowlist",
		"trust", "bypass", "skipscan",
	}
	var entries []ExclusionEntry
	seen := make(map[string]struct{})

	for _, dir := range ax.ProductPaths {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}
		_ = filepath.Walk(dir, func(path string, fi os.FileInfo, err error) error {
			if err != nil || fi == nil || fi.IsDir() {
				return nil
			}
			// Cap file size — config files are small; skip logs/binaries.
			if fi.Size() > 4<<20 {
				return nil
			}
			base := strings.ToLower(fi.Name())
			interesting := false
			for _, kw := range keywords {
				if strings.Contains(base, kw) {
					interesting = true
					break
				}
			}
			if !interesting {
				return nil
			}
			// Read the first 64 KiB looking for path-like strings.
			f, err := os.Open(path)
			if err != nil {
				return nil
			}
			defer f.Close()
			scanner := bufio.NewScanner(f)
			scanner.Buffer(make([]byte, 64<<10), 64<<10)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" || len(line) > 260 {
					continue
				}
				lk := strings.ToLower(line)
				var kind ExclusionKind
				switch {
				case strings.Contains(lk, ":\\") || strings.HasPrefix(lk, "/"):
					kind = ExclPath
				case strings.Contains(lk, ".exe") || strings.Contains(lk, ".dll"):
					kind = ExclProcess
				case strings.HasPrefix(lk, ".") && len(lk) <= 8:
					kind = ExclExtension
				default:
					continue
				}
				key := string(kind) + "|" + lk
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}
				entries = append(entries, ExclusionEntry{
					Kind:   kind,
					Value:  line,
					Source: path,
				})
				if len(entries) > ax.MaxEntries {
					return errors.New("cap reached")
				}
			}
			return nil
		})
	}
	return entries, nil
}

// ---------------------------------------------------------------------------
// Analysis — is *this* process/path excluded? Are any exclusions suspicious?
// ---------------------------------------------------------------------------

// IsSelfExcluded reports whether the current executable's path, name, or
// extension appears in any enumerated exclusion list. A true result means
// on-access scanning will skip us — useful to know, but also a red flag
// that someone (admin or prior attacker) pre-whitelisted us.
func (ax *AntiExclude) IsSelfExcluded(entries []ExclusionEntry) (bool, string) {
	selfPath, err := os.Executable()
	if err != nil {
		selfPath = os.Args[0]
	}
	selfPath = strings.ToLower(filepath.Clean(selfPath))
	selfName := strings.ToLower(filepath.Base(selfPath))
	selfExt := strings.ToLower(filepath.Ext(selfPath))

	for _, e := range entries {
		v := strings.ToLower(strings.TrimSpace(e.Value))
		if v == "" {
			continue
		}
		switch e.Kind {
		case ExclPath:
			// Directory exclusion: does our path live under it?
			if strings.HasPrefix(selfPath, v) || selfPath == v {
				return true, fmt.Sprintf("path exclusion %q from %s", e.Value, e.Source)
			}
		case ExclProcess:
			if selfName == v || strings.HasPrefix(selfName, v) {
				return true, fmt.Sprintf("process exclusion %q from %s", e.Value, e.Source)
			}
		case ExclExtension:
			ext := v
			if !strings.HasPrefix(ext, ".") {
				ext = "." + ext
			}
			if selfExt == ext {
				return true, fmt.Sprintf("extension exclusion %q from %s", e.Value, e.Source)
			}
		}
	}
	return false, ""
}

// SuspiciousExclusions flags entries that are almost never legitimate:
//   - Temp / downloads / public directories
//   - Entire drive roots (C:\)
//   - Wildcard extensions (.exe, .dll, .ps1)
//   - Common LOLBin process names
func (ax *AntiExclude) SuspiciousExclusions(entries []ExclusionEntry) []ExclusionEntry {
	suspiciousPaths := []string{
		`c:\temp`, `c:\tmp`, `c:\windows\temp`,
		`\appdata\local\temp`, `\downloads`, `\public\`,
		`\programdata\`, `\users\public`,
	}
	suspiciousExts := map[string]bool{
		".exe": true, ".dll": true, ".ps1": true, ".bat": true,
		".cmd": true, ".vbs": true, ".js": true, ".hta": true,
		".scr": true, ".msi": true, ".jar": true,
	}
	lolbins := map[string]bool{
		"powershell.exe": true, "pwsh.exe": true, "cmd.exe": true,
		"wscript.exe": true, "cscript.exe": true, "mshta.exe": true,
		"rundll32.exe": true, "regsvr32.exe": true, "certutil.exe": true,
		"bitsadmin.exe": true, "wmic.exe": true, "msbuild.exe": true,
	}

	var out []ExclusionEntry
	for _, e := range entries {
		v := strings.ToLower(strings.TrimSpace(e.Value))
		if v == "" {
			continue
		}
		flagged := false
		switch e.Kind {
		case ExclPath:
			// Drive root like "c:\" — excludes everything on the volume.
			if len(v) <= 3 && strings.HasSuffix(v, `:\`) {
				flagged = true
			}
			for _, sp := range suspiciousPaths {
				if strings.Contains(v, sp) {
					flagged = true
					break
				}
			}
		case ExclProcess:
			if lolbins[filepath.Base(v)] {
				flagged = true
			}
		case ExclExtension:
			ext := v
			if !strings.HasPrefix(ext, ".") {
				ext = "." + ext
			}
			if suspiciousExts[ext] {
				flagged = true
			}
		}
		if flagged {
			out = append(out, e)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Safe drop path derivation — where can we write without being scanned?
// ---------------------------------------------------------------------------

// SafeDropPaths returns directories derived from path exclusions where the
// current user has write access. These are *candidates only* — callers must
// still verify permissions and ethics/scope before use.
func (ax *AntiExclude) SafeDropPaths(entries []ExclusionEntry) []string {
	var out []string
	seen := make(map[string]struct{})
	for _, e := range entries {
		if e.Kind != ExclPath {
			continue
		}
		dir := strings.TrimSpace(e.Value)
		if dir == "" || strings.HasSuffix(dir, `.exe`) || strings.HasSuffix(dir, `.dll`) {
			continue
		}
		// Normalize: if it points at a file, use its parent.
		if info, err := os.Stat(dir); err == nil && !info.IsDir() {
			dir = filepath.Dir(dir)
		}
		// Verify we can actually write there.
		if err := writeProbe(dir); err != nil {
			continue
		}
		lk := strings.ToLower(dir)
		if _, ok := seen[lk]; ok {
			continue
		}
		seen[lk] = struct{}{}
		out = append(out, dir)
	}
	return out
}

// writeProbe tests directory writability by creating and removing a
// zero-byte temp file. Cheap and reversible.
func writeProbe(dir string) error {
	if dir == "" {
		return errors.New("empty dir")
	}
	probe := filepath.Join(dir, ".ax_probe")
	f, err := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	_ = f.Close()
	_ = os.Remove(probe)
	return nil
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

// Enumerate runs the full exclusion discovery pipeline and returns:
//   - all exclusions found (Defender + product configs)
//   - suspicious subset
//   - whether the current process is itself excluded
//   - safe drop paths derived from path exclusions
//
// Errors are non-fatal — callers should proceed with whatever was found.
func (ax *AntiExclude) Enumerate() (all, suspicious []ExclusionEntry, selfExcluded bool, reason string, dropPaths []string) {
	defEntries, _ := ax.EnumerateDefenderExclusions()
	prodEntries, _ := ax.ScanProductPaths()
	all = append(all, defEntries...)
	all = append(all, prodEntries...)

	suspicious = ax.SuspiciousExclusions(all)
	selfExcluded, reason = ax.IsSelfExcluded(all)
	dropPaths = ax.SafeDropPaths(all)
	return
}

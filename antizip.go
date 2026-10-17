package main

import (
	"encoding/binary"
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
// Anti-ZIP Module
//
// Archive-aware execution analysis. Answers:
//   - Was I launched from inside an archive?
//   - Does my on-disk file carry Mark-of-the-Web (MOTW)?
//   - Is the archive container MOTW-tagged (and hence likely scanned)?
//   - Is this host monitoring archive extraction (7-Zip, Explorer, AV)?
//   - Which container type delivered me (zip/iso/img/wim/7z/rar/cab/tar)?
//   - Where can I safely extract/execute without triggering archive scan?
//
// All operations are read-only. Nothing here extracts, rewrites, or strips
// MOTW — that would be tampering and is outside this module's scope.
// ============================================================================

// ContainerKind classifies the delivery container.
type ContainerKind string

const (
	ContainerNone ContainerKind = "none"     // not from an archive
	ContainerZIP  ContainerKind = "zip"
	Container7z   ContainerKind = "7z"
	ContainerRAR  ContainerKind = "rar"
	ContainerCAB  ContainerKind = "cab"
	ContainerISO  ContainerKind = "iso"
	ContainerIMG  ContainerKind = "img"
	ContainerWIM  ContainerKind = "wim"
	ContainerVHD  ContainerKind = "vhd"
	ContainerTAR  ContainerKind = "tar"
	ContainerGZ   ContainerKind = "gz"
	ContainerXZ   ContainerKind = "xz"
	ContainerMSIX ContainerKind = "msix"
	ContainerAPPX ContainerKind = "appx"
	ContainerUnknown ContainerKind = "unknown"
)

// MOTWState describes the Mark-of-the-Web posture of a file.
type MOTWState string

const (
	MOTWNone     MOTWState = "none"        // no Zone.Identifier ADS
	MOTWPresent  MOTWState = "present"     // Zone.Identifier exists
	MOTWLocal    MOTWState = "zone-local"  // ZoneId=0 — explicitly trusted
	MOTWIntranet MOTWState = "zone-intranet" // ZoneId=1
	MOTWTrusted  MOTWState = "zone-trusted"  // ZoneId=2
	MOTWInternet MOTWState = "zone-internet" // ZoneId=3
	MOTWRestricted MOTWState = "zone-restricted" // ZoneId=4
	MOTWUnreadable MOTWState = "unreadable" // ADS read denied
)

// ContainerEvidence captures the analysis of one container.
type ContainerEvidence struct {
	Kind       ContainerKind
	Path       string        // path to the container or containing extraction dir
	MOTW       MOTWState
	Scanned    bool          // best-effort: container likely scanned by AV
	Extracted  bool          // true if we are inside a mount/extraction point
	MountPoint string        // for ISO/IMG/WIM/VHD: the mount root
	Detail     string
	Severity   PatchSeverity
}

// SelfArchiveReport is the full analysis.
type SelfArchiveReport struct {
	SelfPath       string
	SelfDir        string
	SelfName       string
	SelfExt        string
	SelfMOTW       MOTWState
	SelfZoneID     int
	Container      ContainerEvidence
	Containers     []ContainerEvidence // all matching containers, sorted by proximity
	ExtractMonitors []ExtractMonitor
	SafePaths      []string
	Notes          string
}

// ExtractMonitor describes a process/service that monitors extraction.
type ExtractMonitor struct {
	Name       string
	Kind       string // "service", "process", "shell-ext", "driver"
	Path       string
	Detail     string
	Severity   PatchSeverity
}

// AntiZIP is the scanner.
type AntiZIP struct {
	// ArchiveExts are extensions treated as archives.
	ArchiveExts map[string]ContainerKind

	// MountRoots are directories where Windows mounts ISO/IMG/VHD/WIM.
	// Volumes appear as drive letters under these roots, or as directories
	// under C:\ when mounted via dismount.
	MountRoots []string

	// ExtractMonitorServices are service names whose presence indicates
	// archive scanning is monitored.
	ExtractMonitorServices []string

	// ExtractMonitorDrivers are driver/service names that host AV minifilters
	// over the archive-extraction path.
	ExtractMonitorDrivers []string

	mu sync.Mutex
}

// DefaultAntiZIP returns a configuration covering Windows' native archive
// formats plus the common third-party ones.
func DefaultAntiZIP() *AntiZIP {
	return &AntiZIP{
		ArchiveExts: map[string]ContainerKind{
			".zip":  ContainerZIP,
			".7z":   Container7z,
			".rar":  ContainerRAR,
			".cab":  ContainerCAB,
			".iso":  ContainerISO,
			".img":  ContainerIMG,
			".wim":  ContainerWIM,
			".vhd":  ContainerVHD,
			".vhdx": ContainerVHD,
			".tar":  ContainerTAR,
			".gz":   ContainerGZ,
			".tgz":  ContainerTAR,
			".xz":   ContainerXZ,
			".txz":  ContainerTAR,
			".msix": ContainerMSIX,
			".appx": ContainerAPPX,
		},
		MountRoots: []string{
			`C:\`,
			`D:\`,
			`E:\`,
			`F:\`,
		},
		ExtractMonitorServices: []string{
			// Windows Defender archive scanning is on by default.
			"WinDefend",
			"MsMpSvc",
			// Windows Filtering + archive-aware minifilters.
			"WdFilter",
			"WdNisSvc",
			// Third-party EDRs that scan archives on extract.
			"CrowdStrike",
			"CSFalconService",
			"SentinelAgent",
			"Sense",
			"CarbonBlack",
			"cb",
			"Sophos",
			"SAVService",
			"ekrn", // ESET
			"avp",  // Kaspersky
		},
		ExtractMonitorDrivers: []string{
			"WdFilter",   // Defender minifilter
			"FileInfo",   // file info minifilter
			"fltmgr",     // filter manager (loads all minifilters)
			"cldflt",     // Cloud Files minifilter
			"bindflt",    // bind filter
		},
	}
}

// ---------------------------------------------------------------------------
// Self-path analysis
// ---------------------------------------------------------------------------

// analyzeSelf populates the self-fields and returns the current MOTW state.
func (az *AntiZIP) analyzeSelf() (selfPath, selfDir, selfName, selfExt string, motw MOTWState, zoneID int) {
	p, err := os.Executable()
	if err != nil {
		p = os.Args[0]
	}
	selfPath = filepath.Clean(p)
	selfDir = filepath.Dir(selfPath)
	selfName = filepath.Base(selfPath)
	selfExt = strings.ToLower(filepath.Ext(selfPath))
	motw, zoneID = readMOTW(selfPath)
	return
}

// readMOTW reads the Zone.Identifier alternate data stream on Windows.
// Returns MOTWNone if the ADS doesn't exist, MOTWUnreadable if access is
// denied, and the specific zone otherwise.
func readMOTW(path string) (MOTWState, int) {
	if runtime.GOOS != "windows" {
		return MOTWNone, 0
	}
	adsPath := path + ":Zone.Identifier"
	data, err := os.ReadFile(adsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return MOTWNone, 0
		}
		// Access denied or other — we can't tell, so mark unreadable.
		return MOTWUnreadable, 0
	}
	// Parse INI-style [ZoneTransfer] section.
	zoneID := -1
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToLower(line), "zoneid=") {
			var z int
			if _, err := fmt.Sscanf(line, "ZoneId=%d", &z); err == nil {
				zoneID = z
			}
		}
	}
	switch zoneID {
	case 0:
		return MOTWLocal, zoneID
	case 1:
		return MOTWIntranet, zoneID
	case 2:
		return MOTWTrusted, zoneID
	case 3:
		return MOTWInternet, zoneID
	case 4:
		return MOTWRestricted, zoneID
	default:
		return MOTWPresent, zoneID
	}
}

// ---------------------------------------------------------------------------
// Container discovery — walk ancestors looking for archive indicators
// ---------------------------------------------------------------------------

// detectContainers inspects selfDir and every ancestor up to the drive
// root, looking for:
//   - extraction directories created by Explorer's built-in extractor
//     (e.g. "foo.zip (extracted)", "foo (1)")
//   - mount points created by Mount-DiskImage (drive letters)
//   - directories named after an archive (e.g. "foo.zip" dir)
func (az *AntiZIP) detectContainers(selfPath, selfDir string) []ContainerEvidence {
	var out []ContainerEvidence

	// 1. Direct: the file's own extension.
	ext := strings.ToLower(filepath.Ext(selfPath))
	if kind, ok := az.ArchiveExts[ext]; ok {
		out = append(out, ContainerEvidence{
			Kind:     kind,
			Path:     selfPath,
			MOTW:     readMOTWFor(selfPath),
			Detail:   fmt.Sprintf("executable itself is an archive (%s)", ext),
			Severity: SevSuspicious,
		})
	}

	// 2. Extract-dir heuristic: look for "<name>.<ext> (extracted)" or
	//    "<name> (extracted)" siblings in the same directory.
	if sibling := findExtractSibling(selfDir, az.ArchiveExts); sibling != "" {
		out = append(out, ContainerEvidence{
			Kind:      ContainerUnknown,
			Path:      sibling,
			MOTW:      readMOTWFor(sibling),
			Extracted: true,
			Detail:    "sibling archive-extracted directory found",
			Severity:  SevSuspicious,
		})
	}

	// 3. Ancestor heuristic: walk up from selfDir looking for mount points
	//    (drive letters under a mount root, or dirs under \mount\).
	if mount, kind, detail := detectMountAncestor(selfDir, az.MountRoots, az.ArchiveExts); mount != "" {
		out = append(out, ContainerEvidence{
			Kind:       kind,
			Path:       mount,
			MOTW:       readMOTWFor(mount),
			Extracted:  true,
			MountPoint: mount,
			Detail:     detail,
			Severity:   SevCritical,
		})
	}

	// 4. Path signature: Explorer's extractor leaves the archive name in a
	//    parent directory, e.g. C:\Users\x\Downloads\payload.zip\payload.exe.
	if parentArchive, kind := findArchiveInPath(selfDir, az.ArchiveExts); parentArchive != "" {
		out = append(out, ContainerEvidence{
			Kind:      kind,
			Path:      parentArchive,
			MOTW:      readMOTWFor(parentArchive),
			Extracted: true,
			Detail:    "archive name appears as a path component",
			Severity:  SevCritical,
		})
	}

	return out
}

// findExtractSibling looks for "*.<ext>" or "*.<ext> (extracted)" entries
// in dir that match the current executable's name family.
func findExtractSibling(dir string, exts map[string]ContainerKind) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	// Look for " (extracted)" / " (1)" siblings that match an archive ext.
	for _, e := range entries {
		name := strings.ToLower(e.Name())
		if e.IsDir() && (strings.Contains(name, "(extracted)") ||
			strings.Contains(name, " - copy") ||
			strings.HasSuffix(name, " (1)") ||
			strings.HasSuffix(name, " (2)")) {
			return filepath.Join(dir, e.Name())
		}
		for ext := range exts {
			// "payload.zip" as a directory (Windows extractor sometimes
			// creates a dir with the full archive name).
			if e.IsDir() && strings.HasSuffix(name, ext) {
				return filepath.Join(dir, e.Name())
			}
		}
	}
	return ""
}

// detectMountAncestor walks up from dir looking for a Windows mount point:
//   - a drive letter whose root is not C:\ (ISO/IMG/VHD mounts)
//   - a directory under \mount\ (Server Core / dismount mounts)
//
// Returns the mount root, its container kind, and a detail string.
func detectMountAncestor(dir string, roots []string, exts map[string]ContainerKind) (string, ContainerKind, string) {
	cur := dir
	for {
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		// Drive-letter mount detection: if `cur` is `X:\` for X != C.
		if len(cur) == 3 && cur[1] == ':' && cur[2] == '\\' {
			if !strings.EqualFold(cur, `C:\`) {
				return cur, ContainerISO, fmt.Sprintf("executable lives on non-system drive %s (likely mounted ISO/IMG/VHD)", cur)
			}
		}
		// \mount\ heuristic: a directory under a known mount root that
		// contains only a single subdir and no Windows/.
		if isMountLike(parent) {
			return parent, ContainerUnknown, "executable lives under a mount-like directory"
		}
		cur = parent
	}
	return "", ContainerNone, ""
}

// isMountLike returns true if dir looks like an extracted/mounted root:
// no "Windows", "Program Files", or "Users" subdirs, but has "autorun.inf",
// "sources", "setup.exe", or "install.*".
func isMountLike(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	hasWindows := false
	hasMountMarker := false
	for _, e := range entries {
		n := strings.ToLower(e.Name())
		switch n {
		case "windows", "program files", "program files (x86)", "users":
			hasWindows = true
		case "autorun.inf", "sources", "setup.exe", "install.exe",
			"install.wim", "bootmgr", "bootmgr.efi", "efi", "boot":
			hasMountMarker = true
		}
	}
	return !hasWindows && hasMountMarker
}

// findArchiveInPath walks the path components of dir and returns the first
// one whose extension matches an archive ext.
func findArchiveInPath(dir string, exts map[string]ContainerKind) (string, ContainerKind) {
	cur := dir
	for {
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		ext := strings.ToLower(filepath.Ext(cur))
		if kind, ok := exts[ext]; ok {
			return cur, kind
		}
		cur = parent
	}
	return "", ContainerNone
}

// readMOTWFor is a convenience wrapper.
func readMOTWFor(path string) MOTWState {
	s, _ := readMOTW(path)
	return s
}

// ---------------------------------------------------------------------------
// Extraction monitor detection — services and shell extensions
// ---------------------------------------------------------------------------

// detectExtractMonitors checks for services and shell extensions that
// indicate the host scans archive contents.
func (az *AntiZIP) detectExtractMonitors() []ExtractMonitor {
	if runtime.GOOS != "windows" {
		return nil
	}
	var out []ExtractMonitor

	// 1. Services.
	advapi32 := syscall.NewLazyDLL("advapi32.dll")
	openSCManager := advapi32.NewProc("OpenSCManagerW")
	openService := advapi32.NewProc("OpenServiceW")
	closeServiceHandle := advapi32.NewProc("CloseServiceHandle")

	scm, _, _ := openSCManager.Call(0, 0, 0x0001) // SC_MANAGER_CONNECT
	if scm != 0 {
		for _, svc := range az.ExtractMonitorServices {
			namePtr, _ := syscall.UTF16PtrFromString(svc)
			// SERVICE_QUERY_STATUS = 0x0004
			hSvc, _, _ := openService.Call(scm, uintptr(unsafe.Pointer(namePtr)), 0x0004)
			if hSvc != 0 {
				closeServiceHandle.Call(hSvc)
				out = append(out, ExtractMonitor{
					Name:     svc,
					Kind:     "service",
					Detail:   "service present — archive/extraction scanning likely active",
					Severity: SevSuspicious,
				})
			}
		}
		closeServiceHandle.Call(scm)
	}

	// 2. Shell extensions — 7-Zip and WinRAR install shell handlers that
	//    are called by Explorer during extraction.
	shellExtKeys := []string{
		`SOFTWARE\Classes\7-Zip.zip`,
		`SOFTWARE\Classes\7-Zip.7z`,
		`SOFTWARE\Classes\WinRAR`,
		`SOFTWARE\Classes\WinRAR.ZIP`,
	}
	advapi32Open := advapi32.NewProc("RegOpenKeyExW")
	for _, key := range shellExtKeys {
		ptr, _ := syscall.UTF16PtrFromString(key)
		var hKey syscall.Handle
		// HKEY_LOCAL_MACHINE = 0x80000002, KEY_READ = 0x20019
		ret, _, _ := advapi32Open.Call(
			0x80000002,
			uintptr(unsafe.Pointer(ptr)),
			0,
			0x20019,
			uintptr(unsafe.Pointer(&hKey)),
		)
		if ret == 0 {
			advapi32.NewProc("RegCloseKey").Call(uintptr(hKey))
			out = append(out, ExtractMonitor{
				Name:     key,
				Kind:     "shell-ext",
				Path:     key,
				Detail:   "third-party archive handler installed",
				Severity: SevInfo,
			})
		}
	}

	// 3. Defender real-time archive scanning setting.
	if enabled, ok := defenderArchiveScan(); ok && enabled {
		out = append(out, ExtractMonitor{
			Name:     "Defender-ArchiveScan",
			Kind:     "service",
			Detail:   "Defender real-time archive scanning is enabled",
			Severity: SevCritical,
		})
	}

	return out
}

// defenderArchiveScan reads Defender's DisableArchiveScanning preference.
// Returns (enabled, ok). enabled is true if archive scanning is *not*
// disabled (i.e. it is active).
func defenderArchiveScan() (bool, bool) {
	advapi32 := syscall.NewLazyDLL("advapi32.dll")
	regOpenKeyEx := advapi32.NewProc("RegOpenKeyExW")
	regQueryValueEx := advapi32.NewProc("RegQueryValueExW")
	regCloseKey := advapi32.NewProc("RegCloseKey")

	keyPath, _ := syscall.UTF16PtrFromString(`SOFTWARE\Microsoft\Windows Defender\Real-Time Protection`)
	var hKey syscall.Handle
	// HKLM = 0x80000002, KEY_READ = 0x20019
	ret, _, _ := regOpenKeyEx.Call(
		0x80000002,
		uintptr(unsafe.Pointer(keyPath)),
		0,
		0x20019,
		uintptr(unsafe.Pointer(&hKey)),
	)
	if ret != 0 {
		// Try policy key.
		keyPath, _ = syscall.UTF16PtrFromString(`SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection`)
		ret, _, _ = regOpenKeyEx.Call(
			0x80000002,
			uintptr(unsafe.Pointer(keyPath)),
			0,
			0x20019,
			uintptr(unsafe.Pointer(&hKey)),
		)
		if ret != 0 {
			return false, false
		}
	}
	defer regCloseKey.Call(uintptr(hKey))

	namePtr, _ := syscall.UTF16PtrFromString("DisableArchiveScanning")
	var data [4]byte
	dataLen := uint32(4)
	// REG_DWORD = 4
	ret, _, _ = regQueryValueEx.Call(
		uintptr(hKey),
		uintptr(unsafe.Pointer(namePtr)),
		0,
		0,
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(unsafe.Pointer(&dataLen)),
	)
	if ret != 0 {
		// Value missing = default = archive scanning enabled.
		return true, true
	}
	disabled := binary.LittleEndian.Uint32(data[:]) != 0
	return !disabled, true
}

// ---------------------------------------------------------------------------
// Safe path derivation
// ---------------------------------------------------------------------------

// safePaths returns directories derived from container metadata where the
// payload can be extracted without inheriting MOTW (because they are on a
// mounted volume or a filesystem that doesn't support ADS).
func (az *AntiZIP) safePaths(report *SelfArchiveReport) []string {
	var out []string
	seen := make(map[string]struct{})

	// Mount points don't support MOTW ADS on FAT/exFAT — these are
	// effectively MOTW-free.
	for _, c := range report.Containers {
		if c.MountPoint == "" {
			continue
		}
		if writeProbe(c.MountPoint) == nil {
			key := strings.ToLower(c.MountPoint)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, c.MountPoint)
		}
	}

	// Fall back to writable temp dirs — MOTW is inherited from the
	// *source* file, not the destination, so extracting into temp
	// avoids the "downloaded from internet" taint *only if* the source
	// archive is MOTW-free.
	tmp := os.Getenv("TEMP")
	if tmp != "" && writeProbe(tmp) == nil {
		key := strings.ToLower(tmp)
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			out = append(out, tmp)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

// Scan runs the full anti-ZIP pipeline.
func (az *AntiZIP) Scan() *SelfArchiveReport {
	az.mu.Lock()
	defer az.mu.Unlock()

	selfPath, selfDir, selfName, selfExt, selfMOTW, zoneID := az.analyzeSelf()

	rep := &SelfArchiveReport{
		SelfPath: selfPath,
		SelfDir:  selfDir,
		SelfName: selfName,
		SelfExt:  selfExt,
		SelfMOTW: selfMOTW,
		SelfZoneID: zoneID,
	}

	rep.Containers = az.detectContainers(selfPath, selfDir)
	// Pick the most specific container (deepest mount, or first).
	for _, c := range rep.Containers {
		if c.MountPoint != "" {
			rep.Container = c
			break
		}
	}
	if rep.Container.Kind == "" && len(rep.Containers) > 0 {
		rep.Container = rep.Containers[0]
	}

	rep.ExtractMonitors = az.detectExtractMonitors()
	rep.SafePaths = az.safePaths(rep)

	// Compose notes.
	var notes []string
	switch selfMOTW {
	case MOTWNone:
		notes = append(notes, "no MOTW on executable")
	case MOTWInternet:
		notes = append(notes, "MOTW zone=internet (downloaded)")
	case MOTWRestricted:
		notes = append(notes, "MOTW zone=restricted")
	case MOTWUnreadable:
		notes = append(notes, "MOTW unreadable (ADS protected)")
	}
	if rep.Container.MountPoint != "" {
		notes = append(notes, "launched from mount "+rep.Container.MountPoint)
	}
	if rep.Container.Extracted {
		notes = append(notes, "launched from extracted archive dir")
	}
	critical := 0
	for _, m := range rep.ExtractMonitors {
		if m.Severity == SevCritical {
			critical++
		}
	}
	if critical > 0 {
		notes = append(notes, fmt.Sprintf("%d critical extraction monitors", critical))
	}
	rep.Notes = strings.Join(notes, "; ")
	return rep
}

// Summary returns a compact one-line description.
func (r *SelfArchiveReport) Summary() string {
	if r == nil {
		return "no archive analysis"
	}
	parts := []string{fmt.Sprintf("motw=%s", r.SelfMOTW)}
	if r.Container.Kind != ContainerNone {
		parts = append(parts, fmt.Sprintf("container=%s", r.Container.Kind))
	}
	if r.Container.MountPoint != "" {
		parts = append(parts, "mounted")
	}
	if n := len(r.ExtractMonitors); n > 0 {
		parts = append(parts, fmt.Sprintf("monitors=%d", n))
	}
	return strings.Join(parts, " ")
}

// ZoneID returns the raw Zone.Identifier ZoneId (or -1 if absent).
func (r *SelfArchiveReport) ZoneID() int {
	if r == nil {
		return -1
	}
	return r.SelfZoneID
}

// IsMOTWTainted returns true if the executable carries a non-trusted MOTW.
func (r *SelfArchiveReport) IsMOTWTainted() bool {
	if r == nil {
		return false
	}
	switch r.SelfMOTW {
	case MOTWInternet, MOTWRestricted:
		return true
	}
	return false
}

// CrossReference combines anti-ZIP findings with the sibling modules'
// outputs into a single operator-facing line.
func (az *AntiZIP) CrossReference(zip *SelfArchiveReport, pomp *POMPReport, hooks *HookMap, patches []PatchReport) string {
	var parts []string
	if zip != nil {
		if zip.IsMOTWTainted() {
			parts = append(parts, "motw=tainted")
		}
		if zip.Container.Kind != ContainerNone {
			parts = append(parts, fmt.Sprintf("container=%s", zip.Container.Kind))
		}
	}
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
		return "clean"
	}
	return strings.Join(parts, " ")
}

// ErrNotFromArchive is a convenience sentinel.
var ErrNotFromArchive = errors.New("executable did not originate from an archive")

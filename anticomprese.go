package main

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
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
// Anti-Compression Module
//
// Analyzes the compression landscape around the running payload:
//
//   1. Archive ratio analysis — zip bombs, nested archives, quines
//   2. Extraction-tree detection — is our parent an unpacker?
//   3. Decompressor footprint — which tools/processes did the extraction?
//   4. Buffer-size detection — was the payload decompressed into memory?
//   5. Compression-tool config — 7-Zip, WinRAR, WinZip, built-in zip
//   6. Safe decompression paths — where to unpack without triggering heuristics
//
// All operations are read-only. No archives are extracted or modified.
// ============================================================================

// CompressionSignal enumerates the anomaly classes.
type CompressionSignal string

const (
	SigZipBomb        CompressionSignal = "zip-bomb"        // ratio > 1000:1
	SigNestedArchive  CompressionSignal = "nested-archive"  // archive inside archive
	SigQuine          CompressionSignal = "quine-archive"   // archive contains itself
	SigDeepNesting    CompressionSignal = "deep-nesting"    // nesting depth >= 3
	SigHugeUncompressed CompressionSignal = "huge-uncompressed" // > 1 GiB expanded
	SigEncryptedZip   CompressionSignal = "encrypted-zip"   // password-protected
	SigSplitArchive   CompressionSignal = "split-archive"   // multi-volume
	SigUnpackerParent CompressionSignal = "unpacker-parent" // parent = 7z/winrar
	SigDecompressor   CompressionSignal = "decompressor"    // 7z/winrar/etc. running
	SigMemBuffer      CompressionSignal = "memory-buffer"   // decompressed into RAM
	SigVolumeMount    CompressionSignal = "volume-mount"    // ISO/IMG/VHD mounted
)

// CompressionFinding is one anomaly.
type CompressionFinding struct {
	Signal   CompressionSignal
	Path     string // file, process, or mount
	Detail   string
	Severity PatchSeverity
}

// ArchiveStats captures the analysis of one archive.
type ArchiveStats struct {
	Path             string
	Format           string // "zip", "gzip", "7z", "rar", "cab", "unknown"
	UncompressedSize int64
	CompressedSize   int64
	Ratio            float64
	FileCount        int
	NestedDepth      int
	MaxNestedRatio   float64
	IsEncrypted      bool
	IsSplit          bool
	Entries          []ArchiveEntry
}

// ArchiveEntry is a single entry in a parsed archive.
type ArchiveEntry struct {
	Name             string
	UncompressedSize int64
	CompressedSize   int64
	Ratio            float64
	IsNested         bool
	NestedFormat     string
}

// UnpackerProcess describes a running compression tool.
type UnpackerProcess struct {
	Name     string
	PID      uint32
	Path     string
	Kind     string // "archiver", "extractor", "shell-ext"
	Detail   string
	Severity PatchSeverity
}

// AntiCompression is the scanner.
type AntiCompression struct {
	// ArchiveExts are extensions considered archives for nesting analysis.
	ArchiveExts map[string]string // ext -> format name

	// UnpackerNames are process names that indicate a decompressor is
	// running in the ancestry.
	UnpackerNames []string

	// BombRatioThreshold is the compression ratio above which an entry is
	// flagged as a zip bomb. Default 1000:1 (the classic threshold).
	BombRatioThreshold float64

	// HugeSizeThreshold is the uncompressed size above which an entry is
	// flagged as "huge". Default 1 GiB.
	HugeSizeThreshold int64

	// MaxNestingDepth is the nesting depth above which an archive is
	// flagged. Default 3.
	MaxNestingDepth int

	// MaxNestedScan caps the number of archives we descend into.
	MaxNestedScan int

	// SafeExtractPaths are pre-vetted directories for extraction.
	SafeExtractPaths []string

	mu sync.Mutex
}

// DefaultAntiCompression returns a sensible configuration.
func DefaultAntiCompression() *AntiCompression {
	return &AntiCompression{
		ArchiveExts: map[string]string{
			".zip":  "zip",
			".7z":   "7z",
			".rar":  "rar",
			".cab":  "cab",
			".gz":   "gzip",
			".tgz":  "tar+gzip",
			".tar":  "tar",
			".xz":   "xz",
			".txz":  "tar+xz",
			".bz2":  "bzip2",
			".tbz2": "tar+bzip2",
			".lz":   "lzma",
			".lzma": "lzma",
			".zst":  "zstd",
			".iso":  "iso",
			".img":  "img",
			".wim":  "wim",
			".vhd":  "vhd",
			".vhdx": "vhd",
		},
		UnpackerNames: []string{
			"7z.exe", "7za.exe", "7zg.exe",
			"winrar.exe", "rar.exe", "unrar.exe",
			"winzip32.exe", "winzip64.exe", "wzzip.exe", "wzunzip.exe",
			"peazip.exe", "bandizip.exe", "izarc.exe",
			"tar.exe", "bsdtar.exe", "gzip.exe", "xz.exe",
			"expand.exe", "extrac32.exe", "makecab.exe",
			// PowerShell's Expand-Archive / ZipFile class host
			"powershell.exe", "pwsh.exe",
			// Third-party EDR unpackers (sandbox emulation)
			"unpacker.exe", "sandbox.exe",
		},
		BombRatioThreshold: 1000.0,
		HugeSizeThreshold:  1 << 30, // 1 GiB
		MaxNestingDepth:    3,
		MaxNestedScan:      32,
		SafeExtractPaths: []string{
			`C:\ProgramData\Microsoft\Windows\WER\Temp\`,
			`C:\Windows\Temp\`,
		},
	}
}

// ---------------------------------------------------------------------------
// Archive analysis
// ---------------------------------------------------------------------------

// analyzeZip reads a ZIP's central directory and computes per-entry ratios.
// The central directory is authoritative and doesn't require decompression.
func (ac *AntiCompression) analyzeZip(path string) (*ArchiveStats, error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	stats := &ArchiveStats{Path: path, Format: "zip"}
	stats.FileCount = len(r.File)

	// Detect split archives: split zips have files named .z01, .z02, etc.
	// or a single .zip containing the "split" flag in the entry.
	dirEntries, _ := os.ReadDir(filepath.Dir(path))
	base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	for _, e := range dirEntries {
		n := strings.ToLower(e.Name())
		if strings.HasPrefix(n, base+".") && (strings.HasSuffix(n, ".z01") ||
			strings.HasSuffix(n, ".z02") ||
			strings.Contains(n, ".part")) {
			stats.IsSplit = true
			break
		}
	}

	for _, f := range r.File {
		// Encrypted if the flag is set or if a password is required.
		if f.Flags&0x1 != 0 {
			stats.IsEncrypted = true
		}
		// Directories: skip.
		if f.FileInfo().IsDir() {
			continue
		}
		ratio := 0.0
		if f.CompressedSize64 > 0 {
			ratio = float64(f.UncompressedSize64) / float64(f.CompressedSize64)
		}
		entry := ArchiveEntry{
			Name:             f.Name,
			UncompressedSize: int64(f.UncompressedSize64),
			CompressedSize:   int64(f.CompressedSize64),
			Ratio:            ratio,
		}
		// Nested archive detection: does the entry name end in an archive ext?
		ext := strings.ToLower(filepath.Ext(f.Name))
		if format, ok := ac.ArchiveExts[ext]; ok {
			entry.IsNested = true
			entry.NestedFormat = format
		}
		stats.Entries = append(stats.Entries, entry)
		stats.UncompressedSize += entry.UncompressedSize
		stats.CompressedSize += entry.CompressedSize
		if ratio > stats.MaxNestedRatio {
			stats.MaxNestedRatio = ratio
		}
	}
	if stats.CompressedSize > 0 {
		stats.Ratio = float64(stats.UncompressedSize) / float64(stats.CompressedSize)
	}
	return stats, nil
}

// analyzeGzip reads a gzip header and computes expanded size via the ISIZE
// trailer (last 4 bytes, mod 2^32). This is cheap — no decompression.
func (ac *AntiCompression) analyzeGzip(path string) (*ArchiveStats, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Read the header to verify it's gzip.
	var hdr [10]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != 0x1f || hdr[1] != 0x8b {
		return nil, errors.New("not gzip")
	}
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	compressed := info.Size()

	// Read ISIZE from the last 4 bytes.
	if _, err := f.Seek(-4, io.SeekEnd); err != nil {
		return nil, err
	}
	var isize uint32
	if err := binary.Read(f, binary.LittleEndian, &isize); err != nil {
		return nil, err
	}

	stats := &ArchiveStats{
		Path:             path,
		Format:           "gzip",
		CompressedSize:   compressed,
		UncompressedSize: int64(isize),
		FileCount:        1,
	}
	if compressed > 0 {
		stats.Ratio = float64(isize) / float64(compressed)
		stats.MaxNestedRatio = stats.Ratio
	}
	// Check for nested archive by looking at the decompressed name hint
	// in the gzip FNAME field (byte 3 of FLG = FNAME flag).
	if hdr[3]&0x08 != 0 {
		var nameBuf [256]byte
		n, _ := f.Read(nameBuf[:])
		if n > 0 {
			name := strings.TrimRight(string(nameBuf[:n]), "\x00")
			ext := strings.ToLower(filepath.Ext(name))
			if format, ok := ac.ArchiveExts[ext]; ok {
				stats.Entries = append(stats.Entries, ArchiveEntry{
					Name:         name,
					IsNested:     true,
					NestedFormat: format,
				})
			}
		}
	}
	return stats, nil
}

// analyzeGeneric reads the magic bytes for formats we can't parse cheaply
// (7z, rar, cab, tar, etc.) and returns a minimal stats struct.
func (ac *AntiCompression) analyzeGeneric(path, format string) (*ArchiveStats, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	stats := &ArchiveStats{
		Path:           path,
		Format:         format,
		CompressedSize: info.Size(),
		FileCount:      -1, // unknown without full parse
	}
	// For formats with a header size field, read it. Otherwise, leave
	// UncompressedSize=0 (unknown).
	f, err := os.Open(path)
	if err != nil {
		return stats, nil
	}
	defer f.Close()

	var magic [8]byte
	n, _ := f.Read(magic[:])
	if n < 8 {
		return stats, nil
	}

	// 7z: "7z\xBC\xAF\x27\x1C" + version(2) + startHeaderCRC(4).
	if bytes.Equal(magic[:6], []byte{0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c}) {
		stats.Format = "7z"
		// StartHeader contains NextHeaderOffset + Size; we don't
		// parse it without a full 7z reader.
	}
	// RAR5: "Rar!\x1A\x07\x01\x00"
	if bytes.Equal(magic[:8], []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00}) {
		stats.Format = "rar5"
	}
	// RAR4: "Rar!\x1A\x07\x00"
	if bytes.Equal(magic[:7], []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00}) {
		stats.Format = "rar4"
	}
	// CAB: "MSCF"
	if bytes.Equal(magic[:4], []byte{0x4D, 0x53, 0x43, 0x46}) {
		stats.Format = "cab"
	}
	// WIM: "MSWIM\x00\x00\x00"
	if bytes.Equal(magic[:8], []byte{0x4D, 0x53, 0x57, 0x49, 0x4D, 0x00, 0x00, 0x00}) {
		stats.Format = "wim"
	}
	// XZ: "\xFD7zXZ\x00"
	if bytes.Equal(magic[:6], []byte{0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00}) {
		stats.Format = "xz"
	}
	// ZSTD: "\x28\xB5\x2F\xFD"
	if bytes.Equal(magic[:4], []byte{0x28, 0xB5, 0x2F, 0xFD}) {
		stats.Format = "zstd"
	}
	return stats, nil
}

// analyzeArchive dispatches on extension and returns ArchiveStats.
func (ac *AntiCompression) analyzeArchive(path string) (*ArchiveStats, error) {
	ext := strings.ToLower(filepath.Ext(path))
	format, ok := ac.ArchiveExts[ext]
	if !ok {
		return nil, errors.New("not an archive extension")
	}
	switch ext {
	case ".zip":
		return ac.analyzeZip(path)
	case ".gz", ".tgz":
		return ac.analyzeGzip(path)
	default:
		return ac.analyzeGeneric(path, format)
	}
}

// ---------------------------------------------------------------------------
// Anomaly detection — turn ArchiveStats into CompressionFindings
// ---------------------------------------------------------------------------

// assessArchive produces findings from a single archive's stats.
func (ac *AntiCompression) assessArchive(stats *ArchiveStats) []CompressionFinding {
	var out []CompressionFinding

	// Zip bomb: overall ratio or any single entry's ratio.
	if stats.Ratio >= ac.BombRatioThreshold {
		out = append(out, CompressionFinding{
			Signal:   SigZipBomb,
			Path:     stats.Path,
			Detail:   fmt.Sprintf("overall ratio %.0f:1 (%d -> %d bytes)", stats.Ratio, stats.CompressedSize, stats.UncompressedSize),
			Severity: SevCritical,
		})
	}
	for _, e := range stats.Entries {
		if e.Ratio >= ac.BombRatioThreshold {
			out = append(out, CompressionFinding{
				Signal:   SigZipBomb,
				Path:     stats.Path,
				Detail:   fmt.Sprintf("entry %q ratio %.0f:1", e.Name, e.Ratio),
				Severity: SevCritical,
			})
		}
		if e.UncompressedSize >= ac.HugeSizeThreshold {
			out = append(out, CompressionFinding{
				Signal:   SigHugeUncompressed,
				Path:     stats.Path,
				Detail:   fmt.Sprintf("entry %q expands to %d bytes", e.Name, e.UncompressedSize),
				Severity: SevSuspicious,
			})
		}
	}

	// Nested archive.
	for _, e := range stats.Entries {
		if e.IsNested {
			out = append(out, CompressionFinding{
				Signal:   SigNestedArchive,
				Path:     stats.Path,
				Detail:   fmt.Sprintf("entry %q is a %s archive", e.Name, e.NestedFormat),
				Severity: SevSuspicious,
			})
		}
	}

	// Quine: an archive whose entry name matches its own name and whose
	// ratio is ~1:1 — classic zip-quine signature.
	for _, e := range stats.Entries {
		if e.Name == filepath.Base(stats.Path) && e.Ratio >= 0.95 && e.Ratio <= 1.05 {
			out = append(out, CompressionFinding{
				Signal:   SigQuine,
				Path:     stats.Path,
				Detail:   fmt.Sprintf("entry %q matches archive name with 1:1 ratio (quine)", e.Name),
				Severity: SevCritical,
			})
		}
	}

	if stats.IsEncrypted {
		out = append(out, CompressionFinding{
			Signal:   SigEncryptedZip,
			Path:     stats.Path,
			Detail:   "encrypted archive — content not scannable without password",
			Severity: SevSuspicious,
		})
	}
	if stats.IsSplit {
		out = append(out, CompressionFinding{
			Signal:   SigSplitArchive,
			Path:     stats.Path,
			Detail:   "split/multi-volume archive — requires all parts to scan",
			Severity: SevSuspicious,
		})
	}
	return out
}

// ---------------------------------------------------------------------------
// Unpacker process detection — who extracted us?
// ---------------------------------------------------------------------------

// detectUnpackers checks the process list and our own ancestry for
// compression tools.
func (ac *AntiCompression) detectUnpackers() []UnpackerProcess {
	if runtime.GOOS != "windows" {
		return nil
	}
	var out []UnpackerProcess
	seen := make(map[string]struct{})

	// 1. Walk the process list (via tasklist — low-friction and non-invasive).
	if procs, err := listProcesses(); err == nil {
		for _, p := range procs {
			nameLower := strings.ToLower(p.Name)
			for _, u := range ac.UnpackerNames {
				if nameLower == u {
					key := nameLower
					if _, ok := seen[key]; ok {
						continue
					}
					seen[key] = struct{}{}
					out = append(out, UnpackerProcess{
						Name:     p.Name,
						PID:      p.PID,
						Kind:     "extractor",
						Detail:   "unpacker process currently running",
						Severity: SevSuspicious,
					})
					break
				}
			}
		}
	}

	// 2. Walk our own process ancestry to see if a decompressor launched us.
	if ancestors, err := processAncestry(); err == nil {
		for _, a := range ancestors {
			nameLower := strings.ToLower(a.Name)
			for _, u := range ac.UnpackerNames {
				if nameLower == u {
					key := "ancestor:" + nameLower
					if _, ok := seen[key]; ok {
						continue
					}
					seen[key] = struct{}{}
					out = append(out, UnpackerProcess{
						Name:     a.Name,
						PID:      a.PID,
						Kind:     "ancestor",
						Detail:   fmt.Sprintf("launched by %s (PID %d)", a.Name, a.PID),
						Severity: SevCritical,
					})
					break
				}
			}
		}
	}
	return out
}

// procInfo captures one process record.
type procInfo struct {
	Name string
	PID  uint32
	PPID uint32
}

// listProcesses walks the running process list via Toolhelp32Snapshot.
func listProcesses() ([]procInfo, error) {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	createSnapshot := kernel32.NewProc("CreateToolhelp32Snapshot")
	processFirst := kernel32.NewProc("Process32FirstW")
	processNext := kernel32.NewProc("Process32NextW")
	closeHandle := kernel32.NewProc("CloseHandle")

	const th32csSnapProcess = 0x00000002

	snap, _, _ := createSnapshot.Call(th32csSnapProcess, 0)
	// INVALID_HANDLE_VALUE
	if snap == 0 || snap == ^uintptr(0) {
		return nil, errors.New("CreateToolhelp32Snapshot failed")
	}
	defer closeHandle.Call(snap)

	// PROCESSENTRY32W layout.
	type processEntry32 struct {
		Size              uint32
		CntUsage          uint32
		ProcessID         uint32
		DefaultHeapID     uintptr
		ModuleID          uint32
		CntThreads        uint32
		ParentProcessID   uint32
		PriClassBase      int32
		Flags             uint32
		ExeFile           [260]uint16
	}

	var pe processEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))

	ret, _, _ := processFirst.Call(snap, uintptr(unsafe.Pointer(&pe)))
	if ret == 0 {
		return nil, nil
	}
	var out []procInfo
	for {
		name := syscall.UTF16ToString(pe.ExeFile[:])
		out = append(out, procInfo{
			Name: name,
			PID:  pe.ProcessID,
			PPID: pe.ParentProcessID,
		})
		ret, _, _ := processNext.Call(snap, uintptr(unsafe.Pointer(&pe)))
		if ret == 0 {
			break
		}
		if len(out) > 4096 {
			break
		}
	}
	return out, nil
}

// processAncestry returns the chain of parent processes of the current
// process, from immediate parent upward.
func processAncestry() ([]procInfo, error) {
	procs, err := listProcesses()
	if err != nil {
		return nil, err
	}
	byPID := make(map[uint32]procInfo, len(procs))
	for _, p := range procs {
		byPID[p.PID] = p
	}
	self := uint32(os.Getpid())
	var chain []procInfo
	cur := self
	for i := 0; i < 16; i++ {
		p, ok := byPID[cur]
		if !ok {
			break
		}
		if p.PPID == 0 || p.PPID == cur {
			break
		}
		parent, ok := byPID[p.PPID]
		if !ok {
			break
		}
		chain = append(chain, parent)
		cur = parent.PID
	}
	return chain, nil
}

// ---------------------------------------------------------------------------
// In-memory decompression-buffer detection
// ---------------------------------------------------------------------------

// detectMemoryBuffers looks for RWX or readable-writable non-file-backed
// regions larger than 1 MiB, which are typical of decompression buffers.
// Reuses VirtualQuery walking from ScanRWX in antihook.go — that's the
// shared primitive; here we add size and owner filtering.
func (ac *AntiCompression) detectMemoryBuffers() []CompressionFinding {
	if runtime.GOOS != "windows" {
		return nil
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

	var out []CompressionFinding
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
		// MEM_COMMIT + MEM_PRIVATE + large enough to be a decompression
		// buffer, and RW or RWX.
		const (
			memCommit  = 0x1000
			memPrivate = 0x20000
			pageRW     = 0x04
			pageRWX    = 0x40
		)
		if mbi.State == memCommit &&
			mbi.Type == memPrivate &&
			mbi.RegionSize >= 1<<20 &&
			(mbi.Protect == pageRW || mbi.Protect == pageRWX) {
			out = append(out, CompressionFinding{
				Signal:   SigMemBuffer,
				Path:     fmt.Sprintf("%#x", mbi.BaseAddress),
				Detail:   fmt.Sprintf("%.1f MiB RW%s private region — possible decompression buffer", float64(mbi.RegionSize)/(1<<20), rwxSuffix(mbi.Protect)),
				Severity: SevSuspicious,
			})
		}
		next := mbi.BaseAddress + mbi.RegionSize
		if next <= addr {
			break
		}
		addr = next
	}
	return out
}

// rwxSuffix returns "X" if the region is executable, "" otherwise.
func rwxSuffix(protect uint32) string {
	if protect == 0x40 || protect == 0x80 {
		return "X"
	}
	return ""
}

// ---------------------------------------------------------------------------
// Safe decompression paths
// ---------------------------------------------------------------------------

// safeDecompressionPaths returns directories where extracting an archive
// won't trigger archive-extraction heuristics (typically AV-whitelisted
// temp/WER dirs and non-MOTW-supporting mounts).
func (ac *AntiCompression) safeDecompressionPaths() []string {
	var out []string
	seen := make(map[string]struct{})
	for _, p := range ac.SafeExtractPaths {
		if p == "" {
			continue
		}
		if err := writeProbe(p); err != nil {
			continue
		}
		key := strings.ToLower(p)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, p)
	}
	return out
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

// CompressionReport is the module's output.
type CompressionReport struct {
	SelfArchive   *ArchiveStats
	Neighbor      []*ArchiveStats
	Findings      []CompressionFinding
	Unpackers     []UnpackerProcess
	SafeExtract   []string
	NestingDepth  int
	CompositeRisk PatchSeverity
	Notes         string
}

// Scan runs the full anti-compression pipeline.
func (ac *AntiCompression) Scan() *CompressionReport {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	rep := &CompressionReport{}

	// 1. Analyze self if we're an archive (rare but possible — self-extracting).
	selfPath, _ := os.Executable()
	if selfPath != "" {
		if ext := strings.ToLower(filepath.Ext(selfPath)); ext != "" {
			if _, ok := ac.ArchiveExts[ext]; ok {
				if stats, err := ac.analyzeArchive(selfPath); err == nil {
					rep.SelfArchive = stats
					rep.Findings = append(rep.Findings, ac.assessArchive(stats)...)
				}
			}
		}
	}

	// 2. Analyze archives in the same directory (may be siblings of our
	//    extraction point).
	if dir, err := os.ReadDir(filepath.Dir(selfPath)); err == nil {
		count := 0
		for _, e := range dir {
			if count >= ac.MaxNestedScan {
				break
			}
			if e.IsDir() {
				continue
			}
			ext := strings.ToLower(filepath.Ext(e.Name()))
			if _, ok := ac.ArchiveExts[ext]; !ok {
				continue
			}
			full := filepath.Join(filepath.Dir(selfPath), e.Name())
			if stats, err := ac.analyzeArchive(full); err == nil {
				rep.Neighbor = append(rep.Neighbor, stats)
				rep.Findings = append(rep.Findings, ac.assessArchive(stats)...)
				count++
			}
		}
	}

	// 3. Nesting depth: for each neighbor, count how many levels deep it
	//    contains archives. Bounded by MaxNestedScan to avoid unbounded
	//    work on malicious input.
	for _, stats := range rep.Neighbor {
		depth := ac.computeNestingDepth(stats, 0, ac.MaxNestedScan)
		if depth > rep.NestingDepth {
			rep.NestingDepth = depth
		}
		if depth >= ac.MaxNestingDepth {
			rep.Findings = append(rep.Findings, CompressionFinding{
				Signal:   SigDeepNesting,
				Path:     stats.Path,
				Detail:   fmt.Sprintf("%d levels of nesting", depth),
				Severity: SevCritical,
			})
		}
	}

	// 4. Running unpackers / ancestry.
	rep.Unpackers = ac.detectUnpackers()
	for _, u := range rep.Unpackers {
		if u.Kind == "ancestor" {
			rep.Findings = append(rep.Findings, CompressionFinding{
				Signal:   SigUnpackerParent,
				Path:     u.Name,
				Detail:   u.Detail,
				Severity: SevCritical,
			})
		} else {
			rep.Findings = append(rep.Findings, CompressionFinding{
				Signal:   SigDecompressor,
				Path:     u.Name,
				Detail:   u.Detail,
				Severity: u.Severity,
			})
		}
	}

	// 5. Memory buffers.
	rep.Findings = append(rep.Findings, ac.detectMemoryBuffers()...)

	// 6. Safe extraction paths.
	rep.SafeExtract = ac.safeDecompressionPaths()

	// Composite risk from findings.
	rep.CompositeRisk = SevInfo
	crit := 0
	for _, f := range rep.Findings {
		if f.Severity == SevCritical {
			crit++
		}
	}
	if crit > 0 {
		rep.CompositeRisk = SevCritical
	} else if len(rep.Findings) > 0 {
		rep.CompositeRisk = SevSuspicious
	}

	var notes []string
	if rep.SelfArchive != nil {
		notes = append(notes, "self is archive")
	}
	if n := len(rep.Neighbor); n > 0 {
		notes = append(notes, fmt.Sprintf("%d neighbor archives", n))
	}
	if rep.NestingDepth > 0 {
		notes = append(notes, fmt.Sprintf("nesting depth=%d", rep.NestingDepth))
	}
	if n := len(rep.Unpackers); n > 0 {
		notes = append(notes, fmt.Sprintf("%d unpackers", n))
	}
	if crit > 0 {
		notes = append(notes, fmt.Sprintf("%d critical", crit))
	}
	rep.Notes = strings.Join(notes, "; ")
	return rep
}

// computeNestingDepth counts nested archives up to maxDepth levels.
func (ac *AntiCompression) computeNestingDepth(stats *ArchiveStats, depth, maxDepth int) int {
	if depth >= maxDepth || stats == nil {
		return depth
	}
	maxChild := depth
	for _, e := range stats.Entries {
		if !e.IsNested {
			continue
		}
		// We can't descend into nested archives without extracting them
		// (which this module deliberately avoids). Instead, count the
		// nesting presence as one level and stop.
		if depth+1 > maxChild {
			maxChild = depth + 1
		}
	}
	return maxChild
}

// ---------------------------------------------------------------------------
// Reporting helpers
// ---------------------------------------------------------------------------

// Summary returns a one-line status.
func (r *CompressionReport) Summary() string {
	if r == nil {
		return "no compression analysis"
	}
	parts := []string{fmt.Sprintf("risk=%s", r.CompositeRisk)}
	if r.SelfArchive != nil {
		parts = append(parts, fmt.Sprintf("self=%s", r.SelfArchive.Format))
	}
	if n := len(r.Neighbor); n > 0 {
		parts = append(parts, fmt.Sprintf("neighbors=%d", n))
	}
	if r.NestingDepth > 0 {
		parts = append(parts, fmt.Sprintf("nesting=%d", r.NestingDepth))
	}
	if n := len(r.Unpackers); n > 0 {
		parts = append(parts, fmt.Sprintf("unpackers=%d", n))
	}
	return strings.Join(parts, " ")
}

// CriticalFindings returns only the SevCritical findings.
func (r *CompressionReport) CriticalFindings() []CompressionFinding {
	if r == nil {
		return nil
	}
	var out []CompressionFinding
	for _, f := range r.Findings {
		if f.Severity == SevCritical {
			out = append(out, f)
		}
	}
	return out
}

// CrossReference joins compression findings with the sibling modules.
func (ac *AntiCompression) CrossReference(cr *CompressionReport, zip *SelfArchiveReport, pomp *POMPReport, hooks *HookMap, patches []PatchReport) string {
	var parts []string
	if cr != nil && cr.CompositeRisk != SevInfo {
		parts = append(parts, fmt.Sprintf("compression=%s", cr.CompositeRisk))
	}
	if zip != nil && zip.IsMOTWTainted() {
		parts = append(parts, "motw=tainted")
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

// time referenced to avoid unused-import if this file is built alone.
var _ = time.Now

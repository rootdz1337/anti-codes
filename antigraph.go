package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// ============================================================================
// Anti-Graph Module
//
// Builds a behavioral-genealogy graph for the current process and correlates
// all sibling modules' findings (antipatch, antihook, antipomp, antizip,
// anticomprese) into a per-node suspicion score.
//
// A node = one process in the ancestry chain OR a shell/infrastructure
// component (service, mount, archive). Edges = spawn relationships.
//
// Used to answer: "Am I an outlier on this host?" — a payload spawned from
// explorer.exe in Downloads is far more suspicious than one spawned from
// services.exe in C:\Program Files. Same code, different graph position.
//
// All operations are read-only.
// ============================================================================

// NodeKind classifies a graph node.
type NodeKind string

const (
	NodeProcess   NodeKind = "process"   // a running process
	NodeService   NodeKind = "service"   // a Windows service (hosting our EDR, etc.)
	NodeContainer NodeKind = "container" // archive/mount we came from
	NodeFile      NodeKind = "file"      // file marker (MOTW source, dropped artifact)
)

// GraphNode is one process/service/container in the genealogy.
type GraphNode struct {
	Kind       NodeKind
	Name       string
	PID        uint32
	Path       string
	ParentPID  uint32
	Children   []uint32
	Depth      int    // 0 = self, 1 = parent, 2 = grandparent, ...
	Signed     Signer
	Trust      TrustLevel
	Suspicion  int    // 0–100
	Tags       []string
	Notes      string
}

// Signer captures Authenticode signing status of a binary.
type Signer struct {
	Signed     bool
	Publisher  string // e.g. "Microsoft Corporation"
	IsMicrosoft bool
	IsThirdPartyEDR bool
}

// TrustLevel classifies a node's trust posture.
type TrustLevel string

const (
	TrustSystem    TrustLevel = "system"     // signed by MS, in System32
	TrustVendor    TrustLevel = "vendor"     // signed by known vendor
	TrustUser      TrustLevel = "user"       // unsigned / user-writable
	TrustSuspicious TrustLevel = "suspicious" // unsigned from user-writable dir
	TrustUnknown   TrustLevel = "unknown"
)

// GraphEdge is a spawn relationship.
type GraphEdge struct {
	From   uint32
	To     uint32
	Reason string
}

// GraphReport is the module's output.
type GraphReport struct {
	Self        *GraphNode
	Nodes       []*GraphNode
	Edges       []GraphEdge
	RootPID     uint32
	MaxDepth    int
	OutlierScore int    // 0–100: how much of an outlier *we* are
	OutlierTags []string
	Notes       string
}

// AntiGraph is the scanner.
type AntiGraph struct {
	// UserWritablePaths are directory prefixes that make an unsigned binary
	// automatically suspicious.
	UserWritablePaths []string

	// MicrosoftSystemRoot is where MS-signed system binaries live.
	MicrosoftSystemRoot string

	// TrustedPublishers are publisher strings for known-safe vendors.
	TrustedPublishers []string

	// EdrPublishers are publishers that indicate an EDR node.
	EdrPublishers []string

	// MaxAncestryDepth caps the graph walk.
	MaxAncestryDepth int

	// CrossModuleInputs holds the sibling reports for correlation.
	CrossModuleInputs *CrossModuleInputs

	mu sync.Mutex
}

// CrossModuleInputs bundles findings from all sibling modules.
type CrossModuleInputs struct {
	Patches    []PatchReport
	Hooks      *HookMap
	POMP       *POMPReport
	Zip        *SelfArchiveReport
	Compression *CompressionReport
}

// DefaultAntiGraph returns a configuration with the standard Windows paths
// and publisher allowlist.
func DefaultAntiGraph() *AntiGraph {
	return &AntiGraph{
		UserWritablePaths: []string{
			`\users\`, `\temp\`, `\tmp\`, `\downloads\`,
			`\appdata\`, `\public\`, `\desktop\`, `\documents\`,
			`\perflogs\`, `\programdata\`,
		},
		MicrosoftSystemRoot: `C:\Windows\System32\`,
		TrustedPublishers: []string{
			"microsoft corporation", "microsoft windows",
			"microsoft® windows® operating system",
		},
		EdrPublishers: []string{
			"crowdstrike", "sentinelone", "carbon black", "vmware carbon black",
			"cisco", "trend micro", "mcafee", "symantec", "broadcom",
			"kaspersky", "eset", "sophos", "trellix", "cybereason",
			"palo alto networks", "fortinet", "check point",
		},
		MaxAncestryDepth: 16,
		CrossModuleInputs: &CrossModuleInputs{},
	}
}

// ---------------------------------------------------------------------------
// Process tree enumeration
// ---------------------------------------------------------------------------

// rawProc is one row from Toolhelp32 with extra metadata.
type rawProc struct {
	Name      string
	PID       uint32
	PPID      uint32
	ExePath   string
	SessionID uint32
}

// listProcessesFull walks the process list and resolves each process's
// on-disk image path via QueryFullProcessImageNameW.
func (ag *AntiGraph) listProcessesFull() ([]rawProc, error) {
	if runtime.GOOS != "windows" {
		return nil, nil
	}
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	createSnapshot := kernel32.NewProc("CreateToolhelp32Snapshot")
	processFirst := kernel32.NewProc("Process32FirstW")
	processNext := kernel32.NewProc("Process32NextW")
	closeHandle := kernel32.NewProc("CloseHandle")
	openProcess := kernel32.NewProc("OpenProcess")
	queryFullProcessImageName := kernel32.NewProc("QueryFullProcessImageNameW")
	processIdToSessionId := kernel32.NewProc("ProcessIdToSessionId")

	const th32csSnapProcess = 0x00000002

	snap, _, _ := createSnapshot.Call(th32csSnapProcess, 0)
	if snap == 0 || snap == ^uintptr(0) {
		return nil, errors.New("CreateToolhelp32Snapshot failed")
	}
	defer closeHandle.Call(snap)

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

	var out []rawProc
	for {
		name := syscall.UTF16ToString(pe.ExeFile[:])
		pid := pe.ProcessID
		ppid := pe.ParentProcessID

		// Resolve image path. PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
		var path string
		if h, _, _ := openProcess.Call(0x1000, 0, uintptr(pid)); h != 0 {
			var buf [syscall.MAX_PATH]uint16
			size := uint32(len(buf))
			r, _, _ := queryFullProcessImageName.Call(h, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
			if r != 0 {
				path = syscall.UTF16ToString(buf[:size])
			}
			closeHandle.Call(h)
		}

		// Resolve session ID (0=services, 1+=interactive).
		var sessionID uint32
		processIdToSessionId.Call(uintptr(pid), uintptr(unsafe.Pointer(&sessionID)))

		out = append(out, rawProc{
			Name: name, PID: pid, PPID: ppid,
			ExePath: path, SessionID: sessionID,
		})
		ret, _, _ = processNext.Call(snap, uintptr(unsafe.Pointer(&pe)))
		if ret == 0 {
			break
		}
		if len(out) > 8192 {
			break
		}
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Signature verification
// ---------------------------------------------------------------------------

// verifySigner checks whether a file is Authenticode-signed and extracts
// the publisher. Uses WinVerifyTrust (soft fail — missing signature is
// reported, not treated as an error).
func verifySigner(path string) Signer {
	if runtime.GOOS != "windows" || path == "" {
		return Signer{}
	}
	// Use PowerShell Get-AuthenticodeSignature — simplest stdlib-only path.
	// A production tool would call WinVerifyTrust + CryptQueryObject.
	cmd := "powershell -NoProfile -Command \"$s = Get-AuthenticodeSignature '" +
		strings.ReplaceAll(path, "'", "''") +
		"'; Write-Output ($s.Status.ToString() + '|' + $s.SignerCertificate.Subject)\""
	out, err := runPowershell(cmd)
	if err != nil {
		return Signer{}
	}
	out = strings.TrimSpace(out)
	if out == "" || strings.HasPrefix(out, "NotSigned") || strings.Contains(out, "HashMismatch") {
		return Signer{}
	}
	parts := strings.SplitN(out, "|", 2)
	if len(parts) != 2 || parts[1] == "" {
		return Signer{}
	}
	pub := parts[1]
	// Subject is "CN=Microsoft Corporation, O=Microsoft Corporation, ..."
	cn := extractCN(pub)
	s := Signer{Signed: true, Publisher: cn}
	lower := strings.ToLower(cn)
	if strings.Contains(lower, "microsoft") {
		s.IsMicrosoft = true
	}
	for _, edr := range DefaultAntiGraph().EdrPublishers {
		if strings.Contains(lower, edr) {
			s.IsThirdPartyEDR = true
			break
		}
	}
	return s
}

// extractCN pulls the CN=... component out of an X.500 subject.
func extractCN(subject string) string {
	for _, part := range strings.Split(subject, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToUpper(part), "CN=") {
			return strings.TrimSpace(part[3:])
		}
	}
	return subject
}

// runPowershell executes a PowerShell one-liner and returns stdout.
// Kept as a separate function so it's swappable in tests.
func runPowershell(cmd string) (string, error) {
	c := execCommand("cmd.exe", "/c", cmd)
	out, err := c.Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// execCommand is a thin alias so we don't shadow os/exec across files.
var execCommand = func(name string, args ...string) interface {
	Output() ([]byte, error)
} {
	return &cmdRunner{name: name, args: args}
}

type cmdRunner struct {
	name string
	args []string
}

func (c *cmdRunner) Output() ([]byte, error) {
	return runExternal(c.name, c.args...)
}

// runExternal is provided by the shared package helper (see antipatch.go
// or add a stub if not present).
var runExternal = func(name string, args ...string) ([]byte, error) {
	return nil, errors.New("runExternal not wired")
}

// ---------------------------------------------------------------------------
// Trust classification
// ---------------------------------------------------------------------------

// classifyTrust determines a node's TrustLevel from its path and signature.
func (ag *AntiGraph) classifyTrust(path string, sig Signer) TrustLevel {
	if path == "" {
		return TrustUnknown
	}
	lp := strings.ToLower(path)
	inSystem := strings.HasPrefix(lp, strings.ToLower(ag.MicrosoftSystemRoot))
	inUserWritable := false
	for _, p := range ag.UserWritablePaths {
		if strings.Contains(lp, p) {
			inUserWritable = true
			break
		}
	}

	if sig.IsMicrosoft && inSystem {
		return TrustSystem
	}
	if sig.IsMicrosoft {
		return TrustSystem // MS-signed anywhere is still system trust
	}
	if sig.Signed {
		for _, pub := range ag.TrustedPublishers {
			if strings.Contains(strings.ToLower(sig.Publisher), pub) {
				return TrustVendor
			}
		}
		if sig.IsThirdPartyEDR {
			return TrustVendor
		}
		return TrustVendor
	}
	if inUserWritable {
		return TrustSuspicious
	}
	return TrustUser
}

// ---------------------------------------------------------------------------
// Genealogy construction
// ---------------------------------------------------------------------------

// buildGraph constructs the ancestry graph and scores each node.
func (ag *AntiGraph) buildGraph() *GraphReport {
	procs, err := ag.listProcessesFull()
	if err != nil || len(procs) == 0 {
		return &GraphReport{Notes: "process enumeration failed"}
	}

	byPID := make(map[uint32]*rawProc, len(procs))
	for i := range procs {
		byPID[procs[i].PID] = &procs[i]
	}

	selfPID := uint32(os.Getpid())
	selfProc, ok := byPID[selfPID]
	if !ok {
		return &GraphReport{Notes: "self not in process list"}
	}

	rep := &GraphReport{RootPID: selfPID}
	seen := make(map[uint32]bool)
	cur := selfProc
	depth := 0
	for {
		if cur == nil || seen[cur.PID] || depth > ag.MaxAncestryDepth {
			break
		}
		seen[cur.PID] = true

		node := &GraphNode{
			Kind:      NodeProcess,
			Name:      cur.Name,
			PID:       cur.PID,
			Path:      cur.ExePath,
			ParentPID: cur.PPID,
			Depth:     depth,
		}
		node.Signed = verifySigner(cur.ExePath)
		node.Trust = ag.classifyTrust(cur.ExePath, node.Signed)
		rep.Nodes = append(rep.Nodes, node)
		if depth == 0 {
			rep.Self = node
		}
		if depth > 0 {
			// Edge from parent -> current.
			rep.Edges = append(rep.Edges, GraphEdge{
				From:   cur.PPID,
				To:     cur.PID,
				Reason: "spawn",
			})
		}

		next, ok := byPID[cur.PPID]
		if !ok {
			break
		}
		cur = next
		depth++
	}
	rep.MaxDepth = depth

	// Score each node.
	for _, n := range rep.Nodes {
		n.Suspicion = ag.scoreNode(n, rep)
	}
	rep.OutlierScore, rep.OutlierTags = ag.scoreOutlier(rep)
	return rep
}

// ---------------------------------------------------------------------------
// Per-node suspicion scoring
// ---------------------------------------------------------------------------

// scoreNode assigns a 0–100 suspicion score to one graph node.
func (ag *AntiGraph) scoreNode(n *GraphNode, rep *GraphReport) int {
	score := 0
	var tags []string

	// Trust level.
	switch n.Trust {
	case TrustSuspicious:
		score += 40
		tags = append(tags, "unsigned-user-writable")
	case TrustUser:
		score += 20
		tags = append(tags, "unsigned")
	case TrustSystem, TrustVendor:
		// no penalty
	}

	// Position: services session (0) is much safer than interactive (1+).
	if n.Kind == NodeProcess && n.Depth == 0 {
		// Check our session ID via self proc — only meaningful for self.
		// (Simplified: assume session 1 unless Path suggests otherwise.)
	}

	// Cross-module correlation for the self node.
	if n.Depth == 0 && ag.CrossModuleInputs != nil {
		ci := ag.CrossModuleInputs

		if len(ci.Patches) > 0 {
			crit := 0
			for _, p := range ci.Patches {
				if p.Severity == SevCritical {
					crit++
				}
			}
			if crit > 0 {
				score += 15
				tags = append(tags, fmt.Sprintf("patched:%d", crit))
			}
		}

		if ci.Hooks != nil {
			if c := ci.Hooks.CriticalCount(); c > 0 {
				score += 10
				tags = append(tags, fmt.Sprintf("hooked:%d", c))
			}
		}

		if ci.POMP != nil {
			switch ci.POMP.State {
			case CertEDRValidated:
				score += 25
				tags = append(tags, "edr-validated")
			case CertRecentlyRun:
				score += 20
				tags = append(tags, "edr-recent")
			case CertEDRBlind:
				score += 5 // EDR blind is *good* for us
				tags = append(tags, "edr-blind")
			}
		}

		if ci.Zip != nil {
			if ci.Zip.IsMOTWTainted() {
				score += 15
				tags = append(tags, "motw-tainted")
			}
			if ci.Zip.Container.MountPoint != "" {
				score += 10
				tags = append(tags, "mounted")
			}
		}

		if ci.Compression != nil {
			switch ci.Compression.CompositeRisk {
			case SevCritical:
				score += 20
				tags = append(tags, "compression-critical")
			case SevSuspicious:
				score += 10
				tags = append(tags, "compression-suspicious")
			}
			if ci.Compression.NestingDepth >= 3 {
				score += 10
				tags = append(tags, "deep-nesting")
			}
		}
	}

	// Ancestor chain: EDR tooling as a parent is high-signal.
	for _, other := range rep.Nodes {
		if other.Depth <= n.Depth {
			continue
		}
		if other.Signed.IsThirdPartyEDR {
			score += 5
			tags = append(tags, "edr-in-chain")
			break
		}
	}

	// Child process of an unpacker in the chain.
	for _, e := range rep.Edges {
		if e.To == n.PID && n.Depth > 0 {
			// Any lower-trust parent makes the child more suspicious.
			for _, parent := range rep.Nodes {
				if parent.PID == e.From && parent.Trust == TrustSuspicious {
					score += 10
					tags = append(tags, "parent-suspicious")
					break
				}
			}
		}
	}

	if score > 100 {
		score = 100
	}
	n.Tags = dedupStrings(tags)
	return score
}

// scoreOutlier computes the composite outlier score for the self node,
// adjusted by its position in the graph.
func (ag *AntiGraph) scoreOutlier(rep *GraphReport) (int, []string) {
	if rep.Self == nil {
		return 0, nil
	}
	score := rep.Self.Suspicion
	tags := append([]string{}, rep.Self.Tags...)

	// Parent trust bonus.
	if len(rep.Nodes) >= 2 {
		parent := rep.Nodes[1]
		switch parent.Trust {
		case TrustSystem, TrustVendor:
			score -= 15
			tags = append(tags, "parent-trusted")
		case TrustSuspicious:
			score += 15
			tags = append(tags, "parent-suspicious")
		}
		if parent.Signed.IsThirdPartyEDR {
			score += 10
			tags = append(tags, "parent-is-edr")
		}
	}

	// Depth: very shallow chains (self spawned directly by explorer) are
	// higher-signal than deep chains (self under a service wrapper).
	if rep.MaxDepth <= 1 {
		score += 5
	}

	// Unpacker somewhere in the ancestry.
	for _, n := range rep.Nodes {
		if n.Depth > 0 && isUnpackerName(n.Name) {
			score += 20
			tags = append(tags, "unpacker-in-chain")
			break
		}
	}

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return score, dedupStrings(tags)
}

// isUnpackerName is a small convenience for chain analysis.
func isUnpackerName(name string) bool {
	l := strings.ToLower(name)
	for _, u := range []string{"7z", "winrar", "rar.exe", "unrar", "winzip", "peazip", "bandizip", "expand.exe", "extrac32", "makecab"} {
		if strings.HasPrefix(l, u) {
			return true
		}
	}
	return false
}

// dedupStrings removes duplicates while preserving order.
func dedupStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := in[:0]
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

// TopAncestors returns up to n ancestors sorted by suspicion (highest first).
// Useful for logging just the interesting parts of a long chain.
func (r *GraphReport) TopAncestors(n int) []*GraphNode {
	if r == nil {
		return nil
	}
	var anc []*GraphNode
	for _, node := range r.Nodes {
		if node.Depth == 0 {
			continue
		}
		anc = append(anc, node)
	}
	sort.Slice(anc, func(i, j int) bool {
		return anc[i].Suspicion > anc[j].Suspicion
	})
	if n > 0 && len(anc) > n {
		anc = anc[:n]
	}
	return anc
}

// Chain returns "self <- parent <- grandparent ..." as a compact string.
func (r *GraphReport) Chain() string {
	if r == nil || len(r.Nodes) == 0 {
		return ""
	}
	names := make([]string, 0, len(r.Nodes))
	for _, n := range r.Nodes {
		names = append(names, fmt.Sprintf("%s(%d)", n.Name, n.PID))
	}
	return strings.Join(names, " <- ")
}

// Summary returns a one-line status.
func (r *GraphReport) Summary() string {
	if r == nil {
		return "no graph analysis"
	}
	parts := []string{
		fmt.Sprintf("outlier=%d", r.OutlierScore),
		fmt.Sprintf("depth=%d", r.MaxDepth),
	}
	if r.Self != nil {
		parts = append(parts, fmt.Sprintf("self-trust=%s", r.Self.Trust))
	}
	if len(r.OutlierTags) > 0 {
		parts = append(parts, strings.Join(r.OutlierTags, ","))
	}
	return strings.Join(parts, " ")
}

// IsHighRisk returns true if the outlier score exceeds the given threshold
// (default: 60 if passed 0).
func (r *GraphReport) IsHighRisk(threshold int) bool {
	if r == nil {
		return false
	}
	if threshold <= 0 {
		threshold = 60
	}
	return r.OutlierScore >= threshold
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

// Scan builds the graph and correlates with the cross-module inputs.
// Callers must populate ag.CrossModuleInputs before calling Scan.
func (ag *AntiGraph) Scan() *GraphReport {
	ag.mu.Lock()
	defer ag.mu.Unlock()
	return ag.buildGraph()
}

// ScanWith runs the graph build and immediately correlates the given
// cross-module findings.
func (ag *AntiGraph) ScanWith(patches []PatchReport, hooks *HookMap, pomp *POMPReport, zip *SelfArchiveReport, comp *CompressionReport) *GraphReport {
	ag.mu.Lock()
	ag.CrossModuleInputs = &CrossModuleInputs{
		Patches:     patches,
		Hooks:       hooks,
		POMP:        pomp,
		Zip:         zip,
		Compression: comp,
	}
	ag.mu.Unlock()
	return ag.Scan()
}

// time referenced to avoid unused-import if this file is built alone.
var _ = time.Now
var _ = filepath.Join

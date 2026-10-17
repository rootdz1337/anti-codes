package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// ============================================================================
// Anti-EVM Module
//
// Web3 / EVM-aware environmental profiling. Answers:
//
//   1. Is this host a Web3 workstation, validator, or dev box?
//   2. Which wallet extensions are installed in browsers?
//   3. Which wallet desktop apps / hardware-bridge apps are running?
//   4. Are keystores / seed files / .env files reachable?
//   5. Is the host running an EVM node (geth, nethermind, erigon, besu)?
//   6. Are RPC endpoints or chain configs exposed (Anvil, Hardhat, Foundry)?
//
// IMPORTANT: This module NEVER reads, copies, decrypts, or transmits keys,
// seeds, or keystores. It only enumerates the *presence* of artifacts and
// the running state of wallet/EVM-node processes. Reading key material
// would be a crime; mere presence detection is what a defender or a
// scoping assessment needs.
// ============================================================================

// EVMSignal enumerates what an artifact implies about the host.
type EVMSignal string

const (
	SigWalletExtension EVMSignal = "wallet-extension" // browser wallet ext
	SigWalletApp       EVMSignal = "wallet-app"       // desktop wallet
	SigHardwareBridge  EVMSignal = "hw-bridge"        // Ledger/Trezor bridge
	SigEVMNode         EVMSignal = "evm-node"         // geth/erigon/besu/nethermind
	SigDevFramework    EVMSignal = "dev-framework"    // hardhat/anvil/foundry
	SigKeystoreDir     EVMSignal = "keystore-dir"     // geth/eth keystore
	SigSeedFile        EVMSignal = "seed-file"        // mnemonic / seed backup
	SigRPCExposed      EVMSignal = "rpc-exposed"      // local RPC on 8545/8546
	SigConfigFile      EVMSignal = "config-file"      // truffle/hardhat config
	SigEnvFile         EVMSignal = "env-file"         // .env with private keys
	SigSolcArtifacts   EVMSignal = "solc-artifacts"   // .sol sources, ABI JSONs
)

// WalletKind classifies the wallet family.
type WalletKind string

const (
	WalletMetaMask  WalletKind = "metamask"
	WalletPhantom   WalletKind = "phantom"
	WalletCoinbase  WalletKind = "coinbase"
	WalletTrust     WalletKind = "trust"
	WalletRabby     WalletKind = "rabby"
	WalletFrame     WalletKind = "frame"
	WalletLedger    WalletKind = "ledger"
	WalletTrezor    WalletKind = "trezor"
	WalletKeplr     WalletKind = "keplr"     // Cosmos
	WalletKeystone  WalletKind = "keystone"
	WalletUnknown   WalletKind = "unknown"
)

// EVMFinding is one piece of evidence.
type EVMFinding struct {
	Signal   EVMSignal
	Wallet   WalletKind
	Path     string
	PID      uint32
	Detail   string
	Severity PatchSeverity
}

// HostProfile summarizes the host's Web3 posture.
type HostProfile string

const (
	ProfileNone       HostProfile = "none"        // no Web3 artifacts
	ProfileConsumer   HostProfile = "consumer"    // browser wallet, ordinary user
	ProfileTrader     HostProfile = "trader"      // desktop wallets + exchange apps
	ProfileDeveloper  HostProfile = "developer"   // dev framework + .sol sources
	ProfileValidator  HostProfile = "validator"   // running EVM node
	ProfileHWSigner   HostProfile = "hw-signer"   // hardware wallet bridge active
	ProfileMixed      HostProfile = "mixed"       // multiple profiles
)

// EVMReport is the module's output.
type EVMReport struct {
	Profile    HostProfile
	Findings   []EVMFinding
	Wallets    []WalletKind
	EVMNodes   []EVMFinding
	Keystores  []string
	SeedFiles  []string
	RPCs       []EVMFinding
	Confidence int
	Notes      string
}

// AntiEVM is the scanner.
type AntiEVM struct {
	// Browser extension directories — per-browser, per-user.
	BrowserExtPaths []string

	// Desktop wallet install directories.
	DesktopWalletPaths map[WalletKind][]string

	// Hardware bridge process names.
	HWBridgeProcs []string

	// EVM node process names.
	EVMNodeProcs []string

	// Dev framework process names.
	DevFrameworkProcs []string

	// Keystore search paths.
	KeystorePaths []string

	// Seed file name patterns (mnemonic backups).
	SeedFilePatterns []*regexp.Regexp

	// RPC ports to probe on localhost.
	RPCPorts []int

	// Env file globs, relative to HOME and cwd.
	EnvFileGlobs []string

	// Solidity source / ABI dirs, relative to HOME and cwd.
	SolcDirs []string

	// MaxFindings caps enumeration.
	MaxFindings int

	mu sync.Mutex
}

// DefaultAntiEVM returns a configuration covering the mainstream EVM tool
// ecosystem (MetaMask, Phantom, Ledger/Trezor bridges, geth, foundry, etc.).
func DefaultAntiEVM() *AntiEVM {
	home := os.Getenv("USERPROFILE")
	if home == "" {
		home = os.Getenv("HOME")
	}
	appData := os.Getenv("APPDATA")
	localAppData := os.Getenv("LOCALAPPDATA")

	browserExts := []string{
		// Chromium-based extension storage locations
		filepath.Join(localAppData, `Google\Chrome\User Data\Default\Extensions`),
		filepath.Join(localAppData, `Microsoft\Edge\User Data\Default\Extensions`),
		filepath.Join(localAppData, `BraveSoftware\Brave-Browser\User Data\Default\Extensions`),
		filepath.Join(localAppData, `Vivaldi\User Data\Default\Extensions`),
		filepath.Join(localAppData, `Opera Software\Opera Stable\Extensions`),
		// Firefox
		filepath.Join(appData, `Mozilla\Firefox\Profiles`),
	}

	return &AntiEVM{
		BrowserExtPaths: browserExts,
		DesktopWalletPaths: map[WalletKind][]string{
			WalletMetaMask: {
				filepath.Join(localAppData, `MetaMask`),
				filepath.Join(localAppData, `Google\Chrome\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn`),
			},
			WalletPhantom: {
				filepath.Join(appData, `Phantom`),
				filepath.Join(localAppData, `Phantom`),
			},
			WalletCoinbase: {
				filepath.Join(localAppData, `Coinbase Wallet`),
				filepath.Join(appData, `Coinbase Wallet`),
			},
			WalletRabby: {
				filepath.Join(appData, `Rabby`),
				filepath.Join(localAppData, `Rabby`),
			},
			WalletFrame: {
				filepath.Join(localAppData, `Frame`),
			},
			WalletLedger: {
				filepath.Join(localAppData, `Ledger Live`),
			},
			WalletTrezor: {
				filepath.Join(localAppData, `Trezor Suite`),
			},
			WalletKeplr: {
				filepath.Join(appData, `Keplr`),
			},
		},
		HWBridgeProcs: []string{
			"ledger live.exe", "ledgerlive.exe",
			"trezor suite.exe", "trezorsuite.exe",
			"ledger-bridge.exe",
		},
		EVMNodeProcs: []string{
			"geth.exe", "geth",
			"erigon.exe", "erigon",
			"nethermind.exe", "nethermind",
			"besu.exe", "besu",
			"reth.exe", "reth",
			"lighthouse.exe", "prysm.exe", "teku.exe", "nimbus.exe",
		},
		DevFrameworkProcs: []string{
			"anvil.exe", "anvil",
			"hardhat.exe", "hardhat",
			"foundryup.exe",
			"forge.exe", "cast.exe",
		},
		KeystorePaths: []string{
			filepath.Join(appData, `Ethereum\keystore`),
			filepath.Join(home, `.ethereum\keystore`),
			filepath.Join(home, `AppData\Roaming\Ethereum\keystore`),
			filepath.Join(home, `.foundry\keystore`),
		},
		SeedFilePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(seed|mnemonic)[\w\-\. ]*\.(txt|json|bak|enc)$`),
			regexp.MustCompile(`(?i)(recovery|backup)[\w\-\. ]*phrase[\w\-\. ]*\.(txt|json|bak)$`),
			regexp.MustCompile(`(?i)wallet[\w\-\. ]*backup\.(txt|json|bak)$`),
			regexp.MustCompile(`(?i)^\.?secret\.(txt|json)$`),
		},
		RPCPorts: []int{8545, 8546, 8551, 9545, 8547},
		EnvFileGlobs: []string{
			".env", ".env.local", ".env.production",
			".env.development", ".env.secret",
		},
		SolcDirs: []string{
			"contracts", "src/contracts", "solidity",
		},
		MaxFindings: 4096,
	}
}

// ---------------------------------------------------------------------------
// Browser extension detection — folder name matching
// ---------------------------------------------------------------------------

// knownExtensionIDs maps Chromium extension IDs to wallet kinds. These are
// the public store IDs; their presence in a browser profile strongly
// implies the corresponding wallet is installed.
var knownExtensionIDs = map[string]WalletKind{
	"nkbihfbeogaeaoehlefnkodbefgpgknn": WalletMetaMask,
	"bfnaelmomeimhlpmgjnjophhpkkoljpa": WalletPhantom,
	"hnfanknocfeofbddgcijnmhnfnkdnaad": WalletCoinbase,
	"acmacodkjbdgmoleebolmdjonilkdbch": WalletRabby,
	"egjidjbpglichdcondbcbdnbeeppgdph": WalletTrust,
	"dmkamcknogkgcdfhhbddcghachkejeap": WalletKeplr,
	"fmkadmapgofadopljbjfkapdkoienihi": WalletFrame, // devtools-ish, kept broad
}

// scanBrowserExtensions walks each browser extension dir, looking for
// subdirectories whose names match known IDs, OR Firefox profile dirs
// containing wallet-extension markers.
func (ae *AntiEVM) scanBrowserExtensions() []EVMFinding {
	var out []EVMFinding
	seen := make(map[string]struct{})

	for _, dir := range ae.BrowserExtPaths {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			name := strings.ToLower(e.Name())
			// Chromium-style ID match
			if w, ok := knownExtensionIDs[name]; ok {
				full := filepath.Join(dir, e.Name())
				key := "ext:" + strings.ToLower(full)
				if _, dup := seen[key]; dup {
					continue
				}
				seen[key] = struct{}{}
				out = append(out, EVMFinding{
					Signal:   SigWalletExtension,
					Wallet:   w,
					Path:     full,
					Detail:   fmt.Sprintf("%s browser extension installed", w),
					Severity: SevSuspicious,
				})
				continue
			}
			// Firefox-style: profiles are GUID-named dirs, each may contain
			// extensions/ with wallet manifests. Look for "metamask" /
			// "phantom" / etc. inside manifest.json if present.
			if strings.HasPrefix(name, "extensions") || strings.Contains(name, "default") {
				continue
			}
			// Check for a known wallet marker inside the dir.
			marker := filepath.Join(dir, e.Name(), "manifest.json")
			if data, err := os.ReadFile(marker); err == nil {
				low := strings.ToLower(string(data))
				if w := walletFromManifest(low); w != WalletUnknown {
					key := "ext:" + strings.ToLower(marker)
					if _, dup := seen[key]; dup {
						continue
					}
					seen[key] = struct{}{}
					out = append(out, EVMFinding{
						Signal:   SigWalletExtension,
						Wallet:   w,
						Path:     marker,
						Detail:   fmt.Sprintf("%s browser extension installed (manifest hit)", w),
						Severity: SevSuspicious,
					})
				}
			}
		}
	}
	return out
}

// walletFromManifest matches a lower-cased manifest.json against wallet names.
func walletFromManifest(low string) WalletKind {
	switch {
	case strings.Contains(low, "metamask"):
		return WalletMetaMask
	case strings.Contains(low, "phantom wallet") || strings.Contains(low, `"name": "phantom"`):
		return WalletPhantom
	case strings.Contains(low, "coinbase wallet"):
		return WalletCoinbase
	case strings.Contains(low, "rabby"):
		return WalletRabby
	case strings.Contains(low, "trust wallet"):
		return WalletTrust
	case strings.Contains(low, "keplr"):
		return WalletKeplr
	}
	return WalletUnknown
}

// ---------------------------------------------------------------------------
// Desktop wallet app detection
// ---------------------------------------------------------------------------

// scanDesktopWallets checks each configured desktop-wallet path.
func (ae *AntiEVM) scanDesktopWallets() []EVMFinding {
	var out []EVMFinding
	for wallet, paths := range ae.DesktopWalletPaths {
		for _, p := range paths {
			if p == "" {
				continue
			}
			info, err := os.Stat(p)
			if err != nil || !info.IsDir() {
				continue
			}
			out = append(out, EVMFinding{
				Signal:   SigWalletApp,
				Wallet:   wallet,
				Path:     p,
				Detail:   fmt.Sprintf("%s desktop app data present", wallet),
				Severity: SevSuspicious,
			})
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Process detection — nodes, dev frameworks, bridges
// ---------------------------------------------------------------------------

// scanProcesses walks the process list for EVM node, dev-framework, and
// hardware-bridge processes.
func (ae *AntiEVM) scanProcesses() []EVMFinding {
	procs, err := listProcesses()
	if err != nil {
		return nil
	}
	var out []EVMFinding
	for _, p := range procs {
		name := strings.ToLower(p.Name)
		switch {
		case matchName(name, ae.EVMNodeProcs):
			out = append(out, EVMFinding{
				Signal:   SigEVMNode,
				PID:      p.PID,
				Detail:   fmt.Sprintf("EVM node running: %s (PID %d)", p.Name, p.PID),
				Severity: SevCritical,
			})
		case matchName(name, ae.DevFrameworkProcs):
			out = append(out, EVMFinding{
				Signal:   SigDevFramework,
				PID:      p.PID,
				Detail:   fmt.Sprintf("EVM dev framework running: %s (PID %d)", p.Name, p.PID),
				Severity: SevSuspicious,
			})
		case matchName(name, ae.HWBridgeProcs):
			out = append(out, EVMFinding{
				Signal:   SigHardwareBridge,
				PID:      p.PID,
				Detail:   fmt.Sprintf("hardware-wallet bridge running: %s (PID %d)", p.Name, p.PID),
				Severity: SevCritical,
			})
		}
	}
	return out
}

// matchName returns true if name matches any candidate exactly or by prefix.
func matchName(name string, candidates []string) bool {
	for _, c := range candidates {
		if name == strings.ToLower(c) || strings.HasPrefix(name, strings.ToLower(c)) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Keystore and seed-file detection
// ---------------------------------------------------------------------------

// scanKeystores reports reachable keystore directories (never their contents).
func (ae *AntiEVM) scanKeystores() []string {
	var out []string
	for _, dir := range ae.KeystorePaths {
		if dir == "" {
			continue
		}
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}
		out = append(out, dir)
	}
	return out
}

// scanSeedFiles walks well-known user directories looking for filename
// matches against SeedFilePatterns. Filename matching only — files are
// never opened.
func (ae *AntiEVM) scanSeedFiles() []string {
	home := os.Getenv("USERPROFILE")
	if home == "" {
		home = os.Getenv("HOME")
	}
	roots := []string{
		filepath.Join(home, "Desktop"),
		filepath.Join(home, "Documents"),
		filepath.Join(home, "Downloads"),
		filepath.Join(home, "OneDrive"),
	}
	var out []string
	for _, root := range roots {
		if root == "" {
			continue
		}
		_ = filepath.Walk(root, func(path string, fi os.FileInfo, err error) error {
			if err != nil || fi == nil || fi.IsDir() {
				return nil
			}
			name := fi.Name()
			for _, re := range ae.SeedFilePatterns {
				if re.MatchString(name) {
					out = append(out, path)
					break
				}
			}
			if len(out) > ae.MaxFindings {
				return errors.New("cap reached")
			}
			return nil
		})
	}
	return out
}

// ---------------------------------------------------------------------------
// RPC endpoint probing
// ---------------------------------------------------------------------------

// probeRPCs checks localhost RPC ports with a minimal JSON-RPC probe.
// Uses a raw TCP dial (no HTTP client import) — enough to detect listeners.
func (ae *AntiEVM) probeRPCs() []EVMFinding {
	if runtime.GOOS != "windows" && runtime.GOOS != "linux" {
		return nil
	}
	var out []EVMFinding
	for _, port := range ae.RPCPorts {
		addr := fmt.Sprintf("127.0.0.1:%d", port)
		conn, err := dialTCP(addr, 250*time.Millisecond)
		if err != nil {
			continue
		}
		_ = conn.Close()
		out = append(out, EVMFinding{
			Signal:   SigRPCExposed,
			Path:     addr,
			Detail:   fmt.Sprintf("local RPC listener on %s", addr),
			Severity: SevCritical,
		})
	}
	return out
}

// dialTCP is provided by the shared package helper.
var dialTCP = func(addr string, timeout time.Duration) (interface{ Close() error }, error) {
	return netDialTimeout("tcp", addr, timeout)
}

// ---------------------------------------------------------------------------
// Dev-environment artifact detection
// ---------------------------------------------------------------------------

// scanDevArtifacts looks for .env files and Solidity source directories in
// the current directory and immediate parent — the common dev tree layout.
func (ae *AntiEVM) scanDevArtifacts() []EVMFinding {
	var out []EVMFinding
	cwd, err := os.Getwd()
	if err != nil {
		return nil
	}

	// .env files — never open, just presence.
	for _, glob := range ae.EnvFileGlobs {
		p := filepath.Join(cwd, glob)
		if _, err := os.Stat(p); err == nil {
			out = append(out, EVMFinding{
				Signal:   SigEnvFile,
				Path:     p,
				Detail:   fmt.Sprintf("environment file present: %s", glob),
				Severity: SevSuspicious,
			})
		}
	}

	// Solidity source dirs.
	for _, d := range ae.SolcDirs {
		p := filepath.Join(cwd, d)
		info, err := os.Stat(p)
		if err != nil || !info.IsDir() {
			continue
		}
		// Count .sol files, bounded.
		count := 0
		_ = filepath.Walk(p, func(path string, fi os.FileInfo, err error) error {
			if err != nil || fi == nil || fi.IsDir() {
				return nil
			}
			if strings.HasSuffix(strings.ToLower(fi.Name()), ".sol") {
				count++
			}
			if count > 256 {
				return errors.New("cap")
			}
			return nil
		})
		if count > 0 {
			out = append(out, EVMFinding{
				Signal:   SigSolcArtifacts,
				Path:     p,
				Detail:   fmt.Sprintf("%d Solidity source files under %s", count, d),
				Severity: SevSuspicious,
			})
		}
	}

	// Common dev config files.
	for _, f := range []string{
		"hardhat.config.js", "hardhat.config.ts",
		"truffle-config.js", "foundry.toml",
		"package.json", // only flagged if it declares hardhat/ethers/foundry
	} {
		p := filepath.Join(cwd, f)
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if f == "package.json" {
			// Only flag if it declares an EVM dev dependency.
			low := strings.ToLower(string(data))
			if !strings.Contains(low, `"hardhat"`) &&
				!strings.Contains(low, `"ethers"`) &&
				!strings.Contains(low, `"viem"`) &&
				!strings.Contains(low, `"wagmi"`) {
				continue
			}
		}
		out = append(out, EVMFinding{
			Signal:   SigConfigFile,
			Path:     p,
			Detail:   fmt.Sprintf("EVM dev config present: %s", f),
			Severity: SevSuspicious,
		})
	}
	return out
}

// ---------------------------------------------------------------------------
// Profile classification
// ---------------------------------------------------------------------------

// classifyProfile derives the HostProfile from the accumulated findings.
func (ae *AntiEVM) classifyProfile(findings []EVMFinding) HostProfile {
	counts := map[EVMSignal]int{}
	for _, f := range findings {
		counts[f.Signal]++
	}
	hasValidator := counts[SigEVMNode] > 0
	hasDev       := counts[SigDevFramework] > 0 || counts[SigSolcArtifacts] > 0 || counts[SigConfigFile] > 0
	hasWallet    := counts[SigWalletApp] > 0 || counts[SigWalletExtension] > 0
	hasHW        := counts[SigHardwareBridge] > 0

	profiles := 0
	if hasValidator {
		profiles++
	}
	if hasDev {
		profiles++
	}
	if hasWallet {
		profiles++
	}
	if hasHW {
		profiles++
	}
	if profiles == 0 {
		return ProfileNone
	}
	if profiles > 1 {
		return ProfileMixed
	}
	switch {
	case hasValidator:
		return ProfileValidator
	case hasDev:
		return ProfileDeveloper
	case hasHW:
		return ProfileHWSigner
	case hasWallet:
		return ProfileTrader
	}
	return ProfileNone
}

// ---------------------------------------------------------------------------
// Confidence scoring
// ---------------------------------------------------------------------------

// confidence returns 0–100 based on the strength of the evidence.
func (ae *AntiEVM) confidence(rep *EVMReport) int {
	if rep == nil {
		return 0
	}
	score := 0
	for _, f := range rep.Findings {
		switch f.Severity {
		case SevCritical:
			score += 15
		case SevSuspicious:
			score += 5
		case SevInfo:
			score += 1
		}
	}
	switch rep.Profile {
	case ProfileValidator, ProfileHWSigner:
		score += 25
	case ProfileDeveloper:
		score += 15
	case ProfileTrader:
		score += 10
	case ProfileMixed:
		score += 20
	}
	if score > 100 {
		score = 100
	}
	return score
}

// ---------------------------------------------------------------------------
// Orchestration
// ---------------------------------------------------------------------------

// Scan runs the full anti-EVM pipeline.
func (ae *AntiEVM) Scan() *EVMReport {
	ae.mu.Lock()
	defer ae.mu.Unlock()

	rep := &EVMReport{}

	rep.Findings = append(rep.Findings, ae.scanBrowserExtensions()...)
	rep.Findings = append(rep.Findings, ae.scanDesktopWallets()...)
	rep.Findings = append(rep.Findings, ae.scanProcesses()...)
	rep.Keystores = ae.scanKeystores()
	for _, k := range rep.Keystores {
		rep.Findings = append(rep.Findings, EVMFinding{
			Signal:   SigKeystoreDir,
			Path:     k,
			Detail:   "Ethereum keystore directory reachable",
			Severity: SevCritical,
		})
	}
	rep.SeedFiles = ae.scanSeedFiles()
	for _, s := range rep.SeedFiles {
		rep.Findings = append(rep.Findings, EVMFinding{
			Signal:   SigSeedFile,
			Path:     s,
			Detail:   "possible seed/mnemonic backup file (filename match only)",
			Severity: SevCritical,
		})
	}
	rep.RPCs = ae.probeRPCs()
	rep.Findings = append(rep.Findings, rep.RPCs...)
	rep.Findings = append(rep.Findings, ae.scanDevArtifacts()...)

	// Distinct wallets.
	seenW := make(map[WalletKind]struct{})
	for _, f := range rep.Findings {
		if f.Wallet == WalletUnknown || f.Wallet == "" {
			continue
		}
		if _, ok := seenW[f.Wallet]; ok {
			continue
		}
		seenW[f.Wallet] = struct{}{}
		rep.Wallets = append(rep.Wallets, f.Wallet)
	}

	// EVM nodes list.
	for _, f := range rep.Findings {
		if f.Signal == SigEVMNode {
			rep.EVMNodes = append(rep.EVMNodes, f)
		}
	}

	rep.Profile = ae.classifyProfile(rep.Findings)
	rep.Confidence = ae.confidence(rep)

	// Notes.
	var notes []string
	switch rep.Profile {
	case ProfileNone:
		notes = append(notes, "no Web3 artifacts")
	case ProfileValidator:
		notes = append(notes, "EVM node host")
	case ProfileDeveloper:
		notes = append(notes, "Solidity/EVM dev host")
	case ProfileTrader:
		notes = append(notes, "wallet user host")
	case ProfileHWSigner:
		notes = append(notes, "hardware-signer host")
	case ProfileMixed:
		notes = append(notes, "mixed Web3 roles")
	}
	if n := len(rep.Keystores); n > 0 {
		notes = append(notes, fmt.Sprintf("%d keystore dirs", n))
	}
	if n := len(rep.SeedFiles); n > 0 {
		notes = append(notes, fmt.Sprintf("%d seed-file name matches", n))
	}
	if n := len(rep.RPCs); n > 0 {
		notes = append(notes, fmt.Sprintf("%d local RPC listeners", n))
	}
	rep.Notes = strings.Join(notes, "; ")
	return rep
}

// ---------------------------------------------------------------------------
// Cross-reference and reporting helpers
// ---------------------------------------------------------------------------

// Summary returns a compact one-line status.
func (r *EVMReport) Summary() string {
	if r == nil {
		return "no EVM analysis"
	}
	parts := []string{
		fmt.Sprintf("profile=%s", r.Profile),
		fmt.Sprintf("confidence=%d", r.Confidence),
	}
	if n := len(r.Wallets); n > 0 {
		ws := make([]string, 0, n)
		for _, w := range r.Wallets {
			ws = append(ws, string(w))
		}
		parts = append(parts, "wallets="+strings.Join(ws, ","))
	}
	if n := len(r.EVMNodes); n > 0 {
		parts = append(parts, fmt.Sprintf("nodes=%d", n))
	}
	if n := len(r.RPCs); n > 0 {
		parts = append(parts, fmt.Sprintf("rpcs=%d", n))
	}
	return strings.Join(parts, " ")
}

// CriticalFindings returns only SevCritical findings.
func (r *EVMReport) CriticalFindings() []EVMFinding {
	if r == nil {
		return nil
	}
	var out []EVMFinding
	for _, f := range r.Findings {
		if f.Severity == SevCritical {
			out = append(out, f)
		}
	}
	return out
}

// IsCryptoHost returns true if the host shows strong Web3 posture.
func (r *EVMReport) IsCryptoHost() bool {
	if r == nil {
		return false
	}
	switch r.Profile {
	case ProfileValidator, ProfileDeveloper, ProfileHWSigner, ProfileTrader, ProfileMixed:
		return true
	}
	return false
}

// CrossReference combines anti-EVM findings with the sibling modules into
// a single operator-facing line.
func (ae *AntiEVM) CrossReference(evm *EVMReport, graph *GraphReport, pomp *POMPReport, hooks *HookMap, patches []PatchReport) string {
	var parts []string
	if evm != nil && evm.Profile != ProfileNone {
		parts = append(parts, fmt.Sprintf("evm=%s/%d", evm.Profile, evm.Confidence))
	}
	if graph != nil && graph.OutlierScore > 0 {
		parts = append(parts, fmt.Sprintf("outlier=%d", graph.OutlierScore))
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

// HashReport returns the SHA-256 of the (JSON-serialized) report, useful
// for correlating findings across hosts without transmitting content.
func (r *EVMReport) HashReport() (string, error) {
	data, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// ---------------------------------------------------------------------------
// Helpers — provided by the shared package, stubbed here to keep the file
// self-contained enough to compile during review.
// ---------------------------------------------------------------------------

var netDialTimeout = func(network, addr string, timeout time.Duration) (interface{ Close() error }, error) {
	return nil, errors.New("netDialTimeout not wired")
}

// time referenced to avoid unused-import if this file is built alone.
var _ = time.Now
var _ = bytes.Equal
var _ = syscall.Getpid
var _ = unsafe.Pointer(nil)

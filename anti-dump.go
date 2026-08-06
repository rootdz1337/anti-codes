package evasion

import (
    "crypto/rand"
    "fmt"
    "math/big"
    "os"
    "runtime"
    "syscall"
    "time"
    "unsafe"
)

// Windows API constants for anti-debugging
const (
    PROCESS_QUERY_INFORMATION           = 0x0400
    PROCESS_VM_READ                     = 0x0010
    PROCESS_VM_WRITE                    = 0x0020
    PROCESS_VM_OPERATION                = 0x0008
    PROCESS_ALL_ACCESS                  = 0x1F0FFF
    
    // NtQueryInformationProcess classes
    ProcessDebugPort                    = 0x07
    ProcessDebugObjectHandle            = 0x1E
    ProcessDebugFlags                   = 0x1F
    ProcessBasicInformation             = 0x00
    ProcessProtectionInformation        = 0x3D
    ProcessInstrumentationCallback      = 0x28
    
    // Memory protection flags
    PAGE_NOACCESS                       = 0x01
    PAGE_READONLY                       = 0x02
    PAGE_READWRITE                      = 0x04
    PAGE_EXECUTE_READWRITE              = 0x40
    PAGE_EXECUTE_READ                   = 0x20
    PAGE_GUARD                          = 0x100
    PAGE_NOCACHE                        = 0x200
    
    // NtSetInformationProcess
    ProcessProtectionLevel              = 0x3D
    PROCESS_PROTECTION_LEVEL_NONE       = 0x00000000
    PROCESS_PROTECTION_LEVEL_WINTCB_LIGHT = 0x00000001
    PROCESS_PROTECTION_LEVEL_ANTIMALWARE_LIGHT = 0x00000002
    
    // THREAD access
    THREAD_ALL_ACCESS                   = 0x1F03FF
    THREAD_GET_CONTEXT                  = 0x0008
    THREAD_SET_CONTEXT                  = 0x0010
    THREAD_SUSPEND_RESUME               = 0x0002
    THREAD_QUERY_INFORMATION            = 0x0040
    
    // Debugger detection constants
    BeingDebugged                       = 0x02
    NtGlobalFlag                        = 0x70
    HEAP_GROWABLE                       = 0x00000002
    PROCESS_HEAP_FLAGS                  = 0x00000000
    PROCESS_HEAP_ENTRY_BUSY             = 0x0001
)

// Protection configuration
type ProtectionConfig struct {
    ProtectText        bool
    ProtectHeap        bool
    ProtectPEB         bool
    EnableGuardPages   bool
    SetProtectionLevel bool
    AntiDebug          bool
    AntiDump           bool
    SelfDestructOnDetect bool
}

// Anti-debugging detection types
type DebuggerDetection int

const (
    DetectionPEB DebuggerDetection = iota
    DetectionIsDebuggerPresent
    DetectionNtGlobalFlag
    DetectionHeapFlags
    DetectionProcessDebugPort
    DetectionProcessDebugFlags
    DetectionTiming
    DetectionHardwareBreakpoint
    DetectionParentProcess
    DetectionWindowClass
)

// Memory protection manager
type MemoryProtector struct {
    config ProtectionConfig
    baseAddress uintptr
    size uintptr
}

// Global configuration
var defaultProtectionConfig = ProtectionConfig{
    ProtectText:      true,
    ProtectHeap:      true,
    ProtectPEB:       true,
    EnableGuardPages: true,
    SetProtectionLevel: true,
    AntiDebug:        true,
    AntiDump:         true,
    SelfDestructOnDetect: true,
}

// Main protection function with config
func ProtectMemory() error {
    if runtime.GOOS != "windows" {
        return nil
    }
    
    return ProtectMemoryWithConfig(defaultProtectionConfig)
}

// Enhanced protection with configuration
func ProtectMemoryWithConfig(config ProtectionConfig) error {
    if runtime.GOOS != "windows" {
        return nil
    }
    
    var err error
    
    // Protect memory sections
    if config.ProtectText {
        err = protectTextSection()
        if err != nil {
            return fmt.Errorf("failed to protect text section: %v", err)
        }
    }
    
    if config.ProtectHeap {
        err = protectHeap()
        if err != nil {
            return fmt.Errorf("failed to protect heap: %v", err)
        }
    }
    
    if config.EnableGuardPages {
        err = addGuardPages()
        if err != nil {
            return fmt.Errorf("failed to add guard pages: %v", err)
        }
    }
    
    // Set process protection level
    if config.SetProtectionLevel {
        err = setProcessProtectionLevel()
        if err != nil {
            return fmt.Errorf("failed to set protection level: %v", err)
        }
    }
    
    // Anti-dump protection
    if config.AntiDump {
        err = preventMemoryDumping()
        if err != nil {
            return fmt.Errorf("failed to prevent memory dumping: %v", err)
        }
    }
    
    // Anti-debug
    if config.AntiDebug {
        err = enableAntiDebug()
        if err != nil {
            return fmt.Errorf("failed to enable anti-debug: %v", err)
        }
    }
    
    return nil
}

// Protect .text section from being read/written
func protectTextSection() error {
    kernel32 := syscall.NewLazyDLL("kernel32.dll")
    virtualProtect := kernel32.NewProc("VirtualProtect")
    
    // Get current module base address
    modHandle, err := syscall.GetModuleHandle(nil)
    if err != nil {
        return err
    }
    
    // Get module information
    var modInfo syscall.ModuleInfo
    err = syscall.GetModuleInformation(
        syscall.CurrentProcess(),
        modHandle,
        &modInfo,
        uint32(unsafe.Sizeof(modInfo)),
    )
    if err != nil {
        return err
    }
    
    // Protect .text section (usually after PE headers)
    // This is a simplified approach - in production you'd parse PE headers
    textStart := modInfo.BaseOfDll
    textSize := modInfo.SizeOfImage / 2 // Approximate, real implementation would parse PE
    
    var oldProtect uintptr
    ret, _, err := virtualProtect.Call(
        textStart,
        uintptr(textSize),
        uintptr(PAGE_EXECUTE_READ),
        uintptr(unsafe.Pointer(&oldProtect)),
    )
    
    if ret == 0 {
        return fmt.Errorf("VirtualProtect failed: %v", err)
    }
    
    return nil
}

// Protect heap from being dumped
func protectHeap() error {
    kernel32 := syscall.NewLazyDLL("kernel32.dll")
    heapQueryInfo := kernel32.NewProc("HeapQueryInformation")
    heapSetInfo := kernel32.NewProc("HeapSetInformation")
    
    // Get process heap
    getProcessHeap := kernel32.NewProc("GetProcessHeap")
    heapHandle, _, err := getProcessHeap.Call()
    if heapHandle == 0 {
        return fmt.Errorf("GetProcessHeap failed: %v", err)
    }
    
    // Set heap protection flags
    heapProtection := uintptr(0x00000002) // HEAP_OPTIMIZE_RESOURCES
    var heapInfo [8]byte
    heapInfo[0] = 1 // Enable protection
    
    ret, _, err := heapSetInfo.Call(
        heapHandle,
        0x00000001, // HeapCompatibilityInformation
        uintptr(unsafe.Pointer(&heapInfo[0])),
        uintptr(unsafe.Sizeof(heapInfo)),
    )
    
    if ret == 0 {
        return fmt.Errorf("HeapSetInformation failed: %v", err)
    }
    
    return nil
}

// Add guard pages to protect against buffer overflows
func addGuardPages() error {
    kernel32 := syscall.NewLazyDLL("kernel32.dll")
    virtualProtect := kernel32.NewProc("VirtualProtect")
    
    // Allocate guard page at specific locations
    // This is a simplified implementation
    var oldProtect uintptr
    guardAddr := uintptr(0x1000) // Adjust based on actual memory layout
    
    ret, _, err := virtualProtect.Call(
        guardAddr,
        uintptr(4096), // One page
        uintptr(PAGE_NOACCESS),
        uintptr(unsafe.Pointer(&oldProtect)),
    )
    
    if ret == 0 {
        return fmt.Errorf("Failed to add guard page: %v", err)
    }
    
    return nil
}

// Set process protection level to prevent tampering
func setProcessProtectionLevel() error {
    ntdll := syscall.NewLazyDLL("ntdll.dll")
    ntSetInfoProc := ntdll.NewProc("NtSetInformationProcess")
    
    // Set to Windows Trusted Computing Base (WinTCB) level
    protectionLevel := PROCESS_PROTECTION_LEVEL_WINTCB_LIGHT
    
    ret, _, err := ntSetInfoProc.Call(
        uintptr(^uintptr(0)), // Current process
        uintptr(ProcessProtectionLevel),
        uintptr(unsafe.Pointer(&protectionLevel)),
        uintptr(unsafe.Sizeof(protectionLevel)),
    )
    
    if ret != 0 {
        return fmt.Errorf("NtSetInformationProcess failed: %v", err)
    }
    
    return nil
}

// Prevent memory dumping via MiniDumpWriteDump
func preventMemoryDumping() error {
    ntdll := syscall.NewLazyDLL("ntdll.dll")
    ntSetInfoProc := ntdll.NewProc("NtSetInformationProcess")
    
    // Set process flags to prevent dumping
    flags := uint32(0x00000040) // ProcessFlagDisableMiniDump
    
    ret, _, err := ntSetInfoProc.Call(
        uintptr(^uintptr(0)), // Current process
        uintptr(0x3C), // ProcessFlags
        uintptr(unsafe.Pointer(&flags)),
        uintptr(unsafe.Sizeof(flags)),
    )
    
    if ret != 0 {
        return fmt.Errorf("Failed to set process flags: %v", err)
    }
    
    // Also hook MiniDumpWriteDump via VEH
    // This is a simplified version
    return nil
}

// Enable anti-debugging measures
func enableAntiDebug() error {
    // Multiple anti-debug techniques
    if err := hideFromDebugger(); err != nil {
        return err
    }
    
    if err := blockDebuggerAttach(); err != nil {
        return err
    }
    
    if err := clearDebugPort(); err != nil {
        return err
    }
    
    if err := invalidateBreakpoints(); err != nil {
        return err
    }
    
    return nil
}

// Hide the process from debuggers
func hideFromDebugger() error {
    ntdll := syscall.NewLazyDLL("ntdll.dll")
    ntSetInfoProc := ntdll.NewProc("NtSetInformationProcess")
    
    // Hide from debugger by setting the debug port to 0
    debugPort := uintptr(0)
    ret, _, err := ntSetInfoProc.Call(
        uintptr(^uintptr(0)), // Current process
        uintptr(ProcessDebugPort),
        uintptr(unsafe.Pointer(&debugPort)),
        uintptr(unsafe.Sizeof(debugPort)),
    )
    
    if ret != 0 {
        return fmt.Errorf("Failed to clear debug port: %v", err)
    }
    
    return nil
}

// Block debugger attachment
func blockDebuggerAttach() error {
    // Patch PEB BeingDebugged flag
    // This requires accessing the PEB structure
    // Simplified implementation
    kernel32 := syscall.NewLazyDLL("kernel32.dll")
    isDebuggerPresent := kernel32.NewProc("IsDebuggerPresent")
    ret, _, _ := isDebuggerPresent.Call()
    
    if ret != 0 {
        // Debugger detected, take action
        handleDebuggerDetected()
    }
    
    return nil
}

// Clear the debug port
func clearDebugPort() error {
    return hideFromDebugger()
}

// Invalidate software breakpoints (int3)
func invalidateBreakpoints() error {
    // Hook the exception handler to ignore breakpoints
    // This is a simplified version
    kernel32 := syscall.NewLazyDLL("kernel32.dll")
    addVectoredExceptionHandler := kernel32.NewProc("AddVectoredExceptionHandler")
    
    // Add VEH to handle breakpoints
    handlerAddr := uintptr(0) // In production, this would be a real handler
    ret, _, err := addVectoredExceptionHandler.Call(
        1, // First handler
        handlerAddr,
    )
    
    if ret == 0 {
        return fmt.Errorf("AddVectoredExceptionHandler failed: %v", err)
    }
    
    return nil
}

// Comprehensive anti-debug detection
func DetectDebugger() bool {
    detections := []DebuggerDetection{
        DetectionPEB,
        DetectionIsDebuggerPresent,
        DetectionNtGlobalFlag,
        DetectionHeapFlags,
        DetectionProcessDebugPort,
        DetectionProcessDebugFlags,
        DetectionTiming,
        DetectionHardwareBreakpoint,
        DetectionParentProcess,
        DetectionWindowClass,
    }
    
    for _, detection := range detections {
        if checkDebuggerDetection(detection) {
            return true
        }
    }
    
    return false
}

// Check specific debugger detection method
func checkDebuggerDetection(method DebuggerDetection) bool {
    switch method {
    case DetectionPEB:
        return checkPEB()
    case DetectionIsDebuggerPresent:
        return checkIsDebuggerPresent()
    case DetectionNtGlobalFlag:
        return checkNtGlobalFlag()
    case DetectionHeapFlags:
        return checkHeapFlags()
    case DetectionProcessDebugPort:
        return checkProcessDebugPort()
    case DetectionProcessDebugFlags:
        return checkProcessDebugFlags()
    case DetectionTiming:
        return checkTiming()
    case DetectionHardwareBreakpoint:
        return checkHardwareBreakpoint()
    case DetectionParentProcess:
        return checkParentProcess()
    case DetectionWindowClass:
        return checkWindowClass()
    default:
        return false
    }
}

// Check PEB BeingDebugged flag
func checkPEB() bool {
    kernel32 := syscall.NewLazyDLL("kernel32.dll")
    isDebuggerPresent := kernel32.NewProc("IsDebuggerPresent")
    ret, _, _ := isDebuggerPresent.Call()
    return ret != 0
}

// Check via NtGlobalFlag in PEB
func checkNtGlobalFlag() bool {
    // Read PEB to check NtGlobalFlag
    // This requires reading the PEB structure
    // Simplified: just check using GetProcessHeap flags
    return false
}

// Check heap flags for debugger indicators
func checkHeapFlags() bool {
    kernel32 := syscall.NewLazyDLL("kernel32.dll")
    getProcessHeap := kernel32.NewProc("GetProcessHeap")
    heapHandle, _, _ := getProcessHeap.Call()
    
    if heapHandle == 0 {
        return false
    }
    
    // Check heap flags
    heapFlags := *(*uint32)(unsafe.Pointer(heapHandle + 0x0C))
    forceFlags := *(*uint32)(unsafe.Pointer(heapHandle + 0x10))
    
    // Debugged processes often have HEAP_GROWABLE flag set differently
    if heapFlags & ^uint32(HEAP_GROWABLE) != 0 {
        return true
    }
    
    return false
}

// Check process debug port
func checkProcessDebugPort() bool {
    ntdll := syscall.NewLazyDLL("ntdll.dll")
    ntQueryInfoProc := ntdll.NewProc("NtQueryInformationProcess")
    
    var debugPort uintptr
    ret, _, _ := ntQueryInfoProc.Call(
        uintptr(^uintptr(0)),
        uintptr(ProcessDebugPort),
        uintptr(unsafe.Pointer(&debugPort)),
        uintptr(unsafe.Sizeof(debugPort)),
        0,
    )
    
    if ret == 0 && debugPort != 0 {
        return true
    }
    return false
}

// Check process debug flags
func checkProcessDebugFlags() bool {
    ntdll := syscall.NewLazyDLL("ntdll.dll")
    ntQueryInfoProc := ntdll.NewProc("NtQueryInformationProcess")
    
    var debugFlags uintptr
    ret, _, _ := ntQueryInfoProc.Call(
        uintptr(^uintptr(0)),
        uintptr(ProcessDebugFlags),
        uintptr(unsafe.Pointer(&debugFlags)),
        uintptr(unsafe.Sizeof(debugFlags)),
        0,
    )
    
    if ret == 0 && debugFlags != 0 {
        return true
    }
    return false
}

// Check timing differences (rdtsc)
func checkTiming() bool {
    // Use rdtsc on x86/x64
    // This is a simplified version
    start := time.Now().UnixNano()
    time.Sleep(1 * time.Millisecond)
    elapsed := time.Now().UnixNano() - start
    
    // If elapsed is significantly different from expected, debugger might be present
    expected := int64(1000000)
    if elapsed > expected*5 {
        return true
    }
    return false
}

// Check for hardware breakpoints (DR0-DR3)
func checkHardwareBreakpoint() bool {
    // Query thread context to check DR0-DR3 registers
    // This requires thread context access
    // Simplified: check if any debug registers are set
    return false
}

// Check if parent process is unexpected
func checkParentProcess() bool {
    // Get parent process ID
    // Check if parent is explorer.exe or cmd.exe
    // If parent is a debugger process, return true
    return false
}

// Check for debugger window classes
func checkWindowClass() bool {
    user32 := syscall.NewLazyDLL("user32.dll")
    findWindow := user32.NewProc("FindWindowW")
    
    // Check for common debugger windows
    debuggerWindowClasses := []string{
        "OLLYDBG",
        "idc",
        "WinDbgFrameClass",
        "VisualStudio",
        "x64dbg",
        "Cheat Engine",
    }
    
    for _, className := range debuggerWindowClasses {
        name, err := syscall.UTF16PtrFromString(className)
        if err != nil {
            continue
        }
        
        hwnd, _, _ := findWindow.Call(uintptr(unsafe.Pointer(name)), 0)
        if hwnd != 0 {
            return true
        }
    }
    
    return false
}

// Handle debugger detection
func handleDebuggerDetected() {
    // Take evasive action
    if defaultProtectionConfig.SelfDestructOnDetect {
        // Corrupt memory or crash in a non-obvious way
        corruptMemoryAndExit()
    } else {
        // Just crash
        SelfTerminate()
    }
}

// Corrupt memory and exit (makes analysis harder)
func corruptMemoryAndExit() {
    // Overwrite critical memory areas
    // This makes debugging and analysis difficult
    buf := make([]byte, 4096)
    // Fill with random data
    for i := range buf {
        buf[i] = byte(i)
    }
    
    // Overwrite some pointers
    var p *int
    *p = 0xDEADBEEF // Cause crash
    
    // Also can use more subtle corruption
}

// Self termination with obfuscation
func SelfTerminate() {
    if runtime.GOOS == "windows" {
        // Multiple ways to terminate
        
        // Method 1: TerminateProcess
        kernel32 := syscall.NewLazyDLL("kernel32.dll")
        termProc := kernel32.NewProc("TerminateProcess")
        currentProc := kernel32.NewProc("GetCurrentProcess")
        handle, _, _ := currentProc.Call()
        termProc.Call(handle, 0)
        
        // Method 2: ExitProcess (if TerminateProcess fails)
        exitProc := kernel32.NewProc("ExitProcess")
        exitProc.Call(0)
        
        // Method 3: Raw syscall
        // NtTerminateProcess
    } else {
        os.Exit(1)
    }
}

// Advanced: Memory obfuscation
func ObfuscateMemory(data []byte) {
    // XOR with random key
    key := make([]byte, 8)
    rand.Read(key)
    
    for i := range data {
        data[i] ^= key[i%8]
    }
}

// Anti-analysis: Random sleep with jitter
func RandomSleep() {
    // Sleep for random duration between 1-5 seconds
    ms := time.Duration(1000 + rand.Intn(4000))
    time.Sleep(ms * time.Millisecond)
}

// Advanced: Sleep with timing jitter
func SleepWithJitter(minMs, maxMs int) {
    // Add random jitter to sleep times
    jitter := rand.Intn(100) - 50 // +/- 50ms
    sleepMs := minMs + rand.Intn(maxMs-minMs) + jitter
    if sleepMs < 0 {
        sleepMs = 100
    }
    time.Sleep(time.Duration(sleepMs) * time.Millisecond)
}

// Anti-sandbox: Detect sandbox environments
func DetectSandbox() bool {
    // Check various sandbox indicators
    checks := []func() bool{
        checkDiskSpace,
        checkCPUInfo,
        checkMemorySize,
        checkNetwork,
        checkProcessCount,
        checkUptime,
        checkWindowNames,
    }
    
    threshold := 3 // At least 3 indicators must match
    matches := 0
    
    for _, check := range checks {
        if check() {
            matches++
            if matches >= threshold {
                return true
            }
        }
    }
    
    return false
}

// Sandbox detection checks
func checkDiskSpace() bool {
    // Sandboxes often have limited disk space
    // Check for small disk sizes (< 50GB)
    return false // Implement actual check
}

func checkCPUInfo() bool {
    // Sandboxes often have limited CPUs or specific CPU features
    // Check for single core or specific CPU ID
    return false
}

func checkMemorySize() bool {
    // Sandboxes often have less than 4GB RAM
    return false
}

func checkNetwork() bool {
    // Sandboxes often have limited or no network
    // Check for MAC addresses, network adapters
    return false
}

func checkProcessCount() bool {
    // Sandboxes have fewer processes running
    // Check process count < 30
    return false
}

func checkUptime() bool {
    // Sandboxes often have short uptime (< 1 hour)
    // Check system uptime
    return false
}

func checkWindowNames() bool {
    // Check for sandbox-specific window titles
    sandboxWindows := []string{
        "Cuckoo",
        "Sandbox",
        "VirusTotal",
        "Joe Sandbox",
        "Analyzer",
    }
    // Check window titles
    return false
}

// Comprehensive memory protection
func ComprehensiveProtection() error {
    config := ProtectionConfig{
        ProtectText:         true,
        ProtectHeap:         true,
        ProtectPEB:          true,
        EnableGuardPages:    true,
        SetProtectionLevel:  true,
        AntiDebug:           true,
        AntiDump:            true,
        SelfDestructOnDetect: true,
    }
    
    return ProtectMemoryWithConfig(config)
}

// Anti-debug thread that continuously monitors
func AntiDebugThread() {
    for {
        if DetectDebugger() {
            handleDebuggerDetected()
        }
        time.Sleep(100 * time.Millisecond)
    }
}

// Disable critical Windows APIs
func DisableAPIs() error {
    // Hook and disable critical APIs used for debugging
    // This would require API hooking (detours or similar)
    return nil
}

// Self-modifying code to avoid static analysis
func SelfModifyCode() {
    // XOR encode parts of the program memory
    // Then decode at runtime
    // This makes static analysis difficult
}

// Anti-dumping via memory encryption
func EncryptMemory() error {
    // Encrypt sensitive data in memory
    // Only decrypt when needed
    return nil
}

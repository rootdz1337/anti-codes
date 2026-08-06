package evasion

import (
    "fmt"
    "os"
    "os/exec"
    "runtime"
    "strconv"
    "strings"
    "syscall"
    "time"
    "unsafe"
)

// Windows API constants
const (
    // Process access rights
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ          = 0x0010
    
    // Memory status
    MEMORY_STATUS_LENGTH = 64
)

// SandboxDetector structure
type SandboxDetector struct {
    IsSandbox   bool
    Reason      string
    Details     map[string]interface{}
    Confidence  int // 0-100 percentage
}

// Sandbox detection configuration
type SandboxConfig struct {
    MinUptimeMinutes        int
    MinCPUCores            int
    MinMemoryGB            int
    MinDiskGB              int
    MinProcessCount        int
    MaxProcessCount        int
    CheckUserActivity      bool
    CheckNetwork           bool
    CheckMouseMovement     bool
    CheckWindowNames       bool
    CheckRunningProcesses  bool
    CheckInstalledSoftware bool
    CheckLanguage          bool
    CheckTimezone          bool
    CheckScreenResolution  bool
    CheckRecentFiles       bool
    ConfidenceThreshold    int
}

// Default configuration
var defaultSandboxConfig = SandboxConfig{
    MinUptimeMinutes:        10,
    MinCPUCores:            2,
    MinMemoryGB:            2,
    MinDiskGB:              50,
    MinProcessCount:        30,
    MaxProcessCount:        200,
    CheckUserActivity:      true,
    CheckNetwork:           true,
    CheckMouseMovement:     true,
    CheckWindowNames:       true,
    CheckRunningProcesses:  true,
    CheckInstalledSoftware: true,
    CheckLanguage:          true,
    CheckTimezone:          true,
    CheckScreenResolution:  true,
    CheckRecentFiles:       true,
    ConfidenceThreshold:    70,
}

// Windows system information structures
type MEMORYSTATUSEX struct {
    dwLength                uint32
    dwMemoryLoad            uint32
    ullTotalPhys            uint64
    ullAvailPhys            uint64
    ullTotalPageFile        uint64
    ullAvailPageFile        uint64
    ullTotalVirtual         uint64
    ullAvailVirtual         uint64
    ullAvailExtendedVirtual uint64
}

type SYSTEM_INFO struct {
    dwOemId                     uint32
    dwPageSize                  uint32
    lpMinimumApplicationAddress uintptr
    lpMaximumApplicationAddress uintptr
    dwActiveProcessorMask       uintptr
    dwNumberOfProcessors        uint32
    dwProcessorType             uint32
    dwAllocationGranularity     uint32
    wProcessorLevel             uint16
    wProcessorRevision          uint16
}

type FILETIME struct {
    dwLowDateTime  uint32
    dwHighDateTime uint32
}

type SYSTEMTIMEOFDAY struct {
    dwLowDateTime  uint32
    dwHighDateTime uint32
}

type DISK_SPACE struct {
    FreeBytesAvailable     uint64
    TotalBytes             uint64
    TotalFreeBytes         uint64
}

// Main detection function
func DetectSandbox() SandboxDetector {
    return DetectSandboxWithConfig(defaultSandboxConfig)
}

// Enhanced detection with configuration
func DetectSandboxWithConfig(config SandboxConfig) SandboxDetector {
    detector := SandboxDetector{
        IsSandbox: false,
        Details:   make(map[string]interface{}),
        Confidence: 0,
    }
    
    var reasons []string
    var confidence int
    
    // Check uptime
    if uptime := getUptime(); uptime < time.Duration(config.MinUptimeMinutes)*time.Minute {
        reasons = append(reasons, fmt.Sprintf("Uptime less than %d minutes", config.MinUptimeMinutes))
        confidence += 15
        detector.Details["uptime"] = uptime.String()
    }
    
    // Check CPU cores
    cores := runtime.NumCPU()
    if cores < config.MinCPUCores {
        reasons = append(reasons, fmt.Sprintf("Less than %d CPU cores", config.MinCPUCores))
        confidence += 10
        detector.Details["cpu_cores"] = cores
    }
    
    // Check memory
    if memGB := getMemoryGB(); memGB < float64(config.MinMemoryGB) {
        reasons = append(reasons, fmt.Sprintf("Less than %dGB RAM", config.MinMemoryGB))
        confidence += 15
        detector.Details["memory_gb"] = memGB
    }
    
    // Check disk size
    if diskGB := getDiskSizeGB(); diskGB < float64(config.MinDiskGB) {
        reasons = append(reasons, fmt.Sprintf("Less than %dGB disk", config.MinDiskGB))
        confidence += 10
        detector.Details["disk_gb"] = diskGB
    }
    
    // Check process count
    if procCount := getProcessCount(); procCount < config.MinProcessCount {
        reasons = append(reasons, fmt.Sprintf("Too few processes (%d)", procCount))
        confidence += 10
        detector.Details["process_count"] = procCount
    } else if procCount > config.MaxProcessCount {
        reasons = append(reasons, fmt.Sprintf("Too many processes (%d)", procCount))
        confidence += 5
        detector.Details["process_count"] = procCount
    }
    
    // Check user activity
    if config.CheckUserActivity {
        if !hasRecentUserActivity() {
            reasons = append(reasons, "No recent user activity")
            confidence += 10
            detector.Details["user_activity"] = false
        } else {
            detector.Details["user_activity"] = true
        }
    }
    
    // Check network
    if config.CheckNetwork {
        if !hasNetworkConnection() {
            reasons = append(reasons, "No network connection")
            confidence += 10
            detector.Details["network"] = false
        } else {
            detector.Details["network"] = true
        }
    }
    
    // Check mouse movement
    if config.CheckMouseMovement {
        if !hasMouseMovement() {
            reasons = append(reasons, "No mouse movement detected")
            confidence += 5
            detector.Details["mouse_movement"] = false
        } else {
            detector.Details["mouse_movement"] = true
        }
    }
    
    // Check window names
    if config.CheckWindowNames {
        if hasSandboxWindowNames() {
            reasons = append(reasons, "Sandbox window detected")
            confidence += 15
            detector.Details["window_names"] = true
        } else {
            detector.Details["window_names"] = false
        }
    }
    
    // Check running processes
    if config.CheckRunningProcesses {
        if hasSandboxProcesses() {
            reasons = append(reasons, "Sandbox process detected")
            confidence += 15
            detector.Details["sandbox_processes"] = true
        } else {
            detector.Details["sandbox_processes"] = false
        }
    }
    
    // Check installed software
    if config.CheckInstalledSoftware {
        if hasSandboxSoftware() {
            reasons = append(reasons, "Sandbox software detected")
            confidence += 10
            detector.Details["sandbox_software"] = true
        } else {
            detector.Details["sandbox_software"] = false
        }
    }
    
    // Check language
    if config.CheckLanguage {
        if isSandboxLanguage() {
            reasons = append(reasons, "Suspicious system language")
            confidence += 5
            detector.Details["language"] = true
        } else {
            detector.Details["language"] = false
        }
    }
    
    // Check timezone
    if config.CheckTimezone {
        if isSandboxTimezone() {
            reasons = append(reasons, "Suspicious timezone")
            confidence += 5
            detector.Details["timezone"] = true
        } else {
            detector.Details["timezone"] = false
        }
    }
    
    // Check screen resolution
    if config.CheckScreenResolution {
        if isSandboxResolution() {
            reasons = append(reasons, "Suspicious screen resolution")
            confidence += 5
            detector.Details["resolution"] = true
        } else {
            detector.Details["resolution"] = false
        }
    }
    
    // Check recent files
    if config.CheckRecentFiles {
        if !hasRecentFiles() {
            reasons = append(reasons, "No recent files found")
            confidence += 5
            detector.Details["recent_files"] = false
        } else {
            detector.Details["recent_files"] = true
        }
    }
    
    // Determine if sandbox
    detector.Confidence = confidence
    if confidence >= config.ConfidenceThreshold {
        detector.IsSandbox = true
        detector.Reason = strings.Join(reasons, "; ")
    } else {
        detector.Reason = "Not a sandbox (confidence: " + strconv.Itoa(confidence) + "%)"
    }
    
    return detector
}

// Get system uptime
func getUptime() time.Duration {
    if runtime.GOOS == "windows" {
        kernel32 := syscall.NewLazyDLL("kernel32.dll")
        proc := kernel32.NewProc("GetTickCount64")
        ret, _, _ := proc.Call()
        return time.Duration(ret) * time.Millisecond
    } else if runtime.GOOS == "linux" {
        data, err := os.ReadFile("/proc/uptime")
        if err == nil {
            parts := strings.Fields(string(data))
            if len(parts) > 0 {
                seconds, err := strconv.ParseFloat(parts[0], 64)
                if err == nil {
                    return time.Duration(seconds * float64(time.Second))
                }
            }
        }
    } else if runtime.GOOS == "darwin" {
        cmd := exec.Command("sysctl", "kern.boottime")
        output, err := cmd.Output()
        if err == nil {
            // Parse boottime
            // Simplified: calculate from system boot time
        }
    }
    return 0
}

// Get total memory in GB
func getMemoryGB() float64 {
    if runtime.GOOS == "windows" {
        var memStatus MEMORYSTATUSEX
        memStatus.dwLength = uint32(unsafe.Sizeof(memStatus))
        
        kernel32 := syscall.NewLazyDLL("kernel32.dll")
        proc := kernel32.NewProc("GlobalMemoryStatusEx")
        ret, _, _ := proc.Call(uintptr(unsafe.Pointer(&memStatus)))
        
        if ret != 0 {
            return float64(memStatus.ullTotalPhys) / (1024 * 1024 * 1024)
        }
    } else if runtime.GOOS == "linux" {
        data, err := os.ReadFile("/proc/meminfo")
        if err == nil {
            lines := strings.Split(string(data), "\n")
            for _, line := range lines {
                if strings.HasPrefix(line, "MemTotal:") {
                    parts := strings.Fields(line)
                    if len(parts) >= 2 {
                        kb, err := strconv.ParseFloat(parts[1], 64)
                        if err == nil {
                            return kb / (1024 * 1024)
                        }
                    }
                }
            }
        }
    } else if runtime.GOOS == "darwin" {
        cmd := exec.Command("sysctl", "hw.memsize")
        output, err := cmd.Output()
        if err == nil {
            parts := strings.Split(string(output), ":")
            if len(parts) == 2 {
                bytes, err := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
                if err == nil {
                    return bytes / (1024 * 1024 * 1024)
                }
            }
        }
    }
    return 0
}

// Get disk size in GB
func getDiskSizeGB() float64 {
    if runtime.GOOS == "windows" {
        kernel32 := syscall.NewLazyDLL("kernel32.dll")
        proc := kernel32.NewProc("GetDiskFreeSpaceExW")
        
        // Get system drive
        drive, err := syscall.UTF16PtrFromString("C:\\")
        if err != nil {
            return 0
        }
        
        var freeBytes, totalBytes, totalFreeBytes uint64
        ret, _, _ := proc.Call(
            uintptr(unsafe.Pointer(drive)),
            uintptr(unsafe.Pointer(&freeBytes)),
            uintptr(unsafe.Pointer(&totalBytes)),
            uintptr(unsafe.Pointer(&totalFreeBytes)),
        )
        
        if ret != 0 {
            return float64(totalBytes) / (1024 * 1024 * 1024)
        }
    } else if runtime.GOOS == "linux" {
        var stat syscall.Statfs_t
        err := syscall.Statfs("/", &stat)
        if err == nil {
            total := stat.Blocks * uint64(stat.Bsize)
            return float64(total) / (1024 * 1024 * 1024)
        }
    } else if runtime.GOOS == "darwin" {
        cmd := exec.Command("df", "-g", "/")
        output, err := cmd.Output()
        if err == nil {
            lines := strings.Split(string(output), "\n")
            if len(lines) >= 2 {
                fields := strings.Fields(lines[1])
                if len(fields) >= 2 {
                    size, err := strconv.ParseFloat(fields[1], 64)
                    if err == nil {
                        return size
                    }
                }
            }
        }
    }
    return 0
}

// Get process count
func getProcessCount() int {
    if runtime.GOOS == "windows" {
        kernel32 := syscall.NewLazyDLL("kernel32.dll")
        proc := kernel32.NewProc("CreateToolhelp32Snapshot")
        
        snapshot, _, _ := proc.Call(
            0x00000002, // TH32CS_SNAPPROCESS
            0,
        )
        
        if snapshot == 0 {
            return 0
        }
        defer syscall.CloseHandle(syscall.Handle(snapshot))
        
        count := 0
        var pe32 syscall.ProcessEntry32
        pe32.Size = uint32(unsafe.Sizeof(pe32))
        
        process32First := kernel32.NewProc("Process32First")
        ret, _, _ := process32First.Call(snapshot, uintptr(unsafe.Pointer(&pe32)))
        if ret == 0 {
            return 0
        }
        
        for {
            count++
            process32Next := kernel32.NewProc("Process32Next")
            ret, _, _ := process32Next.Call(snapshot, uintptr(unsafe.Pointer(&pe32)))
            if ret == 0 {
                break
            }
        }
        return count
    } else if runtime.GOOS == "linux" {
        files, err := os.ReadDir("/proc")
        if err != nil {
            return 0
        }
        count := 0
        for _, f := range files {
            if f.IsDir() && isNumeric(f.Name()) {
                count++
            }
        }
        return count
    } else if runtime.GOOS == "darwin" {
        cmd := exec.Command("ps", "-e")
        output, err := cmd.Output()
        if err != nil {
            return 0
        }
        lines := strings.Split(string(output), "\n")
        return len(lines) - 1
    }
    return 0
}

// Check for recent user activity
func hasRecentUserActivity() bool {
    if runtime.GOOS == "windows" {
        // Check last input time
        user32 := syscall.NewLazyDLL("user32.dll")
        proc := user32.NewProc("GetLastInputInfo")
        
        var lastInput struct {
            cbSize uint32
            dwTime uint32
        }
        lastInput.cbSize = uint32(unsafe.Sizeof(lastInput))
        
        ret, _, _ := proc.Call(uintptr(unsafe.Pointer(&lastInput)))
        if ret != 0 {
            kernel32 := syscall.NewLazyDLL("kernel32.dll")
            tickProc := kernel32.NewProc("GetTickCount")
            tick, _, _ := tickProc.Call()
            
            // If no input in last 5 minutes
            if tick-uintptr(lastInput.dwTime) > 300000 {
                return false
            }
            return true
        }
    } else if runtime.GOOS == "linux" {
        // Check /dev/input/mice or /var/log/lastlog
        // Simplified: check if X server is running
        if _, err := os.Stat("/tmp/.X11-unix"); err == nil {
            // X server is running, likely user activity
            return true
        }
    }
    return true // Default to true if can't determine
}

// Check network connection
func hasNetworkConnection() bool {
    // Check if any network interface is up and has an IP
    interfaces, err := net.Interfaces()
    if err != nil {
        return false
    }
    
    for _, iface := range interfaces {
        if iface.Flags&net.FlagUp == 0 {
            continue
        }
        if iface.Flags&net.FlagLoopback != 0 {
            continue
        }
        addrs, err := iface.Addrs()
        if err != nil {
            continue
        }
        for _, addr := range addrs {
            if ipnet, ok := addr.(*net.IPNet); ok {
                if !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
                    return true
                }
            }
        }
    }
    return false
}

// Check mouse movement
func hasMouseMovement() bool {
    if runtime.GOOS == "windows" {
        user32 := syscall.NewLazyDLL("user32.dll")
        getCursorPos := user32.NewProc("GetCursorPos")
        
        var pt struct{ x, y int32 }
        ret, _, _ := getCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
        if ret != 0 {
            // Check if cursor position has changed recently
            // For simplicity, just check if not at (0,0)
            return !(pt.x == 0 && pt.y == 0)
        }
    }
    return true // Default to true
}

// Check for sandbox window names
func hasSandboxWindowNames() bool {
    if runtime.GOOS == "windows" {
        user32 := syscall.NewLazyDLL("user32.dll")
        findWindow := user32.NewProc("FindWindowW")
        
        sandboxWindows := []string{
            "OLLYDBG", "idc", "WinDbgFrameClass", "VisualStudio",
            "x64dbg", "Cheat Engine", "Cuckoo", "Sandbox",
            "VirusTotal", "Joe Sandbox", "Analyzer",
        }
        
        for _, name := range sandboxWindows {
            wname, err := syscall.UTF16PtrFromString(name)
            if err != nil {
                continue
            }
            hwnd, _, _ := findWindow.Call(uintptr(unsafe.Pointer(wname)), 0)
            if hwnd != 0 {
                return true
            }
        }
    }
    return false
}

// Check for sandbox processes
func hasSandboxProcesses() bool {
    sandboxProcesses := []string{
        "vmtoolsd.exe", "VBoxService.exe", "vmsrvc.exe",
        "procmon.exe", "processhacker.exe", "wireshark.exe",
        "cuckoo", "sandbox", "analyzer",
    }
    
    // Check running processes
    processes, err := getRunningProcesses()
    if err != nil {
        return false
    }
    
    for _, proc := range processes {
        procLower := strings.ToLower(proc)
        for _, sandboxProc := range sandboxProcesses {
            if strings.Contains(procLower, strings.ToLower(sandboxProc)) {
                return true
            }
        }
    }
    return false
}

// Get running processes list
func getRunningProcesses() ([]string, error) {
    var processes []string
    
    if runtime.GOOS == "windows" {
        kernel32 := syscall.NewLazyDLL("kernel32.dll")
        proc := kernel32.NewProc("CreateToolhelp32Snapshot")
        snapshot, _, _ := proc.Call(0x00000002, 0)
        if snapshot == 0 {
            return nil, fmt.Errorf("failed to create snapshot")
        }
        defer syscall.CloseHandle(syscall.Handle(snapshot))
        
        var pe32 syscall.ProcessEntry32
        pe32.Size = uint32(unsafe.Sizeof(pe32))
        
        process32First := kernel32.NewProc("Process32First")
        ret, _, _ := process32First.Call(snapshot, uintptr(unsafe.Pointer(&pe32)))
        if ret == 0 {
            return nil, fmt.Errorf("failed to get first process")
        }
        
        for {
            processes = append(processes, string(pe32.ExeFile[:]))
            process32Next := kernel32.NewProc("Process32Next")
            ret, _, _ := process32Next.Call(snapshot, uintptr(unsafe.Pointer(&pe32)))
            if ret == 0 {
                break
            }
        }
    } else if runtime.GOOS == "linux" {
        files, err := os.ReadDir("/proc")
        if err != nil {
            return nil, err
        }
        for _, f := range files {
            if f.IsDir() && isNumeric(f.Name()) {
                cmdline, err := os.ReadFile("/proc/" + f.Name() + "/cmdline")
                if err == nil && len(cmdline) > 0 {
                    processes = append(processes, string(cmdline))
                }
            }
        }
    }
    
    return processes, nil
}

// Check for sandbox software
func hasSandboxSoftware() bool {
    // Check for common sandbox software installations
    sandboxPaths := []string{
        "C:\\Program Files\\VMware\\VMware Tools",
        "C:\\Program Files\\Oracle\\VirtualBox",
        "C:\\Program Files\\VirtualBox Guest Additions",
        "C:\\Program Files\\Process Explorer",
        "C:\\Program Files\\Procmon",
        "C:\\Program Files\\Wireshark",
        "C:\\Program Files\\Debugging Tools for Windows",
    }
    
    for _, path := range sandboxPaths {
        if _, err := os.Stat(path); err == nil {
            return true
        }
    }
    return false
}

// Check language
func isSandboxLanguage() bool {
    // Check if language is not typical for the region
    // For example, many sandboxes use English (US)
    if runtime.GOOS == "windows" {
        kernel32 := syscall.NewLazyDLL("kernel32.dll")
        proc := kernel32.NewProc("GetUserDefaultLangID")
        langID, _, _ := proc.Call()
        
        // English (US) is 0x0409
        // Check if it's a common sandbox language
        if langID == 0x0409 {
            // Could be suspicious if in a non-English region
            // For now, return false
            return false
        }
    }
    return false
}

// Check timezone
func isSandboxTimezone() bool {
    // Check if timezone is UTC (common in sandboxes)
    // This is a simplified check
    name, offset := time.Now().Zone()
    _ = name
    if offset == 0 {
        return true // UTC timezone
    }
    return false
}

// Check screen resolution
func isSandboxResolution() bool {
    if runtime.GOOS == "windows" {
        user32 := syscall.NewLazyDLL("user32.dll")
        getSystemMetrics := user32.NewProc("GetSystemMetrics")
        
        width, _, _ := getSystemMetrics.Call(0)  // SM_CXSCREEN
        height, _, _ := getSystemMetrics.Call(1) // SM_CYSCREEN
        
        // Common sandbox resolutions
        if width == 800 && height == 600 {
            return true
        }
        if width == 1024 && height == 768 {
            return true
        }
        if width == 1280 && height == 720 {
            return true
        }
    }
    return false
}

// Check for recent files
func hasRecentFiles() bool {
    // Check if there are recent files in the user's directories
    userHome, err := os.UserHomeDir()
    if err != nil {
        return false
    }
    
    // Check common recent files locations
    recentPaths := []string{
        userHome + "/Documents",
        userHome + "/Downloads",
        userHome + "/Desktop",
        userHome + "/Pictures",
        userHome + "/Music",
        userHome + "/Videos",
    }
    
    if runtime.GOOS == "windows" {
        recentPaths = append(recentPaths, 
            userHome+"\\AppData\\Roaming\\Microsoft\\Windows\\Recent",
            "C:\\Users\\Public\\Documents",
        )
    }
    
    // Check if any files were modified in the last 24 hours
    twentyFourHoursAgo := time.Now().Add(-24 * time.Hour)
    
    for _, path := range recentPaths {
        files, err := os.ReadDir(path)
        if err != nil {
            continue
        }
        for _, file := range files {
            info, err := file.Info()
            if err != nil {
                continue
            }
            if info.ModTime().After(twentyFourHoursAgo) {
                return true
            }
        }
    }
    
    return false
}

// Helper function
func isNumeric(s string) bool {
    for _, c := range s {
        if c < '0' || c > '9' {
            return false
        }
    }
    return true
}

// Get detailed sandbox analysis
func GetSandboxAnalysis() string {
    detector := DetectSandbox()
    
    var result strings.Builder
    result.WriteString("=== Sandbox Detection Analysis ===\n")
    result.WriteString(fmt.Sprintf("Is Sandbox: %v\n", detector.IsSandbox))
    result.WriteString(fmt.Sprintf("Confidence: %d%%\n", detector.Confidence))
    result.WriteString(fmt.Sprintf("Reason: %s\n", detector.Reason))
    result.WriteString("\nDetails:\n")
    
    for key, value := range detector.Details {
        result.WriteString(fmt.Sprintf("  %s: %v\n", key, value))
    }
    
    return result.String()
}

// Quick sandbox check (returns bool only)
func IsSandbox() bool {
    detector := DetectSandbox()
    return detector.IsSandbox
}

// Continuous sandbox monitoring
func MonitorSandboxDetection(interval time.Duration, callback func(bool)) {
    ticker := time.NewTicker(interval)
    defer ticker.Stop()
    
    for range ticker.C {
        if IsSandbox() {
            callback(true)
        }
    }
}

// Anti-sandbox evasion techniques
func AntiSandbox() {
    // If sandbox detected, take evasive action
    if IsSandbox() {
        // Multiple evasion techniques
        // 1. Random sleep
        RandomSleep()
        
        // 2. Delay execution
        time.Sleep(time.Duration(5+rand.Intn(10)) * time.Minute)
        
        // 3. Perform benign operations
        performBenignOperations()
        
        // 4. Change behavior
        alterExecutionPath()
    }
}

func performBenignOperations() {
    // Do harmless operations that mimic legitimate software
    // This can help bypass sandbox detection
    for i := 0; i < 100; i++ {
        // Simulate file operations
        time.Sleep(10 * time.Millisecond)
    }
}

func alterExecutionPath() {
    // Change execution flow to confuse sandbox analysis
    // This is a simplified placeholder
}

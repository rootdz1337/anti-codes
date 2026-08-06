package evasion

import (
    "bytes"
    "fmt"
    "io/ioutil"
    "net"
    "os"
    "os/exec"
    "runtime"
    "strconv"
    "strings"
    "syscall"
    "unsafe"

    "golang.org/x/sys/windows"
    "golang.org/x/sys/windows/registry"
)

// VM Detection Suite
type VMDetector struct {
    IsVM     bool
    VMType   string
}

func DetectVM() VMDetector {
    detector := VMDetector{IsVM: false, VMType: "Physical"}
    
    if runtime.GOOS == "windows" {
        detector = detectVMWindows()
    } else if runtime.GOOS == "linux" {
        detector = detectVMLinux()
    } else if runtime.GOOS == "darwin" {
        detector = detectVMMac()
    }
    
    // Additional checks
    if checkMACAddresses() {
        detector.IsVM = true
        detector.VMType = "VM (MAC)"
    }
    
    if checkVMRegistry() {
        detector.IsVM = true
        detector.VMType = "VM (Registry)"
    }
    
    if checkVMFiles() {
        detector.IsVM = true
        detector.VMType = "VM (Files)"
    }
    
    if checkMemory() {
        detector.IsVM = true
        detector.VMType = "VM (Memory)"
    }
    
    if checkCPUCores() {
        detector.IsVM = true
        detector.VMType = "VM (CPU Cores)"
    }
    
    return detector
}

// Windows VM Detection
func detectVMWindows() VMDetector {
    detector := VMDetector{IsVM: false, VMType: "Physical"}
    
    // Check system firmware via WMI
    cmd := exec.Command("wmic", "computersystem", "get", "model")
    output, err := cmd.Output()
    if err == nil {
        model := strings.ToLower(string(output))
        if strings.Contains(model, "vmware") ||
           strings.Contains(model, "virtualbox") ||
           strings.Contains(model, "virtual machine") {
            detector.IsVM = true
            detector.VMType = "VM (System Model)"
        }
    }
    
    // Check common VM processes
    processes := []string{"vmtoolsd.exe", "VBoxService.exe", "vmsrvc.exe", "vmware.exe", "vbox.exe"}
    for _, proc := range processes {
        if processExistsWindows(proc) {
            detector.IsVM = true
            if strings.Contains(proc, "VMware") || strings.Contains(proc, "vmtools") || strings.Contains(proc, "vmware") {
                detector.VMType = "VMware"
            } else if strings.Contains(proc, "VBox") || strings.Contains(proc, "vbox") {
                detector.VMType = "VirtualBox"
            }
        }
    }
    
    // Check for VM-specific services
    services := []string{"VMTools", "VBoxGuest", "vmware"}
    for _, service := range services {
        if serviceExistsWindows(service) {
            detector.IsVM = true
            detector.VMType = "VM (Service)"
        }
    }
    
    return detector
}

// Linux VM Detection
func detectVMLinux() VMDetector {
    detector := VMDetector{IsVM: false, VMType: "Physical"}
    
    // Check DMI info
    dmiPaths := []string{
        "/sys/class/dmi/id/product_name",
        "/sys/class/dmi/id/sys_vendor",
        "/sys/class/dmi/id/board_vendor",
    }
    
    for _, path := range dmiPaths {
        dmiData, err := ioutil.ReadFile(path)
        if err == nil {
            product := strings.TrimSpace(string(dmiData))
            lowerProduct := strings.ToLower(product)
            if strings.Contains(lowerProduct, "vmware") ||
               strings.Contains(lowerProduct, "virtualbox") ||
               strings.Contains(lowerProduct, "qemu") ||
               strings.Contains(lowerProduct, "kvm") ||
               strings.Contains(lowerProduct, "xen") {
                detector.IsVM = true
                detector.VMType = product
                break
            }
        }
    }
    
    // Check CPU info
    cpuData, err := ioutil.ReadFile("/proc/cpuinfo")
    if err == nil {
        cpu := strings.ToLower(string(cpuData))
        if strings.Contains(cpu, "vmware") ||
           strings.Contains(cpu, "virtual") ||
           strings.Contains(cpu, "hypervisor") ||
           strings.Contains(cpu, "qemu") ||
           strings.Contains(cpu, "kvm") {
            detector.IsVM = true
            detector.VMType = "VM (CPU)"
        }
    }
    
    // Check for VM-specific devices
    devices := []string{"/dev/vmware", "/dev/vboxguest", "/dev/kvm"}
    for _, dev := range devices {
        if _, err := os.Stat(dev); err == nil {
            detector.IsVM = true
            detector.VMType = "VM (Device)"
            break
        }
    }
    
    // Check /proc/scsi/scsi
    scsiData, err := ioutil.ReadFile("/proc/scsi/scsi")
    if err == nil {
        scsi := strings.ToLower(string(scsiData))
        if strings.Contains(scsi, "vmware") || strings.Contains(scsi, "virtualbox") {
            detector.IsVM = true
            detector.VMType = "VM (SCSI)"
        }
    }
    
    // Check dmesg for VM clues
    cmd := exec.Command("dmesg")
    output, err := cmd.Output()
    if err == nil {
        dmesg := strings.ToLower(string(output))
        if strings.Contains(dmesg, "vmware") || 
           strings.Contains(dmesg, "virtualbox") ||
           strings.Contains(dmesg, "hypervisor") {
            detector.IsVM = true
            detector.VMType = "VM (dmesg)"
        }
    }
    
    return detector
}

// Mac VM Detection
func detectVMMac() VMDetector {
    detector := VMDetector{IsVM: false, VMType: "Physical"}
    
    // Check system_profiler
    cmd := exec.Command("system_profiler", "SPHardwareDataType")
    output, err := cmd.Output()
    if err == nil {
        info := strings.ToLower(string(output))
        if strings.Contains(info, "vmware") ||
           strings.Contains(info, "virtualbox") ||
           strings.Contains(info, "parallels") {
            detector.IsVM = true
            detector.VMType = "VM (Hardware)"
        }
    }
    
    // Check for VM-specific processes
    processes := []string{"vmware", "vbox", "parallels"}
    for _, proc := range processes {
        cmd := exec.Command("pgrep", proc)
        err := cmd.Run()
        if err == nil {
            detector.IsVM = true
            detector.VMType = "VM (Process)"
            break
        }
    }
    
    return detector
}

// MAC Address Check
func checkMACAddresses() bool {
    interfaces, err := net.Interfaces()
    if err != nil {
        return false
    }
    
    vmPrefixes := []string{
        "00:0C:29", // VMware
        "00:50:56", // VMware
        "00:05:69", // VMware
        "00:1C:42", // Parallels
        "00:16:3E", // Xen
        "08:00:27", // VirtualBox
        "52:54:00", // QEMU/KVM
        "54:52:00", // QEMU/KVM
        "02:00:4C", // Microsoft Hyper-V
        "00:15:5D", // Microsoft Hyper-V
    }
    
    for _, iface := range interfaces {
        if iface.HardwareAddr == nil {
            continue
        }
        mac := iface.HardwareAddr.String()
        for _, prefix := range vmPrefixes {
            if strings.HasPrefix(mac, prefix) {
                return true
            }
        }
    }
    return false
}

// Registry Check (Windows)
func checkVMRegistry() bool {
    if runtime.GOOS != "windows" {
        return false
    }
    
    vmRegKeys := []struct {
        path string
        key  string
    }{
        {`SYSTEM\CurrentControlSet\Services\VMTools`, ""},
        {`SOFTWARE\VMware, Inc.`, ""},
        {`SOFTWARE\Oracle\VirtualBox`, ""},
        {`HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0`, ""},
        {`SYSTEM\CurrentControlSet\Enum\PCI`, "VEN_15AD"}, // VMware
        {`SYSTEM\CurrentControlSet\Enum\PCI`, "VEN_80EE"}, // VirtualBox
    }
    
    for _, regKey := range vmRegKeys {
        // Try to open the key
        key, err := registry.OpenKey(registry.LOCAL_MACHINE, regKey.path, registry.QUERY_VALUE)
        if err == nil {
            key.Close()
            return true
        }
    }
    
    // Check for VM-specific registry values
    if vmRegValueExists(`SYSTEM\CurrentControlSet\Control\SystemInformation`, "SystemManufacturer", []string{"VMware", "VirtualBox", "Microsoft Corporation"}) {
        return true
    }
    
    return false
}

// Helper function to check registry values
func vmRegValueExists(path, valueName string, expectedValues []string) bool {
    if runtime.GOOS != "windows" {
        return false
    }
    
    key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
    if err != nil {
        return false
    }
    defer key.Close()
    
    value, _, err := key.GetStringValue(valueName)
    if err != nil {
        return false
    }
    
    for _, expected := range expectedValues {
        if strings.Contains(value, expected) {
            return true
        }
    }
    return false
}

// VM Files Check
func checkVMFiles() bool {
    vmFiles := []string{
        // Windows
        "C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe",
        "C:\\Program Files\\Oracle\\VirtualBox\\VBoxService.exe",
        "C:\\Program Files\\VirtualBox Guest Additions\\VBoxService.exe",
        "C:\\Windows\\System32\\drivers\\vmhgfs.sys",
        "C:\\Windows\\System32\\drivers\\vm3dmp.sys",
        "C:\\Windows\\System32\\drivers\\vmmouse.sys",
        "C:\\Windows\\System32\\drivers\\vmusb.sys",
        "C:\\Windows\\System32\\drivers\\vmci.sys",
        // Linux
        "/usr/bin/vmtoolsd",
        "/usr/bin/VBoxService",
        "/usr/sbin/vmtoolsd",
        "/usr/lib/vmware-tools",
        "/etc/vmware-tools",
        "/usr/share/virtualbox",
        "/var/log/vmware",
        "/var/log/vbox",
        // Mac
        "/Library/Application Support/VMware Tools",
        "/Library/Application Support/VirtualBox",
        "/Applications/VMware Tools.app",
        "/Applications/VirtualBox.app",
    }
    
    for _, file := range vmFiles {
        if _, err := os.Stat(file); err == nil {
            return true
        }
    }
    return false
}

// Memory Check
func checkMemory() bool {
    if runtime.GOOS == "windows" {
        var mem windows.MemoryStatusEx
        mem.Length = uint32(unsafe.Sizeof(mem))
        err := windows.GlobalMemoryStatusEx(&mem)
        if err != nil {
            return false
        }
        // Sandboxes often have less than 4GB RAM
        if mem.TotalPhys < 4*1024*1024*1024 {
            return true
        }
    } else if runtime.GOOS == "linux" {
        // Read /proc/meminfo
        data, err := ioutil.ReadFile("/proc/meminfo")
        if err == nil {
            lines := strings.Split(string(data), "\n")
            for _, line := range lines {
                if strings.HasPrefix(line, "MemTotal:") {
                    parts := strings.Fields(line)
                    if len(parts) >= 2 {
                        memKB, err := strconv.ParseInt(parts[1], 10, 64)
                        if err == nil {
                            // Convert to bytes and check if less than 4GB
                            if memKB*1024 < 4*1024*1024*1024 {
                                return true
                            }
                        }
                    }
                    break
                }
            }
        }
    } else if runtime.GOOS == "darwin" {
        // Use sysctl for Mac
        cmd := exec.Command("sysctl", "hw.memsize")
        output, err := cmd.Output()
        if err == nil {
            parts := strings.Split(string(output), ":")
            if len(parts) == 2 {
                memBytes, err := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
                if err == nil && memBytes < 4*1024*1024*1024 {
                    return true
                }
            }
        }
    }
    return false
}

// Check CPU Cores (Sandboxes often have limited cores)
func checkCPUCores() bool {
    cores := runtime.NumCPU()
    // Most sandboxes have 1-2 cores
    if cores <= 2 {
        return true
    }
    return false
}

// Helper functions
func processExistsWindows(name string) bool {
    if runtime.GOOS != "windows" {
        return false
    }
    
    // Use Windows API to enumerate processes
    handle, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
    if err != nil {
        return false
    }
    defer windows.CloseHandle(handle)
    
    var pe windows.ProcessEntry32
    pe.Size = uint32(unsafe.Sizeof(pe))
    
    err = windows.Process32First(handle, &pe)
    if err != nil {
        return false
    }
    
    for {
        // Convert process name from UTF-16 to string
        exeFile := windows.UTF16ToString(pe.ExeFile[:])
        if strings.Contains(strings.ToLower(exeFile), strings.ToLower(name)) {
            return true
        }
        
        err = windows.Process32Next(handle, &pe)
        if err != nil {
            break
        }
    }
    
    return false
}

func serviceExistsWindows(name string) bool {
    if runtime.GOOS != "windows" {
        return false
    }
    
    // Try to open the service manager
    scmHandle, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
    if err != nil {
        return false
    }
    defer windows.CloseServiceHandle(scmHandle)
    
    // Try to open the service
    serviceHandle, err := windows.OpenService(scmHandle, windows.StringToUTF16Ptr(name), windows.SERVICE_QUERY_STATUS)
    if err != nil {
        return false
    }
    defer windows.CloseServiceHandle(serviceHandle)
    
    return true
}

// Enhanced Linux detection with additional checks
func checkLinuxProcesses() bool {
    if runtime.GOOS != "linux" {
        return false
    }
    
    // Read /proc directory for processes
    files, err := ioutil.ReadDir("/proc")
    if err != nil {
        return false
    }
    
    vmProcesses := []string{"vmtoolsd", "VBoxService", "vmware", "vbox"}
    
    for _, f := range files {
        if !f.IsDir() {
            continue
        }
        
        // Check if directory name is a number (PID)
        if _, err := strconv.Atoi(f.Name()); err != nil {
            continue
        }
        
        // Read cmdline
        cmdline, err := ioutil.ReadFile("/proc/" + f.Name() + "/cmdline")
        if err != nil {
            continue
        }
        
        cmdStr := strings.ToLower(string(cmdline))
        for _, procName := range vmProcesses {
            if strings.Contains(cmdStr, procName) {
                return true
            }
        }
    }
    
    return false
}

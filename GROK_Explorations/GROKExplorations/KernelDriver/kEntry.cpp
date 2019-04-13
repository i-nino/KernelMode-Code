#include "kCommon.h"

#pragma warning(disable: 4201)
extern "C" {
    DRIVER_INITIALIZE DriverEntry;
}

#pragma alloc_text(INIT, DriverEntry)

PDRIVER_OBJECT global::DriverObj;
PUNICODE_STRING global::RegistryPath;
PDEVICE_OBJECT global::DeviceObj;



auto OpenFile(
    _In_ PUNICODE_STRING Filename,
    _Out_ PVOID* OutBuffer
)
{
    OBJECT_ATTRIBUTES ObjAttrs =
        RTL_CONSTANT_OBJECT_ATTRIBUTES(Filename, OBJ_CASE_INSENSITIVE);
    HANDLE hFile;
    IO_STATUS_BLOCK StatusBlk;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_DEVICE_STATE;

    auto Status = ZwCreateFile(&hFile,
                               GENERIC_READ,
                               &ObjAttrs,
                               &StatusBlk,
                               nullptr,
                               FILE_ATTRIBUTE_NORMAL,
                               FILE_SHARE_READ,
                               FILE_OPEN,
                               FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_ALERT,
                               nullptr,
                               0);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    FILE_STANDARD_INFORMATION FileInfo = { sizeof(FileInfo) };
    Status = ZwQueryInformationFile(hFile,
                                    &StatusBlk,
                                    &FileInfo,
                                    sizeof FileInfo,
                                    FileStandardInformation);
    if (!NT_SUCCESS(Status))
    {
        ZwClose(hFile);
        return Status;
    }
    auto BufferSize = FileInfo.EndOfFile.LowPart;
    auto Buffer = (PUCHAR) ExAllocatePoolWithTag(NonPagedPoolNx, BufferSize, ALLOC_TAG);
    LARGE_INTEGER ByteOffset {};
    Status = ZwReadFile(hFile,
                        nullptr,
                        nullptr,
                        nullptr,
                        &StatusBlk,
                        Buffer, BufferSize,
                        &ByteOffset,
                        nullptr);

    if (!NT_SUCCESS(Status))
    {
        ZwClose(hFile);
        return Status;
    }

    *OutBuffer = Buffer;
    return Status;

}


//
// ntdll return imagebase, k32 return AddressOfEntry on x64
//
PVOID ResolveKnownDll(SYSTEM_DLL Module)
{
    UNICODE_STRING SectionName;
    wchar_t ModulePath[100] {};

    switch (Module)
    {
        case SYSTEM_DLL::ntdll: 
        {
            RtlInitUnicodeString(&SectionName, KNOWN_DLLS_PATH NTDLL);
            wcscpy(ModulePath, SYSTEM_PATH NTDLL);
        
        } break;
        case SYSTEM_DLL::kernel32: 
        {
            RtlInitUnicodeString(&SectionName, KNOWN_DLLS_PATH KERNEL32);
            wcscpy(ModulePath, SYSTEM_PATH KERNEL32);
        } break;
        case SYSTEM_DLL::kernelbase:
        {
            RtlInitUnicodeString(&SectionName, KNOWN_DLLS_PATH KERNELBASE);
            wcscpy(ModulePath, SYSTEM_PATH KERNELBASE);
        } break;
        default:
            return nullptr;
    }

    OBJECT_ATTRIBUTES SectionAttrs =
        RTL_CONSTANT_OBJECT_ATTRIBUTES(&SectionName, 
                                        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE);

    HANDLE hSection;
    auto Status = ZwOpenSection(&hSection,
                                SECTION_QUERY,
                                &SectionAttrs);
    
    if (!NT_SUCCESS(Status))
    {
        dprintf("ZwOpenSection(): 0x%08X [%d]\n", Status, __LINE__);
        return nullptr;
    }

    SECTION_IMAGE_INFORMATION SectionInfo;
    Status = ZwQuerySection(hSection,
                            SECTION_INFORMATION_CLASS::Image,
                            &SectionInfo,
                            sizeof SectionInfo,
                            nullptr);

    ZwClose(hSection);
    if (!NT_SUCCESS(Status))
    {
        dprintf("ZwQuerySection(): 0x%08X [%d]\n", Status, __LINE__);
        return nullptr;
    }

    PVOID ImageBase {};
    if (Module != SYSTEM_DLL::ntdll)
    {
        DBG_BREAK;
        PUCHAR Buffer {};
        Status = OpenFile(&SectionName, (PVOID*) &Buffer);
        if (NT_SUCCESS(Status) && Buffer != nullptr)
        {
            auto NtHeader = (PIMAGE_NT_HEADERS) (Buffer + ((PIMAGE_DOS_HEADER) Buffer)->e_lfanew);
            ImageBase = (PVOID) (NtHeader->OptionalHeader.AddressOfEntryPoint - (ULONG_PTR) SectionInfo.TransferAddress);
            ExFreePool(Buffer);
        }
    } else
        ImageBase = (PVOID) SectionInfo.TransferAddress;

    dprintf("--[ 0x%p |\n", SectionInfo.TransferAddress);
    return ImageBase;

}


NTSTATUS DriverEntry(
    PDRIVER_OBJECT DriverObj,
    PUNICODE_STRING RegistryPath
)
{
    auto Status = STATUS_SUCCESS;

    global::DriverObj = DriverObj;
    global::RegistryPath = RegistryPath;

    GROK_Explorations();

    /*auto a = ResolveKnownDll(SYSTEM_DLL::kernel32);
    auto b = ResolveKnownDll(SYSTEM_DLL::ntdll);
    auto c = ResolveKnownDll(SYSTEM_DLL::kernelbase);
    dprintf("--[ 0x%p] | [ 0x%p] | [0x%p\n", a, b, c);
*/
    DriverObj->DriverUnload = [](PDRIVER_OBJECT) -> VOID { return; };

    return Status;
}

NTSTATUS WnfTest()
{
    auto Status = STATUS_SUCCESS;
    WNF_STATE_NAME StateName;
    PWNF_SUBSCRIPTION WnfSubscription = nullptr;
    WnfSetStateName(&StateName, WNF_NAME_ID::SHEL_DESKTOP_APPLICATION_STARTED);

    Status = ExSubscribeWnfStateChange(&WnfSubscription,
                                        &StateName,
                                        0x1,
                                        nullptr,
                                        [](PWNF_SUBSCRIPTION Sub,
                                           PWNF_STATE_NAME,
                                           ULONG,
                                           WNF_CHANGE_STAMP,
                                           PWNF_TYPE_ID,
                                           PVOID) -> NTSTATUS
    {
        WNF_CHANGE_STAMP changeStamp;
        ULONG bufSize {};
        auto status = ExQueryWnfStateData(Sub,
                                          &changeStamp,
                                          nullptr,
                                          &bufSize);
        if (status != STATUS_BUFFER_TOO_SMALL)
            return status;

        auto psName = ExAllocatePoolWithTag(PagedPool, bufSize, ALLOC_TAG);
        status = ExQueryWnfStateData(Sub, &changeStamp, psName, &bufSize);
        if (NT_SUCCESS(status))
            dprintf("--[ %ws being launched!\n", psName);
        ExFreePool(psName);
        return status;
    },
                                        nullptr);
    return Status;
}
#include "kCommon.h"

extern "C" {
    ///
    ///<summary>GROK implementations of "hidden" function calls</summary>
    ///
    void* ASM_HiddenCall(
        ULONG NumOfArgs,
        PVOID Arg1,
        PVOID Arg2,
        PVOID Arg3,
        PVOID Arg4,
        PVOID Arg5,
        PVOID Arg6);

    void  ASM_CallRsi();
    signed int ASM_HashExportedFn(PCHAR);

    void ASM_LocateKernelBaseFromRoutine(
        PVOID Routine, 
        ULONG Size, 
        ULONG_PTR* OutResult);
}

///
/// for the dummy test
///

struct SYSTEM_MODULE_ENTRY_INFORMATION
{
    HANDLE 	Section;
    PVOID 	MappedBase;
    PVOID 	ImageBase;
    ULONG 	ImageSize;
    ULONG 	Flags;
    USHORT 	LoadOrderIndex;
    USHORT 	InitOrderIndex;
    USHORT 	LoadCount;
    USHORT 	OffsetToFileName;
    UCHAR 	FullPathName[256];
};
struct SYSTEM_MODULES_INFORMATION
{
    ULONG NumberOfModules;
    SYSTEM_MODULE_ENTRY_INFORMATION Modules[1];
};

///
/// Routines it uses
///
using QUERY_INFO = NTSTATUS(*)(SYSTEM_INFO, PVOID, SIZE_T, PSIZE_T);
using POOL_ALLOC = PVOID(*)(POOL_TYPE, SIZE_T);
using POOL_FREE = VOID(*)(PVOID);

static QUERY_INFO GROK_QueryInfo;
static POOL_ALLOC GROK_Alloc;
static POOL_FREE  GROK_Free;

#pragma warning(push)
#pragma warning(disable: 4311 4302)  // to cast freely is a great responsibility
namespace hidden {

    auto QuerySysInfo(
        SYSTEM_INFO Class,
        PVOID Buffer,
        SIZE_T BufferSize,
        SIZE_T* RequiredSize
    )
    {
        return (NTSTATUS) ASM_HiddenCall(4,
                                         (void*) Class,
                                         (void*) Buffer,
                                         (void*) BufferSize,
                                         (void*) RequiredSize,
                                         (void*) GROK_QueryInfo,
                                         (void*) ASM_CallRsi);
    }

    auto Alloc(
        POOL_TYPE PoolType,
        SIZE_T BufferSize
    )
    {
        return ASM_HiddenCall(2,
                              (void*) PoolType,
                              (void*) BufferSize,
                              (void*) GROK_Alloc,
                              (void*) ASM_CallRsi,
                              nullptr, nullptr);
    }

    auto Free(
        PVOID Buffer
    )
    {
        return ASM_HiddenCall(1,
                              (void*) Buffer,
                              (void*) GROK_Free,
                              (void*) ASM_CallRsi,
                              nullptr, nullptr, nullptr);
    }


}
#pragma warning(pop)

auto GROK_Explorations() -> NTSTATUS
{
    
    ULONG_PTR NtosBase {};
    ASM_LocateKernelBaseFromRoutine((void*) NtQueryDirectoryFile, 0x1000, &NtosBase);
    
    auto GetFunctionFromHash = [&NtosBase](INT32 FunctionHash) -> void*
    {
        auto NtHeader = (PIMAGE_NT_HEADERS) (NtosBase + ((PIMAGE_DOS_HEADER) NtosBase)->e_lfanew);
        auto ExportDir = (PIMAGE_EXPORT_DIRECTORY) (NtosBase + NtHeader->OptionalHeader.DataDirectory[0].VirtualAddress);
        if (!ExportDir)
            return nullptr;
        
        auto Fns   = (PULONG)  (NtosBase + ExportDir->AddressOfFunctions);
        auto Names = (PULONG)  (NtosBase + ExportDir->AddressOfNames);
        auto Ords  = (PUSHORT) (NtosBase + ExportDir->AddressOfNameOrdinals);

        void* RoutineAddress {};
        for (UINT32 i {}; i < ExportDir->NumberOfNames; ++i)
        {
            auto NameOfRoutine = (PCHAR) (NtosBase + Names[i]);
            if (FunctionHash == ASM_HashExportedFn(NameOfRoutine))
            {
                RoutineAddress = (void*)(NtosBase + Fns[Ords[i]]);
                break;
            }
        }

        return RoutineAddress;
    };


    GROK_QueryInfo = (QUERY_INFO) GetFunctionFromHash(0x212FB41E);
    GROK_Alloc     = (POOL_ALLOC) GetFunctionFromHash(0xE016F24C);
    GROK_Free      = (POOL_FREE)  GetFunctionFromHash(0xCBD0FC0D);

    if (!GROK_QueryInfo || !GROK_Alloc || !GROK_Free)
        return STATUS_UNSUCCESSFUL;

    //
    // Useless Dummy test to validate it's working
    
    SIZE_T BufferSize {};
    auto Status = hidden::QuerySysInfo(SYSTEM_INFO::Module, nullptr, 0, &BufferSize);
    auto DriverInfo = (SYSTEM_MODULES_INFORMATION*) hidden::Alloc(NonPagedPoolNx, BufferSize);
    if (!DriverInfo)
        return STATUS_INSUFFICIENT_RESOURCES;
   
    Status = hidden::QuerySysInfo(SYSTEM_INFO::Module, DriverInfo, BufferSize, nullptr);
    if (NT_SUCCESS(Status))
    {
        for (unsigned int i {}; i < DriverInfo->NumberOfModules; ++i)
        {
            auto BaseOffset = DriverInfo->Modules[i].OffsetToFileName;
            auto DriverName = (LPCSTR) &DriverInfo->Modules[i].FullPathName[BaseOffset];
            dprintf("--[ 0x%p | %s\n", DriverInfo->Modules[i].ImageBase, DriverName);
        }
    }
    
    hidden::Free(DriverInfo);

    return Status;

}

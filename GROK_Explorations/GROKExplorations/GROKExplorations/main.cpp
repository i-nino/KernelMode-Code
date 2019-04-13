#include <Windows.h>
#include <cinttypes>
#include <memory>

extern "C" {
   
   void* hiddenCall(
       uint32_t NumOfArgs,
       void* Arg1,
       void* Arg2,
       void* Arg3,
       void* Arg4,
       void* Arg5,
       void* Arg6
   );

   //
   // instead of searching through the memory for another,
   // just stick with Captain Obvious
   //
   void* callRsi();

}

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
} ;


using QUERY_INFO   = long(*)(uint32_t, void*, unsigned long, unsigned long*);
auto NtQuerySystemInfo = (QUERY_INFO)::GetProcAddress(::GetModuleHandle(L"ntdll.dll"),
                                                      "NtQuerySystemInformation");

auto HiddenNtQuery(
    DWORD Class,
    PVOID DriverInfo,
    SIZE_T DriverInfoSize,
    SIZE_T* ReturnedDriverInfoSize
)
{
    return hiddenCall(4,
                      (void*) Class,
                      (void*) DriverInfo,
                      (void*) DriverInfoSize,
                      (void*) ReturnedDriverInfoSize,
                      (void*) NtQuerySystemInfo,
                      (void*) callRsi);
}


int main()
{ 
    size_t requiredSize {};
    HiddenNtQuery(11, nullptr, 0, &requiredSize);
    auto DriverInfo = std::make_unique<SYSTEM_MODULES_INFORMATION[]>(requiredSize);
    HiddenNtQuery(11, DriverInfo.get(), requiredSize, nullptr);

    for (uint32_t i {}; i < DriverInfo.get()->NumberOfModules; ++i)
    {
        auto OffsetToFileName = DriverInfo.get()->Modules[i].OffsetToFileName;
        auto DriverBaseName   = &DriverInfo.get()->Modules[i].FullPathName[OffsetToFileName];
        ::printf("--[ 0x%p : %s\n", DriverInfo.get()->Modules[i].ImageBase, DriverBaseName);
    }
    
}

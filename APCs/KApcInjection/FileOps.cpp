#include <ntifs.h>
#include <ntimage.h>
#include "Common.h"

#define GET_PTR(CAST_TYPE, RVA) \
	((CAST_TYPE*) (((PBYTE)Module)+ RawOffsetByRVA(Section, \
												  NumOfSections, \
												  szModule, \
												  (RVA))))
#define ERROR(status)  \
	DbgPrint("NT_ERROR: 0x%08X [%s]\n", status, __FUNCTION__); \
	return status 

#define IS_ADDRESS_BETWEEN(left, right, address) \
		( (address) >= (left) && (address) < (right) ) 

#define GET_FN_DISK_ADDRESS() \
	ULONG_PTR( ((PBYTE)Module) + \
		Text->PointerToRawData + Fns[Ords[i]] - Text->VirtualAddress)





static
PIMAGE_SECTION_HEADER
SectionByRVA(
	PIMAGE_SECTION_HEADER Section,
	ULONG NumOfSections,
	ULONG Rva)
{
	auto Header = Section;
	for (size_t i {}; i < NumOfSections; ++Header) {
		if (IS_ADDRESS_BETWEEN(Header->VirtualAddress,
			(Header->VirtualAddress + Header->SizeOfRawData),
								Rva))
			return Section;
	}
	return nullptr;
}

static
ULONG
RawOffsetByRVA(
	PIMAGE_SECTION_HEADER Section,
	ULONG NumOfSections,
	ULONG FileSz,
	ULONG Rva)
{
	auto SectionHeader = SectionByRVA(Section,
										NumOfSections,
										Rva);
	if (!SectionHeader)
		return { 0 };
	auto Delta = Rva - SectionHeader->VirtualAddress;
	auto Offset = SectionHeader->PointerToRawData + Delta;

	return (Offset < FileSz) ? Offset : 0ul;
}





NTSTATUS
Injection::
KOpenFile(
	LPCWSTR FileName,
	PBYTE * ModuleBase,
	ULONG * szModule)
{
	OBJECT_ATTRIBUTES ObjAttrs;
	UNICODE_STRING Name {};
	RtlInitUnicodeString(&Name, FileName);
	InitializeObjectAttributes(&ObjAttrs,
							   &Name,
							   OBJ_CASE_INSENSITIVE,
							   nullptr,
							   nullptr);

	HANDLE FileHandle;
	IO_STATUS_BLOCK StatusBlk;
	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
		return STATUS_INVALID_DEVICE_STATE;
	auto status = ZwCreateFile(&FileHandle,
							   GENERIC_READ,
							   &ObjAttrs,
							   &StatusBlk,
							   nullptr,
							   FILE_ATTRIBUTE_NORMAL,
							   FILE_SHARE_READ,
							   FILE_OPEN,
							   FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
							   nullptr,
							   0);
	if (!NT_SUCCESS(status)) {
		ERROR(status);
	}

	FILE_STANDARD_INFORMATION FileInfo = { sizeof(FileInfo) };
	status = ZwQueryInformationFile(FileHandle,
									&StatusBlk,
									&FileInfo,
									sizeof(FileInfo),
									FileStandardInformation);
	if (!NT_SUCCESS(status)) {
		ZwClose(FileHandle);
		ERROR(status);
	}

	*szModule = FileInfo.EndOfFile.LowPart;
	DbgPrint("[+] %ws file size: %08X\n", Name.Buffer, *szModule);
	*ModuleBase = (PBYTE) ExAllocatePoolWithTag(NonPagedPool,
												*szModule,
												KAPC_TAG);
	if (!(*ModuleBase)) {
		ZwClose(FileHandle);
		ERROR(status);
	}
	LARGE_INTEGER ByteOffset {};
	status = ZwReadFile(FileHandle,
						nullptr,
						nullptr,
						nullptr,
						&StatusBlk,
						*ModuleBase, *szModule,
						&ByteOffset,
						nullptr);

	if (!NT_SUCCESS(status)) {
		ExFreePoolWithTag(ModuleBase, KAPC_TAG);
		ZwClose(FileHandle);
		ERROR(status);
	}
	ZwClose(FileHandle);
	DbgPrint("[+] %ws @ : 0x%p\n", Name.Buffer, *ModuleBase);
	return status;

}

NTSTATUS
Injection::
KGetRoutineAddressFromModule(
	LPCWSTR ModulePath,
	LPCSTR FunctionName,
	ULONG* FunctionRva)
{
	PBYTE Module {};
	ULONG szModule {};
	auto status = KOpenFile(ModulePath,
							&Module,
							&szModule);
	if (!NT_SUCCESS(status))
		return status;

	auto Dos = (PIMAGE_DOS_HEADER) Module;
	auto Nt = (PIMAGE_NT_HEADERS) (Module + Dos->e_lfanew);
	auto NumOfSections = Nt->FileHeader.NumberOfSections;
	auto ExportRva = Nt->OptionalHeader.DataDirectory[0].VirtualAddress;
	auto ExportSz = Nt->OptionalHeader.DataDirectory[0].Size;
	if (ExportRva && ExportSz) {
		auto Section = IMAGE_FIRST_SECTION(Nt);
		auto Text = Section; //used for parsing later, as fns are in .text section
		PIMAGE_EXPORT_DIRECTORY ExportDir {};
		for (USHORT i = 0; i < Nt->FileHeader.NumberOfSections; ++i) {
			if (Section[i].VirtualAddress <= ExportRva &&
				ExportRva < Section[i].VirtualAddress + Section[i].Misc.VirtualSize) {
				Section = (PIMAGE_SECTION_HEADER) &Section[i];
				ExportDir = (PIMAGE_EXPORT_DIRECTORY) ((PBYTE) Module +
													   Section->PointerToRawData +
													   ExportRva - Section->VirtualAddress);
				break;
			}
		}
		auto Fns = GET_PTR(ULONG, ExportDir->AddressOfFunctions);
		auto Names = GET_PTR(ULONG, ExportDir->AddressOfNames);
		auto Ords = GET_PTR(USHORT, ExportDir->AddressOfNameOrdinals);


		for (size_t i {}; i < ExportDir->NumberOfNames; ++i) {
			auto NameRaw = RawOffsetByRVA(Section,
										  NumOfSections,
										  szModule,
										  Names[i]);
			auto Name = (PCHAR) (Module + NameRaw);

			if (strcmp(FunctionName, Name) == 0) {
				if (Fns[Ords[i]] < ExportRva ||
					Fns[Ords[i]] > (ExportRva + ExportSz)) {
					auto FnRva = Fns[Ords[i]];
					auto FunctionOnDisk = GET_FN_DISK_ADDRESS();
					DbgPrint("0x%X: %s [ON_DISK]\n", FunctionOnDisk, Name);
					DbgPrint("%lu:  %s [RVA]\n", FnRva, Name);
					*FunctionRva = FnRva;
					break;
				}
			}

		}
		if (*FunctionRva == 0ul)
			status = STATUS_UNSUCCESSFUL;

	}
	ExFreePoolWithTag(Module, KAPC_TAG);
	return status;
}
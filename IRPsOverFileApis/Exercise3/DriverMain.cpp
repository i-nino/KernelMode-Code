#include "common.h"
#include "io_ops.h"

/*
	Completey decompiled and rewritten in C++ (with several modifications)
	of SampleE's technique of attempting to bypass security software that
	keep a close eye (hooks) on the Native Api syscall functionality

	Also, demonstrate how to "properly" delete a file 
	
*/

extern "C" {

	DRIVER_INITIALIZE
		DriverEntry;

	DRIVER_UNLOAD
		DriverUnload;

}


#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DriverUnload)
#endif

PDRIVER_OBJECT KDriverObj {};

NTSTATUS
DriverEntry(
	PDRIVER_OBJECT DriverObject,
	PUNICODE_STRING RegistryPath
)
{
	TRACER();
	UNREFERENCED_PARAMETER(RegistryPath);
	KDriverObj = DriverObject;

	auto Status = IO_OPS::CreateSystemThreadToDeleteFile();
	Status = IO_OPS::DeleteFile(L"\\??\\C:\\users\\pro\\Desktop\\DELETE_ME.txt");

	DriverObject->DriverUnload = 
		[](PDRIVER_OBJECT DriverObj)
	{
		UNREFERENCED_PARAMETER(DriverObj);
		return;
	};
	return Status;
}
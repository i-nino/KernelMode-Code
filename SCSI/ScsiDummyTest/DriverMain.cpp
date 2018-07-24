#include "Common.h" 
#include "SCSI.h"

extern "C" {
	DRIVER_INITIALIZE DriverEntry; 

	
}

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)

#endif

 /**/
NTSTATUS
DriverEntry(
	PDRIVER_OBJECT DriverObject,
	PUNICODE_STRING RegistryPath
)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	auto Status = STATUS_SUCCESS; 

	SCSI::InitializeSCSISystemThread();

	DriverObject->DriverUnload = [](PDRIVER_OBJECT DriverObj)
	{
		UNREFERENCED_PARAMETER(DriverObj);
	};

	/* beginning of sample_f routine */
	ULONG NumOfActualDevices;
	PDEVICE_OBJECT DeviceObjs[1024];
	PDRIVER_OBJECT DiskDriver;
	UNICODE_STRING DiskDriverPath = RTL_CONSTANT_STRING(L"\\Driver\\Disk");
	Status = ObReferenceObjectByName(&DiskDriverPath,
					 OBJ_CASE_INSENSITIVE,
					 nullptr,
					 0,
					 (POBJECT_TYPE) *IoDriverObjectType,
					 KernelMode,
					 nullptr,
					 (PVOID*) &DiskDriver);
	if (NT_SUCCESS(Status)) {
		IoEnumerateDeviceObjectList(DiskDriver,
					    DeviceObjs,
					    0x400,
					    &NumOfActualDevices);
		if (NumOfActualDevices) {
			do {
				--NumOfActualDevices;
				DbgPrint("[+] Worked!\n");
				ObDereferenceObject(DeviceObjs[NumOfActualDevices]);
			} while (NumOfActualDevices != 0);
		}
		ObDereferenceObject(DiskDriver);
	}


	return Status;
}
	




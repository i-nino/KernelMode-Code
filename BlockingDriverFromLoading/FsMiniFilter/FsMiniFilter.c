 
#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <Ntstrsafe.h>
#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")


PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = 0;


#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

/*************************************************************************
    Prototypes
*************************************************************************/

EXTERN_C_START

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    );

NTSTATUS
FsMiniFilterInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    );

VOID
FsMiniFilterInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

VOID
FsMiniFilterInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    );

NTSTATUS
FsMiniFilterUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    );

NTSTATUS
FsMiniFilterInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    );
    
/* most of the stuff is auto-generated : here's the primary routine */    
#pragma region MyRoutines
FLT_PREOP_CALLBACK_STATUS
FsMiniFilterPreOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

FLT_PREOP_CALLBACK_STATUS
FsMiniPreReadCallback(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);
/* prevents certain content in files b*/
FLT_PREOP_CALLBACK_STATUS
FsMiniPreWriteCallback(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);
/**********************************************************/
/* prevents specified drivers/images from being loaded*/
FLT_PREOP_CALLBACK_STATUS
FsMiniPreSectionSyncCallback(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);
/**********************************************************/

#pragma endregion
VOID
FsMiniFilterOperationStatusCallback (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
    );

FLT_POSTOP_CALLBACK_STATUS
FsMiniFilterPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    );

FLT_PREOP_CALLBACK_STATUS
FsMiniFilterPreOperationNoPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    );

BOOLEAN
FsMiniFilterDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
    );

EXTERN_C_END
 

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, FsMiniFilterUnload)
#pragma alloc_text(PAGE, FsMiniFilterInstanceQueryTeardown)
#pragma alloc_text(PAGE, FsMiniFilterInstanceSetup)
#pragma alloc_text(PAGE, FsMiniFilterInstanceTeardownStart)
#pragma alloc_text(PAGE, FsMiniFilterInstanceTeardownComplete)
#endif


const
FLT_OPERATION_REGISTRATION
Callbacks[] = {
	{ IRP_MJ_CREATE,
	  0,
	  FsMiniPreReadCallback,
	  FsMiniFilterPostOperation },
	{ IRP_MJ_WRITE,
	  0,
	  FsMiniPreWriteCallback,
	  NULL
	},
	{ IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION, /* <== to prevent image from loading */
	  0,
	  FsMiniPreSectionSyncCallback,
	  NULL
	},
	{ IRP_MJ_OPERATION_END }

};
/* This defines what we want to filter with FltMgr */
CONST 
FLT_REGISTRATION 
FilterRegistration = {

    sizeof( FLT_REGISTRATION ),         //  Size
    FLT_REGISTRATION_VERSION,           //  Version
    0,                                  //  Flags

    NULL,                               //  Context
    Callbacks,                          //  Operation callbacks

    FsMiniFilterUnload,                           //  MiniFilterUnload

    FsMiniFilterInstanceSetup,                    //  InstanceSetup
    FsMiniFilterInstanceQueryTeardown,            //  InstanceQueryTeardown
    FsMiniFilterInstanceTeardownStart,            //  InstanceTeardownStart
    FsMiniFilterInstanceTeardownComplete,         //  InstanceTeardownComplete

    NULL,                               //  GenerateFileName
    NULL,                               //  GenerateDestinationFileName
    NULL                                //  NormalizeNameComponent

};



NTSTATUS
FsMiniFilterInstanceSetup (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
    )
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );
    UNREFERENCED_PARAMETER( VolumeDeviceType );
    UNREFERENCED_PARAMETER( VolumeFilesystemType );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FsMiniFilter!FsMiniFilterInstanceSetup: Entered\n") );

    return STATUS_SUCCESS;
}


NTSTATUS
FsMiniFilterInstanceQueryTeardown (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FsMiniFilter!FsMiniFilterInstanceQueryTeardown: Entered\n") );

    return STATUS_SUCCESS;
}


VOID
FsMiniFilterInstanceTeardownStart (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FsMiniFilter!FsMiniFilterInstanceTeardownStart: Entered\n") );
}


VOID
FsMiniFilterInstanceTeardownComplete (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FsMiniFilter!FsMiniFilterInstanceTeardownComplete: Entered\n") );
}


/*************************************************************************
    MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS Status;

    UNREFERENCED_PARAMETER( RegistryPath );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FsMiniFilter!DriverEntry: Entered\n") );

   
    Status = FltRegisterFilter( DriverObject,
                                &FilterRegistration,
                                &gFilterHandle );

    FLT_ASSERT(NT_SUCCESS(Status));

    if (NT_SUCCESS(Status)) {
		/* Start filtering i/o */
		Status = FltStartFiltering(gFilterHandle);
        if (!NT_SUCCESS(Status)) {
            FltUnregisterFilter( gFilterHandle );
        }
    }

    return Status;
}

NTSTATUS
FsMiniFilterUnload (
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
    )
{
    UNREFERENCED_PARAMETER( Flags );

    PAGED_CODE();

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FsMiniFilter!FsMiniFilterUnload: Entered\n") );

    FltUnregisterFilter( gFilterHandle );

    return STATUS_SUCCESS;
}


/*************************************************************************
    MiniFilter callback routines.
*************************************************************************/
FLT_PREOP_CALLBACK_STATUS
FsMiniFilterPreOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FsMiniFilter!FsMiniFilterPreOperation: Entered\n") );

    //
    //  See if this is an operation we would like the operation status
    //  for.  If so request it.
    //
    //  NOTE: most filters do NOT need to do this.  You only need to make
    //        this call if, for example, you need to know if the oplock was
    //        actually granted.
    //
 
    if (FsMiniFilterDoRequestOperationStatus( Data )) {

        status = FltRequestOperationStatusCallback( Data,
                                                    FsMiniFilterOperationStatusCallback,
                                                    (PVOID)(++OperationStatusCtx) );
        if (!NT_SUCCESS(status)) {

            PT_DBG_PRINT( PTDBG_TRACE_OPERATION_STATUS,
                          ("FsMiniFilter!FsMiniFilterPreOperation: FltRequestOperationStatusCallback Failed, status=%08x\n",
                           status) );
        }
    }

    // This template code does not do anything with the callbackData, but
    // rather returns FLT_PREOP_SUCCESS_WITH_CALLBACK.
    // This passes the request down to the next miniFilter in the chain.

    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

/* here we are */
#pragma region MyCallbacks

FLT_PREOP_CALLBACK_STATUS
FsMiniPreReadCallback(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
) 
{
	NTSTATUS status; 
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	
	 
	PFLT_FILE_NAME_INFORMATION FileNameInfo = { 0 };
	status = FltGetFileNameInformation(Data,
					   FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
					   &FileNameInfo);
	if (NT_SUCCESS(status)) {
		status = FltParseFileNameInformation(FileNameInfo);
		if (NT_SUCCESS(status)) {
			if (FileNameInfo->Name.Length > 2) { 
				wchar_t* TargetFileName = wcsstr(FileNameInfo->Name.Buffer,
                                         L"help_me.txt");
				if (TargetFileName) {
					if (_wcsicmp(L"help_me.txt", TargetFileName) == 0) {
						DbgPrint("(!) [%ws] BLOCKED!\n", TargetFileName);
						Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
						Data->IoStatus.Information = 0;
						FltReleaseFileNameInformation(FileNameInfo);
						return FLT_PREOP_COMPLETE;
					}
				}
			}
		}
		FltReleaseFileNameInformation(FileNameInfo);
	}
 
	 
	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS
FsMiniPreWriteCallback(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
{
	NTSTATUS status;
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	PFLT_FILE_NAME_INFORMATION FileNameInfo = { 0 };
	status = FltGetFileNameInformation(Data,
					   FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
					   &FileNameInfo);
	if (NT_SUCCESS(status)) {
		status = FltParseFileNameInformation(FileNameInfo);
		if (NT_SUCCESS(status)) {
			if (FileNameInfo->Name.Length > 2) {
				//DbgPrint("[+] (FileName) %wZ\n", FileNameInfo->Name);
				wchar_t* TargetFileName = wcsstr(FileNameInfo->Name.Buffer,  L"open_me.txt");
				if (TargetFileName) { 
					TargetFileName = _wcsupr(TargetFileName);
					if (_wcsicmp(L"OPEN_ME.txt",  TargetFileName) == 0) 
					{
						DbgPrint("(!) [%ws] BLOCKED!\n", TargetFileName);
						Data->IoStatus.Status = STATUS_INVALID_PARAMETER;
						Data->IoStatus.Information = 0;
						FltReleaseFileNameInformation(FileNameInfo);
						return FLT_PREOP_COMPLETE;
					}
				} 
			}
		}
		FltReleaseFileNameInformation(FileNameInfo);
	}


	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

/* Interestingly enough, using C-Style string fns prevents the driver 
   from loading every time, whereas using the RtlUnicode* routines 
   denys loading the driver irregularly - perhaps the callback routines
   in general need to be short and snappy since they are actively called - 
   TODO: see why this is the case, maybe I'm making a mistake somewhere*/
FLT_PREOP_CALLBACK_STATUS 
FsMiniPreSectionSyncCallback(
	PFLT_CALLBACK_DATA Data, 
	PCFLT_RELATED_OBJECTS FltObjects, 
	_Flt_CompletionContext_Outptr_ PVOID * CompletionContext
)
{
	NTSTATUS status;
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	if (Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection == PAGE_EXECUTE) {
		PFLT_FILE_NAME_INFORMATION FileNameInfo = { 0 };
		status = FltGetFileNameInformation(Data,
						   FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
						   &FileNameInfo);
		if (NT_SUCCESS(status)) {
			status = FltParseFileNameInformation(FileNameInfo);
			if (NT_SUCCESS(status)) {
				if (FileNameInfo->Name.Buffer && FileNameInfo->Name.Length > 2) { 
				
					wchar_t* TargetFileName = FileNameInfo->Name.Buffer;
					TargetFileName = _wcsupr(TargetFileName);
					DbgPrint("-- %ws\n", TargetFileName);
					TargetFileName = wcsstr(TargetFileName, L"KERNELEXPLORER.SYS");
					
					if (TargetFileName) {
						if (_wcsicmp(L"KERNELEXPLORER.SYS", TargetFileName) == 0) 
						{
							DbgPrint("(!) BLOCKING [%ws] FROM LOADING!\n", TargetFileName);
							Data->IoStatus.Status = STATUS_ACCESS_DENIED;
							Data->IoStatus.Information = 0;
							FltReleaseFileNameInformation(FileNameInfo);
							return FLT_PREOP_COMPLETE;
						}
					}
				}
			}
			FltReleaseFileNameInformation(FileNameInfo);
		}
	}
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

#pragma endregion

VOID
FsMiniFilterOperationStatusCallback (
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
    _In_ NTSTATUS OperationStatus,
    _In_ PVOID RequesterContext
    )
/*++

Routine Description:

    This routine is called when the given operation returns from the call
    to IoCallDriver.  This is useful for operations where STATUS_PENDING
    means the operation was successfully queued.  This is useful for OpLocks
    and directory change notification operations.

    This callback is called in the context of the originating thread and will
    never be called at DPC level.  The file object has been correctly
    referenced so that you can access it.  It will be automatically
    dereferenced upon return.

    This is non-pageable because it could be called on the paging path

Arguments:

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    RequesterContext - The context for the completion routine for this
        operation.

    OperationStatus -

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( FltObjects );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FsMiniFilter!FsMiniFilterOperationStatusCallback: Entered\n") );

    PT_DBG_PRINT( PTDBG_TRACE_OPERATION_STATUS,
                  ("FsMiniFilter!FsMiniFilterOperationStatusCallback: Status=%08x ctx=%p IrpMj=%02x.%02x \"%s\"\n",
                   OperationStatus,
                   RequesterContext,
                   ParameterSnapshot->MajorFunction,
                   ParameterSnapshot->MinorFunction,
                   FltGetIrpName(ParameterSnapshot->MajorFunction)) );
}


FLT_POSTOP_CALLBACK_STATUS
FsMiniFilterPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags
    )
/*++

Routine Description:

    This routine is the post-operation completion routine for this
    miniFilter.

    This is non-pageable because it may be called at DPC level.

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The completion context set in the pre-operation routine.

    Flags - Denotes whether the completion is successful or is being drained.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );
    UNREFERENCED_PARAMETER( Flags );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FsMiniFilter!FsMiniFilterPostOperation: Entered\n") );

    return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
FsMiniFilterPreOperationNoPostOperation (
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext
    )
/*++

Routine Description:

    This routine is a pre-operation dispatch routine for this miniFilter.

    This is non-pageable because it could be called on the paging path

Arguments:

    Data - Pointer to the filter callbackData that is passed to us.

    FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
        opaque handles to this filter, instance, its associated volume and
        file object.

    CompletionContext - The context for the completion routine for this
        operation.

Return Value:

    The return value is the status of the operation.

--*/
{
    UNREFERENCED_PARAMETER( Data );
    UNREFERENCED_PARAMETER( FltObjects );
    UNREFERENCED_PARAMETER( CompletionContext );

    PT_DBG_PRINT( PTDBG_TRACE_ROUTINES,
                  ("FsMiniFilter!FsMiniFilterPreOperationNoPostOperation: Entered\n") );

    // This template code does not do anything with the callbackData, but
    // rather returns FLT_PREOP_SUCCESS_NO_CALLBACK.
    // This passes the request down to the next miniFilter in the chain.

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


BOOLEAN
FsMiniFilterDoRequestOperationStatus(
    _In_ PFLT_CALLBACK_DATA Data
    )
/*++

Routine Description:

    This identifies those operations we want the operation status for.  These
    are typically operations that return STATUS_PENDING as a normal completion
    status.

Arguments:

Return Value:

    TRUE - If we want the operation status
    FALSE - If we don't

--*/
{
    PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

    //
    //  return boolean state based on which operations we are interested in
    //

    return (BOOLEAN)

            //
            //  Check for oplock operations
            //

             (((iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) &&
               ((iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_FILTER_OPLOCK)  ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_BATCH_OPLOCK)   ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_1) ||
                (iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_2)))

              ||

              //
              //    Check for directy change notification
              //

              ((iopb->MajorFunction == IRP_MJ_DIRECTORY_CONTROL) &&
               (iopb->MinorFunction == IRP_MN_NOTIFY_CHANGE_DIRECTORY))
             );
}

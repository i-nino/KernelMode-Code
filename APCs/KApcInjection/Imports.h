#pragma once

extern "C" {

	extern PDRIVER_OBJECT* IoDriverObjectType;

	/* close cousin to ObReferenceObjectByHandle, this routine returns
	a ptr to any object in the object directory, if the name of the
	obj is known.  ObDeref obj when finished with it*/
	NTKERNELAPI
		NTSTATUS
		NTAPI
		ObReferenceObjectByName(
			PUNICODE_STRING ObjectPath,
			ULONG Attributes,
			PACCESS_STATE PassedAccessState OPTIONAL,
			ACCESS_MASK DesiredAccess OPTIONAL,
			POBJECT_TYPE ObjectType OPTIONAL,
			KPROCESSOR_MODE AccessMode,
			PVOID ParseContext OPTIONAL,
			OUT PVOID* ObjectPtr
		);



	typedef enum _KAPC_ENVIRONMENT
	{
		OriginalApcEnvironment,
		AttachedApcEnvironment,
		CurrentApcEnvironment,
		InsertApcEnvironment
	} KAPC_ENVIRONMENT, *PKAPC_ENVIRONMENT;

	typedef VOID(NTAPI *PKNORMAL_ROUTINE)(
		_In_ PVOID NormalContext,
		_In_ PVOID SystemArgument1,
		_In_ PVOID SystemArgument2
		);

	typedef VOID KKERNEL_ROUTINE(
		_In_ PRKAPC Apc,
		_Inout_ PKNORMAL_ROUTINE *NormalRoutine,
		_Inout_ PVOID *NormalContext,
		_Inout_ PVOID *SystemArgument1,
		_Inout_ PVOID *SystemArgument2
	);

	typedef KKERNEL_ROUTINE(NTAPI *PKKERNEL_ROUTINE);

	typedef VOID(NTAPI *PKRUNDOWN_ROUTINE)(
		_In_ PRKAPC Apc
		);

	NTKERNELAPI
		VOID
		NTAPI
		KeInitializeApc(
			_Out_ PRKAPC Apc,
			_In_ PRKTHREAD Thread,
			_In_ KAPC_ENVIRONMENT Environment,
			_In_ PKKERNEL_ROUTINE KernelRoutine,
			_In_opt_ PKRUNDOWN_ROUTINE RundownRoutine,
			_In_opt_ PKNORMAL_ROUTINE NormalRoutine,
			_In_opt_ KPROCESSOR_MODE ProcessorMode,
			_In_opt_ PVOID NormalContext
		);

	NTKERNELAPI
		BOOLEAN
		NTAPI
		KeInsertQueueApc(
			_Inout_ PRKAPC Apc,
			_In_opt_ PVOID SystemArgument1,
			_In_opt_ PVOID SystemArgument2,
			_In_ KPRIORITY Increment
		);

	NTKERNELAPI
		NTSTATUS
		NTAPI
		PsLookupProcessThreadByCid(
			_In_ PCLIENT_ID ClientId,
			_Out_opt_ PEPROCESS *Process,
			_Out_ PETHREAD *Thread
		);

	NTKERNELAPI
		PCHAR
		NTAPI
		PsGetProcessImageFileName(
			_In_ PEPROCESS Process
		);

	NTKERNELAPI
		PVOID
		NTAPI
		PsGetProcessSectionBaseAddress(
			_In_ PEPROCESS Process
		);

	NTKERNELAPI
		PVOID
		NTAPI
		PsGetProcessPeb(
			_In_ PEPROCESS Process
		);

}



namespace Injection {
	NTSTATUS
		KOpenFile(
			LPCWSTR FileName,
			_Inout_ PBYTE* Module,
			_Inout_ ULONG* ModuleSize
		);


	NTSTATUS
		KGetRoutineAddressFromModule(
			LPCWSTR ModulePath,
			LPCSTR FunctionName,
			_Inout_ ULONG* FunctionRva
		);
}

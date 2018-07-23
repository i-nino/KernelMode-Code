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


}



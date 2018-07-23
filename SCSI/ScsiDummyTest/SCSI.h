#pragma once

namespace SCSI {

	

	NTSTATUS
	SendScsiCmd(
		PDEVICE_OBJECT DeviceObj,
		BYTE OperationCode,
		BYTE DataIn,
		PVOID DataBuffer,
		ULONG DataTransferLen,
		ULONG_PTR LogicalBlockAddress,
		USHORT TransferLen
	);

	void
	ScsiQueryCapacity(
		PDEVICE_OBJECT DeviceObj
	);

	NTSTATUS
	InitializeSCSISystemThread();


}
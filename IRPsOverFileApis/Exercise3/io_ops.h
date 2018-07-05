#pragma once

namespace IO_OPS {

	typedef struct
	{
		LPWSTR FileName;
		PIO_WORKITEM WorkItemDelete;
	} WORKITEM_DATA, *PWORKITEM_DATA;


	/* allocate own IRP and send it to underlying device object */
	NTSTATUS
	CreateSystemThreadToDeleteFile();

	/* how a standard (documented) deletion takes place */
	NTSTATUS
	DeleteFile(
		LPCWSTR FileName
	);

}
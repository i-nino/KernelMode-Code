
* SampleE (3rd question) *

Instead of deleting a file the documented way, the malware skips the native api
and creates an IRP from scratch that resembles the file deletion process.

DeleteFile (WinAPI) internally (eventually) calls ntdll!NtSetInformationFile with the
FILE_DISPOSITION_INFORMATION struct and its only (visible) memeber, DeleteFile,
set to true if its intention is to delete.   The rootkit here, in a sense, imitates what 
the I/O Manager would do, by creating an IRP from scratch to service the deletion request of a specific .sys file (mbam.sys) in the standard drivers directory where most drivers are stored.  It initializes a UNICODE_STRING of the full path to mbam.sys and gets a handle to it.  It uses the handle to get a pointer (the address) of the actual FILE_OBJ itself (ObReferenceObjectByHandle)  and uses the FILE_OBJECT and HANDLE value for the next subroutine that implements the actual deletion procedure.  It starts out my getting the underlying DEVICE_OBJ in which to send the IRP, created and properly filled out, to.  So, it turns "the mundane task" of "simply" deleting a file into some sick shit.

I decompiled all the routines involved and created a driver that implements them successfully, as well
as demonstrating how a standard file deletion would take place from kernel mode.

![Alt Text](irpdelete.gif)

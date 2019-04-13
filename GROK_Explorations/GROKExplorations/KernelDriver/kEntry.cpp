#include "kCommon.h"

#pragma warning(disable: 4201)
extern "C" {
    DRIVER_INITIALIZE DriverEntry;
}

#pragma alloc_text(INIT, DriverEntry)


NTSTATUS DriverEntry(
    PDRIVER_OBJECT DriverObj,
    PUNICODE_STRING
)
{
    GROK_Explorations();

    DriverObj->DriverUnload = [](PDRIVER_OBJECT) -> VOID { return; };

    return STATUS_SUCCESS;
}

#pragma once

#pragma warning(push)
#pragma warning(disable:4201)
#pragma warning(disable:5040)
#include <ntifs.h>

///
///<summary>Using ProcessHacker includes for data structs and APIs</summary>
///
#if defined(USE_PH_INCLUDES)
#include <ntexapi.h>
#include <ntmmapi.h>
#endif
#define _DBG
#if defined(_DBG)
#include "kImports.hpp"
#endif
#include <aux_klib.h>
#pragma warning(pop)

#define KEXP_NAME			L"Zero"
#define KEXP_DRIVERNAME		L"Zero.sys"
#define DEVICE_NAME     	L"\\Device\\"
#define ALLOC_TAG           'oreZ'


#define dprintf(Format, ...)	DbgPrint("[Zero] " Format, __VA_ARGS__)
#define DEBUG_BREAK
#if defined(DEBUG_BREAK)
#define DBG_BREAK   __debugbreak()
#else
#define DBG_BREAK   __noop
#endif

namespace global {

    extern PDRIVER_OBJECT DriverObj;
    extern PDEVICE_OBJECT DeviceObj;
    extern PUNICODE_STRING RegistryPath;
    const UNICODE_STRING uDeviceName =
        RTL_CONSTANT_STRING(LR"(\Device\)" DEVICE_NAME);
    const UNICODE_STRING uDosDeviceName =
        RTL_CONSTANT_STRING(LR"(\DosDevices\)" DEVICE_NAME);
}


auto GROK_Explorations()->NTSTATUS;



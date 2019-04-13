#pragma once

#pragma warning(push)
#pragma warning(disable:4201)
#pragma warning(disable:5040)
#include <ntifs.h>

#pragma warning(pop)


#define dprintf(Format, ...)	DbgPrint("[Zero] " Format, __VA_ARGS__)
#define DEBUG_BREAK
#if defined(DEBUG_BREAK)
#define DBG_BREAK   __debugbreak()
#else
#define DBG_BREAK   __noop
#endif


auto GROK_Explorations()->NTSTATUS;



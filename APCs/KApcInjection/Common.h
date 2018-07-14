#pragma once

using BYTE = unsigned char;
using PBYTE = unsigned char*;

#define KAPC_TAG	'cpaK'
#define dprintf(Format, ...)	DbgPrint("KApcInjection: " Format, __VA_ARGS__)


#include <ntifs.h>
#include <ntddk.h>
#include "Imports.h"
#include <ntstrsafe.h>
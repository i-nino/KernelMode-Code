#pragma once
using BYTE = unsigned char;
using PBYTE = BYTE * ;
#define KEXP_TAG	'pxeK'

#define dprintf(Format, ...) DbgPrint("KExplorer: " Format, __VA_ARGS__)


#include <ntifs.h>
#include <ntddk.h>
#include "Imports.h"
#include <ntstrsafe.h>


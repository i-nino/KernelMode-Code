#pragma once

#include <ntifs.h>

#define KEXP_TAG	'pxeK'

class Trace
{
	LPCSTR _fn {};
public:
	Trace(LPCSTR func) : _fn(func) { DbgPrint("Entry: %s\n", _fn); }
	~Trace() { DbgPrint("Exit: %s\n", _fn); }
};
#define TRACER()		Trace _aelf_(__FUNCTION__)


extern PDRIVER_OBJECT KDriverObj;

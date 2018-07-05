#pragma once

#include <ntifs.h>


class Trace
{
	LPCSTR fn_ {};
public:
	Trace(LPCSTR func) : fn_(func) { DbgPrint("Entry: %s\n", fn_); }
	~Trace() { DbgPrint("Exit: %s\n", fn_); }
};
#define TRACER()		Trace _aelf_(__FUNCTION__)
#define KEXP_TAG	'kkkK'
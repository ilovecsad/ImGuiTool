#pragma once
#include <windows.h>
typedef struct _user_info_
{
	BOOL bLoadDriver;
	ULONG dwPid;
	HANDLE hProcess;
}user_info;
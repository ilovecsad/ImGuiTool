#include "tls_protect.h"

void NTAPI t_TlsCallBack_A(PVOID DllHandle, DWORD Reason, PVOID Red);
#ifdef _M_IX86
#pragma comment (linker, "/INCLUDE:__tls_used")
#pragma comment (linker, "/INCLUDE:__tls_callback")
#else
#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:_tls_callback")
#endif
//创建TLS段
EXTERN_C
#ifdef _M_X64
#pragma const_seg (".CRT$XLB")
const
#else
#pragma data_seg (".CRT$XLB")
#endif
//end linker

//tls import定义多个回调函数
PIMAGE_TLS_CALLBACK _tls_callback[] = { t_TlsCallBack_A, 0 };
#pragma data_seg ()
#pragma const_seg ()

typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION
{
	BOOLEAN DebuggerEnabled;
	BOOLEAN DebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, * PSYSTEM_KERNEL_DEBUGGER_INFORMATION;
void NTAPI t_TlsCallBack_A(PVOID DllHandle, DWORD Reason, PVOID Red)
{
	if (DLL_PROCESS_ATTACH == Reason)
	{

		SYSTEM_KERNEL_DEBUGGER_INFORMATION Info = { 0 };
		if (NT_SUCCESS(NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)35, &Info, sizeof(Info), NULL)))
		{
			if (Info.DebuggerEnabled)
			{
				MessageBoxW(NULL, L"运行在虚拟机中", 0, 0);
			}
		}

		PVOID ProcessInfo = NULL;

		if (NT_SUCCESS(NtQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort, &ProcessInfo, sizeof(ProcessInfo), NULL)))
		{
			if (ProcessInfo == (PVOID)-1)
			{
				//MessageBoxW(NULL, L"运行在调试器中", 0, 0);
			}
		}

	}
}
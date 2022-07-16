#pragma once
#include <windows.h>
#include <vector>
#include <string>
using namespace std;


typedef struct _PROCESS_INFO_
{
	ULONG pid;
	HANDLE hOpenhandle;
	PVOID pObject;
	string szPath;
	string szFullPath;
}PROCESS_INF, * PPROCESS_INF;


typedef struct _dllexportFun_
{
	ULONG_PTR fva;
	string szFunName;
}dllexportFun;

typedef struct _module_info_
{
	ULONG dwPid;//标志 所属于的进程
	DWORD DllFlags;
	ULONG_PTR dllBase;
	ULONG_PTR dllOfImageSize;
	string dllBaseName;
	string fulldllPath;
}module_info,*pmodule_info;


typedef struct _symbol_info_
{
	SIZE_T rva;
	string Belonging_to_module;
	string szFuncName;
}symbol_info, *psymbol_info;


typedef struct _INLINE_HOOK_INFO
{
	ULONG_PTR dwAddress;		// 模块基地址
	string szFunc;
	string Belonging_to_module;
}INLINE_HOOK_INFO, * PINLINE_HOOK_INFO;



typedef struct _IAT_HOOK_INFO
{
	string szHookedModule; // 被hook的模块名
	string szExpModule;	// 导出函数的模块
	string szFunction;		// 函数名
	ULONG_PTR dwHookAddress;	// hook后的函数地址
	ULONG_PTR dwOriginAddress;	// 原始函数地址
	ULONG_PTR dwIatAddress;
}IAT_HOOK_INFO, * PIAT_HOOK_INFO;


typedef struct 
{
	BOOL bAlread_Fix_buffer;
	PVOID pFileBuffer;
	string Belonging_to_module;
}record_module,*precord_module;

typedef struct
{
	HMODULE hDllBase;
	string szLoadDll;
}loadDll,*ploadDll;


typedef struct 
{
	ACCESS_MASK    GrantedAccess;
	DWORD dwProcessPid;
	HANDLE handleValue;
	PVOID pObject;
	char szProcessName[MAX_PATH];
}handle_info,*phandle_info;
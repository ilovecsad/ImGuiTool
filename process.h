#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include "struct.h"
#include <map>
using namespace std;


class process
{
public:
	process(PVOID pObject,DWORD dwPid);
	~process();

	void EnumModule(vector<module_info>& ModuleInfo);


	VOID EnumProcessInlinkeHook(PVOID pFileBuffer,module_info* pInfo, vector<symbol_info>& pvectorsymbolInfo,map<ULONG_PTR, INLINE_HOOK_INFO>& pMapInlineHook);
	VOID EnumProcessIATHook(PVOID pFileBuffer, module_info* pInfo, vector<symbol_info>& pvectorsymbolInfo, map<ULONG_PTR, INLINE_HOOK_INFO>& pMapIATHook);
private:
	HANDLE m_hProcess = 0;
	DWORD m_dwPid = 0;
	PVOID m_pObject;
	bool m_bSelf_open_handle = false;//自己打开的句柄


	PVOID m_pImageBuffer = NULL;

private:
	HANDLE Find_VM_READ_OPERATION_Handle(PVOID pObject);
	HANDLE GetOpenHanleByInjectType(ULONG dwPid, PVOID pObject);
	wstring stringToWstring(const string& str);
	string wstringToString(const wstring& wstr);
};


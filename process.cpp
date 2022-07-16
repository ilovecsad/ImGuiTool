#include "process.h"
#include "importfun.h"
#include <algorithm>

#define peb_32_offset 0x1000

process::process(PVOID pObject, DWORD dwPid)
{
	m_dwPid = dwPid;
	m_pObject = pObject;

	m_hProcess = GetOpenHanleByInjectType(m_dwPid, m_pObject);
	if (!m_hProcess)
	{
		MessageBoxW(NULL, L"打开句柄失败", L"提示", MB_OKCANCEL);
	}
}

process::~process()
{
	if (m_bSelf_open_handle && m_hProcess)
	{
		CloseHandle(m_hProcess);
		m_hProcess = 0;
	}
	if (m_pImageBuffer)
	{
		free(m_pImageBuffer);
		m_pImageBuffer = NULL;
	}
}

void process::EnumModule(vector<module_info>& ModuleInfo)
{
	ModuleInfo.clear();

	BOOL bWowProcess = FALSE;

	IsWow64Process(m_hProcess, &bWowProcess);

	PROCESS_BASIC_INFORMATION pbi = { 0 };

	SIZE_T n = 0;
	module_info dwInfo;

	//pPeb->Ldr ->

	if (NT_SUCCESS(ZwQueryInformationProcess_(m_hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL)))
	{
		wchar_t sz[256] = {0};

		DWORD64 Ldr64 = 0;
		LIST_ENTRY64 ListEntry64 = { 0 };
		LDR_DATA_TABLE_ENTRY64 LDTE64 = { 0 };
		if (ReadProcessMemory_(m_hProcess, (PVOID64)((ULONG_PTR)pbi.PebBaseAddress + offsetof(PEB64, Ldr)), &Ldr64, sizeof(Ldr64), NULL))
		{
			if (ReadProcessMemory_(m_hProcess, (PVOID64)(Ldr64 + offsetof(PEB_LDR_DATA64, InLoadOrderModuleList)), &ListEntry64, sizeof(LIST_ENTRY64), NULL))
			{
				if (ReadProcessMemory_(m_hProcess, (PVOID64)(ListEntry64.Flink), &LDTE64, sizeof(_LDR_DATA_TABLE_ENTRY64), NULL))
				{
					while (1)
					{
						if ((ULONG_PTR)LDTE64.InLoadOrderLinks.Flink == ListEntry64.Flink) break;
						RtlSecureZeroMemory(sz, sizeof(sz));
						if (ReadProcessMemory_(m_hProcess, (PVOID64)LDTE64.FullDllName.Buffer, sz, sizeof(sz), NULL))
						{
							RtlSecureZeroMemory(&dwInfo, sizeof(dwInfo));
							dwInfo.dllBase = (ULONG_PTR)LDTE64.DllBase;
							dwInfo.dllOfImageSize = LDTE64.SizeOfImage;
							dwInfo.fulldllPath = wstringToString(sz);
							transform(dwInfo.fulldllPath.begin(), dwInfo.fulldllPath.end(), dwInfo.fulldllPath.begin(), ::tolower);
							dwInfo.dwPid = m_dwPid;
							if (!dwInfo.fulldllPath.empty())
							{
								int a = dwInfo.fulldllPath.rfind("\\");
								if (a != -1)
								{
									dwInfo.dllBaseName = dwInfo.fulldllPath.substr(a + 1, dwInfo.fulldllPath.length() - a);
								}
							}

							ModuleInfo.push_back(dwInfo);

						}
						if (!ReadProcessMemory_(m_hProcess, (PVOID64)LDTE64.InLoadOrderLinks.Flink, &LDTE64, sizeof(_LDR_DATA_TABLE_ENTRY64), NULL)) break;
					}
				}
			}
		}
	
		
		if (bWowProcess)
		{

			DWORD Ldr32 = 0;
			LIST_ENTRY32 ListEntry32 = { 0 };
			LDR_DATA_TABLE_ENTRY32 LDTE32 = { 0 };

			if (ReadProcessMemory_(m_hProcess, (PVOID)((ULONG_PTR)pbi.PebBaseAddress + peb_32_offset + offsetof(PEB32, Ldr)), &Ldr32, sizeof(Ldr32), NULL))
			{
				if (ReadProcessMemory_(m_hProcess, (PVOID)(Ldr32 + offsetof(PEB_LDR_DATA32, InLoadOrderModuleList)), &ListEntry32, sizeof(LIST_ENTRY32), NULL))
				{
					if (ReadProcessMemory_(m_hProcess, (PVOID)(ListEntry32.Flink), &LDTE32, sizeof(_LDR_DATA_TABLE_ENTRY32), NULL))
					{
						while (1)
						{
							if (LDTE32.InLoadOrderLinks.Flink == ListEntry32.Flink) break;
							RtlSecureZeroMemory(sz, sizeof(sz));
							if (ReadProcessMemory_(m_hProcess, (PVOID)LDTE32.FullDllName.Buffer, sz, sizeof(sz), NULL))
							{
								RtlSecureZeroMemory(&dwInfo, sizeof(dwInfo));
								dwInfo.dllBase = (ULONG_PTR)LDTE32.DllBase;
								dwInfo.dllOfImageSize = LDTE32.SizeOfImage;
								dwInfo.fulldllPath = wstringToString(sz);
								transform(dwInfo.fulldllPath.begin(), dwInfo.fulldllPath.end(), dwInfo.fulldllPath.begin(), ::tolower);
								// System32 SysWOW64
								int b = dwInfo.fulldllPath.rfind("system32");
								if (b != -1) {
									dwInfo.fulldllPath = dwInfo.fulldllPath.replace(b, strlen("SysWOW64"), "SysWOW64");
								}
								dwInfo.dwPid = m_dwPid;
								if (!dwInfo.fulldllPath.empty())
								{
									int a = dwInfo.fulldllPath.rfind("\\");
									if (a != -1)
									{
										dwInfo.dllBaseName = dwInfo.fulldllPath.substr(a + 1, dwInfo.fulldllPath.length() - a);

										dwInfo.dllBaseName += "x32";

									}
								}
								if (dwInfo.fulldllPath.rfind(".exe") == -1) {
									ModuleInfo.push_back(dwInfo);
								}
							}
							if (!ReadProcessMemory_(m_hProcess, (PVOID)LDTE32.InLoadOrderLinks.Flink, &LDTE32, sizeof(_LDR_DATA_TABLE_ENTRY32), NULL)) break;
						}
					}
				}
			}


		}
	}

}

VOID process::EnumProcessInlinkeHook(PVOID pFileBuffer,module_info* pInfo, vector<symbol_info>& pvectorsymbolInfo,map<ULONG_PTR, INLINE_HOOK_INFO>& pMapInlineHook)
{


	if (!pFileBuffer || !pInfo)return;
	
	

	pMapInlineHook.clear();

	char* pTargetDllBuffer = NULL;
	pTargetDllBuffer = (char*)malloc(pInfo->dllOfImageSize);
	if (pTargetDllBuffer) 
	{
		RtlSecureZeroMemory(pTargetDllBuffer, pInfo->dllOfImageSize);
		SIZE_T n = 0;
		if (ReadProcessMemory_(m_hProcess, (PVOID)pInfo->dllBase, pTargetDllBuffer, pInfo->dllOfImageSize, &n))
		{

			char* pFileBufferDll = (char*)pFileBuffer;

			INLINE_HOOK_INFO inlineHook;

			vector<symbol_info> ::iterator it = pvectorsymbolInfo.begin();
			for (it; it != pvectorsymbolInfo.end(); ++it)
			{
				for (int i = 0; i < 10; i++)
				{
					if (((char*)(pTargetDllBuffer + it->rva))[i] != ((char*)(pFileBufferDll + it->rva))[i])
					{
						inlineHook.dwAddress = it->rva + i + pInfo->dllBase;
						inlineHook.szFunc = it->szFuncName;
						inlineHook.Belonging_to_module = pInfo->dllBaseName;
						pMapInlineHook.insert(make_pair(inlineHook.dwAddress, inlineHook));
						break;
					}
				}

			}
			m_pImageBuffer = pTargetDllBuffer;
		}
	}

}

VOID process::EnumProcessIATHook(PVOID pFileBuffer, module_info* pInfo, vector<symbol_info>& pvectorsymbolInfo, map<ULONG_PTR, INLINE_HOOK_INFO>& pMapIATHook)
{
	if (!pFileBuffer || !pInfo || !m_pImageBuffer) {
		return;
	}




}

HANDLE process::GetOpenHanleByInjectType(ULONG dwPid,PVOID pObject)
{
	HANDLE hTempHanle = 0;

	hTempHanle = Find_VM_READ_OPERATION_Handle(pObject);
	if (!hTempHanle)
	{
		DWORD dwDesiredAccess = 0;
		dwDesiredAccess = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ;


		hTempHanle = OpenProcess_(dwDesiredAccess, FALSE, dwPid);
		if (hTempHanle)
		{
			m_bSelf_open_handle = true;
		}
	}
	return hTempHanle;
}


HANDLE process::Find_VM_READ_OPERATION_Handle(PVOID pObject)
{
	HANDLE pTemp = NULL;
	NTSTATUS Status = 0;
	SYSTEM_HANDLE_INFORMATION dwInfo = { 0 };
	ULONG nRetLength = 0;

	Status = ZwQuerySystemInformation_(16, &dwInfo, sizeof(SYSTEM_HANDLE_INFORMATION), &nRetLength);
	if (Status == 0xC0000004L && nRetLength)
	{
		PSYSTEM_HANDLE_INFORMATION pHandles = NULL;

		pHandles = (PSYSTEM_HANDLE_INFORMATION)malloc(nRetLength);
		if (pHandles)
		{
			RtlSecureZeroMemory(pHandles, nRetLength);

			Status = ZwQuerySystemInformation_(16, pHandles, nRetLength, &nRetLength);

			if (NT_SUCCESS(Status))
			{
				ULONG i = 0;
				for (i = 0; i < pHandles->NumberOfHandles; i++)
				{
					if (GetCurrentProcessId() == (DWORD)pHandles->Handles[i].ProcessId)
					{

						if (pObject == pHandles->Handles[i].Object)
						{
							if ((pHandles->Handles[i].GrantedAccess & PROCESS_VM_READ) &&
								(pHandles->Handles[i].GrantedAccess & PROCESS_QUERY_LIMITED_INFORMATION))
							{
								pTemp = (HANDLE)pHandles->Handles[i].HandleValue;
								break;
							}
						}
					}
				}
			}

		}
		if (pHandles)
		{
			free(pHandles);
			pHandles = NULL;
		}
	}

	return pTemp;
}


string process::wstringToString(const wstring& wstr)
{
	LPCWSTR pwszSrc = wstr.c_str();
	int nLen = WideCharToMultiByte(CP_ACP, 0, pwszSrc, -1, NULL, 0, NULL, NULL);
	if (nLen == 0)
		return string("");
	char* pszDst = new char[nLen];
	if (!pszDst)
		return string("");
	WideCharToMultiByte(CP_ACP, 0, pwszSrc, -1, pszDst, nLen, NULL, NULL);
	string str(pszDst);
	delete[] pszDst;
	pszDst = NULL;
	return str;
}

wstring process::stringToWstring(const string& str)
{
	LPCSTR pszSrc = str.c_str();
	int nLen = MultiByteToWideChar(CP_ACP, 0, pszSrc, -1, NULL, 0);
	if (nLen == 0)
		return wstring(L"");
	wchar_t* pwszDst = new wchar_t[nLen];
	if (!pwszDst)
		return wstring(L"");
	MultiByteToWideChar(CP_ACP, 0, pszSrc, -1, pwszDst, nLen);
	std::wstring wstr(pwszDst);
	delete[] pwszDst;
	pwszDst = NULL;
	return wstr;
}
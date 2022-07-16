#include "importfun.h"
#include "Log.h"
#include "ldasm.h"
#pragma data_seg("ldata")
unsigned char shellSysCall64[] = {
	0xB8, 0x00, 0x0, 0x0, 0x0,   // mov eax,index
	0x4C, 0x8B, 0xD1,           // mov r10,rcx
	0x0F, 0x05,                 // syscall
	0xC3                        // retn
};
#pragma data_seg();
#pragma comment(linker,"/SECTION:ldata,RWE")


ULONG64 GetProcAddressEx(PVOID BaseAddress, char *lpFunctionName) 
{

    PIMAGE_DOS_HEADER       pDosHdr  = (PIMAGE_DOS_HEADER)BaseAddress;
    PIMAGE_NT_HEADERS32     pNtHdr32 = NULL;
    PIMAGE_NT_HEADERS64     pNtHdr64 = NULL;
    PIMAGE_EXPORT_DIRECTORY pExport  = NULL;
    ULONG                   expSize  = 0;
    ULONG_PTR               pAddress = 0;
    PUSHORT                 pAddressOfOrds;
    PULONG                  pAddressOfNames;
    PULONG                  pAddressOfFuncs;
    ULONG                   i;

    if (BaseAddress == NULL)
        return 0;

    /// Not a PE file
    if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
        return 0;

    pNtHdr32 = (PIMAGE_NT_HEADERS32)((PUCHAR)BaseAddress + pDosHdr->e_lfanew);
    pNtHdr64 = (PIMAGE_NT_HEADERS64)((PUCHAR)BaseAddress + pDosHdr->e_lfanew);

    // Not a PE file
    if (pNtHdr32->Signature != IMAGE_NT_SIGNATURE)
        return 0;

    // 64 bit image
    if (pNtHdr32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                                                .VirtualAddress +
                                            (ULONG_PTR)BaseAddress);
        expSize = pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }
    // 32 bit image
    else {
        pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                                                .VirtualAddress +
                                            (ULONG_PTR)BaseAddress);
        expSize = pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }

    pAddressOfOrds  = (PUSHORT)(pExport->AddressOfNameOrdinals + (ULONG_PTR)BaseAddress);
    pAddressOfNames = (PULONG)(pExport->AddressOfNames + (ULONG_PTR)BaseAddress);
    pAddressOfFuncs = (PULONG)(pExport->AddressOfFunctions + (ULONG_PTR)BaseAddress);

    for (i = 0; i < pExport->NumberOfFunctions; ++i) {
        USHORT OrdIndex = 0xFFFF;
        PCHAR  pName    = NULL;

        // Find by index
        if ((ULONG_PTR)lpFunctionName <= 0xFFFF) 
		{
            OrdIndex = (USHORT)i;
        }
        // Find by name
        else if ((ULONG_PTR)lpFunctionName > 0xFFFF && i < pExport->NumberOfNames) {
            pName    = (PCHAR)(pAddressOfNames[i] + (ULONG_PTR)BaseAddress);
            OrdIndex = pAddressOfOrds[i];
        }
        // Weird params
        else
            return 0;

        if (((ULONG_PTR)lpFunctionName <= 0xFFFF && (USHORT)((ULONG_PTR)lpFunctionName) == OrdIndex + pExport->Base) ||
            ((ULONG_PTR)lpFunctionName > 0xFFFF && strcmp(pName, (char *)(PCTSTR)lpFunctionName) == 0)) {
            pAddress = pAddressOfFuncs[OrdIndex] + (ULONG_PTR)BaseAddress;

            // Check forwarded export
            if (pAddress >= (ULONG_PTR)pExport && pAddress <= (ULONG_PTR)pExport + expSize) {
                return 0;
            }

            break;
        }
    }
    return (ULONG_PTR)pAddress;
}
NTSTATUS ZwSetInformationThread_(HANDLE ThreadHandle, THREADINFOCLASS_EX ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength)
{
	static DWORD index = 0;
	t_ZwSetInformationThread ZwSetInformationThread = NULL;
	if (!index)
	{
		char sz[] = { 'Z','w','S','e','t','I','n','f','o','r','m','a','t','i','o','n','T','h','r','e','a','d',0};//ZwQueryInformationThread
		index = get_ssdt_index(sz, TRUE);
	}

	if (index)
	{
		*(PULONG)&shellSysCall64[1] = index;
		ZwSetInformationThread = (t_ZwSetInformationThread)&shellSysCall64;

		NTSTATUS status = ZwSetInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
		xlog::Normal("ZwSetInformationThread:%x", status);

		return  status;

	}
	return 0xC0000005L;
}
DWORD get_ssdt_index(char* szName, BOOL bIs64)
{
	char sz[] = { 'n','t','d','l','l','.','d','l','l',0 };
	DWORD  _eax = 0;
	ldasm_data ld = { 0 };
	size_t len = 0;
	unsigned char* pEip = (unsigned char*)GetProcAddressEx(GetModuleHandleA(sz), szName);

	if (!pEip)return 0;

	while (TRUE)
	{
		len = ldasm(pEip, &ld, bIs64);
		if (len == 5 && pEip[0] == 0xB8) // mov eax,xxxxxx
		{
			_eax = *(DWORD*)(&pEip[1]);
			break;
		}
		pEip += len;
	}


	return _eax;
}

 BOOL IsAddressSafe(ULONG64 StartAddress)
 {
	 UINT_PTR toppart = (StartAddress >> 47);
	 if (toppart & 1)
	 {
		 //toppart must be 0x1ffff
		 if (toppart != 0x1ffff)
			 return FALSE;
	 }
	 else
	 {
		 //toppart must be 0
		 if (toppart != 0)
			 return FALSE;

	 }
	 return TRUE;
 }





BOOL __stdcall WriteProcessMemory_(HANDLE hProcess, LPVOID lpBaseAddress, PVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)
{

	static DWORD index = 0;
	t_ZwWriteVirtualMemory ZwWriteVirtualMemory = NULL;
	if (!index)
	{
		char sz[] = { 'Z','w','W','r','i','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y',0 };//ZwWriteVirtualMemory
		index = get_ssdt_index(sz, TRUE);
	}

	if (index)
	{
		*(PULONG)&shellSysCall64[1] = index;
		ZwWriteVirtualMemory = (t_ZwWriteVirtualMemory)&shellSysCall64;

		NTSTATUS status = ZwWriteVirtualMemory(hProcess, lpBaseAddress, lpBuffer, nSize, (PULONG)lpNumberOfBytesWritten);
	    xlog::Normal("ZwWriteVirtualMemory:%x", status);

		return NT_SUCCESS(status);

	}
	return FALSE;
}

BOOL __stdcall ReadProcessMemory_(HANDLE hProcess, LPVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead)
{
  

	static DWORD index = 0;
	t_ZwReadVirtualMemory ZwReadVirtualMemory = NULL;
	if (!index)
	{
		char sz[] = { 'Z','w','R','e','a','d','V','i','r','t','u','a','l','M','e','m','o','r','y',0 };//ZwReadVirtualMemory
		index = get_ssdt_index(sz, TRUE);
	}

	if (index)
	{
		*(PULONG)&shellSysCall64[1] = index;
		ZwReadVirtualMemory = (t_ZwReadVirtualMemory)&shellSysCall64;


		NTSTATUS status = ZwReadVirtualMemory(hProcess, lpBaseAddress, lpBuffer, nSize, (PULONG)lpNumberOfBytesRead);
		xlog::Normal("ZwReadVirtualMemory:%x", status);


		return NT_SUCCESS(status);

	}
	return FALSE;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
///要成对使用
LPVOID __stdcall VirtualAllocEx_(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
	PVOID pShareMM_User = NULL;
	static DWORD ZwCreateSection_index = 0;
	static DWORD ZwMapViewOfSection_index = 0;
	

	t_ZwCreateSection ZwCreateSection = NULL;
	t_ZwMapViewOfSection ZwMapViewOfSection = NULL;
	if (!ZwCreateSection_index || !ZwMapViewOfSection_index)
	{
		char szZwCreateSection[] = { 'Z','w','C','r','e','a','t','e','S','e','c','t','i','o','n',0 };//ZwCreateSection
		char szZwMapViewOfSection[] = { 'Z','w','M','a','p','V','i','e','w','O','f','S','e','c','t','i','o','n',0 };//ZwMapViewOfSection

		ZwCreateSection_index = get_ssdt_index(szZwCreateSection, TRUE);
		ZwMapViewOfSection_index = get_ssdt_index(szZwMapViewOfSection, TRUE);
	}

	if (ZwCreateSection_index && ZwMapViewOfSection_index)
	{
		LARGE_INTEGER MaximumSize;
		NTSTATUS status = 0;
		HANDLE SectionHandle = 0;
		*(PULONG)&shellSysCall64[1] = ZwCreateSection_index;
		ZwCreateSection = (t_ZwCreateSection)&shellSysCall64;

		MaximumSize.QuadPart = dwSize;

		status = ZwCreateSection(&SectionHandle, SECTION_ALL_ACCESS, NULL, &MaximumSize, flProtect, SEC_COMMIT, NULL);

		xlog::Normal("ZwCreateSection;%x", status);
		if (NT_SUCCESS(status))
		{
			SIZE_T ViewSize = 0;
			*(PULONG)&shellSysCall64[1] = ZwMapViewOfSection_index;
			ZwMapViewOfSection = (t_ZwMapViewOfSection)&shellSysCall64;

			PVOID pTemp = lpAddress;

			status = ZwMapViewOfSection(SectionHandle, hProcess, &pTemp, 0,
				dwSize, NULL, &ViewSize, ViewUnmap, MEM_TOP_DOWN, flProtect);

			xlog::Normal("ZwMapViewOfSection;%x", status);

			if (NT_SUCCESS(status))
			{
				pShareMM_User = pTemp;
			}

		}

		if (SectionHandle)
		{
			CloseHandle(SectionHandle);
			SectionHandle = 0;
		}



	}


    
	return pShareMM_User;
}
///要成对使用
BOOL __stdcall VirtualFreeEx_(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)
{
	
	BOOL bResult = FALSE;
	static DWORD index = 0;
	t_ZwUnmapViewOfSection ZwUnmapViewOfSection = NULL;
	if (!index)
	{
		char sz[] = { 'Z','w','U','n','m','a','p','V','i','e','w','O','f','S','e','c','t','i','o','n',0 };//ZwUnmapViewOfSection
		index = get_ssdt_index(sz, TRUE);
	}

	if (index)
	{
		SIZE_T n = 0;
		*(PULONG)&shellSysCall64[1] = index;
		ZwUnmapViewOfSection = (t_ZwUnmapViewOfSection)&shellSysCall64;
		NTSTATUS status = 0;
		if (dwFreeType == MEM_DECOMMIT) 
		{
			DWORD oldProtect = 0;
			status = ::VirtualProtectEx(hProcess, lpAddress, dwSize, PAGE_NOACCESS, &oldProtect);
	
		}
		else 
		{
			status = ZwUnmapViewOfSection(hProcess, lpAddress);
		}

		bResult = NT_SUCCESS(status);
	}

	return bResult;
}
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

BOOL IsExecutableAddress(HANDLE hProcess, LPVOID pAddress)
{
	MEMORY_BASIC_INFORMATION mi = { 0 };

	static DWORD index = 0;
	t_ZwQueryVirtualMemory ZwQueryVirtualMemory = NULL;
	if (!index)
	{
		char sz[] = { 'Z','w','Q','u','e','r','y','V','i','r','t','u','a','l','M','e','m','o','r','y',0 };//ZwQueryVirtualMemory
		index = get_ssdt_index(sz, TRUE);
	}

	if (index)
	{
		SIZE_T n = 0;
		*(PULONG)&shellSysCall64[1] = index;
		ZwQueryVirtualMemory = (t_ZwQueryVirtualMemory)&shellSysCall64;

		NTSTATUS status = ZwQueryVirtualMemory(hProcess, pAddress, MemoryBasicInformation, &mi, sizeof(MEMORY_BASIC_INFORMATION), &n);
		xlog::Normal("ZwQueryVirtualMemory:%x", status);
		
	}


	return (mi.State == MEM_COMMIT && (mi.Protect & PAGE_EXECUTE_FLAGS));
}

HANDLE __stdcall OpenThread_(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId)
{
	HANDLE pTempHanle = 0;

	static HMODULE hLoadDll = 0;
	if (!hLoadDll)
	{
		hLoadDll = LoadLibraryW(L"12345678.dll");
	}

	if (hLoadDll)
	{
		typedef HANDLE(__stdcall* t_OpenThread)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwThreadId);
		t_OpenThread pDllOpenThread = NULL;
		pDllOpenThread = (t_OpenThread)GetProcAddress(hLoadDll, "OpenThreadEx_");
		if (pDllOpenThread)
		{
			pTempHanle = pDllOpenThread(dwDesiredAccess, bInheritHandle, dwThreadId);
			if (pTempHanle)
			{
				return pTempHanle;
			}
		}
	}



	static DWORD index = 0;
	t_ZwOpenThread ZwOpenThread = NULL;
	if (!index)
	{
		char sz[] = { 'Z','w','O','p','e','n','T','h','r','e','a','d',0 };//ZwOpenThread
		index = get_ssdt_index(sz, TRUE);
	}

	if (index)
	{
		*(PULONG)&shellSysCall64[1] = index;
		ZwOpenThread = (t_ZwOpenThread)&shellSysCall64;
		CLIENT_ID_EX cid = { 0 };
		OBJECT_ATTRIBUTES ObjectAttributes;

		RtlZeroMemory(&ObjectAttributes, sizeof(OBJECT_ATTRIBUTES));
		cid.UniqueProcess = 0;
		cid.UniqueThread = (HANDLE)dwThreadId;

		NTSTATUS Status = ZwOpenThread(&pTempHanle,dwDesiredAccess,&ObjectAttributes,&cid);

		xlog::Normal("ZwOpenThread;%x", Status);

	}

	return pTempHanle;
}

HANDLE __stdcall OpenProcess_(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)
{
	HANDLE pTempHanle = 0;
	static HMODULE hLoadDll = 0;
	if (!hLoadDll) 
	{
		hLoadDll = LoadLibraryW(L"12345678.dll");
	}

	if (hLoadDll)
	{
		typedef HANDLE (__stdcall *t_OpenProcess)(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId);
		t_OpenProcess pDllOpenProcess = NULL;
		pDllOpenProcess = (t_OpenProcess)GetProcAddress(hLoadDll, "OpenProcessEx_");
		if (pDllOpenProcess)
		{
			pTempHanle = pDllOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
			if (pTempHanle)
			{
				return pTempHanle;
			}
		}
	}

	t_ZwOpenProcess ZwOpenProcess = NULL;
	static DWORD index = 0;
	if (!index)
	{
		char sz[] = { 'Z','w','O','p','e','n','P','r','o','c','e','s','s',0 }; // ZwOpenProcess
		index = get_ssdt_index(sz, TRUE);
	}
	if (index)
	{
		*(PULONG)&shellSysCall64[1] = index;
		ZwOpenProcess = (t_ZwOpenProcess)&shellSysCall64;
		CLIENT_ID_EX cid = { 0 };
		OBJECT_ATTRIBUTES ObjectAttributes;

		RtlZeroMemory(&ObjectAttributes, sizeof(OBJECT_ATTRIBUTES));
		cid.UniqueProcess = (HANDLE)dwProcessId;
		cid.UniqueThread = 0;

		NTSTATUS Status = ZwOpenProcess(&pTempHanle, (ACCESS_MASK)dwDesiredAccess, &ObjectAttributes, &cid);
		xlog::Normal("ZwOpenProcess;%x", Status);

	}

	return pTempHanle;
}

NTSTATUS ZwQueryInformationThread_(IN HANDLE ThreadHandle, IN THREADINFOCLASS_EX ThreadInformationClass, OUT PVOID ThreadInformation, IN ULONG ThreadInformationLength, OUT PULONG ReturnLength OPTIONAL)
{
	static DWORD index = 0;
	t_ZwQueryInformationThread ZwQueryInformationThread = NULL;
	if (!index)
	{
		char sz[] = { 'Z','w','Q','u','e','r','y','I','n','f','o','r','m','a','t','i','o','n','T','h','r','e','a','d',0 };//ZwQueryInformationThread
		index = get_ssdt_index(sz, TRUE);
	}

	if (index)
	{
		*(PULONG)&shellSysCall64[1] = index;
		ZwQueryInformationThread = (t_ZwQueryInformationThread)&shellSysCall64;


		NTSTATUS Status = ZwQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength);
	   xlog::Normal("ZwQueryInformationThread:%x", Status);

		return  Status;

	}
	return 0xC0000005L;
}

BOOL QueueUserAPC_(PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData)
{
	BOOL bRet = FALSE;

	static DWORD NtQueueApcThreadEx_index = 0;
	static DWORD NtAllocateReserveObject_index = 0;

	t_NtQueueApcThreadEx NtQueueApcThreadEx = NULL;
	t_NtAllocateReserveObject NtAllocateReserveObject = NULL;
	if (!NtQueueApcThreadEx_index || !NtAllocateReserveObject_index )
	{
	    char szNtQueueApcThreadEx[] = { 'Z','w','Q','u','e','u','e','A','p','c','T','h','r','e','a','d','E','x',0};//NtQueueApcThreadEx
		char szNtAllocateReserveObject[] = { 'Z','w','A','l','l','o','c','a','t','e','R','e','s','e','r','v','e','O','b','j','e','c','t',0};//NtAllocateReserveObject
		NtQueueApcThreadEx_index = get_ssdt_index(szNtQueueApcThreadEx, TRUE);
		NtAllocateReserveObject_index = get_ssdt_index(szNtAllocateReserveObject, TRUE);
	}
	if (NtQueueApcThreadEx_index && NtAllocateReserveObject_index)
	{
		HANDLE MemoryReserveHandle = NULL;
		NTSTATUS Status = 0xc0000005;

		*(PULONG)&shellSysCall64[1] = NtAllocateReserveObject_index;
		NtAllocateReserveObject = (t_NtAllocateReserveObject)&shellSysCall64;


		Status = NtAllocateReserveObject(&MemoryReserveHandle, NULL, MemoryReserveObjectTypeUserApc);

		xlog::Normal("NtAllocateReserveObject;%x", Status);

		if (NT_SUCCESS(Status))
		{

			*(PULONG)&shellSysCall64[1] = NtQueueApcThreadEx_index;
			NtQueueApcThreadEx = (t_NtQueueApcThreadEx)&shellSysCall64;

			Status = NtQueueApcThreadEx(
				hThread,
				MemoryReserveHandle,
				(PPS_APC_ROUTINE)(pfnAPC),
				(PVOID)dwData,
				NULL,
				NULL
			);

			xlog::Normal("NtQueueApcThreadEx;%x", Status);

			if (NT_SUCCESS(Status))
			{
				bRet = TRUE;
			}
		}

	}


	return bRet;
}

BOOL CreateRemoteThread_(HANDLE hProcess, PVOID pExcuteAddress,PVOID pArg,PHANDLE pThreadHanle)
{

	static DWORD index = 0;
	_ZwCreateThreadEx ZwCreateThreadEx = NULL;
	if (!index)
	{
		char sz[] = { 'Z','w','C','r','e','a','t','e','T','h','r','e','a','d','E','x',0 };//ZwCreateThreadEx
		index = get_ssdt_index(sz, TRUE);
	}

	if (index)
	{
		HANDLE hThread = 0;
		*(PULONG)&shellSysCall64[1] = index;
		ZwCreateThreadEx = (_ZwCreateThreadEx)&shellSysCall64;

		NTSTATUS status = ZwCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, (PTHREAD_START_ROUTINE)pExcuteAddress, pArg, 0, 0, 0, 0, NULL);
		if (pThreadHanle)
		{
			*pThreadHanle = hThread;
		}
		xlog::Normal("ZwCreateThreadEx;%x\n", status);

		return NT_SUCCESS(status);

	}
	return FALSE;
}

NTSTATUS  ZwQuerySystemInformation_(IN ULONG SystemInformationClass, OUT PVOID SystemInformation, IN ULONG SystemInformationLength, OUT PULONG ReturnLength OPTIONAL)
{
	static DWORD index = 0;
	static DWORD bOnce = TRUE;
	t_ZwQuerySystemInformation ZwQuerySystemInformation = NULL;
	if (!index)
	{
		char sz[] = { 'Z','w','Q','u','e','r','y','S','y','s','t','e','m','I','n','f','o','r','m','a','t','i','o','n',0};//ZwQuerySystemInformation
		index = get_ssdt_index(sz, TRUE);
	}

	if (index)
	{
		*(PULONG)&shellSysCall64[1] = index;
		ZwQuerySystemInformation= (t_ZwQuerySystemInformation)&shellSysCall64;
		NTSTATUS Status = ZwQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
		if (!bOnce) 
		{
			xlog::Normal("ZwQuerySystemInformation:%x", Status);
		}
		bOnce = FALSE;
		return  Status;

	}
	return 0xC0000005L;
}

NTSTATUS ZwQueryInformationProcess_(IN HANDLE ProcessHandle, IN PROCESSINFOCLASS ProcessInformationClass, OUT PVOID ProcessInformation, IN ULONG ProcessInformationLength, OUT PULONG ReturnLength OPTIONAL)
{
	static DWORD index = 0;
	static DWORD bOnce = TRUE;
	t_ZwQueryInformationProcess ZwQueryInformationProcess = NULL;
	if (!index)
	{
		char sz[] = { 'Z','w','Q','u','e','r','y','I','n','f','o','r','m','a','t','i','o','n','P','r','o','c','e','s','s',0 };//ZwQueryInformationProcess
		index = get_ssdt_index(sz, TRUE);
	}

	if (index)
	{
		*(PULONG)&shellSysCall64[1] = index;
		ZwQueryInformationProcess = (t_ZwQueryInformationProcess)&shellSysCall64;

		NTSTATUS Status = ZwQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength,ReturnLength);
		
		if (!bOnce)
		{
			xlog::Normal("ZwQueryInformationProcess:%x", Status);
		}
		bOnce = FALSE;
		return  Status;

	}
	return 0xC0000005L;
}

LPVOID __stdcall VirtualAllocExT_(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
	PVOID pBuffer = NULL;
	int nCnt = 0;
	do
	{
		pBuffer = VirtualAllocEx_(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
		nCnt++;
		if (nCnt > 10) {
			pBuffer = NULL;
			xlog::Error("申请RWE内存地址 已经达到十次，申请失败");
			break;
		}
	} while ((IsExecutableAddress(hProcess, pBuffer) == FALSE));
	return pBuffer;
}



thread_operation::thread_operation(DWORD dwDesiredAccess,DWORD threadId,BOOL bWowProcess)
{
	
	m_threadId = threadId;
	m_bWowProcess = bWowProcess;
	m_dwDesiredAccess = dwDesiredAccess;

}

thread_operation::~thread_operation()
{

	if (m_threadHanle )
	{
		CloseHandle(m_threadHanle);
	}

}

HANDLE thread_operation::OpenThread()
{
	if (m_threadId) 
	{
		m_threadHanle = 0;

		m_threadHanle = ::OpenThread_(m_dwDesiredAccess, FALSE, m_threadId);
	}
	return m_threadHanle;
}

BOOL thread_operation::SuspendThread()
{
	BOOL bRet = FALSE;

	if (m_bWowProcess)
	{
	
		if (::Wow64SuspendThread(m_threadHanle) != (DWORD)-1)
		{
			bRet = TRUE;
		}
	}
	else
	{

		static DWORD index = 0;
		_ZwSuspendThread ZwSuspendThread = NULL;
		if (!index)
		{
			char sz[] = { 'Z','w','S','u','s','p','e','n','d','T','h','r','e','a','d',0 };//ZwSuspendThread
			index = get_ssdt_index(sz, TRUE);
		}

		if (index)
		{
			DWORD PreviousSuspendCount = 0;
			*(PULONG)&shellSysCall64[1] = index;
			ZwSuspendThread = (_ZwSuspendThread)&shellSysCall64;

			NTSTATUS status = ZwSuspendThread(m_threadHanle, &PreviousSuspendCount);

			xlog::Normal("ZwSuspendThread;%x", status);

			bRet = NT_SUCCESS(status);

		}

	}



	return bRet;
}

BOOL thread_operation::ResumeThread()
{
	BOOL bRet = FALSE;

	//if (::ResumeThread(m_threadHanle) != (DWORD)-1) {
	//	bRet = TRUE;
	//}

	static DWORD index = 0;
	_ZwResumeThread ZwResumeThread = NULL;
	if (!index)
	{
		char sz[] = { 'Z','w','R','e','s','u','m','e','T','h','r','e','a','d',0 };//ZwResumeThread
		index = get_ssdt_index(sz, TRUE);
	}

	if (index)
	{
		DWORD PreviousSuspendCount = 0;
		*(PULONG)&shellSysCall64[1] = index;
		ZwResumeThread = (_ZwResumeThread)&shellSysCall64;

		NTSTATUS status = ZwResumeThread(m_threadHanle, &PreviousSuspendCount);

		xlog::Normal("ZwResumeThread;%x", status);

		bRet = NT_SUCCESS(status);

	}



	return bRet;
}

BOOL __stdcall thread_operation::SetThreadContext(CONTEXT* lpContext)
{

	BOOL bRet = FALSE;

	if (m_bWowProcess)
	{
		 bRet = ::Wow64SetThreadContext(m_threadHanle, (WOW64_CONTEXT*)lpContext);
	}
	else 
	{
       // bRet = ::SetThreadContext(m_threadHanle, lpContext);

		static DWORD index = 0;
		_ZwSetContextThread ZwSetContextThread = NULL;
		if (!index)
		{
			char sz[] = { 'Z','w','S','e','t','C','o','n','t','e','x','t','T','h','r','e','a','d',0 };//ZwSetContextThread
			index = get_ssdt_index(sz, TRUE);
		}

		if (index)
		{
	
			*(PULONG)&shellSysCall64[1] = index;
			ZwSetContextThread = (_ZwSetContextThread)&shellSysCall64;

			NTSTATUS status = ZwSetContextThread(m_threadHanle, lpContext);

			xlog::Normal("ZwSetContextThread;%x", status);

			bRet = NT_SUCCESS(status);

		}

	}

	return bRet;
}

BOOL __stdcall thread_operation::GetThreadContext(CONTEXT* lpContext)
{
	BOOL bRet = FALSE;

	if (m_bWowProcess)
	{
		 bRet = ::Wow64GetThreadContext(m_threadHanle, (WOW64_CONTEXT*)lpContext);
	}
	else 
		
	{
       // bRet = ::GetThreadContext(m_threadHanle, lpContext);
		static DWORD index = 0;
		_ZwGetContextThread ZwGetContextThread = NULL;
		if (!index)
		{
			char sz[] = { 'Z','w','G','e','t','C','o','n','t','e','x','t','T','h','r','e','a','d',0 };//ZwGetContextThread
			index = get_ssdt_index(sz, TRUE);
		}

		if (index)
		{
			*(PULONG)&shellSysCall64[1] = index;
			ZwGetContextThread = (_ZwGetContextThread)&shellSysCall64;

			NTSTATUS status = ZwGetContextThread(m_threadHanle,lpContext);

			xlog::Normal("ZwGetContextThread;%x", status);

			bRet =  NT_SUCCESS(status);

		}

	}

	return bRet;
}

PVOID thread_operation::GetThreadTebBaseAddress64()
{
	THREAD_BASIC_INFORMATION    tbi = { 0 };

	LONG  status;
	status = ZwQueryInformationThread_(m_threadHanle, ThreadBasicInformation, &tbi, sizeof(tbi), NULL);

	if (NT_SUCCESS(status))
	{
		return tbi.TebBaseAddress;
	}
	
	return NULL;
}




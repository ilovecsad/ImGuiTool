#include <windows.h>
#include <TlHelp32.h>
#include <winternl.h>
#include "injector.h"
#include "Log.h"
#include "importfun.h"
#include "CommonStruct.h"
#include "injectShellcode.hpp"
extern user_info g_data;

injector::injector(ULONG PID, HANDLE hProcess, bool bNormalInject, WCHAR* pstrDllPath,BOOL bWow64Process,DWORD nFlags)
{
	m_PID = PID;
	m_hProcess = hProcess;
	m_bNormalInject = bNormalInject;
	m_pszDllPath = pstrDllPath;
	m_bWow64Process = bWow64Process;
	m_nFlags = nFlags;
}

injector::~injector()
{
	m_PID = 0;
	m_hProcess = 0;
	m_bNormalInject = true;

}

PVOID injector::Get_call_rip_code_64(PVOID pCallAddress)
{
	PVOID pAllcoateAddress = NULL;
	PVOID pTemp = NULL;

	pTemp = malloc(sizeof(call_rip_shellcode_64::payload));
	if (pTemp)
	{
		RtlSecureZeroMemory(pTemp, sizeof(call_rip_shellcode_64::payload));
		RtlCopyMemory(pTemp, call_rip_shellcode_64::payload, sizeof(call_rip_shellcode_64::payload));

	
		*(PULONG_PTR)((ULONG_PTR)pTemp + call_rip_shellcode_64::rva::pfnFunc) = (ULONG_PTR)pCallAddress;

		pAllcoateAddress = VirtualAllocExT_(m_hProcess, NULL, sizeof(call_rip_shellcode_64::payload), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (pAllcoateAddress)
		{
			size_t n = 0;
			if (WriteProcessMemory_(m_hProcess, pAllcoateAddress, pTemp, sizeof(call_rip_shellcode_64::payload), &n))
			{
				xlog::Normal("Get_normal_code_64->写入成功");
			}
			else
			{
				xlog::Error("Get_normal_code_64->写入失败");
				VirtualFreeEx_(m_hProcess, pAllcoateAddress, 0, MEM_RELEASE);
				pAllcoateAddress = NULL;
			}
		}
		else {
			xlog::Error("Get_normal_code_64->申请地址失败");
		}

		free(pTemp);
		pTemp = NULL;
	}
	return  pAllcoateAddress;
}
PVOID injector::GetConextThreadM_CALL_Shellcode64(ULONG64 nJmpAddess, PVOID pCallAddress,PVOID* pShellcodeAddress)
{
	if (!pCallAddress || !nJmpAddess)return NULL;
	PVOID pAllocateAddress = NULL;

	UCHAR code[] =
	{
	0x50,//push        rax
	0x53 ,//push        rbx 
	0x51 ,// push        rcx 
	0x52 ,//push        rdx
	0x55 ,//push        rbp 
	0x54 ,//push        rsp 
	0x56 ,// push        rsi 
	0x57 ,//push        rdi
	0x41 ,0x50 ,//push        r8 
	0x41 ,0x51 ,// push        r9 
	0x41 ,0x52 ,//push        r10 
	0x41 ,0x53 ,// push        r11 
	0x41 ,0x54 ,
	0x41 ,0x55 ,
	0x41 ,0x56 ,
	0x41 ,0x57 ,
	0x9c ,
	0x48 ,0x83 ,0xec ,0x30 ,
	0xe8,0x24 ,0xfd ,0xff ,0xff , //+
	0x48 ,0x83 ,0xc4 ,0x30 ,
	0x9d ,0x41 ,0x5f ,0x41 ,0x5e ,0x41 ,0x5d ,0x41 ,0x5c ,0x41 ,0x5b ,0x41 ,0x5a ,0x41 ,0x59 ,0x41 ,0x58 ,0x5f ,0x5e ,0x5c ,0x5d ,0x5a
	,0x59 ,0x5b ,0x58 ,
	0xff,0x25,0,0,0,0, // jmp dword [xxxxxxxxx]
	0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90  // jmpAddress  offset +0x3DB
	};

	PVOID pTemp = NULL;
	SIZE_T nSize = 0;
	SIZE_T n = 0;
	PVOID pOffset = NULL;

	//修复code代码
	*(PULONG_PTR)((ULONG_PTR)code + 0x45) = nJmpAddess;

	nSize = sizeof(call_rip_shellcode_64::payload) + sizeof(code);
	pTemp = malloc(nSize);
	if (pTemp)
	{
		RtlSecureZeroMemory(pTemp, nSize);
		
		//拷贝 shellcode
		RtlCopyMemory(pTemp, call_rip_shellcode_64::payload, sizeof(call_rip_shellcode_64::payload));

		pOffset = (PVOID)((ULONG_PTR)pTemp +  sizeof(call_rip_shellcode_64::payload));
		//拷贝code
		RtlCopyMemory(pOffset, code, sizeof(code));


		pAllocateAddress = VirtualAllocExT_(m_hProcess, NULL, nSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (pAllocateAddress)
		{
			//修复shellcode
			*(PULONG_PTR)((ULONG_PTR)pTemp + call_rip_shellcode_64::rva::pfnFunc) = (ULONG_PTR)pCallAddress;

			//修复E8
			*(PULONG)((ULONG_PTR)pOffset + 30) = ((ULONG_PTR)pAllocateAddress + call_rip_shellcode_64::rva::start) - ((ULONG_PTR)pAllocateAddress + sizeof(call_rip_shellcode_64::payload) + 34) ;

			if (!WriteProcessMemory_(m_hProcess, pAllocateAddress, pTemp, nSize, &n))
			{
				VirtualFreeEx_(m_hProcess, pAllocateAddress, 0, MEM_RELEASE);
				pAllocateAddress = NULL;
			}
			else {
				*pShellcodeAddress = (PVOID)(((ULONG_PTR)pAllocateAddress + sizeof(call_rip_shellcode_64::payload)));
			}
		}


	}



	if (pTemp)
	{
		free(pTemp);
		pTemp = NULL;
	}

	return pAllocateAddress;
}
BOOL injector::UseThreadContextCall_Rip(PVOID pCallAddress)
{
	BOOL bRet = FALSE;
	HANDLE hThreadHanle = NULL;
	DWORD64 pJmpAddress = NULL;
	PVOID pBuffer = NULL;

	DWORD dwMainThreadTid = GetMainThread(m_PID);

	thread_operation pThread(THREAD_ALL_ACCESS,dwMainThreadTid, FALSE);

	if (pThread.OpenThread())
	{

		if (pThread.SuspendThread())
		{
			CONTEXT ct = { 0 };
			ct.ContextFlags = CONTEXT_CONTROL;
			//获取 CONTEXT 结构体
			if (pThread.GetThreadContext(&ct))
			{
				pJmpAddress = ct.Rip;
				if (pJmpAddress)
				{
					PVOID pShellcodeAddress = NULL;
					pBuffer = GetConextThreadM_CALL_Shellcode64(pJmpAddress, pCallAddress,&pShellcodeAddress);
					if (pBuffer && pCallAddress && pShellcodeAddress)
					{
						ct.Rip = (DWORD64)pShellcodeAddress;

						bRet = pThread.SetThreadContext(&ct);
					}
				}
			}

			pThread.ResumeThread();
		}

	}
	if (pBuffer)
	{
		bRet = FALSE;
		shellcode_state_64 main_data = { 0 };
		SIZE_T bRetLength = 0;
		int nCnt = 100;
		do
		{
			if (ReadProcessMemory_(m_hProcess, pBuffer, &main_data, sizeof(shellcode_state_64), &bRetLength))
			{
				if ((main_data.nAlreadRun == CALL_COMPLETE))
				{
					bRet = TRUE;

					Sleep(200);
					if (VirtualFreeEx_(m_hProcess, pBuffer, 0, MEM_RELEASE))
					{
						
					}

					break;
				}

			}
			else
			{
				
				bRet = TRUE;
				break;
			}

			Sleep(100);
			nCnt--;

			if (nCnt == 0 || nCnt < 0)
			{
				

				break;
			}

		} while (!bRet);
	}


	return bRet;
}


BOOL injector::MapInject_UseThreadContextCall_64()
{
	BOOL bRet = FALSE;
	HANDLE hThreadHanle = NULL;
	DWORD64 pJmpAddress = NULL;
	PVOID pBuffer = NULL;
	PVOID pCallAddress = NULL;
	xlog::Critical("开始使用MapInject_UseThreadContextCall_64");

	DWORD dwMainThreadTid = GetMainThread(m_PID);

	thread_operation pThread(THREAD_ALL_ACCESS,dwMainThreadTid, FALSE);

	PVOID pShellcodePos = NULL;
	if (pThread.OpenThread())
	{

		if (pThread.SuspendThread())
		{
			CONTEXT ct = { 0 };
			ct.ContextFlags = CONTEXT_CONTROL;
			//获取 CONTEXT 结构体
			if (pThread.GetThreadContext(&ct))
			{
				pJmpAddress = ct.Rip;
				if (pJmpAddress)
				{
		
					pBuffer = GetConextThreadMemoryInjectShellcode64(pJmpAddress, &pCallAddress,m_nFlags,&pShellcodePos);
					if (pBuffer && pCallAddress)
					{
						ct.Rip = (DWORD64)pCallAddress;

						bRet = pThread.SetThreadContext(&ct);
					}
				}
			}

			pThread.ResumeThread();
		}

	}
	if (pBuffer && bRet)
	{
		bRet = FALSE;
		shellcode_state_64 main_data = { 0 };
		SIZE_T bRetLength = 0;
		int nCnt = 100;
		do
		{
			if (ReadProcessMemory_(m_hProcess, pShellcodePos, &main_data, sizeof(shellcode_state_64), &bRetLength))
			{
				if ((main_data.nAlreadRun == CALL_COMPLETE) || (main_data.nAlreadRun == CALL_COMPLETE_SUCCESS))
				{
					bRet = TRUE;

					if (VirtualFreeEx_(m_hProcess, pShellcodePos, sizeof(MapInject_64::payload), MEM_DECOMMIT))
					{
						xlog::Normal("MapInject_UseThreadContextCall_64执行清理内存工作成功");
					}

					break;
				}

			}
			else
			{
				xlog::Error("MapInject_UseThreadContextCall_64执行清理内存工作 失败");
				bRet = TRUE;
				break;
			}

			Sleep(100);
			nCnt--;

			if (nCnt == 0 || nCnt < 0)
			{
				xlog::Error("MapInject_UseThreadContextCall_64执行清理内存工作 失败");

				break;
			}

		} while (!bRet);
		if ((main_data.nAlreadRun == CALL_COMPLETE_SUCCESS))
		{
			m_hInjectDllBase = (ULONG64)pBuffer;
			bRet = TRUE;
		}
	}
	

	return bRet;
}

PVOID injector::GetConextThreadMemoryInjectShellcode64(ULONG64 nJmpAddess, PVOID* pCallAddress,DWORD nFlags,PVOID* pShellcodeAddressPos)
{
	if (!pCallAddress || !nJmpAddess)return NULL;
	PVOID pAllocateAddress = NULL;

	UCHAR code[] =
	{
	0x50,//push        rax
	0x53 ,//push        rbx 
	0x51 ,// push        rcx 
	0x52 ,//push        rdx
	0x55 ,//push        rbp 
	0x54 ,//push        rsp 
	0x56 ,// push        rsi 
	0x57 ,//push        rdi
	0x41 ,0x50 ,//push        r8 
	0x41 ,0x51 ,// push        r9 
	0x41 ,0x52 ,//push        r10 
	0x41 ,0x53 ,// push        r11 
	0x41 ,0x54 ,
	0x41 ,0x55 ,
	0x41 ,0x56 ,
	0x41 ,0x57 ,
	0x9c ,
	0x48 ,0x83 ,0xec ,0x30 ,
	0xe8,0x24 ,0xfd ,0xff ,0xff , //+
	0x48 ,0x83 ,0xc4 ,0x30 ,
	0x9d ,0x41 ,0x5f ,0x41 ,0x5e ,0x41 ,0x5d ,0x41 ,0x5c ,0x41 ,0x5b ,0x41 ,0x5a ,0x41 ,0x59 ,0x41 ,0x58 ,0x5f ,0x5e ,0x5c ,0x5d ,0x5a
	,0x59 ,0x5b ,0x58 ,
	0xff,0x25,0,0,0,0, // jmp dword [xxxxxxxxx]
	0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90  // jmpAddress  offset +0x3DB
	};

	PVOID pTemp = NULL;
	SIZE_T nSize = 0;
	SIZE_T n = 0;
	PVOID pPEBuffer = NULL;
	DWORD nImageSize = 0;
	if (!m_bNormalInject)
	{

		//修复code代码
		*(PULONG_PTR)((ULONG_PTR)code + 0x45) = nJmpAddess;

		pPEBuffer = file_to_image_buffer(m_pszDllPath, nImageSize);

		PVOID offset = 0;
		nSize = sizeof(MapInject_64::payload) + sizeof(code) + nImageSize;

		pTemp = malloc(nSize);
		if (pTemp)
		{
			RtlSecureZeroMemory(pTemp, nSize);

			//先拷贝dll文件
			RtlCopyMemory(pTemp, pPEBuffer, nImageSize);
			offset = (PVOID)((ULONG_PTR)pTemp + nImageSize);

			RtlCopyMemory(offset, MapInject_64::payload, sizeof(MapInject_64::payload));
			offset = (PVOID)((ULONG_PTR)pTemp + sizeof(MapInject_64::payload) + nImageSize);
			RtlCopyMemory(offset, code, sizeof(code));


			pAllocateAddress = VirtualAllocExT_(m_hProcess, NULL, nSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (pAllocateAddress)
			{
				// 定位shellcode位置 同时往shellcode 传入参数
				*(int*)((ULONG_PTR)pTemp + MapInject_64::rva::nFlags + nImageSize) = nFlags;
				*(PULONG_PTR)((ULONG_PTR)pTemp + MapInject_64::rva::nPEBuffer + nImageSize) = (ULONG_PTR)pAllocateAddress;

				//E8XXXX = 目标地址-下一行地址  修复 Code 中的E8 位置
				*(PULONG)((ULONG_PTR)pTemp + nImageSize + sizeof(MapInject_64::payload) + 30) = ((ULONG_PTR)pAllocateAddress + nImageSize + MapInject_64::rva::start) - ((ULONG_PTR)pAllocateAddress + nImageSize + sizeof(MapInject_64::payload) + 29);

				if (WriteProcessMemory_(m_hProcess, pAllocateAddress, pTemp, nSize, &n))
				{
					//获取 map 执行地址
					*pCallAddress = (PVOID)((ULONG_PTR)pAllocateAddress + sizeof(MapInject_64::payload) + nImageSize);
					*pShellcodeAddressPos = (PVOID)((ULONG_PTR)pAllocateAddress + nImageSize);
				}
			}
		}
	}

	if (pTemp)
	{
		free(pTemp);
		pTemp = NULL;
	}
	if (pPEBuffer)
	{
		free(pPEBuffer);
		pPEBuffer = NULL;
	}

	return pAllocateAddress;
}
PVOID injector::GetConextThreadNormalInjectShellcode64(ULONG64 nJmpAddess, PVOID* pCallAddress)
{
	if (!pCallAddress || !nJmpAddess)return NULL;
	PVOID pAllocateAddress = NULL;

	UCHAR code[] =
	{
	0x50,//push        rax
	0x53 ,//push        rbx 
	0x51 ,// push        rcx 
	0x52 ,//push        rdx
	0x55 ,//push        rbp 
	0x54 ,//push        rsp 
	0x56 ,// push        rsi 
	0x57 ,//push        rdi
	0x41 ,0x50 ,//push        r8 
	0x41 ,0x51 ,// push        r9 
	0x41 ,0x52 ,//push        r10 
	0x41 ,0x53 ,// push        r11 
	0x41 ,0x54 ,
	0x41 ,0x55 ,
	0x41 ,0x56 ,
	0x41 ,0x57 ,
	0x9c ,
	0x48 ,0x83 ,0xec ,0x30 ,
	0xe8,0x24 ,0xfd ,0xff ,0xff ,
	0x48 ,0x83 ,0xc4 ,0x30 ,
	0x9d ,0x41 ,0x5f ,0x41 ,0x5e ,0x41 ,0x5d ,0x41 ,0x5c ,0x41 ,0x5b ,0x41 ,0x5a ,0x41 ,0x59 ,0x41 ,0x58 ,0x5f ,0x5e ,0x5c ,0x5d ,0x5a
	,0x59 ,0x5b ,0x58 ,
	0xff,0x25,0,0,0,0, // jmp dword [xxxxxxxxx]
	0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90  // jmpAddress  offset +0x3DB
	};

	PVOID pTemp = NULL;
	SIZE_T nSize = 0;
	SIZE_T n = 0;
	if (m_bNormalInject)
	{

		//修复code代码
		*(PULONG_PTR)((ULONG_PTR)code + 0x45) = nJmpAddess;


		PVOID offset = 0;
		nSize = sizeof(normalInject_64::payload) + sizeof(code);
		pTemp = malloc(nSize);
		if (pTemp)
		{
			RtlSecureZeroMemory(pTemp, nSize);

			RtlCopyMemory(pTemp, normalInject_64::payload, sizeof(normalInject_64::payload));
			offset = (PVOID)((ULONG_PTR)pTemp + sizeof(normalInject_64::payload));
			RtlCopyMemory(offset, code, sizeof(code));

			//往shellcode写入 dll路径
			lstrcpyW((WCHAR*)((ULONG_PTR)pTemp + normalInject_64::rva::szDllPath), m_pszDllPath);


			pAllocateAddress = VirtualAllocExT_(m_hProcess, NULL, nSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (pAllocateAddress)
			{
			
				*(PULONG)((ULONG_PTR)pTemp + sizeof(normalInject_64::payload) + 30) = ((ULONG_PTR)pAllocateAddress + normalInject_64::rva::start) - ((ULONG_PTR)pAllocateAddress + sizeof(normalInject_64::payload) + 29) - 5;
				if (WriteProcessMemory_(m_hProcess, pAllocateAddress, pTemp, nSize, &n))
				{

					*pCallAddress = (PVOID)((ULONG_PTR)pAllocateAddress + sizeof(normalInject_64::payload));
				}
			}
		}
	}

	if (pTemp)
	{
		free(pTemp);
		pTemp = NULL;
	}

	return pAllocateAddress;
}
BOOL injector::NormalInject_UseThreadContextCall_64()
{
	BOOL bRet = FALSE;
	HANDLE hThreadHanle = NULL;
	DWORD64 pJmpAddress = NULL;
	PVOID pBuffer = NULL;
	PVOID pCallAddress = NULL;
	xlog::Critical("开始使用UseThreadContextCall");

	DWORD dwMainThreadTid = GetMainThread(m_PID);

	thread_operation pThread(THREAD_ALL_ACCESS,dwMainThreadTid,FALSE);


    if(pThread.OpenThread())
	{

		if (pThread.SuspendThread())
		{
			CONTEXT ct = { 0 };
			ct.ContextFlags = CONTEXT_CONTROL;
			//获取 CONTEXT 结构体
			if (pThread.GetThreadContext(&ct))
			{
				pJmpAddress = ct.Rip;
				if (pJmpAddress)
				{
					pBuffer = GetConextThreadNormalInjectShellcode64(pJmpAddress,&pCallAddress);
					if (pBuffer && pCallAddress)
					{
						ct.Rip = (DWORD64)pCallAddress;

						bRet = pThread.SetThreadContext(&ct);
					}
				}
			}

			pThread.ResumeThread();
		}

	}
	if (pBuffer && bRet)
	{
		bRet = FALSE;
		shellcode_state_64 main_data = { 0 };
		SIZE_T bRetLength = 0;
		int nCnt = 100;
		do
		{
			if (ReadProcessMemory_(m_hProcess, pBuffer, &main_data, sizeof(shellcode_state_64), &bRetLength))
			{
				if (main_data.nAlreadRun == CALL_COMPLETE)
				{
					bRet = TRUE;

					if (VirtualFreeEx_(m_hProcess, pBuffer, 0, MEM_RELEASE))
					{
						xlog::Normal("执行清理内存工作成功");
					}

					break;
				}

			}
			else
			{
				xlog::Error("执行清理内存工作 失败");
				bRet = TRUE;
				break;
			}

			Sleep(100);
			nCnt--;

			if (nCnt == 0 || nCnt < 0)
			{
				xlog::Error("执行清理内存工作 失败");
			
				break;
			}

		} while (!bRet);
		if (main_data.dllBase)
		{
			m_hInjectDllBase = main_data.dllBase;
		}
	}
	

	return bRet;
}


BOOL injector::user_windows_messages_call_rip_64(PVOID pCallAddress)
{
	BOOL bRet = FALSE;
	PVOID pAllcoateAdress = NULL;
	pAllcoateAdress = Get_call_rip_code_64(pCallAddress);
	if (pAllcoateAdress)
	{
		DWORD hThreadId = 0;
		HHOOK h_hook = NULL;
		PVOID pCallAddress = NULL;
		HMODULE hNdtdll = 0;

		hNdtdll = GetModuleHandleW(L"ntdll.dll");
		pCallAddress = (PVOID)((ULONG_PTR)pAllcoateAdress + call_rip_shellcode_64::rva::start);
		hThreadId = GetMainThread(m_PID);

		h_hook = SetWindowsHookExW(WH_GETMESSAGE, (HOOKPROC)(pCallAddress), hNdtdll, hThreadId);
		shellcode_state_64 main_data = { 0 };
		if (h_hook)
		{
			xlog::Critical("user_windows_messages_call_rip_64->SetWindowsHookExW 成功");

			SIZE_T bRetLength = 0;
			int nCnt = 100;

			do
			{
				PostThreadMessageW(hThreadId, WM_NULL, 0, 0);

				if (ReadProcessMemory_(m_hProcess, pAllcoateAdress, &main_data, sizeof(shellcode_state_64), &bRetLength))
				{
					if ((main_data.nAlreadRun == CALL_COMPLETE))
					{
						bRet = UnhookWindowsHookEx(h_hook);
						if (bRet)
						{
							xlog::Critical("user_windows_messages_call_rip_64->UnhookWindowsHookEx 成功");

						}
						bRet = TRUE;
						break;
					}

				}
				else
				{
					xlog::Error("user_windows_messages_call_rip_64->读取数据失败,结束循环");
					bRet = TRUE;
					break;
				}

				Sleep(100);
				nCnt--;

				if (nCnt < 0)
				{
					break;
				}

			} while (!bRet);

		}

		if ((main_data.nAlreadRun == CALL_COMPLETE))
		{

			if (VirtualFreeEx_(m_hProcess, pAllcoateAdress, 0, MEM_RELEASE))
			{
				xlog::Normal("user_windows_messages_call_rip_64->执行清理内存工作成功");
				pAllcoateAdress = NULL;
				bRet = TRUE;

			}
		}


	}

	return bRet;
}



BOOL injector::insert_apc_to_thread(HANDLE hThread)
{
	BOOL bRet = FALSE;

	static PVOID pExecute_address = NULL;

	if (!m_pApc_allcoate_memory_base) 
	{
		if (m_bNormalInject) 
		{
			m_pApc_allcoate_memory_base = Get_normal_code_64();
			if (m_pApc_allcoate_memory_base) {
				pExecute_address = (PVOID)((ULONG_PTR)m_pApc_allcoate_memory_base + normalInject_64::rva::start);
			}
		}
		else 
		{
			m_pApc_allcoate_memory_base = Get_map_code_64(&pExecute_address,m_nFlags);
			m_Apc_allocoate_map_shellcode_pos = pExecute_address;
			pExecute_address = (PVOID)(MapInject_64::rva::start + (ULONG_PTR)pExecute_address);
		}
	}

	if (m_pApc_allcoate_memory_base && pExecute_address)
	{
		bRet = QueueUserAPC_((PAPCFUNC)(pExecute_address), hThread, NULL);
	}

	return bRet;
}


BOOL injector::CreateThreadToInject()
{
	BOOL bRet = FALSE;

	if (m_bWow64Process) 
	{

	}
	else 
	{
		if (m_bNormalInject)
		{
			bRet = CreateThreadNormalInjectDll64();
		}
		else 
		{
			bRet = CreateThreadMapInjectDll64();
		}

	}

	return bRet;
}

BOOL injector::CreateThreadMapInjectDll64()
{
	BOOL bRet = FALSE;
	PVOID pAllcoateMemory = NULL;
	PVOID pExcuteAddress = NULL;
	PVOID pShellcodeAddress = NULL;
	pAllcoateMemory = Get_map_code_64(&pShellcodeAddress, m_nFlags);

	if (pAllcoateMemory) 
	{
		pExcuteAddress = (PVOID)((ULONG_PTR)pShellcodeAddress + MapInject_64::rva::start);

		bRet = CreateRemoteThread_(m_hProcess, (LPTHREAD_START_ROUTINE)pExcuteAddress);

		if (bRet)
		{
			bRet = FALSE;
			shellcode_state_64 main_data = { 0 };
			SIZE_T bRetLength = 0;
			int nCnt = 100;
			do
			{
				if (ReadProcessMemory_(m_hProcess, pShellcodeAddress, &main_data, sizeof(shellcode_state_64), &bRetLength))
				{
					if ((main_data.nAlreadRun == CALL_COMPLETE) || (main_data.nAlreadRun == CALL_COMPLETE_SUCCESS))
					{
						bRet = TRUE;

						if (VirtualFreeEx_(m_hProcess, pShellcodeAddress, sizeof(MapInject_64::payload), MEM_DECOMMIT))
						{
							
						}

						break;
					}

				}
				else
				{

					bRet = TRUE;
					break;
				}

				Sleep(100);
				nCnt--;

				if (nCnt == 0 || nCnt < 0)
				{


					break;
				}

			} while (!bRet);
			if ((main_data.nAlreadRun == CALL_COMPLETE_SUCCESS))
			{
				m_hInjectDllBase = (ULONG64)pAllcoateMemory;
				bRet = TRUE;
			}
		}
	}

	return bRet;
}

BOOL injector::CreateThreadNormalInjectDll64()
{
	BOOL bRet = FALSE;
	PVOID pAllcoateMemory = NULL;
	PVOID pExcuteAddress = NULL;

	pAllcoateMemory = Get_normal_code_64();
	if (pAllcoateMemory) {
		pExcuteAddress = (PVOID)((ULONG_PTR)pAllcoateMemory + normalInject_64::rva::start);

		bRet = CreateRemoteThread_(m_hProcess, (LPTHREAD_START_ROUTINE)pExcuteAddress);

		if (bRet)
		{
			bRet = FALSE;
			shellcode_state_64 main_data = { 0 };
			SIZE_T bRetLength = 0;
			int nCnt = 100;
			do
			{
				if (ReadProcessMemory_(m_hProcess, pAllcoateMemory, &main_data, sizeof(shellcode_state_64), &bRetLength))
				{
					if (main_data.nAlreadRun == CALL_COMPLETE)
					{
						bRet = TRUE;

						if (VirtualFreeEx_(m_hProcess, pAllcoateMemory, 0, MEM_RELEASE))
						{

						}

						break;
					}

				}
				else
				{
					bRet = TRUE;
					break;
				}

				Sleep(100);
				nCnt--;

				if (nCnt == 0 || nCnt < 0)
				{


					break;
				}

			} while (!bRet);
			if (main_data.dllBase)
			{
				m_hInjectDllBase = main_data.dllBase;
			}
		}

	}
	return bRet;
}

BOOL injector::Apc_inject(DWORD nThreadId,PVOID ppTeb64,PVOID ppTeb32,BOOL isWow64)
{

	if (m_bAlreadApcInject) return FALSE;

	BOOL bRet = FALSE;
	thread_operation dwThread(THREAD_ALL_ACCESS,nThreadId, isWow64);

	HANDLE hThread = dwThread.OpenThread();

	PVOID pTebBaseAddress64 = NULL;
	PVOID pTebBaseAddress32 = NULL;

	PTEB64 pTeb64 = (PTEB64)ppTeb64;
	PTEB32 pTeb32 = (PTEB32)ppTeb32;

	RtlSecureZeroMemory(pTeb64, sizeof(TEB64));
	RtlSecureZeroMemory(ppTeb32, sizeof(TEB32));

	pTebBaseAddress64 = dwThread.GetThreadTebBaseAddress64();

	SIZE_T n = 0;
	if (pTebBaseAddress64) 
	{
		if (ReadProcessMemory_(m_hProcess, pTebBaseAddress64, pTeb64, sizeof(TEB64), &n))
		{
			if ((pTeb64->Win32ThreadInfo != 0))
			{
				return TRUE;

			}

			if (isWow64) 
			{
				pTebBaseAddress32 = (PVOID)((ULONG_PTR)pTebBaseAddress64 + 0x2000);
				if (ReadProcessMemory_(m_hProcess,pTebBaseAddress32, pTeb32, sizeof(TEB32), &n))
				{
					if (pTeb32->ActivationContextStackPointer == 0) 
					{
						return TRUE;
					}

					if (pTeb32->ThreadLocalStoragePointer == 0)
					{
						return TRUE;
					}

				}

			}
			else 
			{
				if (pTeb64->ActivationContextStackPointer == 0)
				{

					return TRUE;
				}

				if (pTeb64->ThreadLocalStoragePointer == 0)
				{

					return TRUE;
				}
			}


			if (!m_bAlreadApcInject)
			{
				m_bAlreadApcInject = insert_apc_to_thread(hThread);
				if (m_bAlreadApcInject && m_pApc_allcoate_memory_base)
				{

					m_hApc_ThreadHanle = CreateThread(NULL, 0, apc_clear_work_thread, this, 0, 0);
					if (m_hApc_ThreadHanle)
					{
						WaitForSingleObject(m_hApc_ThreadHanle, 60000);
						CloseHandle(m_hApc_ThreadHanle);
					}
				}
			}


		}


	}
	return bRet;
}

BOOL injector::use_apc_inject_64()
{
	BOOL bRet = FALSE;
	PVOID pTemp = NULL;
	PTEB64 pTeb64 = NULL;
	PTEB32 pTeb32 = NULL;
	NTSTATUS Status;
	
	
	DWORD nSize = 0;
	PSYSTEM_PROCESS_INFO pInfo = NULL;
	// 获取信息所需的缓冲区大小
	Status = ZwQuerySystemInformation_(5, NULL, 0, &nSize);

	pInfo =  (PSYSTEM_PROCESS_INFO)malloc(nSize);
	if (Status == 0xC0000004) /*STATUS_INFO_LENGTH_MISMATCH*/
	{
		if (pInfo)
		{
			pTemp = (PVOID)pInfo;
			RtlSecureZeroMemory(pInfo, nSize);

			Status = ZwQuerySystemInformation_(5, pInfo, nSize, &nSize);
			if (NT_SUCCESS(Status))
			{

				
				pTeb64 = (PTEB64)malloc(sizeof(TEB64));
				pTeb32 = (PTEB32)malloc(sizeof(TEB32));
				while (1)
				{
					if (pInfo->NextEntryOffset == 0) 
					{
						break;
					}

					if (pInfo->UniqueProcessId == (HANDLE)m_PID)
					{

						for (DWORD i = 0; i < pInfo->NumberOfThreads; i++)
						{

							if (!Apc_inject((DWORD)pInfo->Threads[i].ClientId.UniqueThread,pTeb64,pTeb32,m_bWow64Process))
							{
								bRet = TRUE;
								break;
							}
						}
						break;
					}

					pInfo = (PSYSTEM_PROCESS_INFO)(((PUCHAR)pInfo) + pInfo->NextEntryOffset);
				}


			}

		}
	}

	if (pTemp)
	{
		free(pTemp);
		pTemp = NULL;
	}
	if (pTeb64)
	{
		free(pTeb64);
		pTeb64 = NULL;
	}
	if (pTeb32)
	{
		free(pTeb32);
		pTeb32 = NULL;
	}
	return bRet;
}


BOOL injector::user_windows_messages_load_normal_dll_64()
{
	m_hInjectDllBase = 0;
	BOOL bRet = FALSE;
	PVOID pAllcoateAdress = NULL;
	DWORD hThreadId = 0;
	HHOOK h_hook = NULL;
	PVOID pCallAddress = NULL;
	HMODULE hNdtdll = 0;

	//获取分配内存的 开始地址
	pAllcoateAdress = Get_normal_code_64();
	if (pAllcoateAdress)
	{
		//获取shellcode 执行地址
		pCallAddress = (PVOID)((ULONG_PTR)pAllcoateAdress + normalInject_64::rva::start);
	}
	if (pAllcoateAdress && pCallAddress)
	{
		hNdtdll = GetModuleHandleW(L"ntdll.dll");
		hThreadId = GetMainThread(m_PID);

		h_hook = SetWindowsHookExW(WH_GETMESSAGE, (HOOKPROC)(pCallAddress), hNdtdll, hThreadId);
		shellcode_state_64 main_data = { 0 };
		if (h_hook)
		{
			xlog::Critical("user_windows_messages_load_dll_64->SetWindowsHookExW 成功");

			SIZE_T bRetLength = 0;
			int nCnt = 100;
			
			do
			{
				PostThreadMessageW(hThreadId, WM_NULL, 0, 0);

				if (ReadProcessMemory_(m_hProcess, pAllcoateAdress, &main_data, sizeof(shellcode_state_64), &bRetLength))
				{
					if ((main_data.nAlreadRun == CALL_COMPLETE))
					{
						bRet = UnhookWindowsHookEx(h_hook);
						if (bRet)
						{
							xlog::Critical("user_windows_messages_load_dll_64->UnhookWindowsHookEx 成功");

						}
						bRet = TRUE;
						break;
					}

				}
				else
				{
					xlog::Error("user_windows_messages_load_dll_64->读取数据失败,结束循环");
					bRet = TRUE;
					break;
				}

				Sleep(100);
				nCnt--;

				if (nCnt < 0)
				{
					break;
				}

			} while (!bRet);

		}

		if ((main_data.nAlreadRun == CALL_COMPLETE))
		{

			if (VirtualFreeEx_(m_hProcess, pAllcoateAdress, 0, MEM_RELEASE))
			{
				xlog::Normal("user_windows_messages_load_dll_64->执行清理内存工作成功");
				pAllcoateAdress = NULL;

			}
		}

		m_hInjectDllBase = main_data.dllBase;
	}
	return bRet;
}



ULONG64 injector::GetInjectDllBase()
{
	return m_hInjectDllBase;
}


DWORD injector::GetMainThread(ULONG dwPid)
{
	DWORD hMainThreadId = 0;
	THREADENTRY32 ThreadEntry32 = { 0 };
	HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
	ThreadEntry32.dwSize = sizeof(THREADENTRY32);
	//创建快照

	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hThreadSnap == INVALID_HANDLE_VALUE)
	{
		return 0;
	}
	if (!Thread32First(hThreadSnap, &ThreadEntry32))
	{
		CloseHandle(hThreadSnap);
		return 0;
	}
	do
	{
		//遍历线程  
		if (ThreadEntry32.th32OwnerProcessID == dwPid)
		{
			hMainThreadId = ThreadEntry32.th32ThreadID;
			break;
		}
	} while (Thread32Next(hThreadSnap, &ThreadEntry32));
	CloseHandle(hThreadSnap);

	return hMainThreadId;
}

PVOID injector::Get_normal_code_64()
{
	PVOID pAllcoateAddress = NULL;
	PVOID pTemp = NULL;

	pTemp = malloc(sizeof(normalInject_64::payload));
	if (pTemp) 
	{
		RtlSecureZeroMemory(pTemp, sizeof(normalInject_64::payload));
		RtlCopyMemory(pTemp, normalInject_64::payload, sizeof(normalInject_64::payload));

		lstrcpyW((WCHAR *)((ULONG_PTR)pTemp + normalInject_64::rva::szDllPath), m_pszDllPath);
		
		pAllcoateAddress = VirtualAllocExT_(m_hProcess, NULL, sizeof(normalInject_64::payload), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (pAllcoateAddress)
		{
			size_t n = 0;
			if (WriteProcessMemory_(m_hProcess, pAllcoateAddress, pTemp, sizeof(normalInject_64::payload), &n))
			{
				xlog::Normal("Get_normal_code_64->写入成功");
			}
			else 
			{
				xlog::Error("Get_normal_code_64->写入失败");
				VirtualFreeEx_(m_hProcess, pAllcoateAddress, 0, MEM_RELEASE);
				pAllcoateAddress = NULL;
			}
		}
		else {
			xlog::Error("Get_normal_code_64->申请地址失败");
		}

		free(pTemp);
		pTemp = NULL;
	}
	return  pAllcoateAddress;
}



BOOL injector::UserThreadContextCall_eip(DWORD pCallAddress)
{
	BOOL bRet = FALSE;
	DWORD pJmpAddress = NULL;
	PVOID pBuffer = NULL;
	xlog::Critical("开始使用UseThreadContextLoadDll_32");

	DWORD dwMainThreadTid = GetMainThread(m_PID);

	thread_operation pThread(THREAD_ALL_ACCESS,dwMainThreadTid, TRUE);


	if (pThread.OpenThread())
	{

		if (pThread.SuspendThread())
		{
			WOW64_CONTEXT ct = { 0 };
			ct.ContextFlags = CONTEXT_CONTROL;
			//获取 CONTEXT 结构体
			if (pThread.GetThreadContext((CONTEXT*)&ct))
			{
				pJmpAddress = ct.Eip;
				if (pJmpAddress)
				{
	
					pBuffer = Get_thread_context_code_call_eip_32(pJmpAddress, pCallAddress);
					if (pBuffer)
					{
						ct.Eip = (DWORD)pBuffer;

						bRet = pThread.SetThreadContext((CONTEXT*)&ct);
					}
				}
			}

			bRet = pThread.ResumeThread();
		}

	}


	return bRet;
}

BOOL injector::inject32(int nType)
{
	BOOL bRet = FALSE;
	//32位 只提供正常注入
	switch (nType)
	{
	case 0:
	{
		break;
	}
	case 1://CreateThread
	{
		bRet = CreateThreadNormalInjectDll32();
		break;
	}
	case 2:
	{

		break;
	}
	case 3:
	{
		bRet = UseThreadContextLoadDll_32();
		break;
	}
	case 4:
	{

		break;
	}
	default:
		bRet = FALSE;
	}
	return bRet;
}

BOOL injector::inject64(int nType)
{
	BOOL bRet = FALSE;
	switch (nType)
	{
	case 0://没事发生
	{
		break;
	}
	case 1://CreateThread
	{
		bRet = CreateThreadToInject();
		break;
	}
	case 2://APC
	{
		bRet = use_apc_inject_64();
		break;
	}
	case 3: //线程上下文
	{
		bRet = UseThreadContextLoadDll_64();
		break;
	}
	case 4://setwindowshook
	{
		bRet = user_windows_messages_load_dll_64();

		break;
	}
	case 5: //hook peb
	{
		bRet = peb_UserSharedInfoPtr_inect64();
		break;
	}



	default:
		bRet = FALSE;
	}

	return bRet;
}

BOOL injector::CallRip(int nType,PVOID pCallAddress)
{
	BOOL bRet = FALSE;
	switch (nType)
	{
	case 0:
	{
		break;
	}
	case 1:
	{
		bRet = CreateThreadCall_Rip(pCallAddress);
		break;
	}
	case 2:
	{
		bRet = UserApcCall_Rip(pCallAddress);
		break;
	}
	case 3:
	{
		bRet = UseThreadContextCall_Rip(pCallAddress);
		break;
	}
	case 4:
	{
		bRet = user_windows_messages_call_rip_64(pCallAddress);


		break;
	}
	case  5:
	{
		bRet = peb_UserSharedInfoPtrCall_Rip(pCallAddress);
		break;
	}

	default:
		bRet = FALSE;
	}

	return bRet;
}

BOOL injector::CallEip(int nType,PVOID pCallAddress)
{
	BOOL bRet = FALSE;
	switch (nType)
	{
	case 0:
	{
		break;
	}
	case 1:
	{
		bRet = CreateThreadCall_Eip(pCallAddress);
		break;
	}
	case 2:
	{
		break;
	}
	case 3:
	{
		bRet = UserThreadContextCall_eip((DWORD)pCallAddress);
		break;
	}
	case 4:
	{
		
		break;
	}
	default:
		bRet = FALSE;
	}

	return bRet;
}

BOOL injector::CreateThreadNormalInjectDll32()
{
	BOOL bRet = FALSE;

	PVOID pAllcoateAddress = NULL;
	pAllcoateAddress = Get_normal_code_32();

	bRet = CreateRemoteThread_(m_hProcess, pAllcoateAddress);

	if (pAllcoateAddress && bRet)
	{
		bRet = FALSE;
		dll_info_32 main_data = { 0 };
		SIZE_T bRetLength = 0;
		int nCnt = 100;
		PVOID pTemp = NULL;
		pTemp = (PVOID)((ULONG_PTR)pAllcoateAddress + normalInject_32::rva::shellcode_end);
		do
		{
			if (ReadProcessMemory_(m_hProcess, pTemp, &main_data, sizeof(dll_info_32), &bRetLength))
			{
				if (main_data.nAlreadRun == CALL_COMPLETE)
				{
					bRet = TRUE;

					Sleep(200);
					if (VirtualFreeEx_(m_hProcess, pAllcoateAddress, 0, MEM_RELEASE))
					{
					
					}

					break;
				}

			}
			else
			{
				
				bRet = TRUE;
				break;
			}

			Sleep(100);
			nCnt--;

			if (nCnt == 0 || nCnt < 0)
			{
				
				break;
			}

		} while (!bRet);
		if (main_data.dllBase)
		{
			m_hInjectDllBase = main_data.dllBase;
		}
	}


	return bRet;
}

BOOL injector::UseThreadContextLoadDll_32()
{

	if (!m_bNormalInject)return FALSE;

	BOOL bRet = FALSE;
	DWORD pJmpAddress = NULL;
	PVOID pBuffer = NULL;
	

	DWORD dwMainThreadTid = GetMainThread(m_PID);

	thread_operation pThread(THREAD_ALL_ACCESS,dwMainThreadTid, TRUE);


	if (pThread.OpenThread())
	{

		if (pThread.SuspendThread())
		{
			WOW64_CONTEXT ct = { 0 };
			ct.ContextFlags = CONTEXT_CONTROL;
			//获取 CONTEXT 结构体
			if (pThread.GetThreadContext((CONTEXT*)&ct))
			{
				pJmpAddress = ct.Eip;
				if (pJmpAddress)
				{
					PVOID pCallAddress = NULL;

					pBuffer = Get_thread_context_code_32(pJmpAddress,&pCallAddress);
					if (pBuffer)
					{
						ct.Eip = (DWORD)pCallAddress;

						bRet = pThread.SetThreadContext((CONTEXT*)&ct);
					}
				}
			}

			pThread.ResumeThread();
		}

	}
	if (pBuffer && bRet)
	{
		bRet = FALSE;
		dll_info_32 main_data = { 0 };
		SIZE_T bRetLength = 0;
		int nCnt = 100;
		PVOID pTemp = NULL;
		pTemp = (PVOID)((ULONG_PTR)pBuffer + normalInject_32::rva::shellcode_end);
		do
		{
			if (ReadProcessMemory_(m_hProcess, pTemp, &main_data, sizeof(dll_info_32), &bRetLength))
			{
				if (main_data.nAlreadRun == CALL_COMPLETE)
				{
					bRet = TRUE;

					Sleep(200);
					if (VirtualFreeEx_(m_hProcess, pBuffer, 0, MEM_RELEASE))
					{
						
					}

					break;
				}

			}
			else
			{
				
				bRet = TRUE;
				break;
			}

			Sleep(100);
			nCnt--;

			if (nCnt == 0 || nCnt < 0)
			{
			
				break;
			}

		} while (!bRet);
		if (main_data.dllBase)
		{
			m_hInjectDllBase = main_data.dllBase;
		}
	}


	return bRet;
}

PVOID injector::Get_thread_context_code_call_eip_32(DWORD dwJmpAddress, DWORD pCallAddress)
{
	PVOID pAllcoateAddress = NULL;
	UCHAR code[] =
	{
		0x60,
		0x9c,
		0xe8,0,0,0,0,
		0x9d,
		0x61,
		0xe9,0,0,0,0
	};

	pAllcoateAddress = VirtualAllocExT_(m_hProcess, NULL, sizeof(code), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (pAllcoateAddress)
	{
		DWORD dwOffset1 = (ULONG_PTR)pCallAddress - ((ULONG_PTR)pAllcoateAddress  + 2) - 5;
		*(PULONG)((ULONG_PTR)code +  3) = dwOffset1;

		//定位 shellcode的 E9的位置
		DWORD dwOffset2 = (ULONG_PTR)dwJmpAddress - ((ULONG_PTR)pAllcoateAddress  + 9) - 5;
		*(PULONG)((ULONG_PTR)code + 10) = dwOffset2;


		size_t n = 0;
		if (WriteProcessMemory_(m_hProcess, pAllcoateAddress, code, sizeof(code), &n))
		{
		
		}
		else
		{
			VirtualFreeEx_(m_hProcess, pAllcoateAddress, 0, MEM_RELEASE);
			pAllcoateAddress = NULL;
		}
	}

	return  pAllcoateAddress;
}

PVOID injector::Get_thread_context_code_32(DWORD dwJmpAddress,PVOID *pCallAddress)
{
	PVOID pAllcoateAddress = NULL;
	PVOID pTemp = NULL;
	SIZE_T nSize = 0;
	PVOID pOffset = NULL;
	UCHAR code[] =
	{
		0x60,
		0x9c,
		0xe8,0,0,0,0,
		0x9d,
		0x61,
		0xe9,0,0,0,0
	};

	nSize = sizeof(normalInject_32::payload) + sizeof(code);

	pTemp = malloc(nSize);
	if (pTemp)
	{
		RtlSecureZeroMemory(pTemp, nSize);

		//先填充shellcode
		RtlCopyMemory(pTemp, normalInject_32::payload, sizeof(normalInject_32::payload));

		pOffset = (PVOID)((ULONG_PTR)pTemp + sizeof(normalInject_32::payload));
		//
		RtlCopyMemory(pOffset, code, sizeof(code));

		dll_info_32 dw = { 0 };
		 lstrcpyW(dw.wszDllPath, m_pszDllPath);
		

		pAllcoateAddress = VirtualAllocExT_(m_hProcess, NULL, nSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (pAllcoateAddress)
		{

			 *(PULONG)((ULONG_PTR)pTemp + normalInject_32::rva::struct_offset) = (ULONG)pAllcoateAddress + normalInject_32::rva::shellcode_end;
			 RtlCopyMemory((PVOID)((ULONG64)pTemp + normalInject_32::rva::shellcode_end), &dw, sizeof(dll_info_32));

			 pOffset = NULL;
			 //定位 shellcode的 E8的位置
			 DWORD dwOffset1 = (ULONG_PTR)pAllcoateAddress - ((ULONG_PTR)pAllcoateAddress + sizeof(normalInject_32::payload) + 2) - 5;
			 *(PULONG)((ULONG_PTR)pTemp + sizeof(normalInject_32::payload) + 3) = dwOffset1;

			 //定位 shellcode的 E9的位置
			 DWORD dwOffset2 = (ULONG_PTR)dwJmpAddress - ((ULONG_PTR)pAllcoateAddress + sizeof(normalInject_32::payload) + 9) - 5;
			  *(PULONG)((ULONG_PTR)pTemp + sizeof(normalInject_32::payload) + 10) = dwOffset2;

			size_t n = 0;
			if (WriteProcessMemory_(m_hProcess, pAllcoateAddress, pTemp, nSize, &n))
			{
		
				*pCallAddress = (PVOID)(sizeof(normalInject_32::payload) + (ULONG_PTR)pAllcoateAddress);
			}
			else
			{
				
				VirtualFreeEx_(m_hProcess, pAllcoateAddress, 0, MEM_RELEASE);
				pAllcoateAddress = NULL;
			}
		}


		free(pTemp);
		pTemp = NULL;
	}
	return  pAllcoateAddress;
}

DWORD injector::apc_clear_work_thread(PVOID pArg)
{
	injector* pThis = (injector*)pArg;

	PVOID pTemp = NULL;
	
	if (pThis->m_bNormalInject)
	{
		pTemp = pThis->m_pApc_allcoate_memory_base;
	}
	else 
	{
		pTemp = pThis->m_Apc_allocoate_map_shellcode_pos;
	}

	shellcode_state_64 main_data = { 0 };
	BOOL bRet = FALSE;
	if (pThis->m_pApc_allcoate_memory_base)
	{
		SIZE_T bRetLength = 0;
		int nCnt = 1000;
		do
		{

			if (ReadProcessMemory_(pThis->m_hProcess, pTemp, &main_data, sizeof(shellcode_state_64), &bRetLength))
			{
				if ((main_data.nAlreadRun == CALL_COMPLETE) || (main_data.nAlreadRun == CALL_COMPLETE_SUCCESS))
				{
			
					bRet = TRUE;
					break;
				}

			}
			else
			{
				
				bRet = TRUE;
				break;
			}

			Sleep(100);
			nCnt--;

			if (nCnt < 0)
			{
				break;
			}

		} while (!bRet);

	}

	if ((main_data.nAlreadRun == CALL_COMPLETE) || (main_data.nAlreadRun == CALL_COMPLETE_SUCCESS))
	{

		if (VirtualFreeEx_(pThis->m_hProcess, pTemp, 0, MEM_RELEASE))
		{
			pThis->m_pApc_allcoate_memory_base = NULL;
			pThis->m_Apc_allocoate_map_shellcode_pos = NULL;

		}
	}
	if (main_data.dllBase) 
	{
		pThis->m_hInjectDllBase = main_data.dllBase;
	}


	return 0;
}



BOOL CALLBACK injector:: EnumWindowFunc(HWND hwnd, LPARAM param)
{
	injector* pThis = (injector*)param;
	DWORD pid = 0;
	GetWindowThreadProcessId(hwnd, &pid);
	if (pid == pThis->m_PID)
	{
		pThis->m_bHaveGuiThread = TRUE;
		return FALSE;
	}
	return TRUE;
}

BOOL injector::peb_UserSharedInfoPtr_inect64()
{
	BOOL bRet = FALSE;


	EnumWindows(EnumWindowFunc, (LPARAM)this);

	if (m_bHaveGuiThread) 
	{
		if (m_bNormalInject)
		{
			bRet = hook_peb_UserSharedInfoPtr_normal_inject64();
		}
		else
		{
			bRet = hook_peb_UserSharedInfoPtr_map_inject64();
		}
	}

	return bRet;
}

PVOID injector::get_peb_inject_normal_shellcode64(ULONG64 nJmpAddess, PVOID pold_tab_ptr,PVOID* pCallAddress, PVOID* pNew_Tab_ptr)
{
	if (!pCallAddress || !nJmpAddess)return NULL;
	PVOID pAllocateAddress = NULL;

	UCHAR code[] =
	{
	0x50,//push        rax
	0x53 ,//push        rbx 
	0x51 ,// push        rcx 
	0x52 ,//push        rdx
	0x55 ,//push        rbp 
	0x54 ,//push        rsp 
	0x56 ,// push        rsi 
	0x57 ,//push        rdi
	0x41 ,0x50 ,//push        r8 
	0x41 ,0x51 ,// push        r9 
	0x41 ,0x52 ,//push        r10 
	0x41 ,0x53 ,// push        r11 
	0x41 ,0x54 ,
	0x41 ,0x55 ,
	0x41 ,0x56 ,
	0x41 ,0x57 ,
	0x9c ,
	0x48 ,0x83 ,0xec ,0x30 ,
	0xe8,0x24 ,0xfd ,0xff ,0xff ,
	0x48 ,0x83 ,0xc4 ,0x30 ,
	0x9d ,0x41 ,0x5f ,0x41 ,0x5e ,0x41 ,0x5d ,0x41 ,0x5c ,0x41 ,0x5b ,0x41 ,0x5a ,0x41 ,0x59 ,0x41 ,0x58 ,0x5f ,0x5e ,0x5c ,0x5d ,0x5a
	,0x59 ,0x5b ,0x58 ,
	0xff,0x25,0,0,0,0, // jmp dword [xxxxxxxxx]
	0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90  // jmpAddress  offset +0x3DB
	};

	PVOID pTemp = NULL;
	SIZE_T nSize = 0;
	SIZE_T n = 0;
	if (m_bNormalInject)
	{

		//修复code代码
		*(PULONG_PTR)((ULONG_PTR)code + 0x45) = nJmpAddess;


		PVOID offset = 0;
		nSize = sizeof(normalInject_64::payload) + sizeof(code) +  sizeof(ULONG64) * 128;
		pTemp = malloc(nSize);
		if (pTemp)
		{
			RtlSecureZeroMemory(pTemp, nSize);

			RtlCopyMemory(pTemp, normalInject_64::payload, sizeof(normalInject_64::payload));
			offset = (PVOID)((ULONG_PTR)pTemp + sizeof(normalInject_64::payload));
			RtlCopyMemory(offset, code, sizeof(code));

			offset = (PVOID)((ULONG_PTR)pTemp + sizeof(normalInject_64::payload) + sizeof(code));

			RtlCopyMemory(offset, pold_tab_ptr, sizeof(ULONG64) * 128);

			//往shellcode写入 dll路径
			lstrcpyW((WCHAR*)((ULONG_PTR)pTemp + normalInject_64::rva::szDllPath), m_pszDllPath);


			pAllocateAddress = VirtualAllocExT_(m_hProcess, NULL, nSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (pAllocateAddress)
			{

				*(PULONG)((ULONG_PTR)pTemp + sizeof(normalInject_64::payload) + 30) = ((ULONG_PTR)pAllocateAddress + normalInject_64::rva::start) - ((ULONG_PTR)pAllocateAddress + sizeof(normalInject_64::payload) + 29) - 5;
				*pCallAddress = (PVOID)((ULONG_PTR)pAllocateAddress + sizeof(normalInject_64::payload));

				ULONG64* pTempTab = (ULONG64*)offset;
				pTempTab[2] =  (ULONG64)((ULONG_PTR)pAllocateAddress + sizeof(normalInject_64::payload));

				if (WriteProcessMemory_(m_hProcess, pAllocateAddress, pTemp, nSize, &n))
				{
					*pNew_Tab_ptr = (PVOID)((ULONG_PTR)pAllocateAddress + sizeof(normalInject_64::payload) + sizeof(code));
				}
				else 
				{
					pAllocateAddress=NULL;
				}
			}
		}
	}

	if (pTemp)
	{
		free(pTemp);
		pTemp = NULL;
	}

	return pAllocateAddress;
}

PVOID injector::get_peb_inject_map_shellcode64(ULONG64 nJmpAddess, PVOID pold_tab_ptr, PVOID* pCallAddress, PVOID* pNew_Tab_ptr)
{
	if (!pCallAddress || !nJmpAddess)return NULL;
	PVOID pAllocateAddress = NULL;

	UCHAR code[] =
	{
	0x50,//push        rax
	0x53 ,//push        rbx 
	0x51 ,// push        rcx 
	0x52 ,//push        rdx
	0x55 ,//push        rbp 
	0x54 ,//push        rsp 
	0x56 ,// push        rsi 
	0x57 ,//push        rdi
	0x41 ,0x50 ,//push        r8 
	0x41 ,0x51 ,// push        r9 
	0x41 ,0x52 ,//push        r10 
	0x41 ,0x53 ,// push        r11 
	0x41 ,0x54 ,
	0x41 ,0x55 ,
	0x41 ,0x56 ,
	0x41 ,0x57 ,
	0x9c ,
	0x48 ,0x83 ,0xec ,0x30 ,
	0xe8,0x24 ,0xfd ,0xff ,0xff , //+
	0x48 ,0x83 ,0xc4 ,0x30 ,
	0x9d ,0x41 ,0x5f ,0x41 ,0x5e ,0x41 ,0x5d ,0x41 ,0x5c ,0x41 ,0x5b ,0x41 ,0x5a ,0x41 ,0x59 ,0x41 ,0x58 ,0x5f ,0x5e ,0x5c ,0x5d ,0x5a
	,0x59 ,0x5b ,0x58 ,
	0xff,0x25,0,0,0,0, // jmp dword [xxxxxxxxx]
	0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90  // jmpAddress  offset +0x3DB
	};

	PVOID pTemp = NULL;
	SIZE_T nSize = 0;
	SIZE_T n = 0;
	PVOID pPEBuffer = NULL;
	DWORD nImageSize = 0;
	if (!m_bNormalInject)
	{

		//修复code代码
		*(PULONG_PTR)((ULONG_PTR)code + 0x45) = nJmpAddess;

		pPEBuffer = file_to_image_buffer(m_pszDllPath, nImageSize);

		PVOID offset = 0;
		nSize = sizeof(MapInject_64::payload) + sizeof(code) + nImageSize + sizeof(ULONG64) * 128;

		pTemp = malloc(nSize);
		if (pTemp)
		{
			RtlSecureZeroMemory(pTemp, nSize);

			//先拷贝dll文件
			RtlCopyMemory(pTemp, pPEBuffer, nImageSize);
			offset = (PVOID)((ULONG_PTR)pTemp + nImageSize);

			//拷贝 shellcode
			RtlCopyMemory(offset, MapInject_64::payload, sizeof(MapInject_64::payload));
			offset = (PVOID)((ULONG_PTR)pTemp + sizeof(MapInject_64::payload) + nImageSize);
			RtlCopyMemory(offset, code, sizeof(code));

			//拷贝 tab
			offset = (PVOID)((ULONG_PTR)pTemp + sizeof(MapInject_64::payload) + nImageSize + sizeof(code));
			RtlCopyMemory(offset, pold_tab_ptr, sizeof(ULONG64) * 128);

			pAllocateAddress = VirtualAllocExT_(m_hProcess, NULL, nSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (pAllocateAddress)
			{
				// 定位shellcode位置 同时往shellcode 传入参数
				*(int*)((ULONG_PTR)pTemp + MapInject_64::rva::nFlags + nImageSize) = m_nFlags;
				*(PULONG_PTR)((ULONG_PTR)pTemp + MapInject_64::rva::nPEBuffer + nImageSize) = (ULONG_PTR)pAllocateAddress;

				//E8XXXX = 目标地址-下一行地址  修复 Code 中的E8 位置
				*(PULONG)((ULONG_PTR)pTemp + nImageSize + sizeof(MapInject_64::payload) + 30) = ((ULONG_PTR)pAllocateAddress + nImageSize + MapInject_64::rva::start) - ((ULONG_PTR)pAllocateAddress + nImageSize + sizeof(MapInject_64::payload) + 29);


				//修复
				ULONG64* pTempTab = (ULONG64*)offset;
				pTempTab[2] = (ULONG64)((ULONG_PTR)pAllocateAddress + sizeof(MapInject_64::payload) + nImageSize);

				if (WriteProcessMemory_(m_hProcess, pAllocateAddress, pTemp, nSize, &n))
				{
					//获取 map 执行地址
					*pCallAddress = (PVOID)((ULONG_PTR)pAllocateAddress + nImageSize);
					*pNew_Tab_ptr = (PVOID)((ULONG_PTR)pAllocateAddress + sizeof(MapInject_64::payload) + nImageSize + sizeof(code));
				}
			}
		}
	}

	if (pTemp)
	{
		free(pTemp);
		pTemp = NULL;
	}
	if (pPEBuffer)
	{
		free(pPEBuffer);
		pPEBuffer = NULL;
	}

	return pAllocateAddress;
}



BOOL injector::hook_peb_UserSharedInfoPtr_map_inject64()
{
	BOOL bRet = FALSE;

	PVOID pAllcoateAddress = NULL;
	PVOID pShellcodeAddress = NULL;
	PVOID pNew_tab = NULL;
	char* dispatch_table_ptr = NULL;
	char* dispatch_table = NULL;

	SIZE_T n = 0;

	PROCESS_BASIC_INFORMATION pbi = { 0 };
	if (!NT_SUCCESS(ZwQueryInformationProcess_(m_hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL)))
		return bRet;

	char* peb = (char*)(pbi.PebBaseAddress);
	dispatch_table_ptr = peb + 0x58;//	/*0x058*/         UINT64       UserSharedInfoPtr;
	dispatch_table = nullptr;
	if (ReadProcessMemory_(m_hProcess, dispatch_table_ptr, &dispatch_table, 8, &n) || !dispatch_table)
	{
		char* tab[128] = { 0 };
		if (ReadProcessMemory_(m_hProcess, dispatch_table, tab, sizeof(tab), &n))
		{

			pAllcoateAddress =get_peb_inject_map_shellcode64((ULONG64)tab[2], &tab, &pShellcodeAddress, &pNew_tab);


			if (pAllcoateAddress && pNew_tab)
			{
				//更改RIP
				bRet = WriteProcessMemory_(m_hProcess, dispatch_table_ptr, &pNew_tab, sizeof(PVOID), &n);
			}

		}
	}


	if (bRet && pNew_tab)
	{
		bRet = FALSE;
		shellcode_state_64 main_data = { 0 };
		SIZE_T bRetLength = 0;
		int nCnt = 100;
		do
		{
			if (ReadProcessMemory_(m_hProcess, pShellcodeAddress, &main_data, sizeof(shellcode_state_64), &bRetLength))
			{
				if ((main_data.nAlreadRun == CALL_COMPLETE) || (main_data.nAlreadRun == CALL_COMPLETE_SUCCESS))
				{
					bRet = TRUE;
					if (WriteProcessMemory_(m_hProcess, dispatch_table_ptr, &dispatch_table, sizeof(PVOID), &n)) 
					{
						Sleep(100);
						if (VirtualFreeEx_(m_hProcess, pShellcodeAddress, sizeof(MapInject_64::payload), MEM_DECOMMIT))
						{
				
						}
					}

					break;
				}

			}
			else
			{

				bRet = TRUE;
				break;
			}

			Sleep(100);
			nCnt--;

			if (nCnt == 0 || nCnt < 0)
			{


				break;
			}

		} while (!bRet);
		if ((main_data.nAlreadRun == CALL_COMPLETE_SUCCESS))
		{
			m_hInjectDllBase = (ULONG64)pAllcoateAddress;
			bRet = TRUE;
		}
	}



	return bRet;
}

BOOL injector::hook_peb_UserSharedInfoPtr_normal_inject64()
{
	BOOL bRet = FALSE;
	PVOID pAllcoateAddress = NULL;
	PVOID pCallAddress = NULL;
	PVOID pNew_tab = NULL;
	char* dispatch_table_ptr = NULL;
	char* dispatch_table = NULL;

	SIZE_T n = 0;

	PROCESS_BASIC_INFORMATION pbi = { 0 };
	if (!NT_SUCCESS(ZwQueryInformationProcess_(m_hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL)))
		return bRet;

	char* peb = (char*)(pbi.PebBaseAddress);
	dispatch_table_ptr = peb + 0x58;//	/*0x058*/         UINT64       UserSharedInfoPtr;
	dispatch_table = nullptr;
	if (ReadProcessMemory_(m_hProcess, dispatch_table_ptr, &dispatch_table, 8, &n) || !dispatch_table) 
	{
		char* tab[128] = { 0 };
		if (ReadProcessMemory_(m_hProcess, dispatch_table, tab, sizeof(tab), &n))
		{

			pAllcoateAddress = get_peb_inject_normal_shellcode64((ULONG64)tab[2], &tab, &pCallAddress, &pNew_tab);


			if (pAllcoateAddress && pNew_tab)
			{
				//更改RIP
	
				bRet = WriteProcessMemory_(m_hProcess, dispatch_table_ptr, &pNew_tab, sizeof(PVOID), &n);
			}

		}
	}

	if (bRet && pNew_tab)
	{
		if (bRet)
		{
			bRet = FALSE;
			shellcode_state_64 main_data = { 0 };
			SIZE_T bRetLength = 0;
			int nCnt = 100;
			do
			{
				if (ReadProcessMemory_(m_hProcess, pAllcoateAddress, &main_data, sizeof(shellcode_state_64), &bRetLength))
				{
					if (main_data.nAlreadRun == CALL_COMPLETE)
					{
						bRet = TRUE;
						if (WriteProcessMemory_(m_hProcess, dispatch_table_ptr, &dispatch_table, sizeof(PVOID), &n)) 
						{
							if (VirtualFreeEx_(m_hProcess, pAllcoateAddress, 0, MEM_RELEASE))
							{

							}
						}

						break;
					}

				}
				else
				{
					bRet = TRUE;
					break;
				}

				Sleep(100);
				nCnt--;

				if (nCnt == 0 || nCnt < 0)
				{
					break;
				}

			} while (!bRet);
			if (main_data.dllBase)
			{
				m_hInjectDllBase = main_data.dllBase;
			}
		}
	}

	return bRet;
}


PVOID injector::Get_normal_code_32()
{
	PVOID pAllcoateAddress = NULL;
	PVOID pTemp = NULL;

	pTemp = malloc(sizeof(normalInject_32::payload));
	if (pTemp)
	{
		RtlSecureZeroMemory(pTemp, sizeof(normalInject_32::payload));

		RtlCopyMemory(pTemp, normalInject_32::payload, sizeof(normalInject_32::payload));

		dll_info_32 dw = { 0 };
		lstrcpyW(dw.wszDllPath, m_pszDllPath);


		pAllcoateAddress = VirtualAllocExT_(m_hProcess, NULL, sizeof(normalInject_32::payload), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (pAllcoateAddress)
		{

			*(PULONG)((ULONG_PTR)pTemp + normalInject_32::rva::struct_offset) = (ULONG)pAllcoateAddress + normalInject_32::rva::shellcode_end;
			RtlCopyMemory((PVOID)((ULONG64)pTemp + normalInject_32::rva::shellcode_end), &dw, sizeof(dll_info_32));

			size_t n = 0;
			if (WriteProcessMemory_(m_hProcess, pAllcoateAddress, pTemp, sizeof(normalInject_32::payload), &n))
			{
				xlog::Normal("Get_normal_code_32->写入成功");
			}
			else
			{
				xlog::Error("Get_normal_code_32->写入失败");
				VirtualFreeEx_(m_hProcess, pAllcoateAddress, 0, MEM_RELEASE);
				pAllcoateAddress = NULL;
			}
		}
		else {
			xlog::Error("Get_normal_code_32->申请地址失败");
		}

		free(pTemp);
		pTemp = NULL;
	}
	return  pAllcoateAddress;
}



PVOID injector::Get_map_code_64(PVOID* pShellcodeAddress, DWORD nFlags)
{
	PVOID pAllcoateAddress = NULL;
	PVOID pTemp = NULL;
	DWORD nImageSize = 0;
	DWORD nSize = 0;
	PVOID pPEBuffer = NULL;
	pPEBuffer = file_to_image_buffer(m_pszDllPath, nImageSize);

	nSize = nImageSize + sizeof(MapInject_64::payload);

	pTemp = malloc(nSize);
	if (pTemp)
	{
		RtlSecureZeroMemory(pTemp, nSize);

		PVOID pTemp2 = NULL;
		//先拷贝DLL 文件
		RtlCopyMemory(pTemp, pPEBuffer, nImageSize);

		//在拷贝shellcode
		pTemp2 = (PVOID)((ULONG64)pTemp + nImageSize);
		RtlCopyMemory(pTemp2, MapInject_64::payload, sizeof(MapInject_64::payload));


		//申请地址
		PVOID shell_address = NULL;
		shell_address = VirtualAllocExT_(m_hProcess, 0, nSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (shell_address)
		{

			//修复shellcode


			*(int*)((ULONG_PTR)pTemp + MapInject_64::rva::nFlags + nImageSize) = nFlags;
			*(__int64*)((ULONG_PTR)pTemp + MapInject_64::rva::nPEBuffer + nImageSize) = (__int64)shell_address;

			//把所有 内存 拷贝进 可读可写可执行得内存里
			SIZE_T n = 0;
			if (WriteProcessMemory_(m_hProcess, shell_address, pTemp, nSize, &n))
			{
				pAllcoateAddress = shell_address;
				*pShellcodeAddress = (PVOID)((ULONG_PTR)pAllcoateAddress + nImageSize);
			}
			else {
				VirtualFreeEx_(m_hProcess, shell_address, 0, MEM_RELEASE);
				pAllcoateAddress = NULL;
			}
		}

	}


	return pAllcoateAddress;
}



UINT injector::AlignSize(UINT nSize, UINT nAlign)
{
	return ((nSize + nAlign - 1) / nAlign * nAlign);
}

BOOL injector::ImageFile(PVOID FileBuffer, PVOID* ImageModuleBase, DWORD& ImageSize)
{
	PIMAGE_DOS_HEADER ImageDosHeader = NULL;
	PIMAGE_NT_HEADERS ImageNtHeaders = NULL;
	PIMAGE_SECTION_HEADER ImageSectionHeader = NULL;
	DWORD FileAlignment = 0, SectionAlignment = 0, NumberOfSections = 0, SizeOfImage = 0, SizeOfHeaders = 0;
	DWORD Index = 0;
	PVOID ImageBase = NULL;
	DWORD SizeOfNtHeaders = 0;

	if (!FileBuffer || !ImageModuleBase)
	{
		return FALSE;
	}

	__try
	{
		ImageDosHeader = (PIMAGE_DOS_HEADER)FileBuffer;
		if (ImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			return FALSE;
		}

		HMODULE h = GetModuleHandle(L"ntdll.dll");
		typedef PIMAGE_NT_HEADERS(WINAPI* pfnRtlImageNtHeader)(PVOID Base);
		pfnRtlImageNtHeader RtlImageNtHeader_ = NULL;
		RtlImageNtHeader_ = (pfnRtlImageNtHeader)GetProcAddress(h, "RtlImageNtHeader");

		ImageNtHeaders = RtlImageNtHeader_(FileBuffer);


		if (ImageNtHeaders->Signature != IMAGE_NT_SIGNATURE)
		{
			return FALSE;
		}

		FileAlignment = ImageNtHeaders->OptionalHeader.FileAlignment;
		SectionAlignment = ImageNtHeaders->OptionalHeader.SectionAlignment;
		NumberOfSections = ImageNtHeaders->FileHeader.NumberOfSections;
		SizeOfImage = ImageNtHeaders->OptionalHeader.SizeOfImage;
		SizeOfHeaders = ImageNtHeaders->OptionalHeader.SizeOfHeaders;
		SizeOfImage = AlignSize(SizeOfImage, SectionAlignment);

		ImageSize = SizeOfImage;

		ImageBase = malloc(SizeOfImage);
		if (ImageBase == NULL)
		{
			return FALSE;
		}
		RtlZeroMemory(ImageBase, SizeOfImage);

		SizeOfNtHeaders = sizeof(ImageNtHeaders->FileHeader) + sizeof(ImageNtHeaders->Signature) + ImageNtHeaders->FileHeader.SizeOfOptionalHeader;
		ImageSectionHeader = IMAGE_FIRST_SECTION(ImageNtHeaders);

		for (Index = 0; Index < NumberOfSections; Index++)
		{
			ImageSectionHeader[Index].SizeOfRawData = AlignSize(ImageSectionHeader[Index].SizeOfRawData, FileAlignment);
			ImageSectionHeader[Index].Misc.VirtualSize = AlignSize(ImageSectionHeader[Index].Misc.VirtualSize, SectionAlignment);
		}

		if (ImageSectionHeader[NumberOfSections - 1].VirtualAddress + ImageSectionHeader[NumberOfSections - 1].SizeOfRawData > SizeOfImage)
		{
			ImageSectionHeader[NumberOfSections - 1].SizeOfRawData = SizeOfImage - ImageSectionHeader[NumberOfSections - 1].VirtualAddress;
		}

		RtlCopyMemory(ImageBase, FileBuffer, SizeOfHeaders);

		for (Index = 0; Index < NumberOfSections; Index++)
		{
			DWORD FileOffset = ImageSectionHeader[Index].PointerToRawData;
			DWORD Length = ImageSectionHeader[Index].SizeOfRawData;
			ULONG64 ImageOffset = ImageSectionHeader[Index].VirtualAddress;
			RtlCopyMemory(&((PBYTE)ImageBase)[ImageOffset], &((PBYTE)FileBuffer)[FileOffset], Length);
		}

		*ImageModuleBase = ImageBase;


	}
	__except (1)
	{
		if (ImageBase)
		{
			free(ImageBase);
			ImageBase = NULL;
		}

		*ImageModuleBase = NULL;
		return FALSE;
	}

	return TRUE;
}

PVOID injector::file_to_image_buffer(LPCWSTR szFullPath, DWORD& pImageSize)
{

	HANDLE hFile = CreateFile(
		szFullPath,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		return NULL;
	}

	DWORD dwSize = GetFileSize(hFile, NULL);
	if (dwSize == 0)
	{
		CloseHandle(hFile);
		return NULL;
	}



	PVOID pBuffer = malloc(dwSize);
	if (!pBuffer)
	{
		CloseHandle(hFile);
		return NULL;
	}

	RtlZeroMemory(pBuffer, dwSize);
	DWORD dwRet = 0;
	if (!ReadFile(hFile, pBuffer, dwSize, &dwRet, NULL))
	{
		CloseHandle(hFile);
		free(pBuffer);
		return NULL;
	}

	CloseHandle(hFile);


	PVOID ImageBase = NULL;

	if (!ImageFile((PBYTE)pBuffer, &ImageBase, pImageSize) || ImageBase == NULL)
	{
		free(pBuffer);
		return NULL;
	}


	free(pBuffer);

	return ImageBase;
}


BOOL injector::user_windows_messages_load_dll_64()
{

	BOOL bRet = FALSE;
	if (m_bNormalInject)
	{
		bRet = user_windows_messages_load_normal_dll_64();
	}
	else
	{
		bRet = user_windows_messages_load_map_dll_64();
	}
	return bRet;
}



BOOL injector::UseThreadContextLoadDll_64()
{
	BOOL bRet = FALSE;
	if (m_bNormalInject)
	{
		bRet = NormalInject_UseThreadContextCall_64();
	}
	else
	{
		bRet = MapInject_UseThreadContextCall_64();
	}
	return bRet;
}


BOOL injector::user_windows_messages_load_map_dll_64()
{
	m_hInjectDllBase = 0;
	BOOL bRet = FALSE;
	PVOID pAllcoateAdress = NULL;
	DWORD hThreadId = 0;
	HHOOK h_hook = NULL;
	PVOID pShellcodeAddress = NULL;
	HMODULE hNdtdll = 0;
	PVOID pCallAddress = 0;
	pAllcoateAdress = Get_map_code_64(&pShellcodeAddress,m_nFlags);
	if (pAllcoateAdress)
	{
		pCallAddress = (PVOID)((ULONG_PTR)pShellcodeAddress + MapInject_64::rva::start);
		
	}
	if (pAllcoateAdress && pCallAddress)
	{
		hNdtdll = GetModuleHandleW(L"ntdll.dll");
		hThreadId = GetMainThread(m_PID);

		h_hook = SetWindowsHookExW(WH_GETMESSAGE, (HOOKPROC)(pCallAddress), hNdtdll, hThreadId);
		shellcode_state_64 main_data = { 0 };
		if (h_hook)
		{
			xlog::Critical("user_windows_messages_load_map_dll_64->SetWindowsHookExW 成功");

			SIZE_T bRetLength = 0;
			int nCnt = 100;

			do
			{
				PostThreadMessageW(hThreadId, WM_NULL, 0, 0);

				if (ReadProcessMemory_(m_hProcess, pShellcodeAddress, &main_data, sizeof(shellcode_state_64), &bRetLength))
				{
					if ((main_data.nAlreadRun == CALL_COMPLETE) || (main_data.nAlreadRun == CALL_COMPLETE_SUCCESS))
					{
						bRet = UnhookWindowsHookEx(h_hook);
						if (bRet)
						{
							xlog::Critical("user_windows_messages_load_map_dll_64->UnhookWindowsHookEx 成功");

						}
						bRet = TRUE;
						break;
					}

				}
				else
				{
					xlog::Error("user_windows_messages_load_map_dll_64->读取数据失败,结束循环");
					bRet = TRUE;
					break;
				}

				Sleep(100);
				nCnt--;

				if (nCnt < 0)
				{
					break;
				}

			} while (!bRet);

		}

		if ((main_data.nAlreadRun == CALL_COMPLETE) || (main_data.nAlreadRun == CALL_COMPLETE_SUCCESS))
		{

			if (VirtualFreeEx_(m_hProcess, pShellcodeAddress, sizeof(MapInject_64::payload), MEM_DECOMMIT))
			{
				xlog::Normal("user_windows_messages_load_map_dll_64->执行清理内存工作成功");

			}
		}
		if (main_data.nAlreadRun == CALL_COMPLETE_SUCCESS) 
		{
			m_hInjectDllBase = (ULONG64)pAllcoateAdress;
			bRet = TRUE;
		}
		else {
			bRet = FALSE;
		}
	}
	return bRet;
}

BOOL injector::UserApcCall_Rip(PVOID pCallAddress)
{
	BOOL bRet = FALSE;
	PVOID pTemp = NULL;
	PTEB64 pTeb64 = NULL;
	PTEB32 pTeb32 = NULL;
	NTSTATUS Status;

	
	
	DWORD nSize = 0;
	PSYSTEM_PROCESS_INFO pInfo = NULL;
	// 获取信息所需的缓冲区大小
	Status = ZwQuerySystemInformation_(5, NULL, 0, &nSize);

	pInfo =  (PSYSTEM_PROCESS_INFO)malloc(nSize);
	if (Status == 0xC0000004) /*STATUS_INFO_LENGTH_MISMATCH*/
	{
		if (pInfo)
		{
			pTemp = (PVOID)pInfo;
			RtlSecureZeroMemory(pInfo, nSize);

			Status = ZwQuerySystemInformation_(5, pInfo, nSize, &nSize);
			if (NT_SUCCESS(Status))
			{

				
				pTeb64 = (PTEB64)malloc(sizeof(TEB64));
				pTeb32 = (PTEB32)malloc(sizeof(TEB32));
				while (1)
				{
					if (pInfo->NextEntryOffset == 0) 
					{
						break;
					}

					if (pInfo->UniqueProcessId == (HANDLE)m_PID)
					{

						for (DWORD i = 0; i < pInfo->NumberOfThreads; i++)
						{

							if (!Apc_Call((DWORD)pInfo->Threads[i].ClientId.UniqueThread,pTeb64,pTeb32,m_bWow64Process,pCallAddress))
							{
								bRet = TRUE;
								break;
							}
						}
						break;
					}

					pInfo = (PSYSTEM_PROCESS_INFO)(((PUCHAR)pInfo) + pInfo->NextEntryOffset);
				}


			}

		}
	}

	if (pTemp)
	{
		free(pTemp);
		pTemp = NULL;
	}
	if (pTeb64)
	{
		free(pTeb64);
		pTeb64 = NULL;
	}
	if (pTeb32)
	{
		free(pTeb32);
		pTeb32 = NULL;
	}
	return bRet;
}

BOOL injector::CreateThreadCall_Rip(PVOID pCallAddress)
{
	return CreateRemoteThread_(m_hProcess, pCallAddress);
}
BOOL injector::CreateThreadCall_Eip(PVOID pCallAddress)
{

	return CreateRemoteThread_(m_hProcess, pCallAddress);
}


BOOL injector::Apc_Call(DWORD nThreadId, PVOID ppTeb64, PVOID ppTeb32, BOOL isWow64, PVOID pCallAddress)
{
	BOOL bRet = FALSE;
	thread_operation dwThread(THREAD_ALL_ACCESS, nThreadId, isWow64);

	HANDLE hThread = dwThread.OpenThread();

	PVOID pTebBaseAddress64 = NULL;
	PVOID pTebBaseAddress32 = NULL;

	PTEB64 pTeb64 = (PTEB64)ppTeb64;
	PTEB32 pTeb32 = (PTEB32)ppTeb32;

	RtlSecureZeroMemory(pTeb64, sizeof(TEB64));
	RtlSecureZeroMemory(ppTeb32, sizeof(TEB32));

	pTebBaseAddress64 = dwThread.GetThreadTebBaseAddress64();

	SIZE_T n = 0;
	if (pTebBaseAddress64)
	{
		if (ReadProcessMemory_(m_hProcess, pTebBaseAddress64, pTeb64, sizeof(TEB64), &n))
		{
			if ((pTeb64->Win32ThreadInfo != 0))
			{
				return TRUE;

			}

			if (isWow64)
			{
				pTebBaseAddress32 = (PVOID)((ULONG_PTR)pTebBaseAddress64 + 0x2000);
				if (ReadProcessMemory_(m_hProcess, pTebBaseAddress32, pTeb32, sizeof(TEB32), &n))
				{
					if (pTeb32->ActivationContextStackPointer == 0)
					{
						return TRUE;
					}

					if (pTeb32->ThreadLocalStoragePointer == 0)
					{
						return TRUE;
					}

				}

			}
			else
			{
				if (pTeb64->ActivationContextStackPointer == 0)
				{

					return TRUE;
				}

				if (pTeb64->ThreadLocalStoragePointer == 0)
				{

					return TRUE;
				}
			}


			insert_apc_to_thread(hThread, pCallAddress);
		}



	}
	return bRet;
}

BOOL injector::insert_apc_to_thread(HANDLE hThread, PVOID pCallAddress)
{
	BOOL bRet = FALSE;

	bRet = QueueUserAPC_((PAPCFUNC)(pCallAddress), hThread, NULL);


	return bRet;
}


PVOID injector::Get_peb_hook_Call_Shellcode64(ULONG64 nJmpAddess, PVOID pCallAddress,PVOID pold_tab_ptr, PVOID* pShellcodeAddress,  PVOID* pNew_Tab_ptr)
{
	if (!pCallAddress || !nJmpAddess)return NULL;
	PVOID pAllocateAddress = NULL;

	UCHAR code[] =
	{
	0x50,//push        rax
	0x53 ,//push        rbx 
	0x51 ,// push        rcx 
	0x52 ,//push        rdx
	0x55 ,//push        rbp 
	0x54 ,//push        rsp 
	0x56 ,// push        rsi 
	0x57 ,//push        rdi
	0x41 ,0x50 ,//push        r8 
	0x41 ,0x51 ,// push        r9 
	0x41 ,0x52 ,//push        r10 
	0x41 ,0x53 ,// push        r11 
	0x41 ,0x54 ,
	0x41 ,0x55 ,
	0x41 ,0x56 ,
	0x41 ,0x57 ,
	0x9c ,
	0x48 ,0x83 ,0xec ,0x30 ,
	0xe8,0x24 ,0xfd ,0xff ,0xff , //+
	0x48 ,0x83 ,0xc4 ,0x30 ,
	0x9d ,0x41 ,0x5f ,0x41 ,0x5e ,0x41 ,0x5d ,0x41 ,0x5c ,0x41 ,0x5b ,0x41 ,0x5a ,0x41 ,0x59 ,0x41 ,0x58 ,0x5f ,0x5e ,0x5c ,0x5d ,0x5a
	,0x59 ,0x5b ,0x58 ,
	0xff,0x25,0,0,0,0, // jmp dword [xxxxxxxxx]
	0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90  // jmpAddress  offset +0x3DB
	};

	PVOID pTemp = NULL;
	SIZE_T nSize = 0;
	SIZE_T n = 0;
	PVOID pOffset = NULL;
	PVOID pOffset2 = NULL;

	//修复code代码
	*(PULONG_PTR)((ULONG_PTR)code + 0x45) = nJmpAddess;

	nSize = sizeof(call_rip_shellcode_64::payload) + sizeof(code) + sizeof(ULONG64) * 128;
	pTemp = malloc(nSize);
	if (pTemp)
	{
		RtlSecureZeroMemory(pTemp, nSize);

		//拷贝 shellcode
		RtlCopyMemory(pTemp, call_rip_shellcode_64::payload, sizeof(call_rip_shellcode_64::payload));

		pOffset = (PVOID)((ULONG_PTR)pTemp + sizeof(call_rip_shellcode_64::payload));
		//拷贝code
		RtlCopyMemory(pOffset, code, sizeof(code));
		pOffset2 = pOffset;

		pOffset = (PVOID)((ULONG_PTR)pTemp + sizeof(call_rip_shellcode_64::payload) + sizeof(code));

		RtlCopyMemory(pOffset, pold_tab_ptr, sizeof(ULONG64) * 128);

		pAllocateAddress = VirtualAllocExT_(m_hProcess, NULL, nSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (pAllocateAddress)
		{
			//修复shellcode
			*(PULONG_PTR)((ULONG_PTR)pTemp + call_rip_shellcode_64::rva::pfnFunc) = (ULONG_PTR)pCallAddress;

			//修复E8
			*(PULONG)((ULONG_PTR)pOffset2 + 30) = ((ULONG_PTR)pAllocateAddress + call_rip_shellcode_64::rva::start) - ((ULONG_PTR)pAllocateAddress + sizeof(call_rip_shellcode_64::payload) + 34);


			ULONG64* pTempTab = (ULONG64*)pOffset;
			pTempTab[2] = (ULONG64)((ULONG_PTR)pAllocateAddress + sizeof(call_rip_shellcode_64::payload));

			if (!WriteProcessMemory_(m_hProcess, pAllocateAddress, pTemp, nSize, &n))
			{
				VirtualFreeEx_(m_hProcess, pAllocateAddress, 0, MEM_RELEASE);
				pAllocateAddress = NULL;
			}
			else 
			{
				*pShellcodeAddress = (PVOID)(((ULONG_PTR)pAllocateAddress + sizeof(call_rip_shellcode_64::payload)));
				*pNew_Tab_ptr = (PVOID)(((ULONG_PTR)pAllocateAddress + sizeof(call_rip_shellcode_64::payload) + sizeof(code)));
			}
		}


	}



	if (pTemp)
	{
		free(pTemp);
		pTemp = NULL;
	}

	return pAllocateAddress;
}

BOOL injector::Hide_Memory()
{
	PVOID pTemp = NULL;
	pTemp = malloc(sizeof(hide_memory_shellcode::payload));
	RtlSecureZeroMemory(pTemp, sizeof(hide_memory_shellcode::payload));

	RtlCopyMemory(pTemp, hide_memory_shellcode::payload, sizeof(hide_memory_shellcode::payload));

	*(PULONG_PTR)((ULONG_PTR)pTemp + hide_memory_shellcode::rva::shellcodeAddr) = m_hInjectDllBase;//000B6000
	*(PULONG_PTR)((ULONG_PTR)pTemp + hide_memory_shellcode::rva::shellcodeSize) = 0x00B4000;

	PVOID pAllcoateAddress = NULL;
	pAllcoateAddress = VirtualAllocExT_(m_hProcess, NULL, sizeof(hide_memory_shellcode::payload), MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	if (pAllcoateAddress)
	{
		SIZE_T n = 0;
		if (WriteProcessMemory_(m_hProcess, pAllcoateAddress, pTemp, sizeof(hide_memory_shellcode::payload), &n))
		{
			DWORD a = 0;

			BOOL b = VirtualProtectEx(m_hProcess, (PVOID)m_hInjectDllBase, 0x4000, PAGE_NOACCESS, &a);
			int c = 0;
		}
	}

	return FALSE;
}


BOOL injector::peb_UserSharedInfoPtrCall_Rip(PVOID pCallAddress)
{
	BOOL bRet = FALSE;
	PVOID pAllcoateAddress = NULL;
	PVOID pNew_tab = NULL;
	char* dispatch_table_ptr = NULL;
	char* dispatch_table = NULL;
	PVOID pShellcodeAddress = NULL;

	SIZE_T n = 0;

	PROCESS_BASIC_INFORMATION pbi = { 0 };
	if (!NT_SUCCESS(NtQueryInformationProcess(m_hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL)))
		return bRet;

	char* peb = (char*)(pbi.PebBaseAddress);
	dispatch_table_ptr = peb + 0x58;//	/*0x058*/         UINT64       UserSharedInfoPtr;
	dispatch_table = nullptr;
	if (ReadProcessMemory_(m_hProcess, dispatch_table_ptr, &dispatch_table, 8, &n) || !dispatch_table)
	{
		char* tab[128] = { 0 };
		if (ReadProcessMemory_(m_hProcess, dispatch_table, tab, sizeof(tab), &n))
		{

			pAllcoateAddress = Get_peb_hook_Call_Shellcode64((ULONG64)tab[2],pCallAddress ,&tab, &pShellcodeAddress, &pNew_tab);

			int a = 0;
			if (pAllcoateAddress && pNew_tab)
			{
				//更改RIP
				bRet = WriteProcessMemory_(m_hProcess, dispatch_table_ptr, &pNew_tab, sizeof(PVOID), &n);
			}

		}
	}

	if (pAllcoateAddress && pShellcodeAddress)
	{
		bRet = FALSE;
		shellcode_state_64 main_data = { 0 };
		SIZE_T bRetLength = 0;
		int nCnt = 100;
		do
		{
			if (ReadProcessMemory_(m_hProcess, pAllcoateAddress, &main_data, sizeof(shellcode_state_64), &bRetLength))
			{
				if ((main_data.nAlreadRun == CALL_COMPLETE))
				{
					bRet = TRUE;

					if (WriteProcessMemory_(m_hProcess, dispatch_table_ptr, &dispatch_table, sizeof(PVOID), &n)) 
					{
						Sleep(200);
						if (VirtualFreeEx_(m_hProcess, pAllcoateAddress, 0, MEM_RELEASE))
						{

						}
					}

					break;
				}

			}
			else
			{

				bRet = TRUE;
				break;
			}

			Sleep(100);
			nCnt--;

			if (nCnt == 0 || nCnt < 0)
			{


				break;
			}

		} while (!bRet);
	}


	return bRet;
}

#pragma once
#include <windows.h>


#define CALL_COMPLETE   0xC0371E7E
#define CALL_COMPLETE_SUCCESS   0xC0371E80
#define clear_peHeaders 1
#define protect_peHeaders 0x2
#define EXECUTE_TLS 0x4

#define PAGE_EXECUTE_FLAGS \
    (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

typedef struct _dll_info_
{
	ULONG bOnce = 0;   //不要管
	ULONG ntStatus = 0;  //ldrLoadDll 返回的结果
	ULONG nAlreadRun = 0;
	ULONG dllBase = 0;
	wchar_t wszDllPath[100];
}dll_info_32, * pdll_info_32;

typedef struct _shellcode_state_64_
{
	ULONG ntStatus;
	ULONG nAlreadRun;
	ULONG_PTR dllBase;;
}shellcode_state_64;

class injector
{
public:
	injector(ULONG PID,HANDLE hProcess,bool bNormalInject,WCHAR* pstrDllPath,BOOL bWow64Process/*是不是32位的*/,DWORD nFlags);
	~injector();


	BOOL inject64(int nType);
	BOOL inject32(int nType);
	BOOL CallRip(int nType,PVOID pCallAddress);
	BOOL CallEip(int nType,PVOID pCallAddress);


	ULONG64 GetInjectDllBase();
private:
	BOOL CreateThreadToInject();
	//注入函数
	BOOL CreateThreadMapInjectDll64();
	BOOL CreateThreadNormalInjectDll64();
	BOOL CreateThreadNormalInjectDll32();

	BOOL user_windows_messages_load_dll_64();
	BOOL UseThreadContextLoadDll_64();
	BOOL UseThreadContextLoadDll_32();
	BOOL Apc_inject(DWORD nThreadId,PVOID pTeb64,PVOID ppTeb32,BOOL isWow64);
	BOOL use_apc_inject_64();
	BOOL insert_apc_to_thread(HANDLE hThread);
private:
	//call 函数
	BOOL peb_UserSharedInfoPtrCall_Rip(PVOID pCallAddress);

	BOOL CreateThreadCall_Rip(PVOID pCallAddress);
	BOOL CreateThreadCall_Eip(PVOID pCallAddress);
	BOOL UserThreadContextCall_eip(DWORD pCallAddress);
	BOOL UseThreadContextCall_Rip(PVOID pCallAddress);
	BOOL user_windows_messages_call_rip_64(PVOID pCallAddress);
	BOOL UserApcCall_Rip(PVOID pCallAddress);
	BOOL Apc_Call(DWORD nThreadId, PVOID ppTeb64, PVOID ppTeb32, BOOL isWow64, PVOID pCallAddress);
	BOOL insert_apc_to_thread(HANDLE hThread, PVOID pCallAddress);

private:
	
	DWORD m_nFlags = 0;
	ULONG m_PID = 0;
	HANDLE m_hProcess = 0; 
	bool m_bNormalInject = true; //是内存注入还是正常注入
	WCHAR* m_pszDllPath = NULL;
	BOOL m_bWow64Process = FALSE;
	ULONG64 m_hInjectDllBase = 0;

	BOOL m_bAlreadApcInject = FALSE; //标志APC已经 注入进去了
	PVOID m_pApc_allcoate_memory_base = NULL; //保存APC 申请的地址
	PVOID m_Apc_allocoate_map_shellcode_pos = NULL;
	HANDLE m_hApc_ThreadHanle = NULL; //清理 APC内存的线程句柄
private:

	static DWORD apc_clear_work_thread(PVOID pArg);

	BOOL user_windows_messages_load_normal_dll_64();
	BOOL user_windows_messages_load_map_dll_64();
	BOOL NormalInject_UseThreadContextCall_64();
	BOOL MapInject_UseThreadContextCall_64();


	DWORD GetMainThread(ULONG dwPid);
	PVOID Get_normal_code_64();
	PVOID Get_normal_code_32();
	PVOID Get_thread_context_code_call_eip_32(DWORD dwJmpAddress, DWORD pCallAddress);
	PVOID Get_thread_context_code_32(DWORD dwJmpAddress,PVOID *pCallAddress);
	PVOID Get_call_rip_code_64(PVOID pCallAddress);
	PVOID Get_map_code_64(PVOID* pShellcodeAddress, DWORD nFlags = 0);
	PVOID GetConextThreadNormalInjectShellcode64(ULONG64 nJmpAddess,PVOID* pCallAddress);
	PVOID GetConextThreadM_CALL_Shellcode64(ULONG64 nJmpAddess, PVOID pCallAddress, PVOID* pShellcodeAddress);
	//参数一:
	//参数二:传回 shellcode 的执行地址 也就是 RIP修改的地方
	//参数三:
	//参数四:传回 shellcode的位置在哪里
	PVOID GetConextThreadMemoryInjectShellcode64(ULONG64 nJmpAddess, PVOID* pCallAddress,DWORD nFlags,PVOID* pShellcodeAddressPos);
	UINT AlignSize(UINT nSize, UINT nAlign);
	PVOID file_to_image_buffer(LPCWSTR szFullPath, DWORD& pImageSize);
	BOOL ImageFile(PVOID FileBuffer, PVOID* ImageModuleBase, DWORD& ImageSize);


private:
	BOOL m_bHaveGuiThread = FALSE;  //标志 该进程是否有窗口
	static BOOL CALLBACK EnumWindowFunc(HWND hwnd, LPARAM param);
	BOOL peb_UserSharedInfoPtr_inect64();
	BOOL hook_peb_UserSharedInfoPtr_normal_inject64();
	BOOL hook_peb_UserSharedInfoPtr_map_inject64();
	PVOID get_peb_inject_normal_shellcode64(ULONG64 nJmpAddess, PVOID pold_tab_ptr,  PVOID* pCallAddress, PVOID* pNew_Tab_ptr);
	PVOID get_peb_inject_map_shellcode64(ULONG64 nJmpAddess,PVOID pold_tab_ptr,  PVOID* pCallAddress, PVOID* pNew_Tab_ptr);
	PVOID Get_peb_hook_Call_Shellcode64(ULONG64 nJmpAddess, PVOID pCallAddress, PVOID pold_tab_ptr, PVOID* pShellcodeAddress, PVOID* pNew_Tab_ptr);

public:
	BOOL Hide_Memory();
};






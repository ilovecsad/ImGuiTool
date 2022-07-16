#pragma once
#include <windows.h>
#include "imgui/imgui_window.h"
#include <string>
#include <vector>
#include <TlHelp32.h>
#include <map>
#include "struct.h"

using namespace std;
#define PrintErro(text) MessageBoxA((HWND)0, text, "Erro", MB_OK | MB_TOPMOST)
typedef LRESULT(WINAPI* t_WndProc)(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);



class DearWife
{
public:
	DearWife();
	~DearWife();
	bool create();
	void end();

	HANDLE m_hImGuiThreadHanle = 0;
private:
	HWND m_hwnd = 0;
	bool m_done = false;
	int m_show = 0;
	bool m_bBeginWork = false;
	HANDLE m_hThreadHanleForWork = 0;
	ID3D11ShaderResourceView* m_pDwmCaptureTextureView = NULL;
	vector<PROCESS_INF> m_vectorProcessInfo;
	bool m_bCallDllFunc = false;
	char szDllPath[MAX_PATH] = { 0 };    //保存DLL路径
	wchar_t wszDllPath[MAX_PATH] = { 0 };    //保存DLL路径
	bool bInjectType = true;            //是正常注入 还是内存注入
	bool m_bClearPEHeaders = false;       //是否清楚 PE头信息
	bool m_bChangeProtect = TRUE;
	bool m_EXECUTE_TLS = false;
	bool m_bSelf_open_handle = false;




	ULONG_PTR m_dllBase;


	BOOL m_bWowProcess = FALSE; //是什么位的 进程
	HANDLE m_hProcess = 0; //打开的句柄



private:
	HANDLE GetOpenHanleByInjectType(ULONG dwPid,int nType, PVOID pObject);
	static DWORD wife(PVOID pArg);
	static DWORD ThreadWork(PVOID pArg);
	static LRESULT WINAPI MyNewWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
	string wstringToString(const wstring& wstr);
	wstring stringToWstring(const string& str);
	void createThreadForWork();
	ID3D11ShaderResourceView* DX11LoadTextureImageFromFile(ID3D11Device* pD3dDevice, const wchar_t* lpszFilePath);

	ID3D11ShaderResourceView* DX11LoadTextureImageFromMemroy(ID3D11Device* pD3dDevice, PVOID pSrcData,DWORD nSize);
	ID3D11Device* GetD3dDevice();

	BOOL EnumProcess(vector<PROCESS_INF>& ProcessInfo);
	HANDLE Get_VM_READ_WRITE_OPERATION_Handle(PVOID pObject);
	bool Inject(ULONG pid,int nType,HANDLE hProcess,BOOL bWowProcess);//在这里做真正得工作

private:
	int dll_export_item_current_idx = 0;
	vector<dllexportFun> m_vector_dll_export_fun;
	BOOL ImageFile(PVOID FileBuffer, PVOID* ImageModuleBase, DWORD& ImageSize);
	void get_dll_export_func(vector<dllexportFun>& m_dll_export_fun);
	UINT AlignSize(UINT nSize, UINT nAlign);
	PVOID file_to_image_buffer(LPCWSTR szFullPath, DWORD& pImageSize);
	void ProcessInfoShowInImgui();
	void InjectWayShowInImgui(ULONG pid, string szInjectProcessName,PVOID pObject);
	void ShowRightImgui(int selected);
	void EnumDllExportFunc();

	void EnableDebugPriv();



private://进程模块功能 集合

	void addExportFunToVector(PVOID pFileBuffer,vector<symbol_info>& m_vectorsymbolInfo,string belong_to_module);

	void ImGuiShowProcessModule(PROCESS_INF dwInfo);
	vector<module_info> m_vectorModuleInfo; //保存当前进程的所有模块信息

	void ShowRight_ProcessModule(PROCESS_INF dwProcessInfo,module_info dwInfo);

	vector<symbol_info> m_vectorsymbolInfo;

	vector<loadDll> m_loadDll; //这个是 FixImportTable 加载的DLL 我们要把他卸载


	map<ULONG_PTR,INLINE_HOOK_INFO> m_MapInlineHook;
	map<ULONG_PTR,INLINE_HOOK_INFO> m_MapIATHook;
	//记录模块信息
	record_module m_recordModuleInfo;
	BOOL FixBaseRelocTable(PVOID pPEBuffer, ULONG_PTR dwLoadMemoryAddress);
	BOOL FixImportTable(PVOID pPEBuffer, ULONG_PTR dwLoadMemoryAddress);
	BOOL FixBaseRelocTable32(PVOID pPEBuffer, ULONG_PTR dwLoadMemoryAddress);

private://句柄界面 集合


	vector<handle_info>m_vectorHanle;
	void ImGuiShowProcessHandles(PROCESS_INF dwInfo,vector<handle_info>& vectorHanle);
	void EnumHanleInfo(PROCESS_INF* pInfo,vector<handle_info>& vectorHanle);
};




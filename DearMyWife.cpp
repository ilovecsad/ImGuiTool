#include "DearMyWife.h"
#include <Shlwapi.h>
#include "resource.h"
#include "GetResource.h"
#include "Log.h"
#include "importfun.h"
#include "CommonStruct.h"
#include "injector.h"
#include "tls_protect.h"
#include "process.h"
#include "LoadSymbol.h"
#include <algorithm>
#define  DWORDX ULONG_PTR
#define windows_Width 750 
#define windows_Height 600

static HMENU m_pPopMenu = NULL;
#define MY_MESSAGE WM_USER+0x100
#define  ITEM_MENU_REPLY  40001
static t_WndProc orgWndProc = NULL;

char szBuffer[MAX_PATH * 2];

user_info g_data = { 0 };





DearWife::DearWife()
{
}

DearWife::~DearWife()
{


	if (m_bSelf_open_handle)
	{
		CloseHandle(m_hProcess);
		m_hProcess = 0;

	}


	if (orgWndProc)
	{
		SetWindowLongPtrW(m_hwnd, GWLP_WNDPROC,(LONG_PTR)orgWndProc);
		orgWndProc = NULL;
	}

}

LRESULT WINAPI DearWife::MyNewWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{

	switch (msg)
	{
	case MY_MESSAGE:
	{
		break;
	}
	

	default:
		break;
	}


	return orgWndProc(hWnd, msg, wParam, lParam);
}

DWORD DearWife::wife(PVOID pArg)
{
	DearWife* pThis = (DearWife*)pArg;
	if (!imgui_window::init(windows_Width, windows_Height)) {
		return false;
	}

	pThis->m_hwnd = imgui_window::GetMainHwnd();


	orgWndProc = (t_WndProc)SetWindowLongPtrW(pThis->m_hwnd, GWLP_WNDPROC,(LONG_PTR)pThis->MyNewWndProc);

	while (!pThis->m_done) 
	{
		MSG msg;
		while (::PeekMessage(&msg, NULL, 0U, 0U, PM_REMOVE)) 
		{
			::TranslateMessage(&msg); //���������Ϣ
			::DispatchMessage(&msg);  //���ĺ��������������ڵ���Ϣ������
			if (msg.message == WM_QUIT)
				pThis->m_done = true;
		}
		if (pThis->m_done)
			break;

		if (imgui_window::begin())
		{

			if (pThis->m_show)
			{
				ImGui::SetNextWindowPos({ 0, 0 }, ImGuiCond_Always);
				ImGui::SetNextWindowSize(imgui_window::GetGuiWindowSize(), ImGuiCond_Always);

				if (pThis->m_pDwmCaptureTextureView) {

					//���ñ���
					ImGui::GetBackgroundDrawList()->AddImage(pThis->m_pDwmCaptureTextureView, ImVec2{ 0,0 }, imgui_window::GetGuiWindowSize());
				}

				//�ޱ��������޷�����
				ImGui::Begin("BackGround", NULL,
					ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoTitleBar |
					ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | /*ImGuiWindowFlags_NoBackground |*/
					ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollbar |
					ImGuiWindowFlags_NoSavedSettings);

				/*
				if (pThis->m_pDwmCaptureTextureView)
				{
					ImGui::Image(pThis->m_pDwmCaptureTextureView,
					imgui_window::GetGuiWindowSize(),
					ImVec2(0, 0),
					ImVec2(1, 1),
					ImVec4(1.0f, 1.0f, 1.0f, 1.0f),
					ImVec4(0.0f, 0.0f, 0.0f, 0.0f));
				}
				*/
				//��ʾ���̵���Ϣ
				pThis->ProcessInfoShowInImgui();






				ImGui::End();

			}
			else 
			{

				ImGui::SetNextWindowPos({ 0, 0 }, ImGuiCond_Always);
				ImGui::SetNextWindowSize(imgui_window::GetGuiWindowSize(), ImGuiCond_Always);
				ImGui::Begin("Init",
					0,
					ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize |
					ImGuiWindowFlags_AlwaysAutoResize);

				if (!pThis->m_bBeginWork) {
					if (ImGui::Button(u8"��ʼ����ť"))
					{
						//�����̸߳ɻ�
						pThis->m_bBeginWork = true;
						pThis->createThreadForWork();

						//ZwSetInformationThread_(GetCurrentThread(), ThreadHideFromDebugger, 0, 0);
						

					}
				}



				if (pThis->m_bBeginWork && !pThis->m_show)
				{
					static size_t count = 0;
					count++;
					const char* cursor = 0;

					if (count % 3 == 0)
						cursor = "/";
					else if (count % 3 == 1)
						cursor = "-";
					else
						cursor = "\\";


					ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), u8"���ڳ�ʼ����ȴ�[ %s ]", cursor);


				}




				ImGui::End();
			}
			imgui_window::end();
		}

	}


	return 0;
}


DWORD DearWife::ThreadWork(PVOID pArg)
{
	DearWife* pThis = (DearWife*)pArg;



	pThis->EnableDebugPriv();
	pThis->EnumProcess(pThis->m_vectorProcessInfo);


	//GetResource dw(NULL, MAKEINTRESOURCE(IDB_PNG1), L"PNG");

	//pThis->m_pDwmCaptureTextureView = pThis->DX11LoadTextureImageFromMemroy(pThis->GetD3dDevice(), dw.GetBuffer(), dw.GetBufferSize());

	CloseHandle(pThis->m_hThreadHanleForWork);
	pThis->m_hThreadHanleForWork = 0;
	//�̹߳����Ѿ������� ��ʼ��ʾ��Ϣ
	InterlockedCompareExchange((long*)&pThis->m_show, 1, 0);

	return 0;
}

ID3D11Device* DearWife::GetD3dDevice()
{
	return imgui_window::GetD3D11Device();
}
/*
ID3D11ShaderResourceView* DearWife::DX11LoadTextureImageFromFile(ID3D11Device* pD3dDevice, const wchar_t* lpszFilePath)
{
	if (!PathFileExistsW(lpszFilePath))
	{
		return NULL;
	}
	ID3D11Texture2D* pTexture2D = NULL;
	D3D11_TEXTURE2D_DESC dec = { 0 };

	HRESULT result;
	D3DX11_IMAGE_LOAD_INFO loadInfo;
	ZeroMemory(&loadInfo, sizeof(D3DX11_IMAGE_LOAD_INFO));
	loadInfo.BindFlags = D3D11_BIND_SHADER_RESOURCE;
	loadInfo.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
	loadInfo.MipLevels = D3DX11_DEFAULT; //��ʱ���������mipmaps�㡣 
	loadInfo.MipFilter = D3DX11_FILTER_LINEAR;
	result = D3DX11CreateTextureFromFileW(pD3dDevice, lpszFilePath, &loadInfo, NULL, (ID3D11Resource**)(&pTexture2D), NULL);

	pTexture2D->GetDesc(&dec);

	if (result != S_OK)
	{
		return NULL;
	}

	ID3D11ShaderResourceView* pFontTextureView = NULL;

	// Create texture view
	D3D11_SHADER_RESOURCE_VIEW_DESC srvDesc;
	ZeroMemory(&srvDesc, sizeof(srvDesc));
	srvDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
	srvDesc.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D;
	srvDesc.Texture2D.MipLevels = dec.MipLevels;
	srvDesc.Texture2D.MostDetailedMip = 0;
	pD3dDevice->CreateShaderResourceView(pTexture2D, &srvDesc, &pFontTextureView);
	pTexture2D->Release();

	return pFontTextureView;
}
*/
/*
ID3D11ShaderResourceView* DearWife::DX11LoadTextureImageFromMemroy(ID3D11Device * pD3dDevice, PVOID pSrcData,DWORD nSize)
{
	if (!pSrcData || !pD3dDevice || !nSize) return NULL;
	ID3D11Texture2D* pTexture2D = NULL;
	D3D11_TEXTURE2D_DESC dec = { 0 };

	HRESULT result;
	D3DX11_IMAGE_LOAD_INFO loadInfo;
	ZeroMemory(&loadInfo, sizeof(D3DX11_IMAGE_LOAD_INFO));
	loadInfo.BindFlags = D3D11_BIND_SHADER_RESOURCE;
	loadInfo.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
	loadInfo.MipLevels = D3DX11_DEFAULT; //��ʱ���������mipmaps�㡣 
	loadInfo.MipFilter = D3DX11_FILTER_LINEAR;
	result = D3DX11CreateTextureFromMemory(pD3dDevice, pSrcData, nSize, NULL, NULL,(ID3D11Resource**)(&pTexture2D), NULL);

	pTexture2D->GetDesc(&dec);

	if (result != S_OK)
	{
		return NULL;
	}

	ID3D11ShaderResourceView* pFontTextureView = NULL;

	// Create texture view
	D3D11_SHADER_RESOURCE_VIEW_DESC srvDesc;
	ZeroMemory(&srvDesc, sizeof(srvDesc));
	srvDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
	srvDesc.ViewDimension = D3D11_SRV_DIMENSION_TEXTURE2D;
	srvDesc.Texture2D.MipLevels = dec.MipLevels;
	srvDesc.Texture2D.MostDetailedMip = 0;
	pD3dDevice->CreateShaderResourceView(pTexture2D, &srvDesc, &pFontTextureView);
	pTexture2D->Release();

	return pFontTextureView;
}
*/
void DearWife::createThreadForWork()
{
	if (!m_hThreadHanleForWork)
	{

		CreateRemoteThread_(GetCurrentProcess(), ThreadWork, this, &m_hThreadHanleForWork);
	}
}

bool DearWife::create()
{
	if (!m_hImGuiThreadHanle)
	{

		CreateRemoteThread_(GetCurrentProcess(), wife, this, &m_hImGuiThreadHanle);
	}
	return  m_hImGuiThreadHanle ? TRUE : FALSE;
}

void DearWife::end()
{
	if (m_hImGuiThreadHanle) 
	{
		m_done = true;
		WaitForSingleObject(m_hImGuiThreadHanle,INFINITE);
		m_hImGuiThreadHanle = 0;
	}
	
}







BOOL DearWife::EnumProcess(vector<PROCESS_INF>& ProcessInfo)
{

	PROCESSENTRY32 pe32 = { 0 };
	PROCESS_INF info = { 0 };
	pe32.dwSize = sizeof(PROCESSENTRY32);

	// ��ȡȫ�����̵Ŀ���
	HANDLE hProcessSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hProcessSnap)
	{
		return FALSE;
	}

	ProcessInfo.clear();
	// ��ȡ�����е�һ�����̵���Ϣ
	BOOL bRet = ::Process32First(hProcessSnap, &pe32);
	CHAR szFullPath[MAX_PATH];
	DWORD nSize = 0;
	while (bRet)
	{
		info = { 0 };
		nSize = sizeof(szFullPath);

		info.hOpenhandle = OpenProcess_(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe32.th32ProcessID);
		if (info.hOpenhandle)
		{
			if (QueryFullProcessImageNameA(info.hOpenhandle, 0, szFullPath, &nSize))
			{
				info.szFullPath = szFullPath;
			}
		}

		info.pid = pe32.th32ProcessID;
		info.szPath = wstringToString(pe32.szExeFile);
		transform(info.szPath.begin(), info.szPath.end(), info.szPath.begin(),::tolower);
		ProcessInfo.push_back(info);

		// ��ȡ��������һ����Ϣ
		bRet = ::Process32Next(hProcessSnap, &pe32);
	}
	// �رվ��
	::CloseHandle(hProcessSnap);

	//��ȡ ����Object�ṹ

	SYSTEM_HANDLE_INFORMATION dwInfo = { 0 };
	ULONG nRetLength = 0;
	NTSTATUS Status = 0;

	Status = ZwQuerySystemInformation_(16, &dwInfo, sizeof(SYSTEM_HANDLE_INFORMATION), &nRetLength);
	if (Status == 0xC0000004L && nRetLength)
	{
		PSYSTEM_HANDLE_INFORMATION pHandles = NULL;

		nRetLength += 0x1000;
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

						vector<PROCESS_INF>::iterator it = m_vectorProcessInfo.begin();

						for (it; it != m_vectorProcessInfo.end(); it++)
						{
							if (it->hOpenhandle) 
							{
								if (it->hOpenhandle == (HANDLE)pHandles->Handles[i].HandleValue)
								{
									it->pObject = pHandles->Handles[i].Object;
									if (CloseHandle(it->hOpenhandle)) {
										it->hOpenhandle = 0;
									}
									break;
								}
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



	return TRUE;
}

void DearWife::ProcessInfoShowInImgui()
{
	if (ImGui::Button(u8"ˢ�½���"))
	{
		m_vectorProcessInfo.clear();
		EnumProcess(m_vectorProcessInfo);
	}
	static ImGuiTextFilter filter; //1.��������
	static int selected = 0;
	{
		ImGui::BeginChild("left pane", ImVec2(200, 0), true);
		filter.Draw(u8"����",130);//2.���������

		vector<PROCESS_INF>::iterator it = m_vectorProcessInfo.begin();
		char label[128];
		 int i = 0;
		for (; it != m_vectorProcessInfo.end(); it++)
		{
			sprintf_s(label, "%d:%s",it->pid,it->szPath.c_str());
			if (filter.PassFilter(label))
			{
				if (ImGui::Selectable(label, selected == i)) {
					selected = i;
				}
			}
			i++;
		}
		ImGui::EndChild();
	}

	//��ʾ�ұ� ����
	ImGui::SameLine();
	ShowRightImgui(selected);

	
}

void DearWife::get_dll_export_func(vector<dllexportFun>& m_dll_export_fun)
{
	m_vector_dll_export_fun.clear();
	PVOID BaseAddress = NULL;
	DWORD dwImageSize = 0;
	BaseAddress = file_to_image_buffer(wszDllPath, dwImageSize);


	PIMAGE_DOS_HEADER       pDosHdr = (PIMAGE_DOS_HEADER)BaseAddress;
	PIMAGE_NT_HEADERS32     pNtHdr32 = NULL;
	PIMAGE_NT_HEADERS64     pNtHdr64 = NULL;
	PIMAGE_EXPORT_DIRECTORY pExport = NULL;
	ULONG                   expSize = 0;
	ULONG_PTR               pAddress = 0;
	PUSHORT                 pAddressOfOrds;
	PULONG                  pAddressOfNames;
	PULONG                  pAddressOfFuncs;
	ULONG                   i;

	if (BaseAddress == NULL)
		return;

	/// Not a PE file
	if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return;

	pNtHdr32 = (PIMAGE_NT_HEADERS32)((PUCHAR)BaseAddress + pDosHdr->e_lfanew);
	pNtHdr64 = (PIMAGE_NT_HEADERS64)((PUCHAR)BaseAddress + pDosHdr->e_lfanew);

	// Not a PE file
	if (pNtHdr32->Signature != IMAGE_NT_SIGNATURE)
		return ;

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

	pAddressOfOrds = (PUSHORT)(pExport->AddressOfNameOrdinals + (ULONG_PTR)BaseAddress);
	pAddressOfNames = (PULONG)(pExport->AddressOfNames + (ULONG_PTR)BaseAddress);
	pAddressOfFuncs = (PULONG)(pExport->AddressOfFunctions + (ULONG_PTR)BaseAddress);

	dllexportFun dwTemp = { 0 };
	for (i = 0; i < pExport->NumberOfFunctions; ++i) 
	{
		dwTemp = { 0 };

		dwTemp.fva = pAddressOfFuncs[pAddressOfOrds[i]];
		dwTemp.szFunName = (PCHAR)(pAddressOfNames[i] + (ULONG_PTR)BaseAddress);;

		m_dll_export_fun.push_back(dwTemp);

	}


	if (BaseAddress)
	{
		free(BaseAddress);
		BaseAddress = NULL;
	}

}

PVOID DearWife::file_to_image_buffer(LPCWSTR szFullPath, DWORD& pImageSize)
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
UINT DearWife::AlignSize(UINT nSize, UINT nAlign)
{
	return ((nSize + nAlign - 1) / nAlign * nAlign);
}

BOOL DearWife::ImageFile(PVOID FileBuffer, PVOID* ImageModuleBase, DWORD& ImageSize)
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

void DearWife::EnumHanleInfo(PROCESS_INF* pInfo,vector<handle_info>& vectorHanle)
{
	vectorHanle.clear();
	NTSTATUS Status = 0;
	SYSTEM_HANDLE_INFORMATION dwInfo = { 0 };
	ULONG nRetLength = 0;

	handle_info dwHanleInfo = { 0 };


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
					if (pInfo->pid == (DWORD)pHandles->Handles[i].ProcessId)
					{
						RtlSecureZeroMemory(&dwHanleInfo, sizeof(handle_info));
						vector<PROCESS_INF>::iterator it = m_vectorProcessInfo.begin();
						for (it; it != m_vectorProcessInfo.end(); ++it)
						{
							if (it->pObject == pHandles->Handles[i].Object)
							{
			
								dwHanleInfo.dwProcessPid = (DWORD)pHandles->Handles[i].ProcessId;
								dwHanleInfo.GrantedAccess = pHandles->Handles[i].GrantedAccess;
								dwHanleInfo.handleValue = (HANDLE)pHandles->Handles[i].HandleValue;
								dwHanleInfo.pObject = pHandles->Handles[i].Object;
								sprintf_s(dwHanleInfo.szProcessName, "(PID:%d)%s", it->pid, it->szPath.c_str());
						
								m_vectorHanle.push_back(dwHanleInfo);
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

}


namespace 
{
	enum HanleItemColumnID
	{
		HanleItemColumnID_handleValue,
		HanleItemColumnID_GrantedAccess,
		HanleItemColumnID_Action,
		HanleItemColumnID_szFullPath,
	};
	struct HanleItem
	{
		DWORD    handleValue;
		DWORD    GrantedAccess;
		DWORD    belong_to_pid;
		const char* szProcessName;

		static const ImGuiTableSortSpecs* s_current_sort_specs;

		static int __cdecl CompareWithSortSpecs(const void* lhs, const void* rhs)
		{
			const HanleItem* a = (const HanleItem*)lhs;
			const HanleItem* b = (const HanleItem*)rhs;
			for (int n = 0; n < s_current_sort_specs->SpecsCount; n++)
			{
				// Here we identify columns using the ColumnUserID value that we ourselves passed to TableSetupColumn()
				// We could also choose to identify columns based on their index (sort_spec->ColumnIndex), which is simpler!
				const ImGuiTableColumnSortSpecs* sort_spec = &s_current_sort_specs->Specs[n];
				int delta = 0;
				switch (sort_spec->ColumnUserID)
				{
				case HanleItemColumnID_handleValue:             delta = (a->handleValue - b->handleValue);                break;
				case HanleItemColumnID_GrantedAccess:          delta = (a->GrantedAccess - b->GrantedAccess);                break;
				case HanleItemColumnID_szFullPath:    delta = (strcmp(a->szProcessName, b->szProcessName));     break;
				default: IM_ASSERT(0); break;
				}
				if (delta > 0)
					return (sort_spec->SortDirection == ImGuiSortDirection_Ascending) ? +1 : -1;
				if (delta < 0)
					return (sort_spec->SortDirection == ImGuiSortDirection_Ascending) ? -1 : +1;
			}

			// qsort() is instable so always return a way to differenciate items.
			// Your own compare function may want to avoid fallback on implicit sort specs e.g. a Name compare if it wasn't already part of the sort specs.
			return (a->handleValue - b->handleValue);
		}
	};

	

const ImGuiTableSortSpecs* HanleItem::s_current_sort_specs = NULL;
}


void DearWife::ImGuiShowProcessHandles(PROCESS_INF dwInfo,vector<handle_info>& vectorHanle)
{
	ImGui::BeginGroup();
	static ImVector<HanleItem> items;
	if (ImGui::Button(u8"�������"))
	{
		EnumHanleInfo(&dwInfo,vectorHanle);
		items.Size = 0;
		if (vectorHanle.size() == 0)
		{
			MessageBoxW(m_hwnd, L"û�б������ý��̵Ĵ򿪵Ľ��̾��", L"��ʾ", 0);
		}
	}

	if (!vectorHanle.empty() && vectorHanle.size())
	{
		const float TEXT_BASE_HEIGHT = ImGui::GetTextLineHeightWithSpacing();
		// Create item list
		if (items.Size == 0)
		{
			items.resize(vectorHanle.size(), HanleItem());
			for (int n = 0; n < items.Size; n++)
			{
				HanleItem& item = items[n];
				item.handleValue =(DWORD)vectorHanle.at(n).handleValue;
				item.GrantedAccess = (DWORD)vectorHanle.at(n).GrantedAccess;
				item.szProcessName = vectorHanle.at(n).szProcessName;
				item.belong_to_pid = vectorHanle.at(n).dwProcessPid;
			}
		}
	
		// Options
		static ImGuiTableFlags flags =
			ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable | ImGuiTableFlags_Hideable | ImGuiTableFlags_Sortable | ImGuiTableFlags_SortMulti
			| ImGuiTableFlags_RowBg | ImGuiTableFlags_BordersOuter | ImGuiTableFlags_BordersV | ImGuiTableFlags_NoBordersInBody
			| ImGuiTableFlags_ScrollY;

		if (ImGui::BeginTable("table_sorting", 4, flags, ImVec2(0.0f, TEXT_BASE_HEIGHT * 15), 0.0f))
		{
			ImGui::TableSetupColumn(u8"���", ImGuiTableColumnFlags_DefaultSort | ImGuiTableColumnFlags_WidthFixed, 0.0f, HanleItemColumnID_handleValue);
			ImGui::TableSetupColumn(u8"Ȩ��", ImGuiTableColumnFlags_WidthFixed, 0.0f, HanleItemColumnID_GrantedAccess);
			ImGui::TableSetupColumn(u8"�鿴",   ImGuiTableColumnFlags_NoSort               | ImGuiTableColumnFlags_WidthFixed,   0.0f, HanleItemColumnID_Action);
			ImGui::TableSetupColumn(u8"·��", ImGuiTableColumnFlags_WidthFixed, 0.0f, HanleItemColumnID_szFullPath);
			ImGui::TableSetupScrollFreeze(0, 1); // Make row always visible
			ImGui::TableHeadersRow();


			// Sort our data if sort specs have been changed!
			if (ImGuiTableSortSpecs* sorts_specs = ImGui::TableGetSortSpecs())
				if (sorts_specs->SpecsDirty)
				{
					HanleItem::s_current_sort_specs = sorts_specs; // Store in variable accessible by the sort function.
					if (items.Size > 1)
						qsort(&items[0], (size_t)items.Size, sizeof(items[0]), HanleItem::CompareWithSortSpecs);
					HanleItem::s_current_sort_specs = NULL;
					sorts_specs->SpecsDirty = false;
				}

			// Demonstrate using clipper for large vertical lists
			ImGuiListClipper clipper;
			clipper.Begin(items.Size);
			while (clipper.Step())
				for (int row_n = clipper.DisplayStart; row_n < clipper.DisplayEnd; row_n++)
				{
					// Display a data item
					HanleItem* item = &items[row_n];

					if (item->belong_to_pid != dwInfo.pid) {
						break;
					}


					ImGui::PushID(item->handleValue);
					ImGui::TableNextRow();

					ImGui::TableNextColumn();
					ImGui::Text("0x%x", item->handleValue);
					ImGui::TableNextColumn();
					ImGui::Text("0x%x", item->GrantedAccess);

					ImGui::TableNextColumn();
					if (ImGui::Button(u8"��Ϣ"))
					{
						RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));

						sprintf_s(szBuffer, "PROCESS_TERMINATE:%d\nPROCESS_CREATE_THREAD:%d\nPROCESS_SET_SESSIONID:%d\nPROCESS_VM_OPERATION:%d\nPROCESS_VM_READ:%d\nPROCESS_VM_WRITE:%d\nPROCESS_DUP_HANDLE:%d\nPROCESS_CREATE_PROCESS:%d\nPROCESS_SET_QUOTA:%d\nPROCESS_SET_INFORMATION:%d\nPROCESS_QUERY_INFORMATION:%d\nPROCESS_SUSPEND_RESUME:%d\nPROCESS_QUERY_LIMITED_INFORMATION:%d\nPROCESS_SET_LIMITED_INFORMATION:%d\n",
							item->GrantedAccess & PROCESS_TERMINATE ? 1 : 0,
							item->GrantedAccess & PROCESS_CREATE_THREAD ? 1 : 0,
							item->GrantedAccess & PROCESS_SET_SESSIONID ? 1 : 0,
							item->GrantedAccess & PROCESS_VM_OPERATION ? 1 : 0,
							item->GrantedAccess & PROCESS_VM_READ ? 1 : 0,
							item->GrantedAccess & PROCESS_VM_WRITE ? 1 : 0,
							item->GrantedAccess & PROCESS_DUP_HANDLE ? 1 : 0,
							item->GrantedAccess & PROCESS_CREATE_PROCESS ? 1 : 0,
							item->GrantedAccess & PROCESS_SET_QUOTA ? 1 : 0,
							item->GrantedAccess & PROCESS_SET_INFORMATION ? 1 : 0,
							item->GrantedAccess & PROCESS_QUERY_INFORMATION ? 1 : 0,
							item->GrantedAccess & PROCESS_SUSPEND_RESUME ? 1 : 0,
							item->GrantedAccess & PROCESS_QUERY_LIMITED_INFORMATION ? 1 : 0,
							item->GrantedAccess & PROCESS_SET_LIMITED_INFORMATION ? 1 : 0
						);


						MessageBoxA(m_hwnd, szBuffer,"��Ϣ", 0);
					}


					ImGui::TableNextColumn();
					ImGui::Text(u8"%s", item->szProcessName);

					ImGui::PopID();
				}

			ImGui::EndTable();
		}



	}

	ImGui::EndGroup();
}

void DearWife::ShowRightImgui(int selected)
{
	// Right
	{
		ImGui::BeginGroup();
		ImGui::BeginChild("item view", ImVec2(0, -ImGui::GetFrameHeightWithSpacing())); // Leave room for 1 line below us
		ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f),u8"Pid:%d->��������:%s->0x%llX", m_vectorProcessInfo.at(selected).pid, m_vectorProcessInfo.at(selected).szPath.c_str(),m_vectorProcessInfo.at(selected).pObject);
		ImGui::Separator();
		if (ImGui::BeginTabBar("##Tabs", ImGuiTabBarFlags_None))
		{
			if (m_vectorProcessInfo.at(selected).pObject) 
			{
				if (ImGui::BeginTabItem(u8"ע��"))
				{

					InjectWayShowInImgui(m_vectorProcessInfo.at(selected).pid, m_vectorProcessInfo.at(selected).szPath, m_vectorProcessInfo.at(selected).pObject);

					ImGui::EndTabItem();
				}
				if (ImGui::BeginTabItem(u8"ֻ��ȡ�򿪵�<���̾��>"))
				{

					ImGuiShowProcessHandles(m_vectorProcessInfo.at(selected),m_vectorHanle);


					ImGui::EndTabItem();
				}
				if (ImGui::BeginTabItem(u8"ɨ�蹳��"))
				{

					ImGuiShowProcessModule(m_vectorProcessInfo.at(selected));


					ImGui::EndTabItem();
				}

				if (ImGui::BeginTabItem(u8"��˵��һ��"))
				{
					
					ImGui::TextWrapped(u8"1.ע�빦��:��·���� ��Ŀ�Ľ���д�� shellcode,Ȼ�����shellcode�����ȷ������������PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_VM_OPERATION");
					ImGui::TextWrapped(u8"2.�������̾��:����Ҫ�κ�Ȩ��,ֻ���� ������� ����ʲô����");
					ImGui::TextWrapped(u8"3.ɨ�蹳��:�ù��ܵ�һ��ʹ�û��Զ�����΢��pdb,pdb�����ʱ��Ῠס����!!!���ֻ֧��΢���dll�ͽ���");
					ImGui::TextWrapped(u8"4.Ϊ�˽��ĳЩ�����޷���ȡȨ�޵�����,�ҵ���������__stdcall ����OpenProcess_�� OpenThread_.���� �����ȡȨ�޵�ʱ��,�������ȼ��� 12345678.dll�е�OpenProcessEx_��OpenThreadEx_,����������dll���κβ���");


					ImGui::EndTabItem();
				}


			}
			ImGui::EndTabBar();
		}
		ImGui::EndChild();
		ImGui::EndGroup();
	}
}




HANDLE DearWife::Get_VM_READ_WRITE_OPERATION_Handle(PVOID pObject)
{
	HANDLE pTemp = NULL;
	NTSTATUS Status = 0;
	SYSTEM_HANDLE_INFORMATION dwInfo = { 0 };
	ULONG nRetLength = 0;
	string szTemp;

	
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
								(pHandles->Handles[i].GrantedAccess & PROCESS_VM_WRITE) &&
								(pHandles->Handles[i].GrantedAccess & PROCESS_VM_OPERATION)
								)
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

//�������������ù���
bool DearWife::Inject(ULONG pid,int nType,HANDLE hProcess,BOOL bWowProcess)
{
	bool bRet = false;

	g_data = { 0 };


	g_data.bLoadDriver = FALSE;
	g_data.dwPid = pid;
	g_data.hProcess = hProcess;

	DWORD nFlags = 0;
	if (m_bClearPEHeaders)
	{
		nFlags |= clear_peHeaders;
	}
	if (m_EXECUTE_TLS)
	{
		nFlags |= EXECUTE_TLS;
	}
	if (m_bChangeProtect)
	{
		nFlags |= protect_peHeaders;
	}


	//1.�������PID 2.���̾�� 3.ע������(���ڴ�ע�뻹������ע��) 4.dll·��
	injector helpers(pid, hProcess, bInjectType, wszDllPath, bWowProcess,nFlags);

	if (bWowProcess) 
	{
		if (bInjectType) 
		{
			bRet = helpers.inject32(nType);
			m_dllBase = helpers.GetInjectDllBase();


			if (bRet && m_dllBase && m_bCallDllFunc)
			{
				Sleep(3000);
				helpers.CallEip(nType, (PVOID)(m_vector_dll_export_fun.at(dll_export_item_current_idx).fva + m_dllBase));
			}
		}
		
	}
	else 
	{
		bRet = helpers.inject64(nType);
		
		m_dllBase = helpers.GetInjectDllBase();

		if (bRet && m_dllBase && m_bCallDllFunc)
		{
			Sleep(3000);
			helpers.CallRip(nType, (PVOID)(m_vector_dll_export_fun.at(dll_export_item_current_idx).fva + m_dllBase));
		}
	}




	return bRet;
}




void DearWife::InjectWayShowInImgui(ULONG pid,string szInjectProcessName,PVOID pObject)
{
	if (!pObject)return;
	const char* items[] = { "",u8"CreateThread(x86/x64)", u8"APC(x64)", u8"ThreadContext_Inject(x86/x64)",u8"SetWindowsHook(x64)", u8"WindowsInject_1(x64)" };
	static int item_current_idx = 0; // Here we store our selection data as an index.
	const char* combo_preview_value = items[item_current_idx];  // Pass in the preview value visible before opening the combo (it could be anything)
	if (ImGui::BeginCombo(u8"ע�뷽ʽ:", combo_preview_value,ImGuiComboFlags_HeightSmall))
	{
		for (int n = 0; n < IM_ARRAYSIZE(items); n++)
		{
			const bool is_selected = (item_current_idx == n);
			if (ImGui::Selectable(items[n], is_selected))
				item_current_idx = n;

			// Set the initial focus when opening the combo (scrolling + keyboard navigation focus)
			if (is_selected)
				ImGui::SetItemDefaultFocus();
		}
		ImGui::EndCombo();
	}


	if (item_current_idx == 0) 
	{
		ImGui::Text(u8"NoTing");
	}
	else 
	{
		
		ImGui::Text(u8"����ʹ��%s��ʽ", items[item_current_idx]);

		ImGui::SameLine();
		if (ImGui::Button(u8"ѡ��DLL·��"))
		{
			RtlSecureZeroMemory(wszDllPath, sizeof(wszDllPath));
			RtlSecureZeroMemory(szDllPath, sizeof(szDllPath));
			TCHAR strFeFileExt[128] = TEXT("PE File(*.exe,*.dll,*.sys)\0*.exe;*.dll*;.sys\0") \
				TEXT("All File(*.*)\0*.*\0\0");

			OPENFILENAMEW st = { 0 };
			RtlSecureZeroMemory(&st, sizeof(OPENFILENAME));
			st.lStructSize = sizeof(OPENFILENAME);
			st.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
			st.hwndOwner = NULL;
			st.lpstrFilter = strFeFileExt;
			st.lpstrFile = wszDllPath;
			st.nMaxFile = MAX_PATH;
			st.lpstrTitle = L"Dlll·��";
			if (GetOpenFileName(&st))
			{
				if (PathFileExistsW(st.lpstrFile))
				{
					strcpy_s(szDllPath, wstringToString(st.lpstrFile).c_str());
				}
				else {
					xlog::Error("��ȡDLL·��ʧ��");
				}
			}
		}
		ImGui::Text(u8"Dll:%s", szDllPath);

		if (strlen(szDllPath) > 0)
		{
			ImGui::Checkbox(u8"����ע��(����ѡ�����ڴ�ע��)", &bInjectType);
			ImGui::Checkbox(u8"����DLL�е�ĳһ������", &m_bCallDllFunc);
			if (m_bCallDllFunc)
			{
				EnumDllExportFunc();
			}
			if (!bInjectType)
			{
			
				ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), u8"--------->ע�����������ֻ�� ������ע����Ч<---------");
				ImGui::Checkbox(u8"���PEͷ", &m_bClearPEHeaders);
				ImGui::SameLine();
				ImGui::Checkbox(u8"����DLL����", &m_bChangeProtect);
				ImGui::SameLine();
				ImGui::Checkbox(u8"ִ��TLS", &m_EXECUTE_TLS);

			}


			ImGui::SetWindowPos(ImVec2{ ImGui::GetWindowPos().x,ImGui::GetWindowPos().y + 10 });
			if (ImGui::Button(u8"���ע��"))
			{

				//��ȡ ���̾��Ȩ��
				m_hProcess = GetOpenHanleByInjectType(pid,item_current_idx,pObject);

				IsWow64Process(m_hProcess, &m_bWowProcess);

				if (m_hProcess) 
				{
					RtlSecureZeroMemory(szBuffer, sizeof(szBuffer));
					sprintf_s(szBuffer, "ע��Ľ�����:%s Pid��:%d �򿪵ľ��:0x%x", szInjectProcessName.c_str(), pid, m_hProcess);
					if (MessageBoxA(m_hwnd, szBuffer,"��ʾ", MB_OKCANCEL) == IDOK)
					{
						if (Inject(pid, item_current_idx, m_hProcess, m_bWowProcess))
						{
							xlog::Normal("ע��ɹ� %s", items[item_current_idx]);
						}
						else {
							xlog::Error("ע��ʧ�� %s", items[item_current_idx]);
						}
					}
				}
				else 
				{
					MessageBoxW(m_hwnd, L"�򿪾��ʧ��(һ����˵��Ȩ������)", L"ʧ��", MB_OKCANCEL);
				}
			}
			
			ImGui::SetWindowPos(ImVec2{ ImGui::GetWindowPos().x,ImGui::GetWindowPos().y + 10 });
			ImGui::TextColored(ImVec4(1.0f, 0.0f, 0.0f, 1.0f), u8"���:%x bWowProcess:%d dllBase(Ϊ0��ʧ��):%llx", m_hProcess, m_bWowProcess, m_dllBase);
		}
	
	}


}

void DearWife::EnumDllExportFunc()
{
	if (m_vector_dll_export_fun.empty()==TRUE) 
	{
		get_dll_export_func(m_vector_dll_export_fun);
	}

	if (m_vector_dll_export_fun.empty())return;


	if (ImGui::BeginCombo(u8"��������", m_vector_dll_export_fun.at(dll_export_item_current_idx).szFunName.c_str(), ImGuiComboFlags_HeightSmall))
	{
		for (int n = 0; n < m_vector_dll_export_fun.size(); n++)
		{
			const bool is_selected = (dll_export_item_current_idx == n);
			if (ImGui::Selectable(m_vector_dll_export_fun.at(n).szFunName.c_str(), is_selected))
				dll_export_item_current_idx = n;

			if (is_selected)
				ImGui::SetItemDefaultFocus();
		}
		ImGui::EndCombo();
	}




}



HANDLE DearWife::GetOpenHanleByInjectType(ULONG dwPid,int nType,PVOID pObject)
{
	HANDLE hTempHanle = 0;

	hTempHanle = Get_VM_READ_WRITE_OPERATION_Handle(pObject);
	if (!hTempHanle) 
	{
		DWORD dwDesiredAccess = 0;
		dwDesiredAccess = PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION;

		if (nType == 1)
		{
			dwDesiredAccess |= PROCESS_CREATE_THREAD;
		}

		hTempHanle = OpenProcess_(dwDesiredAccess, FALSE, dwPid);
		if (hTempHanle)
		{
			m_bSelf_open_handle = true;
		}
	}
	return hTempHanle;
}




string DearWife::wstringToString(const wstring& wstr)
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

wstring DearWife::stringToWstring(const string& str)
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




void DearWife::EnableDebugPriv()
{

	HANDLE hToken;

	LUID sedebugnameValue;

	TOKEN_PRIVILEGES tkp;

	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue);

	tkp.PrivilegeCount = 1;

	tkp.Privileges[0].Luid = sedebugnameValue;

	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	AdjustTokenPrivileges(hToken, false, &tkp, sizeof tkp, NULL, NULL);

	CloseHandle(hToken);
}

void DearWife::ImGuiShowProcessModule(PROCESS_INF dwInfo)
{
	if (ImGui::Button(u8"����ģ��"))
	{
		if (dwInfo.pObject) 
		{
			process dwProcess(dwInfo.pObject, dwInfo.pid);
			dwProcess.EnumModule(m_vectorModuleInfo);
		}
	}


	if (!m_vectorModuleInfo.empty())
	{

		static ImGuiTextFilter filter; //1.��������
		static int selected = 0;
		{

			ImGui::BeginChild("left pane", ImVec2(200, 0), true);
			filter.Draw(u8"����", 130);//2.���������

			vector<module_info>::iterator it = m_vectorModuleInfo.begin();
			char label[128];
			int i = 0;
			for (; it != m_vectorModuleInfo.end(); it++)
			{
				if (it->dwPid != dwInfo.pid) {
					break;
				}
				sprintf_s(label, "%s", it->dllBaseName.c_str());
				if (filter.PassFilter(label))
				{
					if (ImGui::Selectable(label, selected == i)) {
						selected = i;
					}
				}
				i++;
			}
			ImGui::EndChild();
		}

		ImGui::SameLine();
		ShowRight_ProcessModule(dwInfo,m_vectorModuleInfo.at(selected));
	}




}


void DearWife::addExportFunToVector(PVOID pFileBuffer, vector<symbol_info>& m_vectorsymbolInfo, string belong_to_module)
{

	PVOID BaseAddress = pFileBuffer;
	PIMAGE_DOS_HEADER       pDosHdr = (PIMAGE_DOS_HEADER)BaseAddress;
	PIMAGE_NT_HEADERS32     pNtHdr32 = NULL;
	PIMAGE_NT_HEADERS64     pNtHdr64 = NULL;
	PIMAGE_EXPORT_DIRECTORY pExport = NULL;
	ULONG                   expSize = 0;
	ULONG_PTR               pAddress = 0;
	PUSHORT                 pAddressOfOrds;
	PULONG                  pAddressOfNames;
	PULONG                  pAddressOfFuncs;
	ULONG                   i;
	PIMAGE_SECTION_HEADER pFirstSection = NULL;

	if (BaseAddress == NULL)
		return;

	/// Not a PE file
	if (pDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return;

	pNtHdr32 = (PIMAGE_NT_HEADERS32)((PUCHAR)BaseAddress + pDosHdr->e_lfanew);
	pNtHdr64 = (PIMAGE_NT_HEADERS64)((PUCHAR)BaseAddress + pDosHdr->e_lfanew);

	// Not a PE file
	if (pNtHdr32->Signature != IMAGE_NT_SIGNATURE)
		return;

	// 64 bit image
	if (pNtHdr32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
			.VirtualAddress +
			(ULONG_PTR)BaseAddress);
		expSize = pNtHdr64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

		pFirstSection = (PIMAGE_SECTION_HEADER)(pNtHdr64 + 1);
	}
	// 32 bit image
	else {
		pExport = (PIMAGE_EXPORT_DIRECTORY)(pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
			.VirtualAddress +
			(ULONG_PTR)BaseAddress);
		expSize = pNtHdr32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

		pFirstSection = (PIMAGE_SECTION_HEADER)(pNtHdr32 + 1);
	}

	pAddressOfOrds = (PUSHORT)(pExport->AddressOfNameOrdinals + (ULONG_PTR)BaseAddress);
	pAddressOfNames = (PULONG)(pExport->AddressOfNames + (ULONG_PTR)BaseAddress);
	pAddressOfFuncs = (PULONG)(pExport->AddressOfFunctions + (ULONG_PTR)BaseAddress);


	//ֻ���Ӵ������ĺ���,���˵� ȫ�ֱ���֮��� IMAGE_SCN_MEM_EXECUTE

	struct SectionData
	{
		DWORD VirtualAddress;
		DWORD VirtualSize;
	};

	vector<SectionData> dwVectortSectionData;

	SectionData dwSectionData = { 0 };
	for (PIMAGE_SECTION_HEADER pSection = pFirstSection;
		pSection < pFirstSection + pNtHdr64->FileHeader.NumberOfSections;
		pSection++)
	{
		if (pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE)
		{
			dwSectionData.VirtualAddress = pSection->VirtualAddress;
			dwSectionData.VirtualSize = pSection->Misc.VirtualSize;
			dwVectortSectionData.push_back(dwSectionData);
		}
	}


	symbol_info dwTemp = { 0 };
	for (i = 0; i < pExport->NumberOfFunctions; i++)
	{
		dwTemp = { 0 };

		if (pAddressOfFuncs[pAddressOfOrds[i]]) {
			dwTemp.rva = pAddressOfFuncs[pAddressOfOrds[i]];
			dwTemp.szFuncName = (PCHAR)(pAddressOfNames[i] + (ULONG_PTR)BaseAddress);;
			dwTemp.Belonging_to_module = belong_to_module;



			vector<SectionData> ::iterator it = dwVectortSectionData.begin();
			for (it; it != dwVectortSectionData.end(); ++it)
			{
				if ((it->VirtualAddress <= dwTemp.rva) && (dwTemp.rva <= (DWORD)((DWORD)it->VirtualAddress + it->VirtualSize))) {
					m_vectorsymbolInfo.push_back(dwTemp);
					break;
				}
			}
		}
	}


}



//ImGui::SetWindowPos(ImVec2{ ImGui::GetWindowPos().x,ImGui::GetWindowPos().y + 10 });
void DearWife::ShowRight_ProcessModule(PROCESS_INF dwProcessInfo,module_info dwInfo)
{
	ImGui::BeginGroup();
	ImGui::TextWrapped(u8"������:%d %s Base:0x%llx Size:0x%x ģ��:%s", dwProcessInfo.pid,dwProcessInfo.szPath.c_str(), dwInfo.dllBase, dwInfo.dllOfImageSize, dwInfo.fulldllPath.c_str());
	
	static bool bScanHook = false;
	ImGui::Checkbox(u8"ɨ���ģ�鹳��", &bScanHook);
	if(bScanHook)
	{

		if (ImGui::Button(u8"��ʼɨ��"))
		{

			if (m_recordModuleInfo.Belonging_to_module != dwInfo.dllBaseName)
			{
				if (m_recordModuleInfo.pFileBuffer)
				{
					free(m_recordModuleInfo.pFileBuffer);
					m_recordModuleInfo.pFileBuffer = 0;
				}
				m_recordModuleInfo.bAlread_Fix_buffer = FALSE;
				m_recordModuleInfo.Belonging_to_module = "";
			}

			if (!m_recordModuleInfo.pFileBuffer && (m_recordModuleInfo.bAlread_Fix_buffer == FALSE)) 
			{
				DWORD dwImageSize = 0;
				PVOID pFileBuffer = NULL;
				pFileBuffer = file_to_image_buffer(stringToWstring(dwInfo.fulldllPath).c_str(), dwImageSize);
				Symbol dwSymbol(dwInfo.fulldllPath.c_str());
				if (pFileBuffer && dwSymbol.LoadSymbol(dwInfo.dllBaseName,m_vectorsymbolInfo))
				{
					if (FixImportTable(pFileBuffer, dwInfo.dllBase))
					{
						m_recordModuleInfo.bAlread_Fix_buffer = TRUE;
						m_recordModuleInfo.pFileBuffer = pFileBuffer;
						m_recordModuleInfo.Belonging_to_module = dwInfo.dllBaseName;

						vector<loadDll> ::iterator it = m_loadDll.begin();
						for (it; it != m_loadDll.end(); it++)
						{
							if (it->hDllBase)
							{
								FreeLibrary(it->hDllBase);
							}
						}

						//ɨ�蹳�Ӳ���

						// ���ӵ������еĺ���
						addExportFunToVector(pFileBuffer, m_vectorsymbolInfo, dwInfo.dllBaseName);

						process dwProcess(dwProcessInfo.pObject,dwProcessInfo.pid);
						dwProcess.EnumProcessInlinkeHook(pFileBuffer, &dwInfo, m_vectorsymbolInfo, m_MapInlineHook);

						if (!m_MapInlineHook.size()) 
						{
							MessageBoxW(m_hwnd, L"û��ɨ������", L"��ʾ", 0);
						}
						else {
							MessageBoxW(m_hwnd, L"ɨ�����", L"��ʾ", 0);
						}
					}

				}
				else 
				{
					MessageBoxW(m_hwnd, L"ɨ��ģ��ʧ��(����΢��pdb����ʧ��)", L"��ʾ", 0);
				}

			}
		}


		if (!m_MapInlineHook.empty() && m_MapInlineHook.size())
		{
			map<ULONG_PTR, INLINE_HOOK_INFO> ::iterator it = m_MapInlineHook.begin();
			for (it;it!=m_MapInlineHook.end();++it)
			{
				if (it->second.Belonging_to_module != dwInfo.dllBaseName)break;

				ImGui::Text(u8"0x%llX->%s :%s", it->first,it->second.Belonging_to_module.c_str(), it->second.szFunc.c_str());

			}
		}



	}
	ImGui::EndGroup();
}

BOOL DearWife::FixBaseRelocTable32(PVOID pPEBuffer, ULONG_PTR dwLoadMemoryAddress)
{
	PIMAGE_DOS_HEADER       pDosHdr = (PIMAGE_DOS_HEADER)pPEBuffer;
	PIMAGE_NT_HEADERS32 pNTHeader32 = NULL;

	pNTHeader32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)pPEBuffer + pDosHdr->e_lfanew);

	if (pNTHeader32->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}

	PIMAGE_BASE_RELOCATION pLoc = NULL;
	DWORD LocSize = 0;
	pLoc = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)pPEBuffer +
		pNTHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
		.VirtualAddress);

	LocSize = (DWORD)(pNTHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);

	if (pLoc && LocSize)
	{

		DWORD  Delta = (ULONG_PTR)dwLoadMemoryAddress - pNTHeader32->OptionalHeader.ImageBase;
		DWORD* pAddress = NULL;
		//ע���ض�λ���λ�ÿ��ܺ�Ӳ���ļ��е�ƫ�Ƶ�ַ��ͬ��Ӧ��ʹ�ü��غ�ĵ�ַ

		while ((pLoc->VirtualAddress + pLoc->SizeOfBlock) != 0) //��ʼɨ���ض�λ��
		{
			WORD* pLocData = (WORD*)((ULONG_PTR)pLoc + sizeof(IMAGE_BASE_RELOCATION));
			//���㱾����Ҫ�������ض�λ���ַ������Ŀ
			int NumberOfReloc = (pLoc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			for (int i = 0; i < NumberOfReloc; i++) {
				if ((DWORD)(pLocData[i] & 0xF000) == 0x00003000 ||
					(DWORD)(pLocData[i] & 0xF000) == 0x0000A000) //����һ����Ҫ�����ĵ�ַ
				{
					// ������
					// pLoc->VirtualAddress = 0��1000;
					// pLocData[i] = 0��313E; ��ʾ����ƫ�Ƶ�ַ0��13E����Ҫ����
					// ��� pAddress = ����ַ + 0��113E
					// ����������� A1 ( 0c d4 02 10) �������ǣ� mov eax , [1002d40c]
					// ��Ҫ����1002d40c�����ַ
					pAddress = (DWORD*)((ULONG_PTR)pPEBuffer + pLoc->VirtualAddress + (pLocData[i] & 0x0FFF));
					*pAddress += Delta;
				}
			}
			//ת�Ƶ���һ���ڽ��д���
			pLoc = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)pLoc + pLoc->SizeOfBlock);
		}
		/***********************************************************************/
	}

	pNTHeader32->OptionalHeader.ImageBase = (DWORD)dwLoadMemoryAddress;


	return TRUE;
}


 BOOL DearWife::FixBaseRelocTable(PVOID pPEBuffer, ULONG_PTR dwLoadMemoryAddress) 
 {
     PIMAGE_DOS_HEADER       pDosHdr  = (PIMAGE_DOS_HEADER)pPEBuffer;
     PIMAGE_NT_HEADERS64 pNTHeader = NULL;
	 PIMAGE_NT_HEADERS32 pNTHeader32 = NULL;
	 BOOL bIs64 = FALSE;

     pNTHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)pPEBuffer + pDosHdr->e_lfanew);
	 pNTHeader32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)pPEBuffer + pDosHdr->e_lfanew);

     if (pNTHeader->Signature != IMAGE_NT_SIGNATURE) {
         return FALSE;
     }

	 PIMAGE_BASE_RELOCATION pLoc = NULL;
	 DWORD LocSize = 0;
	 if (pNTHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	 {
		 pLoc = (PIMAGE_BASE_RELOCATION)((DWORDX)pPEBuffer +
				 pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
				 .VirtualAddress);
		 LocSize = (DWORD)(pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);
		 bIs64 = TRUE;
	 }
	 else
	 {
		 pLoc = (PIMAGE_BASE_RELOCATION)((DWORDX)pPEBuffer +
			 pNTHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
			 .VirtualAddress);
		 LocSize = (DWORD)(pNTHeader32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);

		 return FixBaseRelocTable32(pPEBuffer, dwLoadMemoryAddress);

	 }

    if (pLoc && LocSize) 
	{

         DWORDX  Delta = (DWORDX)dwLoadMemoryAddress - pNTHeader->OptionalHeader.ImageBase;
             DWORDX *pAddress = NULL;
         //ע���ض�λ���λ�ÿ��ܺ�Ӳ���ļ��е�ƫ�Ƶ�ַ��ͬ��Ӧ��ʹ�ü��غ�ĵ�ַ

         while ((pLoc->VirtualAddress + pLoc->SizeOfBlock) != 0) //��ʼɨ���ض�λ��
         {
             WORD *pLocData = (WORD *)((DWORDX)pLoc + sizeof(IMAGE_BASE_RELOCATION));
             //���㱾����Ҫ�������ض�λ���ַ������Ŀ
             int NumberOfReloc = (pLoc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
             for (int i = 0; i < NumberOfReloc; i++) {
                 if ((DWORDX)(pLocData[i] & 0xF000) == 0x00003000 ||
                     (DWORDX)(pLocData[i] & 0xF000) == 0x0000A000) //����һ����Ҫ�����ĵ�ַ
                 {
                     // ������
                     // pLoc->VirtualAddress = 0��1000;
                     // pLocData[i] = 0��313E; ��ʾ����ƫ�Ƶ�ַ0��13E����Ҫ����
                     // ��� pAddress = ����ַ + 0��113E
                     // ����������� A1 ( 0c d4 02 10) �������ǣ� mov eax , [1002d40c]
                     // ��Ҫ����1002d40c�����ַ
                     pAddress = (DWORDX *)((DWORDX)pPEBuffer + pLoc->VirtualAddress + (pLocData[i] & 0x0FFF));
                     *pAddress += Delta;
                 }
             }
             //ת�Ƶ���һ���ڽ��д���
             pLoc = (PIMAGE_BASE_RELOCATION)((DWORDX)pLoc + pLoc->SizeOfBlock);
         }
         /***********************************************************************/
    }
	if (bIs64) {
		pNTHeader->OptionalHeader.ImageBase = (DWORDX)dwLoadMemoryAddress;
	}
	else {
		pNTHeader32->OptionalHeader.ImageBase = (DWORDX)dwLoadMemoryAddress;
	}
   

    return TRUE;
 }



 BOOL DearWife::FixImportTable(PVOID pPEBuffer, ULONG_PTR dwLoadMemoryAddress) 
 {
     PIMAGE_NT_HEADERS64 pNtHeaders = NULL;
	 PIMAGE_NT_HEADERS32 pNtHeaders32 = NULL;
	 PIMAGE_DOS_HEADER       pDosHdr = (PIMAGE_DOS_HEADER)pPEBuffer;
	 pNtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)pPEBuffer + pDosHdr->e_lfanew);
	 pNtHeaders32 = (PIMAGE_NT_HEADERS32)((ULONG_PTR)pPEBuffer + pDosHdr->e_lfanew);
	 ULONG_PTR pImport = 0;
	 BOOL bIs64 = FALSE;

     if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
         return FALSE;
     }

	 if (pNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	 {
		 pImport = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
		 bIs64 = TRUE;
	 }
	 else
	 {
		 pImport = pNtHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	 }

     PIMAGE_IMPORT_DESCRIPTOR pID     = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)pPEBuffer + pImport);
     PIMAGE_IMPORT_BY_NAME    pByName = NULL;

	 loadDll dwLoadInfo;


	 
	 //���Ҫ����IAT�� �����޸����������ǲ���ðIAT�� ֻ��Inlinehook
     while ((pID->Characteristics != 0) && pImport && bIs64) 
	 {

         PIMAGE_THUNK_DATA pRealIAT     = (PIMAGE_THUNK_DATA)((ULONG_PTR)pPEBuffer + pID->FirstThunk);
         PIMAGE_THUNK_DATA pOriginalIAT = (PIMAGE_THUNK_DATA)((ULONG_PTR)pPEBuffer + pID->OriginalFirstThunk);
         //��ȡdll������
         char * pName = (char *)((ULONG_PTR)pPEBuffer + pID->Name);
         HANDLE hDll  = 0;

         hDll = GetModuleHandleA(pName);
		 
         if (!hDll)
         {
             hDll =LoadLibraryA(pName);
			 if (hDll) 
			 {
				 dwLoadInfo.hDllBase =(HMODULE)hDll;
				 dwLoadInfo.szLoadDll = pName;
				m_loadDll.push_back(dwLoadInfo);
			 }
         }

         if (hDll == NULL) {

             return FALSE;
         }

         for (ULONG i = 0;; i++) {
             if (pOriginalIAT[i].u1.Function == 0)
                 break;
             FARPROC lpFunction = NULL;
             if (IMAGE_SNAP_BY_ORDINAL(pOriginalIAT[i].u1.Ordinal)) //�����ֵ�������ǵ������
             {
                 if (IMAGE_ORDINAL(pOriginalIAT[i].u1.Ordinal)) {

                     //LdrGetProcedureAddress_(hDll, NULL, IMAGE_ORDINAL(pOriginalIAT[i].u1.Ordinal), &lpFunction);
                     lpFunction = (FARPROC)GetProcAddress((HMODULE)hDll, (char*)IMAGE_ORDINAL(pOriginalIAT[i].u1.Ordinal));
                 }
             } else //�������ֵ���
             {
                 //��ȡ��IAT���������ĺ�������
                 pByName = (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)pPEBuffer + (ULONG_PTR)(pOriginalIAT[i].u1.AddressOfData));
                 if ((char *)pByName->Name) 
                 {
                     /**
                     RtlInitAnsiString_(&ansiStr, (char *)pByName->Name);
                     LdrGetProcedureAddress_(hDll, &ansiStr, 0, &lpFunction);
                     */
                      lpFunction = (FARPROC)GetProcAddress((HMODULE)hDll, pByName->Name);
                 }
             }

             //���***********

             if (lpFunction != NULL) //�ҵ��ˣ�
                 pRealIAT[i].u1.Function = (ULONG_PTR)lpFunction;
             else {
                 return FALSE;
             }
         }

         // move to next
         pID = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)pID + sizeof(IMAGE_IMPORT_DESCRIPTOR));
     }
   
     return FixBaseRelocTable(pPEBuffer, dwLoadMemoryAddress);
 }



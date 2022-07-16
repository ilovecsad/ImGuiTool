#include "main.h"
#include "DearMyWife.h"

DearWife* pMyWife = NULL;


int WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nShowCmd) 
{



	pMyWife = new DearWife;

	pMyWife->create();




	WaitForSingleObject(pMyWife->m_hImGuiThreadHanle, INFINITE);
	
	delete pMyWife;
	pMyWife = NULL;

	return TRUE;
}

/*

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		if (!pMyWife)
		{
			pMyWife = new DearWife;

			pMyWife->create();
		}
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		if (pMyWife)
		{
			delete pMyWife;
			pMyWife = NULL;
		}

		break;
	}
	return TRUE;
}
*/

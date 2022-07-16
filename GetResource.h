#pragma once
#include <windows.h>
class GetResource
{
public:
	GetResource(HMODULE hModule, LPCWSTR lpName, LPCWSTR lpType);
	~GetResource();
	PVOID GetBuffer();
	DWORD GetBufferSize();
private:
	HRSRC m_hRsrc = NULL;
	DWORD m_dwSize = 0;
	HGLOBAL m_hGlobal = 0;
	PVOID m_pBuffer = NULL;
};


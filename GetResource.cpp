#include "GetResource.h"

GetResource::GetResource(HMODULE hModule,LPCWSTR lpName,LPCWSTR lpType)
{
	//查找资源
	m_hRsrc = FindResourceW(hModule, lpName, lpType);
	if (m_hRsrc)
	{
		//获取资源的大小
		m_dwSize = SizeofResource(hModule, m_hRsrc);
		if (m_dwSize)
		{
			//加载资源
			m_hGlobal = LoadResource(hModule, m_hRsrc);
			if (m_hGlobal)
			{
				//锁定资源,返回资源指针
				m_pBuffer = LockResource(m_hGlobal);

			}
		}
	}
}

GetResource::~GetResource()
{
	if (m_hGlobal)
	{
		FreeResource(m_hGlobal);
		m_hRsrc = NULL;
		m_dwSize = 0;
		m_hGlobal = 0;
		m_pBuffer = NULL;
	}
}

PVOID GetResource::GetBuffer()
{
	return  (m_hRsrc && m_hGlobal) ? m_pBuffer : NULL;
}

DWORD GetResource::GetBufferSize()
{
	return (m_hRsrc && m_hGlobal) ? m_dwSize : NULL;
}

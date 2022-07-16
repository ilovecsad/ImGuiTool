#pragma once
#include <Windows.h>
#include <iostream>
#include <vector>
#include <map>
#include "struct.h"
using namespace std;



struct DebugInfo {
	DWORD Signature;
	GUID  Guid;
	DWORD Age;
	char  PdbFileName[1];
};

//ntdll.dll 不要全路径

class Symbol
{
public:
	
	Symbol(const char* szFullPath);
	~Symbol();
	BOOL LoadSymbol(string szSaveFileName,vector<symbol_info>& vectorsymbolInfo);
private:
	string m_szFullPath;
	string m_szDllBasePath;
	DWORD m_ImageSizeOfDll = 0;
	PVOID m_fileBuffer = NULL;
	BOOL m_is64 = TRUE;
private:
	DebugInfo* GetModuleDebugInfoEx(HMODULE module);
	DebugInfo* GetModuleDebugInfo(const char* moduleName);
	std::string pdburl(DebugInfo* pdb_info);

	BOOL ImageFile(PVOID FileBuffer, PVOID* ImageModuleBase, DWORD& ImageSize);
	PVOID file_to_image_buffer(LPCWSTR szFullPath, DWORD& pImageSize);
	UINT AlignSize(UINT nSize, UINT nAlign);
	void  open_binary_file(const std::string& file, std::vector<uint8_t>& data);
	void  buffer_to_file_bin(unsigned char* buffer, size_t buffer_size, const std::string& filename);
	wstring stringToWstring(const string& str);
	string wstringToString(const wstring& wstr);
	BOOL check_symbol_file(string symbol_name);
	bool init(void* pdbFile_baseAddress,vector<symbol_info>& vectorsymbolInfo,string moduleName);
};


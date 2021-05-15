#pragma once
#include <tchar.h>
#include <windows.h>
#include <iostream>
#include <fstream>


HINSTANCE importEBridge(LPCWSTR bridgeDll);
VOID DumpHex(void* data, size_t size);
VOID WriteBufFile(const char* fileName, const char* buf, size_t sz);

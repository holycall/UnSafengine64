
#include "dbgsymbol_helper.h"
#include <iostream>
#include <string>

using namespace std;
using std::string;

namespace WW {
#include <Windows.h>
#include <DbgHelp.h>
}

typedef bool(__stdcall* SymInitializePtr)(
	WW::HANDLE hProcess,
	WW::PCSTR UserSearchPath,
	bool fInvadeProcess
	);

typedef WW::DWORD(__stdcall* SymSetOptionsPtr)(WW::DWORD SymOptions);

typedef WW::DWORD64(__stdcall* SymLoadModuleExPtr)(
	WW::HANDLE hProcess,
	WW::HANDLE hFile,
	WW::PCSTR ImageName,
	WW::PCSTR ModuleName,
	WW::DWORD64 BaseOfDll,
	WW::DWORD DllSize,
	WW::PMODLOAD_DATA Data,
	WW::DWORD Flags
	);

typedef WW::BOOL(__stdcall* SymEnumSymbolsPtr)(
	WW::HANDLE hProcess,
	WW::ULONG64 BaseOfDll,
	WW::PCSTR Mask,
	WW::PSYM_ENUMERATESYMBOLS_CALLBACK EnumSymbolsCallback,
	WW::PVOID UserContext
	);

typedef bool(__stdcall* SymFromAddrPtr) (
	WW::HANDLE       hProcess,
	WW::DWORD64      Address,
	WW::PDWORD64     Displacement,
	WW::PSYMBOL_INFO Symbol
	);

typedef bool(__stdcall* SymCleanupPtr) (WW::HANDLE hProcess);

WW::HMODULE hDbgHelp;
WW::HANDLE hProcess;
SymInitializePtr symInitialize;
SymSetOptionsPtr symSetOptions;
SymLoadModuleExPtr symLoadModuleEx;
SymFromAddrPtr symFromAddr;
SymEnumSymbolsPtr symEnumSymbols;
SymCleanupPtr symCleanup;
std::ostream* out = &cerr;


bool InitDbgHelp() {
	hDbgHelp = WW::LoadLibrary("dbghelp.dll");
	hProcess = WW::GetCurrentProcess();
	symSetOptions = (SymSetOptionsPtr)WW::GetProcAddress(hDbgHelp, "SymSetOptions");
	symInitialize = (SymInitializePtr)WW::GetProcAddress(hDbgHelp, "SymInitialize");
	symLoadModuleEx = (SymLoadModuleExPtr)WW::GetProcAddress(hDbgHelp, "SymLoadModuleEx");
	symEnumSymbols = (SymEnumSymbolsPtr)WW::GetProcAddress(hDbgHelp, "SymEnumSymbols");
	symFromAddr = (SymFromAddrPtr)WW::GetProcAddress(hDbgHelp, "SymFromAddr");
	symCleanup = (SymCleanupPtr)WW::GetProcAddress(hDbgHelp, "SymCleanup");
	if (hDbgHelp == NULL || symSetOptions == NULL || symInitialize == NULL || symFromAddr == NULL) {		
		return false;
	}
	
	// get undecorated symbols
	symSetOptions(0);
	return true;
}

string GetDbgSymbol(string name, ADDRINT saddr, ADDRINT eaddr, ADDRINT addr) {
	WW::DWORD error;
	symInitialize(hProcess, NULL, TRUE);
	if (!symLoadModuleEx(hProcess,    // target process 
		NULL,        // handle to image - not used
		name.c_str(), // name of image file
		NULL,        // name of module - not required
		saddr,  // base address - not required
		eaddr - saddr,           // size of image - not required
		NULL,        // MODLOAD_DATA used for special cases 
		0))
	{
		error = WW::GetLastError();
		if (error != ERROR_SUCCESS) return "";
	}

	WW::DWORD64 dwDisplacement = 0;
	char buffer[sizeof(WW::SYMBOL_INFO) + MAX_SYM_NAME * sizeof(char)];
	WW::PSYMBOL_INFO pSymbol = (WW::PSYMBOL_INFO)buffer;	
	pSymbol->SizeOfStruct = sizeof(WW::SYMBOL_INFO);
	pSymbol->MaxNameLen = MAX_SYM_NAME;
	if (symFromAddr(hProcess, addr, &dwDisplacement, pSymbol))
	{
		return string(pSymbol->Name);		
	}
	else
	{
		return "";
	}
}


bool CALLBACK EnumSymProc(
	WW::PSYMBOL_INFO pSymInfo,
	WW::ULONG SymbolSize,
	WW::PVOID UserContext)
{
	UNREFERENCED_PARAMETER(UserContext);
	if (out) {
		*out << hex << pSymInfo->Address << ' ' << SymbolSize << ' ' << pSymInfo->Name << endl;
	}
	return TRUE;
}


void PrintSymbols(string name, ADDRINT saddr, ADDRINT eaddr, std::ostream *out0) {	
	WW::DWORD error;
	out = out0;
	symInitialize(hProcess, NULL, TRUE);
	if (!symLoadModuleEx(hProcess,    // target process 
		NULL,        // handle to image - not used
		name.c_str(), // name of image file
		NULL,        // name of module - not required
		saddr,  // base address - not required
		eaddr - saddr,           // size of image - not required
		NULL,        // MODLOAD_DATA used for special cases 
		0)) 
	{
		error = WW::GetLastError();
		if (error != ERROR_SUCCESS) return;
	}

	symEnumSymbols(hProcess,     // Process handle from SymInitialize.
		saddr,   // Base address of module.
		"*",        // Name of symbols to match.
		(WW::PSYM_ENUMERATESYMBOLS_CALLBACK)EnumSymProc, // Symbol handler procedure.
		NULL);       // User context.		
}

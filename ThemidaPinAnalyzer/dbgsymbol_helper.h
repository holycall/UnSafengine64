#pragma once
#include <string>
using std::string;

bool InitDbgHelp();
string GetDbgSymbol(string name, ADDRINT saddr, ADDRINT eaddr, ADDRINT addr);
void PrintSymbols(string name, ADDRINT saddr, ADDRINT eaddr, std::ostream* out0);
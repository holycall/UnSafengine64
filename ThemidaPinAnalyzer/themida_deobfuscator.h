#include <utility>
#include <iostream>
#include <fstream>
#include <map>
#include <set>
#include "pin_helper.h"
#include "config.h"
#include "stringtrim.h"


enum class ObfuscatedCallType {
	kDIRECT_CALL, kINDIRECT_CALL, kINDIRECT_JMP, kINDIRECT_MOV, kUNDEFINED,
};

inline const ObfuscatedCallType ParseObfuscatedCallType(string s) {
	if (s == "DIRECT_CALL") return ObfuscatedCallType::kDIRECT_CALL;
	if (s == "INDIRECT_CALL") return ObfuscatedCallType::kINDIRECT_CALL;
	if (s == "INDIRECT_JMP") return ObfuscatedCallType::kINDIRECT_JMP;
	if (s == "INDIRECT_MOV") return ObfuscatedCallType::kINDIRECT_MOV;
	return ObfuscatedCallType::kUNDEFINED;
}

std::ostream& operator<<(std::ostream& strm, const ObfuscatedCallType& a) {
	switch (a) {
	case ObfuscatedCallType::kDIRECT_CALL: return strm << "DIRECT_CALL";
	case ObfuscatedCallType::kINDIRECT_CALL: return strm << "INDIRECT_CALL";
	case ObfuscatedCallType::kINDIRECT_JMP: return strm << "INDIRECT_JMP";
	case ObfuscatedCallType::kINDIRECT_MOV: return strm << "INDIRECT_MOV";
	}	
	return strm << "UNDEFINED";
}

std::istream& operator>>(std::istream& strm, ObfuscatedCallType& a) {
	string s;
	strm >> s;
	if (s == "DIRECT_CALL") a = ObfuscatedCallType::kDIRECT_CALL;
	else if (s == "INDIRECT_CALL") a = ObfuscatedCallType::kINDIRECT_CALL;
	else if (s == "INDIRECT_JMP") a = ObfuscatedCallType::kINDIRECT_JMP;
	else if (s == "INDIRECT_MOV") a = ObfuscatedCallType::kINDIRECT_MOV;
	else a = ObfuscatedCallType::kUNDEFINED;
	return strm;
}


struct ObfuscatedCall {

	ObfuscatedCall() {};
	ObfuscatedCall(ADDRINT sa, ADDRINT da, ADDRINT ia, ObfuscatedCallType it, string r, size_t g) : 
		src(sa), dst(da), ind_addr(ia), ins_type(it), reg(r), n_prev_pad_bytes(g) {
		next_addr = sa + 6;
	};

	ADDRINT src;
	ADDRINT dst;
	ADDRINT ind_addr;
	ADDRINT next_addr;
	
	ObfuscatedCallType ins_type;
	string reg;
	size_t n_prev_pad_bytes;

	string GetMnem() {
		switch (ins_type) {
		case ObfuscatedCallType::kDIRECT_CALL:
			return "call";
		case ObfuscatedCallType::kINDIRECT_CALL:
			return "call";
		case ObfuscatedCallType::kINDIRECT_JMP:
			return "jmp";
		case ObfuscatedCallType::kINDIRECT_MOV:
			return "mov";
		}
		return "";
	}

	size_t ToBytes(UINT8* byts) {
		ADDRINT reladdr;
		switch (ins_type) {
		case ObfuscatedCallType::kDIRECT_CALL:
			byts[0] = 0xe8;			
			reladdr = dst - (src + 5);
			ADDRINT_TO_BYTES(reladdr, byts + 1);
			return 5;
		case ObfuscatedCallType::kINDIRECT_CALL:
			byts[0] = 0xff;
			byts[1] = 0x15;
			if (ADDRSIZE == 4) {				
				ADDRINT_TO_BYTES(ind_addr, byts + 2);
			}
			else {
				reladdr = ind_addr - (src + 6);
				ADDRINT_TO_BYTES(reladdr, byts + 2);
			}
			return 6;
		case ObfuscatedCallType::kINDIRECT_JMP:
			byts[0] = 0xff;
			byts[1] = 0x25;
			if (ADDRSIZE == 4) {
				ADDRINT_TO_BYTES(ind_addr, byts + 2);
			} 
			else {
				reladdr = ind_addr - (src + 6);
				ADDRINT_TO_BYTES(reladdr, byts + 2);
			}
			return 6;
		case ObfuscatedCallType::kINDIRECT_MOV:
			if (ADDRSIZE == 4) {
				byts[0] = 0x8b;
				if (reg == "eax") byts[1] = 0x05;
				else if (reg == "ebx") byts[1] = 0x1d;
				else if (reg == "ecx") byts[1] = 0x0d;
				else if (reg == "edx") byts[1] = 0x15;
				else if (reg == "esi") byts[1] = 0x35;
				else if (reg == "edi") byts[1] = 0x3d;	
				ADDRINT_TO_BYTES(ind_addr, byts + 2);
				return 6;
			}
			else {	// 64bit
				byts[0] = 0x48;
				byts[1] = 0x8b;
				if (reg == "rax") byts[2] = 0x05;
				else if (reg == "rbx") byts[2] = 0x1d;
				else if (reg == "rcx") byts[2] = 0x0d;
				else if (reg == "rdx") byts[2] = 0x15;
				else if (reg == "rsi") byts[2] = 0x35;
				else if (reg == "rdi") byts[2] = 0x3d;
				reladdr = ind_addr - (src + 7);
				ADDRINT_TO_BYTES(reladdr, byts + 3);
				return 7;
			}		
		}
		return 0;
	}

	string ToString() {
		stringstream ss;
		ss << '[' <<
			toHex(src) << ',' <<
			toHex(dst) << ',' <<
			toHex(ind_addr) << ',' <<
			'"' << ins_type << "\"," <<
			'"' << reg << "\"]" <<
			n_prev_pad_bytes;	
		return ss.str();
	}

	const char* c_str() {
		return ToString().c_str();
	}

	static bool Parse(string s) {
		trim(s);
		s = s.substr(1, s.size() - 2);
		char delim;
		ObfuscatedCall a;
		stringstream ss(s);
		ss >>
			hex >> a.src >> delim >>
			hex >> a.dst >> delim >>
			hex >> a.ind_addr >> delim >>
			a.ins_type >> delim >>
			a.reg >> delim >>
			a.n_prev_pad_bytes;
		return true;
	}
};


std::ostream& operator<<(std::ostream& strm, ObfuscatedCall& a) {
	return strm << 
		'[' <<
		toHex(a.src) << ',' <<
		toHex(a.dst) << ',' <<
		toHex(a.ind_addr) << ',' <<
		'"' << a.ins_type << "\"," <<
		'"' << a.reg << 
		a.n_prev_pad_bytes << 
		"\"]";
}

// obfuscated iat items
struct ObfuscatedIATElement {
	ADDRINT src;
	ADDRINT dst;
};
vector<ObfuscatedIATElement> obf_iat_elems;	


// for resolving "mov register, API_Function" type obfuscation
bool is_register_saved = false;
void RestoreRegisters(LEVEL_VM::CONTEXT* ctxt);
void SaveRegisters(const LEVEL_VM::CONTEXT* ctxt);
string PrintRegisters(LEVEL_VM::CONTEXT* ctxt);
REG GetRegisterAssignedWithAPIFunctionAddress(LEVEL_VM::CONTEXT* ctxt);


enum class RunUntilAPIFunctionStatus {
	kUninitilaized, 
	kCheckNextCall,
	kCheckCurrentFunction,
	kFinalize,
};

std::ostream& operator<<(std::ostream& strm, const RunUntilAPIFunctionStatus& a) {
	switch (a) {
	case RunUntilAPIFunctionStatus::kUninitilaized: return strm << "RUAPI:Uninitialized";
	case RunUntilAPIFunctionStatus::kCheckNextCall: return strm << "RUAPI:Check_Next_Function";
	case RunUntilAPIFunctionStatus::kCheckCurrentFunction: return strm << "RUAPI:Check_Current_Function";
	case RunUntilAPIFunctionStatus::kFinalize: return strm << "Return";
	}
	return strm << "RUAPI:UNDEFINED";
}


void SaveRegisters(LEVEL_VM::CONTEXT * ctxt);
void RestoreRegisters(LEVEL_VM::CONTEXT * ctxt);
string PrintRegisters(LEVEL_VM::CONTEXT* ctxt);

void AdjustLoadedAddress(ADDRINT delta);


// Pintool Instrumentation and Analysis Functions
void ThreadStart(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v);
void ThreadFini(THREADID threadid, const CONTEXT *ctxt, INT32 code, VOID *v);

void Analysis_INS_MW(ADDRINT addr, size_t mSize, ADDRINT targetAddr);
void Analysis_INS_MR(ADDRINT targetAddr);
void Analysis_INS(ADDRINT addr);

void Analysis_TRC_OEP(CONTEXT *ctxt, ADDRINT addr, bool is_ret, THREADID threadid);
void Analysis_TRC_API(CONTEXT* ctxt, ADDRINT addr, bool is_ret, THREADID threadid);
void Analysis_INS_API(CONTEXT* ctxt, ADDRINT addr, ADDRINT it, THREADID tid);
void Analysis_INS_LOG(CONTEXT* ctxt, ADDRINT addr, THREADID tid);

void ToNextObfCall(CONTEXT* ctxt);
int DoRunUntilAPI(CONTEXT* ctxt, ADDRINT addr, bool is_ret);
void DoFinalize();

void Instrument_IMG(IMG img, void* v);
void Instrument_TRC(TRACE trace, void *v);


// Memory Read Write Helper
void ClearMemoryPageWrite();
void ClearMemoryPageExecute();
bool SetMemoryPageWrite(ADDRINT addr);
size_t GetMemoryPageWrite(ADDRINT addr);
bool SetMemoryPageExecute(ADDRINT addr);
size_t GetMemoryPageExecute(ADDRINT addr);

// Dump Related
set<string> kernel32_funcs;

struct IAT_INFO {
	ADDRINT addr;
	ADDRINT func_addr;
	string func_name;
	string dll_name;
	string ToString() {
		stringstream ss;
		ss << '[' << toHex(addr) << "," << toHex(func_addr) << "," << func_name << "," << dll_name << ']';
		return ss.str();
	}
	const char* c_str() {
		return ToString().c_str();
	}
};

struct IAT_DLL_INFO {
	string name;
	UINT32 first_func;
	UINT32 nfunc;
	string ToString() {
		stringstream ss;
		ss << name << ' ' << toHex(first_func) << ' ' << nfunc;
		return ss.str();
	}
	const char* c_str() {
		return ToString().c_str();
	}
};


struct REL_INFO {
	UINT32 pageRVA;
	UINT32 blkSize;
	std::vector<UINT16>* reldata;
};

struct FN_INFO {
	string dll;
	string fn;
};

struct OFFSET_AND_SIZE {
	ADDRINT offset;
	size_t size;
};

void FindObfuscatedAPIJumps();
void FindObfuscatedAPICalls();
bool FindIAT();
void ReconstructImpList();
void ResolveForwardedFunc(vector<IAT_INFO>& imp_list);
FN_INFO ResolveForwardedFunc(string fn_name, string mod_name);
void PrintIATArea();

void FixMemoryProtection();
void FixIAT();
void FixCall();
void DumpUnpackedFile();
void DumpUnpackedFile_Overlay();

void ReadIntermediateResult(string filename);
void WriteIntermediateResult(string filename);

void KeepHeader();
void* MakeImportSection(UINT32* size, UINT32* idt_size, UINT32 vloc);

void GetImportComponentSize(UINT32* iidsize0, UINT32* iltsize0, UINT32* iinsize0);
void MakeDllList();

void PutQWORD(ADDRINT addr, UINT64 val);
void PutDWORD(ADDRINT addr, UINT32 val);
void PutWord(ADDRINT addr, UINT16 val);
void PutXWORD(ADDRINT addr, ADDRINT val);
void PutBytes(ADDRINT dst, ADDRINT src, int len);

UINT64 GetQWORD(ADDRINT addr, ADDRINT* paddr);
UINT32 GetDWORD(ADDRINT addr, ADDRINT* paddr);
UINT16 GetWord(ADDRINT addr, ADDRINT* paddr);
void GetBytes(ADDRINT dst, ADDRINT src, int len);


ADDRINT Align(ADDRINT dwValue, ADDRINT dwAlign);
void DumpData(const char* fname, ADDRINT start, UINT32 size);

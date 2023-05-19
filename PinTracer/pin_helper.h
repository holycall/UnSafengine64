// Common Pin Analyzer Helper Tools 
// Seokwoo Choi

#ifndef PIN_ANALYZER_HELPER
#define PIN_ANALYZER_HELPER

#include <string>
#include "pin.H"
#include <set>
#include <map>
extern "C" {
#include "xed-interface.h"
}


// ===============================================================================================
// Architecture 32/64
// ===============================================================================================
#ifdef TARGET_IA32
constexpr auto ADDRSIZE = 4;
#else
constexpr auto ADDRSIZE = 8;
#endif


// ===============================================================================================
// String Utility
// ===============================================================================================
#define toHex4(val) StringHex(val, 8, false)
#define toHex8(val) hexstr(val, 8).substr(2)
#define	toHex1(val) StringHex(val, 2, false)

#ifdef TARGET_IA32
#define	toHex(val) toHex4(val)
#elif TARGET_IA32E
#define	toHex(val) toHex8(val)
#endif

#define TO_LOWER(str) transform(str.begin(), str.end(), str.begin(), [](unsigned char c) { return std::tolower(c); })

ADDRINT buf2val(UINT8* buf, size_t n);

using std::vector;
using std::map;
using std::set;
using std::transform;
using std::pair;
using std::stringstream;
using std::istringstream;
using std::hex;
using std::string;
using std::endl;
using std::ostream;
using std::ofstream;
using std::ifstream;
using std::ios;
using std::copy;



// ===============================================================================================
// File IO 
// ===============================================================================================
extern ostream* fout;	// result output
extern PIN_LOCK lock;	// pin lock
extern map<ADDRINT, string> asmcode_m;	// code cache



// ===============================================================================================
// ADDRINT utility
// ===============================================================================================
#define TO_ADDRINT(buf) (*static_cast<const ADDRINT*>(static_cast<const void*>(buf)))
#define TO_UINT32(buf) (*static_cast<const UINT32*>(static_cast<const void*>(buf)))
#define ADDRINT_TO_BYTES(val, buf) copy(static_cast<const UINT8*>(static_cast<const void*>(&val)), static_cast<const UINT8*>(static_cast<const void*>(&val)) + ADDRSIZE, buf)


// ===============================================================================================
// Symbol information
// ===============================================================================================
enum ModuleType {
	mod_type_exe, mod_type_dll, mod_type_other
};

// function info
struct FunctionInfo {
	string module_name;
	string name;
	ADDRINT saddr, eaddr;
	set<ADDRINT> obf_addrs;	// for checking obfuscated code writing
	string GetDetailedName();
	FunctionInfo(string m, string n, ADDRINT sa, ADDRINT ea);
	bool operator==(const FunctionInfo&) const;
	bool operator!=(const FunctionInfo&) const;
};


// region info
struct RegionInfo {
	ADDRINT addr;
	size_t size;
	RegionInfo(ADDRINT sa, ADDRINT sz) :addr(sa), size(sz) {};
	bool operator==(const RegionInfo&) const;
	bool operator!=(const RegionInfo&) const;
	bool in(ADDRINT addr);
};

// section info
struct SectionInfo {
	string module_name;
	string name;
	ADDRINT saddr, eaddr;
	SectionInfo(string m, string n, ADDRINT sa, ADDRINT ea) :module_name(m), name(n), saddr(sa), eaddr(ea) {};
	bool operator==(const SectionInfo&) const;
	bool operator!=(const SectionInfo&) const;
};

// module info
struct ModuleInfo {
	string name;
	string path;
	ModuleType type;
	ADDRINT saddr, eaddr;
	vector<SectionInfo*> sec_infos;
	vector<FunctionInfo*> fn_infos;
	FunctionInfo* get_function(ADDRINT addr);
	bool isDLL() {
		return (type == mod_type_dll);
	}
	bool isEXE() {
		return (type == mod_type_exe);
	}
	ModuleInfo(string p, ADDRINT sa, ADDRINT ea);
	bool operator==(const ModuleInfo&) const;
	bool operator!=(const ModuleInfo&) const;
};

// output operators
std::ostream& operator<<(std::ostream& strm, const FunctionInfo& a);
std::ostream& operator<<(std::ostream& strm, const SectionInfo& a);
std::ostream& operator<<(std::ostream& strm, const RegionInfo& a);
std::ostream& operator<<(std::ostream& strm, const ModuleInfo& a);

// information getters
ModuleInfo* GetModuleInfo(ADDRINT addr);
ModuleInfo* GetModuleInfo(string name);
RegionInfo* GetRegionInfo(ADDRINT addr);
SectionInfo* GetSectionInfo(ADDRINT addr);
SectionInfo* GetNextSectionInfo(ADDRINT addr);
FunctionInfo* GetFunctionInfoWithStartAddress(ADDRINT addr);
FunctionInfo* GetFunctionInfo(ADDRINT addr);
FunctionInfo* GetFunctionInfo(string mod_name, string fn_name);
FunctionInfo* GetFunctionInfo(ModuleInfo* mod, ADDRINT addr);
string GetAddrInfo(ADDRINT addr);


// ===============================================================================================
// XED related
// ===============================================================================================
#ifdef TARGET_IA32E
#define MMODE XED_MACHINE_MODE_LONG_64
#define STACK_ADDR_WIDTH XED_ADDRESS_WIDTH_64b
#else
#define MMODE XED_MACHINE_MODE_LEGACY_32
#define STACK_ADDR_WIDTH XED_ADDRESS_WIDTH_32b
#endif	// XED

int get_disasm(ADDRINT addr, string& res);
int get_disasm64(ADDRINT addr, string& res);
size_t check_disasm(ADDRINT addr);
size_t check_disasm2(ADDRINT addr);
bool check_ins_valid(ADDRINT addr);

#endif
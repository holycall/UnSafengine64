// Common Pin Analyzer Tools 
// - Symbol Info Utility
// 2015.04.25. 
// seogu.choi@gmail.com

#include "pin_helper.h"
#include <sstream>
extern "C" {
#include "xed-interface.h"
}

using std::string;
using std::map;

std::ostream* fout;
PIN_LOCK lock;	// pin lock
map<ADDRINT, string> asmcode_m;	// code cache


// region info 
vector<RegionInfo*> region_info_v;

// module info 
map<string, ModuleInfo*> module_info_m;
map<ADDRINT, ModuleInfo*> module_info_m1;

// function info
map<ADDRINT, FunctionInfo*> fn_info_m;
map<pair<string, string>, FunctionInfo*> fn_str_2_fn_info;


FunctionInfo::FunctionInfo(string m, string n, ADDRINT sa, ADDRINT ea) :module_name(m), name(n), saddr(sa), eaddr(ea) {
	fn_info_m[sa] = this;
	auto mod = GetModuleInfo(m);
	if (mod) {
		mod->fn_infos.push_back(this);
	}
};

// output operators
std::ostream& operator<<(std::ostream& strm, const FunctionInfo& a) {
	return strm << a.module_name << ":" << a.name << "[" << toHex(a.saddr) << "," << toHex(a.eaddr) << "]";
}

string FunctionInfo::GetDetailedName() {
	return module_name + ":" + name;
}

std::ostream& operator<<(std::ostream& strm, const SectionInfo& a) {
	return strm << a.name << "[" << toHex(a.saddr) << "," << toHex(a.eaddr) << "]";
}

std::ostream& operator<<(std::ostream& strm, const RegionInfo& a) {
	return strm << toHex(a.addr) << " " << a.size;
}

std::ostream& operator<<(std::ostream& strm, const ModuleInfo& a) {
	return strm << a.path << "[" << toHex(a.saddr) << "," << toHex(a.eaddr) << "]";
}

FunctionInfo* ModuleInfo::get_function(ADDRINT addr)
{
	for (auto fn : fn_infos) {
		if (fn->saddr >= addr && addr < fn->eaddr) {
			return fn;
		}
	}
	return nullptr;
}

ModuleInfo::ModuleInfo(string p, ADDRINT sa, ADDRINT ea) :path(p), saddr(sa), eaddr(ea) {
	size_t pos = p.rfind("\\") + 1;
	name = p.substr(pos);
	TO_LOWER(name);
	if (name.find(".exe") != string::npos) type = mod_type_exe;
	else if (name.find(".dll") != string::npos) type = mod_type_dll;
	else type = mod_type_other;
	module_info_m[name] = this;
	for (ADDRINT i = sa / 0x1000; i < ea / 0x1000; i++) {
		module_info_m1[i] = this;
	}
}

ModuleInfo* GetModuleInfo(ADDRINT addr)
{
	return module_info_m1[addr / 0x1000];
}

ModuleInfo* GetModuleInfo(string name)
{
	return module_info_m[name];
}

RegionInfo* GetRegionInfo(ADDRINT addr)
{
	for (auto reginfo : region_info_v)
	{
		if (addr >= reginfo->addr && addr < reginfo->addr + reginfo->size) return reginfo;
	}
	return NULL;
}

SectionInfo* GetSectionInfo(ADDRINT addr)
{
	ModuleInfo* modinfo = GetModuleInfo(addr);
	if (modinfo == NULL) return NULL;
	for (const auto& secinfo : modinfo->sec_infos)
	{
		if (addr >= secinfo->saddr && addr < secinfo->eaddr)
		{
			return secinfo;
		}
	}
	return NULL;
}


SectionInfo* GetNextSectionInfo(ADDRINT addr)
{
	ModuleInfo* modinfo = GetModuleInfo(addr);
	if (modinfo == NULL) return NULL;

	bool found = false;
	for (const auto& secinfo : modinfo->sec_infos)
	{
		if (addr >= secinfo->saddr && addr < secinfo->eaddr)
		{
			found = true;
			continue;
		}
		if (found) {
			return secinfo;
		}
	}
	return NULL;
}


FunctionInfo* GetFunctionInfoWithStartAddress(ADDRINT addr)
{
	ModuleInfo* modinfo = GetModuleInfo(addr);
	if (modinfo == NULL) return NULL;
	if (fn_info_m.find(addr) != fn_info_m.end())
	{
		return fn_info_m[addr];
	}
	return NULL;
}

FunctionInfo* GetFunctionInfo(ADDRINT addr)
{
	auto mod = GetModuleInfo(addr);
	if (mod) {
		return mod->get_function(addr);;
	}
	return nullptr;
}


FunctionInfo* GetFunctionInfo(ModuleInfo* mod, ADDRINT addr)
{
	return mod->get_function(addr);
}


FunctionInfo* GetFunctionInfo(string mod_name, string fn_name)
{
	const auto it = fn_str_2_fn_info.find(make_pair(mod_name, fn_name));
	if (it == fn_str_2_fn_info.end()) return nullptr;
	return it->second;
}


string GetAddrInfo(ADDRINT addr)
{
	stringstream res;

	ModuleInfo* modinfo = GetModuleInfo(addr);
	if (modinfo != NULL)
	{
		res << (modinfo->name);
		const SectionInfo* secinfo = GetSectionInfo(addr);
		const FunctionInfo* fninfo = GetFunctionInfoWithStartAddress(addr);

		if (secinfo != NULL)
		{
			res << ':' << secinfo->name;
		}
		else {
			res << ':';
		}

		if (fninfo != NULL)
		{
			res << ':' << fninfo->name;
		}
		else {
			res << ':';
		}
	}
	return res.str();
}


/// <summary> Try disassemble at the address and return the length of the disassembled instruciton. </summary>
int get_disasm(ADDRINT addr, string& res)
{

#if defined(TARGET_IA32E)
	static const xed_state_t dstate = { XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b };
#else
	static const xed_state_t dstate = { XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b };
#endif
	xed_decoded_inst_t xedd;
	xed_decoded_inst_zero_set_mode(&xedd, &dstate);

	const unsigned int max_inst_len = 15;

	xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(addr), max_inst_len);
	BOOL xed_ok = (xed_code == XED_ERROR_NONE);
	if (xed_ok) {
		char buf[2048];

		bool ok = xed_format_context(XED_SYNTAX_INTEL, &xedd, buf, 2048, addr, 0, 0);
		if (ok) {
			res = string(buf);
			return xed_decoded_inst_get_length(&xedd);
		}
	}
	return 0;
}


int get_disasm64(ADDRINT addr, string& res)
{
	static const xed_state_t dstate = { XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b };
	xed_decoded_inst_t xedd;
	xed_decoded_inst_zero_set_mode(&xedd, &dstate);

	const unsigned int max_inst_len = 15;

	xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(addr), max_inst_len);
	BOOL xed_ok = (xed_code == XED_ERROR_NONE);
	if (xed_ok) {
		char buf[2048];

		bool ok = xed_format_context(XED_SYNTAX_INTEL, &xedd, buf, 2048, addr, 0, 0);
		if (ok) {
			res = string(buf);
			return xed_decoded_inst_get_length(&xedd);
		}
	}
	return 0;
}




size_t check_disasm2(ADDRINT addr)
{
	static bool xed_ok, ok;
	static const unsigned int max_inst_len = 15;
	static xed_error_enum_t xed_code;
	static xed_decoded_inst_t xedd;
	static char buf[2048];
#if defined(TARGET_IA32E)
	static const xed_state_t dstate = { XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b };
#else
	static const xed_state_t dstate = { XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b };
#endif

	size_t num_check_pass = 0;
	ADDRINT check_addr;

	xed_decoded_inst_zero_set_mode(&xedd, &dstate);
	xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(addr), max_inst_len);
	if (xed_code != XED_ERROR_NONE) {
		return 0;
	}

	// check start	
	for (ADDRINT check_start_addr = addr - 50; check_start_addr < addr - 40; check_start_addr++) {
		check_addr = check_start_addr;
		while (check_addr < addr) {
			LOG("Checking:" + toHex(check_addr) + "\n");
			xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(check_addr), max_inst_len);
			if (xed_code == XED_ERROR_NONE) {
				check_addr += xed_decoded_inst_get_length(&xedd);
				if (check_addr == addr) {
					num_check_pass++;
				}
			}
			else {
				break;
			}

		}
	}

	return num_check_pass;
}



/// <summary> Try disassemble at the address and return the length of the disassembled instruction. </summary>
size_t check_disasm(ADDRINT addr)
{

#if defined(TARGET_IA32E)
	static const xed_state_t dstate = { XED_MACHINE_MODE_LONG_64, XED_ADDRESS_WIDTH_64b };
#else
	static const xed_state_t dstate = { XED_MACHINE_MODE_LEGACY_32, XED_ADDRESS_WIDTH_32b };
#endif
	xed_decoded_inst_t xedd;
	xed_decoded_inst_zero_set_mode(&xedd, &dstate);

	const unsigned int max_inst_len = 15;

	xed_error_enum_t xed_code = xed_decode(&xedd, reinterpret_cast<UINT8*>(addr), max_inst_len);
	BOOL xed_ok = (xed_code == XED_ERROR_NONE);
	if (xed_ok) {
		char buf[2048];

		bool ok = xed_format_context(XED_SYNTAX_INTEL, &xedd, buf, 2048, 0, 0, 0);
		if (ok) {
			return xed_decoded_inst_get_length(&xedd);
		}
	}
	return 0;
}

/// <summary> Check the instruction is correctly disassembled. 
/// Disassemble from certain bytes before the address and check whether the address is disassembled correctly. 
/// </summary>
bool check_ins_valid(ADDRINT addr)
{
	ADDRINT currAddr = addr - 20;
	size_t ins_len;
	while (currAddr < addr) {
		ins_len = check_disasm(currAddr);
		if (ins_len == 0)
		{
			currAddr++;
			continue;
		}
		currAddr += ins_len;
	}
	if (currAddr == addr && check_disasm(currAddr) != 0) {
		return true;
	}
	return false;
}

bool ModuleInfo::operator==(const ModuleInfo& m) const
{
	return saddr == m.saddr;
}

bool SectionInfo::operator==(const SectionInfo& s) const
{
	return s.saddr == saddr;
}

bool RegionInfo::operator==(const RegionInfo& r) const
{
	return r.addr == addr;
}

bool FunctionInfo::operator==(const FunctionInfo& f) const
{
	return f.saddr == saddr;
}

bool ModuleInfo::operator!=(const ModuleInfo& m) const
{
	return saddr != m.saddr;
}

bool SectionInfo::operator!=(const SectionInfo& s) const
{
	return s.saddr != saddr;
}

bool RegionInfo::operator!=(const RegionInfo& r) const
{
	return r.addr != addr;
}

bool RegionInfo::in(ADDRINT a)
{
	return a >= addr && a < addr + size;
}

bool FunctionInfo::operator!=(const FunctionInfo& f) const
{
	return f.saddr != saddr;
}


ADDRINT buf2val(UINT8* buf, size_t n) {
	ADDRINT addr = buf[n - 1];
	for (int i = n - 2; i >= 0; i--) {
		addr = (addr << 8) | buf[i];
	}
	return addr;
}
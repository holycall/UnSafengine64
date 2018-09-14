// Common Pin Analyzer Tools 
// - Symbol Info Utility
// 2015.04.25. 
// seogu.choi@gmail.com

#include "PinSymbolInfoUtil.h"
#include "StrUtil.h"
#include <sstream>

// output operators
std::ostream& operator<<(std::ostream &strm, const fn_info_t &a) {
	return strm << a.module_name << ":" << a.name << "[" << toHex(a.saddr) << "," << toHex(a.eaddr) << "]";
}

string fn_info_t::detailed_name() {
	return module_name + ":" + name;
}

std::ostream& operator<<(std::ostream &strm, const sec_info_t &a) {
	return strm << a.name << "[" << toHex(a.saddr) << "," << toHex(a.eaddr) << "]";
}

std::ostream& operator<<(std::ostream &strm, const mod_info_t &a) {
	return strm << a.name << "[" << toHex(a.saddr) << "," << toHex(a.eaddr) << "]";
}


mod_info_t *GetModuleInfo(ADDRINT addr)
{
	for (auto it = module_info_m.begin(); it != module_info_m.end(); it++)
	{
		mod_info_t *modinfo = it->second;

		if (addr >= modinfo->saddr && addr < modinfo->eaddr) return modinfo;		
	}
	return NULL;
}

reg_info_t *GetRegionInfo(ADDRINT addr)
{
	for (auto it = region_info_v.begin(); it != region_info_v.end(); it++)
	{
		reg_info_t *reginfo = *it;

		if (addr >= reginfo->addr && addr < reginfo->addr + reginfo->size) return reginfo;
	}
	return NULL;
}

sec_info_t *GetSectionInfo(ADDRINT addr)
{	
	mod_info_t *modinfo = GetModuleInfo(addr);
	if (modinfo == NULL) return NULL;

	for (auto it = modinfo->sec_infos.begin(); it != modinfo->sec_infos.end(); it++)
	{
		sec_info_t *secinfo = *it;

		if (addr >= secinfo->saddr && addr < secinfo->eaddr)
		{
			return secinfo;
		}
	}

	return NULL;
}


sec_info_t *GetNextSectionInfo(ADDRINT addr)
{
	mod_info_t *modinfo = GetModuleInfo(addr);
	if (modinfo == NULL) return NULL;

	bool found = false;
	for (auto it = modinfo->sec_infos.begin(); it != modinfo->sec_infos.end(); it++)
	{
		sec_info_t *secinfo = *it;

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


fn_info_t *GetFunctionInfo(ADDRINT addr)
{
	mod_info_t *modinfo = GetModuleInfo(addr);
	if (modinfo == NULL) return NULL;

	if (fn_info_m.find(addr) != fn_info_m.end())
	{
		return fn_info_m[addr];
	}

	for (auto it = modinfo->fn_infos.begin(); it != modinfo->fn_infos.end(); it++)
	{
		fn_info_t *fninfo = *it;

		if (addr >= fninfo->saddr && addr < fninfo->eaddr)
		{
			return fninfo;
		}
	}
	return NULL;
}

fn_info_t *GetFunctionInfo(string mod_name, string fn_name)
{		
	auto it = fn_str_2_fn_info.find(make_pair(mod_name, fn_name));
	if (it == fn_str_2_fn_info.end()) return nullptr;
	return it->second;
}

fn_info_t *GetFunctionInfo(mod_info_t *modinfo, ADDRINT addr)
{	
	if (modinfo == NULL) return NULL;

	for (auto it = modinfo->fn_infos.begin(); it != modinfo->fn_infos.end(); it++)
	{
		fn_info_t *fninfo = *it;

		if (addr >= fninfo->saddr && addr < fninfo->eaddr)
		{
			return fninfo;
		}
	}
	return NULL;
}




string GetAddrInfo(ADDRINT addr)
{
	stringstream res;

	mod_info_t *modinfo = GetModuleInfo(addr);
	if (modinfo != NULL) 
	{
		res << (modinfo->name);
		sec_info_t *secinfo = GetSectionInfo(addr);
		fn_info_t *fninfo = GetFunctionInfo(modinfo, addr);

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

		// set the runtime adddress for disassembly 
		xed_uint64_t runtime_address = static_cast<xed_uint64_t>(addr);

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


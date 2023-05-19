#include "themida_deobfuscator.h"

namespace NW {
#include <Windows.h>
}

#include "ucrtdll.h"
#include "external_function_reader.h"

#include "dbgsymbol_helper.h"


enum class InsType {
	kOTHER,
	kRET,
	kPOPF,	
};


std::ostream& operator<<(std::ostream& strm, const InsType& a) {
	switch (a) {
	case InsType::kRET: return strm << "RET";
	case InsType::kPOPF: return strm << "POPF";
	}
	return strm << "UNDEFINED";
}

#define LOG_TRACE 0

/* ================================================================== */
// Global variables 
/* ================================================================== */

// thread control
size_t thr_cnt;
set<size_t> thread_ids;
PIN_THREAD_UID main_thread_uid;

// internal threads
VOID UnpackThread(VOID* arg);	// unpack thread (main internal thread)
CONTEXT ctx0;

// trace cache
map<ADDRINT, vector<ADDRINT>*> trace_cache_m;
map<ADDRINT, ADDRINT> trace_next_addr_m;


// Buffer
UINT8 memory_buffer[1024 * 1024 * 100];	// code cache buffer size is 100MB


ADDRINT obf_dll_entry_addr;	// themida dll entry address

// dll loader information for obfuscated dll analysis
ADDRINT loader_saddr = 0;
ADDRINT loader_eaddr = 0;

bool dll_is_unpack_started = false;	// dll unpack started

// a copy of original pe header when the image is loaded
void* hdr_at_load;



// trace related variables
ModuleInformation* prevmod;	// previous module
bool except_1;

/////////////////////////////////////////////////////////////////
// KNOB related flags

string packer_type = "themida";

// main file name
string main_file_name = "";

// obfuscated DLL name
string obf_dll_name = "";


/////////////////////////////////////////////////////////////////
// region info 
vector<RegionInformation*> region_info_v;

// module info 
map<string, ModuleInformation*> module_info_m;

// function info
map<ADDRINT, FunctionInformation*> fn_info_m;
map<pair<string, string>, FunctionInformation*> fn_str_2_fn_info;

// runtime function info
FunctionInformation* current_obf_fn = NULL;

// map from obfuscated function into original function
// this map is used for below two purposes
// 1. Because Themida x86 obfuscated API functions in newly allocated memory area, 
//    obfaddr2fn maps obfuscated code address to original API function. 
// 2. Because Themida and Vmprotect obfuscate Virtual call table and API jump targets, 
//    obfaddr2fn maps obfuscated api addresses to original API function. 
//
map<ADDRINT, FunctionInformation*> obfaddr2fn;

// map from obfuscated function into original function of 'mov esi, api' obfuscation
map<ADDRINT, FunctionInformation*> mov_obfaddr2fn;

// map from obfuscated address to original address in IAT
map<ADDRINT, ADDRINT> addr2fnaddr;


// obfuscated call instruction address and target address
// obf_call_candidate_address is a tuple of <call instruction address, opcode bytes, target address>
// opcode bytes are stored in ADDRINT type as follows 
// 
// call type 
// - direct_call : direct call. E8 __ __ __ __  
//   (relative addressing for x86)
// - indirect_call : indirect call using IAT. FF 15 __ __ __ __. call ds:[______] 
//                   ex) FF 15 dd cc bb aa -> call ds:[0xaabbccdd] 
//                      (absolute addressing to indirect address for x86)
//                   ex) FF 15 dd cc bb aa -> call ds:[0xaabbccdd + next_ip] 
//                      (relative addressing to indirect address for x64)
// - indirect_jmp : indirect jmp using IAT. FF 25 __ __ __ __. jmp ds:[______] 
//                  ex) FF 2F dd cc bb aa -> jmp ds:[0xaabbccdd]
//                  (absolute addressing to indirect address)
//                  ex) FF 15 dd cc bb aa -> jmp ds:[0xaabbccdd + next_ip] 
//                     (relative addressing to indirect address for x64)
// - indirect_mov : indirect mov using IAT. 
//     a1 : mov eax, ds : [¡¦]
//     8b 05 : mov eax, ds : [¡¦]
//     8b 1d : mov ebx, ds : [¡¦]
//     8b 0d : mov ecx, ds : [¡¦]
//     8b 15 : mov edx, ds : [¡¦]
//     8b 35 : mov esi, ds : [¡¦]
//     8b 3d : mov edi, ds : [¡¦]
//    (absolute addressing to indirect address for x86)
//
//     48 8b 05 : mov rax, ds : [¡¦]
//     48 8b 1d : mov rbx, ds : [¡¦]
//     48 8b 0d : mov rcx, ds : [¡¦]
//     48 8b 15 : mov rdx, ds : [¡¦]
//     48 8b 35 : mov rsi, ds : [¡¦]
//     48 8b 3d : mov rdi, ds : [¡¦]
//    (relative addressing to indirect address for x64)
//



extern ostream* fout;	// result output
extern PIN_LOCK lock;	
extern map<ADDRINT, string> asmcode_m;	// code cache

// file information
ADDRINT file_size;

// flags for analysis
BOOL is_mem_dump;
BOOL is_direct_call;
bool is_dll_analysis = false;

// obfuscated module information
ModuleInformation* main_img_info;	// main image
ADDRINT main_image_start_address = 0;	// section start address where eip is changed into 
ADDRINT main_image_end_address = 0;
ADDRINT main_text_section_start_address = 0;	// section start address where eip is changed int 
ADDRINT main_text_section_end_address = 0;
ADDRINT main_vmp_section_start_address = 0;	// section start address where eip is changed int 
ADDRINT main_vmp_section_end_address = 0;


inline bool IsMainImage(ADDRINT address) {
	return (address >= main_image_start_address && address < main_image_end_address);
}

inline bool IsMainImageTextSection(ADDRINT address) {
	return(address >= main_text_section_start_address && address < main_text_section_end_address);
}

inline bool IsMainImageVMPSection(ADDRINT address) {
	return(address >= main_vmp_section_start_address && address < main_vmp_section_end_address);
}

ADDRINT obf_rdata_saddr = 0;	// section start address after .text section
ADDRINT obf_rdata_eaddr = 0;	// Added to keep compatibility with VMP deobfuscator

ADDRINT obf_idata_saddr = 0;	// idata start
ADDRINT obf_idata_eaddr = 0;	// idata end

ADDRINT oep = 0;	// oep of unpacked executable


// obfuscated call candidates & obfuscated calls
vector<ObfuscatedCall> obf_call_candidates;
vector<ObfuscatedCall> obf_calls;

RunUntilAPIFunctionStatus run_until_api_function_status;


// When run_until_api_function_status is kCheckNextFunction, 
// API deobfuscation of an API call candidate starts. 
// the address of the context becomes the API call candidate address, 
// then the current status becomes kCheckCurrentFunction
// 
// When run_until_api_function_status is kCheckCurrentFunction,
// the instructions are executed following the control flows 
// until the IP reaches any API function or exception occurs or the number of instructions reaches the limit. 

size_t curr_obf_fn_pos = 0;	
size_t curr_obf_iat_pos = 0;

ObfuscatedCall* curr_obf_call;
ObfuscatedIATElement* curr_obf_iat_elem;

// IAT information
ADDRINT imp_start_addr = 0;
ADDRINT imp_end_addr = 0;
bool found_IAT = false;
bool found_zero_blk = false;

std::ostream& operator<<(std::ostream& strm, const IAT_INFO& a) {
	return strm << '[' << toHex(a.addr) << "," << toHex(a.func_addr) << "," << a.func_name << "," << a.dll_name << ']';
}


std::ostream& operator<<(std::ostream& strm, const IAT_DLL_INFO& a) {
	return strm << a.name << ' ' << toHex(a.first_func) << ' ' << a.nfunc;
}

map<ADDRINT, IAT_INFO> iat_elem_by_addr;
vector<IAT_DLL_INFO> dll_list;


// Run until API trace recording
vector<ADDRINT> trace_address_sequence;
vector<ADDRINT> trace_stack_pointer_sequence;
map<REG, pair<ADDRINT, string>> register_to_value_API_function_name;


#define RECORDTRACE 1


// registers used for obfuscation
#ifdef TARGET_IA32
REG regs_for_obfuscation[] = { REG_EAX, REG_EBX, REG_ECX, REG_EDX, REG_ESI, REG_EDI };
REG regs_ctx[] = { REG_EAX, REG_EBX, REG_ECX, REG_EDX, REG_ESI, REG_EDI, REG_ESP, REG_EBP };
#elif TARGET_IA32E
REG regs_for_obfuscation[] = { REG_RAX, REG_RBX, REG_RCX, REG_RDX, REG_RSI, REG_RDI };
REG regs_ctx[] = { REG_RAX, REG_RBX, REG_RCX, REG_RDX, REG_RSI, REG_RDI, REG_RSP, REG_RBP,
	REG_R8, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15, };
#endif	
map<REG, ADDRINT> regs_saved;


// Two Step Deobufscation
size_t no_stage = 0;
string ir_file;
bool skip_until_oep = false;


/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,  "pintool", "o", "result.txt", "specify file name for the result");
KNOB<BOOL> KnobDump(KNOB_MODE_WRITEONCE, "pintool", "dump", "", "save memory dump");
KNOB<string> KnobDLLFile(KNOB_MODE_WRITEONCE, "pintool", "dll", "", "specify packed dll file");
KNOB<string> KnobPackerType(KNOB_MODE_WRITEONCE, "pintool", "packer", "themida", "packer type: tmd2, tmd3, vmp or enigma");
KNOB<BOOL> KnobDirectCall(KNOB_MODE_WRITEONCE, "pintool", "direct", "", "direct call");
KNOB<size_t> KnobMultiStage(KNOB_MODE_WRITEONCE, "pintool", "multistage", "0", "multi-stage deobfuscation");


// =========================================================================
// memory section write & execute check by block
// ==========================================================================
	
// memory write set
set<ADDRINT> mwaddrs;

// #define DEBUG 2
#define MAX_BLOCKS 100000	// Maximum File Size : 50MB assuming that default file alignment is 512 bytes (= 0.5kB)
#define BLOCK_SIZE 512
size_t mwblocks[MAX_BLOCKS];
size_t meblocks[MAX_BLOCKS];


// register save & restore
void RestoreRegisters(LEVEL_VM::CONTEXT * ctxt)
{
	for (const REG reg : regs_ctx) {
		PIN_SetContextReg(ctxt, reg, regs_saved[reg]);
	}
}

void SaveRegisters(LEVEL_VM::CONTEXT * ctxt)
{
	for (const REG reg : regs_ctx) {
		regs_saved[reg] = PIN_GetContextReg(ctxt, reg);
	}
}

string PrintRegisters(LEVEL_VM::CONTEXT* ctxt) 
{
	stringstream r;
	for (REG reg : regs_ctx) {
		r << REG_StringShort(reg) << ':' << toHex(PIN_GetContextReg(ctxt, reg)) << endl;
	}
	return r.str();
}


// currently assume that only one register is used for storing API function address
// TODO: multiple registers may contain API function addresses
REG GetRegisterAssignedWithAPIFunctionAddress(LEVEL_VM::CONTEXT* ctxt)
{
	REG set_api_reg = REG_INVALID_;
	for (REG reg : regs_for_obfuscation) {
		ADDRINT reg_val = PIN_GetContextReg(ctxt, reg);
		FunctionInformation* fn = GetFunctionInfo(reg_val);
		DLOG(LogType::kLOG_CALL_CHECK, "# MOV " << REG_StringShort(reg) << ' ' << toHex(reg_val));
		if (fn)
		{
			set_api_reg = reg;
			register_to_value_API_function_name[reg] = make_pair(reg_val, fn->GetDetailedName());
			DLOG(LogType::kLOG_CALL_CHECK, fn);
		}
		DLOG(LogType::kLOG_CALL_CHECK, "\n");
	}
	return set_api_reg;
}


void ClearMemoryPageWrite()
{
	memset(mwblocks, 0, MAX_BLOCKS);
}

void ClearMemoryPageExecute()
{
	memset(meblocks, 0, MAX_BLOCKS);
}


// memory write check
bool SetMemoryPageWrite(ADDRINT addr)
{
	size_t idx = (addr - main_image_start_address) / BLOCK_SIZE;
	if (idx > MAX_BLOCKS) return false;

	// if this block is previously executed, set meblock to zero
	if (meblocks[idx] > 0) 
	{
		meblocks[idx] = 0;
		// *fout << "# "  << toHex(addr) << " is rewritten after execution." << endl;
	}

	mwblocks[idx]++;
	return true;
}

size_t GetMemoryPageWrite(ADDRINT addr)
{
	size_t idx = (addr - main_image_start_address) / BLOCK_SIZE;
	if (idx > MAX_BLOCKS) return false;
	return mwblocks[idx];
}

// memory execute check
bool SetMemoryPageExecute(ADDRINT addr)
{
	size_t idx = (addr - main_image_start_address) / BLOCK_SIZE;
	if (idx > MAX_BLOCKS) return false;		
	meblocks[idx]++;
	return true;
}

size_t GetMemoryPageExecute(ADDRINT addr)
{
	size_t idx = (addr - main_image_start_address) / BLOCK_SIZE;
	if (idx > MAX_BLOCKS) return false;
	return meblocks[idx];
}


///////////////////////
static PIN_THREAD_UID unpack_thread_uid;
static PIN_THREAD_UID resolve_api_thread_uid;
PIN_SEMAPHORE sem_oep_found;
PIN_SEMAPHORE sem_resolve_api_end;
PIN_SEMAPHORE sem_unpack_finished;
PIN_SEMAPHORE sem_dump_finished;

///////////////////////



// ========================================================================================================================
// API Detection Functions 
// ========================================================================================================================

/// Find obfuscated API jumps 
///
/// Pattern 1: API wrapping
/// call API_Jmp	E8 ...
/// ...
/// jmp API_Function	E9 ...   (jump relative. obfuscated)
/// <==
/// call API_Jmp	E8 ...
/// ...
/// jmp API_Function	FF 25 ...    (jmp indirect)
///
/// Pattern 2: Virtual Call
/// 
/// virtual_call_1: jmp API_Jmp		E9 __ __ __ __  (jump relative. obfuscated)
///                 db 0x__         __ (garbage byte)        
/// virtual_call_2: NOP; jmp API_Jmp    90 E9 ... (jump relative. obfuscated) 
/// ... 
/// offset virtual_call_1
/// offset virtual_call_2
/// ...
void FindObfuscatedAPIJumps() {
	// only 32bit
	if (ADDRSIZE == 8) return;

	size_t scan_area_size = main_text_section_end_address - main_text_section_start_address;
	UINT8* buf = (UINT8*)malloc(scan_area_size);
	size_t idx, idx2;
	ADDRINT iat_start_addr = 0, iat_size = 0;

	SectionInformation* current_section = NULL, * target_section = NULL;

	unsigned char* pc = reinterpret_cast<unsigned char*>(main_text_section_start_address);

	// buf has executable memory image
	EXCEPTION_INFO* pExinfo = NULL;

	size_t num_copied = PIN_SafeCopyEx(buf, pc, scan_area_size, pExinfo);	
	DLOG(LogType::kLOG_CALL_CHECK, "Searching for call to Obfuscated jmp and offset to Obfuscated jmp\n");

	// pattern 1: 
	// search for address modification in program
	ADDRINT call_src, call_dst, jmp_src, jmp_dst;
	size_t num_redirection; 
	size_t call_search_size;
	if (packer_type == "vmp") {
		call_search_size = imp_start_addr - main_text_section_start_address;
	}
	else {
		call_search_size = num_copied;
	}
	if (num_copied < call_search_size) call_search_size = num_copied;

	DLOG(LogType::kLOG_CALL_CHECK, "call search size: " << toHex(call_search_size) << endl);
	DLOG(LogType::kLOG_CALL_CHECK, "scan size: " << toHex(num_copied) << endl);

	for (idx = 0; idx < call_search_size - 6; idx++)
	{
		// check call to api jmp table
		if (buf[idx] == 0xE8) {			
			call_src = main_text_section_start_address + idx;
			call_dst = call_src + 5 + TO_UINT32(buf + idx + 1);

			DLOG(LogType::kLOG_DUMP, "Call " << toHex(call_src) << " -> " << toHex(call_dst) << endl);
			// *fout << "# Call " << toHex(call_src) << "->" << toHex(call_dst) << endl;

			// check api jmp and wrapped api jmp
			if (call_dst > call_src && call_dst < main_text_section_end_address) {				
				idx2 = call_dst - main_text_section_start_address;
				
				// jmp or NOP; jmp  
				// or  				
				// one more wrapping
				num_redirection = 0;
				while (buf[idx2] == 0xE9 || buf[idx2] == 0x90 && buf[idx2 + 1] == 0xE9) {
					num_redirection++;
					jmp_src = main_text_section_start_address + idx2;
					if (buf[idx2] == 0xE9) {
						jmp_dst = jmp_src + 5 + TO_UINT32(buf + idx2 + 1);
					}
					else {
						jmp_dst = jmp_src + 6 + TO_UINT32(buf + idx2 + 2);
					}

					DLOG(LogType::kLOG_DUMP, "Jmp " << toHex(jmp_src) << " -> " << toHex(jmp_dst) << endl);
					// one more wrapping
					if (jmp_dst > jmp_src && jmp_dst < main_text_section_end_address) {
						idx2 = jmp_dst - main_text_section_start_address;
						continue;
					}

					break;
				}

				if (num_redirection >= 1 && num_redirection <= 2) {
					// check api for themida redirection
					FunctionInformation* fn = GetFunctionInfo(jmp_dst);
					if (fn == NULL) {
						auto it = obfaddr2fn.find(jmp_dst);
						if (it == obfaddr2fn.end()) continue;
						fn = it->second;
					}					
					// add_obfuscated_call_candidates(jmp_src, fn->saddr, INDIRECT_JMP, "", 0);					
					// to fix... 
					obf_calls.push_back(ObfuscatedCall(jmp_src, fn->saddr, 0, ObfuscatedCallType::kINDIRECT_JMP, "", 0));
				}
			}
		}
	}
	fout->flush();

	*fout << "# IAT end " << toHex(imp_end_addr) << endl;

	// pattern 2:
	// search for obfuscated virtual table
	// search after IAT 
	
	*fout << "# Searching for obufscated virtual table\n";

	for (idx = Align(imp_end_addr - main_text_section_start_address, 4); idx < num_copied - 6; idx+=4)
	{
		// check offset
		ADDRINT offset = TO_UINT32(buf + idx);
		if (offset >= main_text_section_start_address && offset < imp_start_addr) {
			// check api jmp
			*fout << "# Offset " << toHex(main_text_section_start_address + idx) << ' ' << toHex(offset) << endl;
			idx2 = offset - main_text_section_start_address;
			// jmp or NOP; jmp 				
			if (buf[idx2] == 0xE9) {
				jmp_dst = offset + 5 + TO_UINT32(buf + idx2 + 1);
			}
			else if (buf[idx2] == 0x90 && buf[idx2+1] == 0xE9) {
				jmp_dst = offset + 6 + TO_UINT32(buf + idx2 + 2);
			}
			else continue;

			// check api
			FunctionInformation* fn = GetFunctionInfo(jmp_dst);
			if (fn == NULL) {
				auto it = obfaddr2fn.find(jmp_dst);
				if (it == obfaddr2fn.end()) continue;
				fn = it->second;
			}
			jmp_src = offset;
			// add_obfuscated_call_candidates(jmp_src, fn->saddr, INDIRECT_JMP, "", 0);
			obf_calls.push_back(ObfuscatedCall(jmp_src, fn->saddr, 0, ObfuscatedCallType::kINDIRECT_JMP, "", 0));
		}
	}
	*fout << "# Finished scanning obfuscated API jumps\n";
	fout->flush();
}

/// Find obfuscated API Calls
void FindObfuscatedAPICalls()
{	
	size_t text_section_size = main_text_section_end_address - main_text_section_start_address;
	size_t imp_section_size = imp_end_addr - imp_start_addr;

	UINT8 *buff_text_section = (UINT8*)malloc(text_section_size);
	UINT8* buff_imp_section = (UINT8*)malloc(imp_section_size);
	size_t idx, idx2;
	ADDRINT addr, addr2, target_addr;	
	
	SectionInformation *current_section = NULL, *target_section = NULL;	
	
	unsigned char* p_text_section = reinterpret_cast<unsigned char*>(main_text_section_start_address);
	unsigned char* p_imp_section = reinterpret_cast<unsigned char*>(imp_start_addr);

	// buf has executable memory image
	EXCEPTION_INFO *pExinfo = NULL;

	size_t text_section_copied = PIN_SafeCopyEx(buff_text_section, p_text_section, text_section_size, pExinfo);
	size_t imp_section_copied = PIN_SafeCopyEx(buff_imp_section, p_imp_section, imp_section_size, pExinfo);

	// search for address modification in program	
	DLOG(LogType::kLOG_CALL_CHECK, "# Searching for Obfuscated Calls\n");
	FindObfuscatedAPIJumps();

	if (packer_type == "tmd2" || packer_type == "tmd3" || packer_type == "enigma") 
	{
		for (idx = 0; idx < text_section_copied - 6; idx++)
		{
			addr = main_text_section_start_address + idx;
			if (ADDRSIZE == 4 && packer_type == "tmd2")
			{
				// Themida x86 2.x
				// --------------
				// CALL r/m32 (FF 1F __ __ __ __)
				// is patched by Themida into
				// CALL rel32; NOP (E8 __ __ __ __ 90)
				// CALL rel32; NOP (90 E8 __ __ __ __)

				ObfuscatedCall obf_call;
				
				// *fout << toHex(main_txt_saddr + idx) << endl;
				if (buff_text_section[idx] == 0xE8) {

					if (buff_text_section[idx + 5] == 0x90) obf_call.n_prev_pad_bytes = 0;
					else if (buff_text_section[idx -1] == 0x90) obf_call.n_prev_pad_bytes = 1;
					else continue;
					obf_call.ins_type = ObfuscatedCallType::kINDIRECT_CALL;
				}
				else if (buff_text_section[idx] == 0xE9) {
					
					if (buff_text_section[idx - 1] == 0x90) obf_call.n_prev_pad_bytes = 1;
					else obf_call.n_prev_pad_bytes = 0;
					// else if (bufp[5] == 0x90) obf_call.n_prev_pad_byts = 0;
					// jmp api. not accurate heuristics. only seh
					// else if (bufp[6] == 0xcc && bufp[7] == 0xcc && bufp[8] == 0xcc && bufp[9] == 0xcc) obf_call.n_prev_pad_byts = 0;
					// else continue;
					obf_call.ins_type = ObfuscatedCallType::kINDIRECT_JMP;
				}
				else continue;

				obf_call.src = main_text_section_start_address + idx - obf_call.n_prev_pad_bytes;
				obf_call.dst = obf_call.src + 6 + TO_UINT32(buff_text_section + idx + 1);
				DLOG(LogType::kLOG_DUMP, toHex(obf_call.src) << "->" << toHex(obf_call.dst) << endl);

				FunctionInformation* fn;
				fn = GetFunctionInfo(obf_call.dst);
				if (fn == NULL) {
					if (obfaddr2fn.find(obf_call.dst) == obfaddr2fn.end())
						continue;
					fn = obfaddr2fn[obf_call.dst];
				}

				obf_call.dst = fn->saddr;								
				obf_calls.push_back(obf_call);

			}
			else if (ADDRSIZE == 4 && packer_type == "enigma") {
				// Enigma Protector x86
				// ---------------------
				// Enigma Protector preserve CALL r/m32
				// CALL [addr] (FF 15 __ __ __ __)
				// But the address points to allocated memory area
				// where the API function is copied into. 
				if (buff_text_section[idx] == 0xFF && buff_text_section[idx + 1] == 0x15)
				{
					// addr: current address
					// addr2: redirection address in bracket
					// target_addr: real API address
					SectionInformation *tmp_sec = GetSectionInfo(addr);

					if (current_section == NULL) {
						current_section = tmp_sec;
					}
					else if (current_section != tmp_sec) {
						break;
					}

					addr2 = TO_ADDRINT(buff_text_section + idx + 2);
					// *fout << toHex(addr) << " call [" << toHex(addr2) << ']' << endl;
					idx2 = addr2 - main_text_section_start_address;

					// skip malformed address
					// address should be inside the image
					if (idx2 > text_section_size) continue;
					
					target_addr = TO_ADDRINT(buff_text_section + idx2);

					// *fout << '[' << toHex(addr2) << "]=" << toHex(target_addr);

					if (obfaddr2fn.find(target_addr) != obfaddr2fn.end())
					{
						FunctionInformation *fn = obfaddr2fn[target_addr];

						string modstr = fn->module_name;
						string fnstr = fn->name;
						string reladdr = toHex(addr - main_image_start_address);
						// *fout << reladdr << "\tcall " << modstr << '\t' << fnstr << endl;
						// add_obfuscated_call_candidates(addr, target_addr, INDIRECT_CALL, "", 0);	
						obf_calls.push_back(ObfuscatedCall(addr, target_addr, 0, ObfuscatedCallType::kINDIRECT_CALL, "", 0));
					}
				}
			}
			else if (ADDRSIZE == 8)
			{
				// CALL r/m32 (FF 1F __ __ __ __)
				// is patched by Themida64 into
				// CALL rel32; db 00 (E8 __ __ __ __ ; 00)
				if (buff_text_section[idx] == 0xE8 && (buff_text_section[idx + 5] == 0x00 || buff_text_section[idx + 5] == 0x90))
				{
					addr = main_text_section_start_address + idx;
					target_addr = addr + 5 + TO_UINT32(buff_text_section + idx + 1);
					current_section = GetSectionInfo(addr);
					target_section = GetSectionInfo(target_addr);
					if (current_section == NULL || target_section == NULL) continue;
					// obfuscated call target is selected by 
					// - call targets into other section of the main executables				

					if (current_section->module_name == target_section->module_name &&
						current_section->saddr != target_section->saddr) {
						if (check_disasm(target_addr) != 0) {
							//add_obfuscated_call_candidates(addr, target_addr, INDIRECT_CALL, "", false);
							obf_call_candidates.push_back(ObfuscatedCall(addr, target_addr, 0, ObfuscatedCallType::kINDIRECT_CALL, "", 0));
						}
					}
				}
			}
		}
	}
	else if (packer_type == "vmp")
	{
		for (idx = 0; idx < text_section_copied - 6; idx++)
		{
			// CALL r/m32 (FF 1F __ __ __ __)
			// is patched by VMProtect into
			// CALL rel32; ?? (E8 __ __ __ __ ; ??)
			if (buff_text_section[idx] == 0xE8)
			{
				addr = main_text_section_start_address + idx;

				// PATTERN 1-1: MOV reg, [e_api_fn] / ... / CALL r32 -> CALL imm32; RET or NOP / ... / CALL r32
				// -----------------------------------------------------------------
				// caller_addr-1: MOV reg, [e_api_fn]	# B8~BF ____ : 6 bytes
				// ...
				// reg_call_addr: CALL reg				# ____ : 2 bytes
				// ->
				// caller_addr-1: PUSH r32		# 50~57 1 bytes
				// caller_addr  : CALL imm32	# E8 ________ 5 bytes
				// ...
				// reg_call_addr: CALL reg		# ____ : 2 bytes


				// PATTERN 1-2: MOV reg, [e_api_fn] / ... / CALL reg -> CALL imm32; db xx (1byte) / ... / CALL reg
				// -----------------------------------------------------------------
				// caller_addr  : MOV ESI, [api_addr]	# B8~BF ____ : 6 bytes
				// ...
				// reg_call_addr: CALL reg				# FFD6 : 2 bytes
				// ->
				// caller_addr  : CALL imm32 	# E8 ________ : 5 bytes
				// caller_addr+5: db __			# __ : 1 byte
				// ...
				// reg_call_addr: CALL reg				# FFD6 : 2 bytes


				// PATTERN 2-1: CALL indirect -> PUSH r32; CALL imm32
				// -----------------------------------------------------------------
				// caller_addr-1: CALL imm32 # (48) FF 15 __ __ __ __	: 6 bytes or 7 bytes (with REX.W prefix)
				// ->
				// caller_addr-1: PUSH r32		# 50~57 1 bytes
				// caller_addr  : CALL ___ # (48) E8 __ __ __ __ : 5 bytes or 6 bytes (with REX.W prefix)		

				// PATTERN 2-2: CALL indirect -> CALL imm32; RET or NOP or INT3
				// caller_addr  : CALL ___ # (48) FF 15 __ __ __ __	: 6~7 bytes
				// ->
				// caller_addr  : CALL ___ # (48) E8 __ __ __ __ : 5~6 bytes
				// caller_addr+5: NOP or RET or INT3 # 90 or C3 or CC : 1 byte


				// PATTERN 3-1: JMP indirect -> PUSH r32; CALL imm32
				// -----------------------------------------------------------------
				// caller_addr-1: JMP ___ # (48) FF 25 __ __ __ __	: 6 bytes or 7 bytes (with REX.W prefix)
				// ->
				// caller_addr-1: PUSH r32		# 50~57 1 bytes
				// caller_addr  : CALL ___ # (48) E8 __ __ __ __ : 5 bytes or 6 bytes (with REX.W prefix)			


				// PATTERN 3-2: JMP indirect -> CALL imm32; RET or NOP
				// -----------------------------------------------------------------
				// caller_addr  : JMP ___ # (48) FF 25 __ __ __ __	: 6 bytes or 7 bytes (with REX.W prefix)
				// ->
				// caller_addr  : CALL ___ # (48) E8 __ __ __ __ : 5 bytes or 6 bytes (with REX.W prefix)
				// caller_addr+5: NOP or RET # 90 or C3 : 1 byte


				size_t pattern_before_push_reg = 0;				
				bool has_rexw = false;

				// check rex.w before & int 3 after
				if (ADDRSIZE == 8 && buff_text_section[idx - 1] == 0x48 && buff_text_section[idx +5] != 0xcc) {
					has_rexw = true;
				}

				// Heuristic: Need to prove
				// push reg at caller_addr : PATTERN 1-1, 2-1, 3-1
				if (buff_text_section[idx - 1] >= 0x50 && buff_text_section[idx - 1] <= 0x57) {
					pattern_before_push_reg = 1;
					// sometimes vmprotect add rex.w prefix
					if (ADDRSIZE == 8 && buff_text_section[idx - 2] == 0x48) {						
						pattern_before_push_reg++;
					}						
				}

				target_addr = addr + 5 + buff_text_section[idx + 1] + (buff_text_section[idx + 2] << 8) + (buff_text_section[idx + 3] << 16) + (buff_text_section[idx + 4] << 24);

				if (target_addr >= main_text_section_start_address && target_addr < main_text_section_end_address)
				{
					continue;	// skip function call into the same section
				}
				SectionInformation *current_section = GetSectionInfo(addr);
				SectionInformation *target_section = GetSectionInfo(target_addr);

				if (current_section == NULL || target_section == NULL) continue;

				// obfuscated call target is selected by 
				// - call targets into other section of the main executables
				if (current_section->module_name == target_section->module_name &&
					current_section->saddr != target_section->saddr) {
					if (has_rexw) addr--;
					// add_obfuscated_call_candidates(addr, target_addr, INDIRECT_CALL, "", pattern_before_push_reg);
					obf_call_candidates.push_back(ObfuscatedCall(addr, target_addr, 0, ObfuscatedCallType::kINDIRECT_CALL, "", pattern_before_push_reg));
				}
			}
		}
	}
	DLOG(LogType::kLOG_CALL_CHECK, "Searching for Obfuscated Calls Finished \n");
	free(buff_text_section);
	free(buff_imp_section);
}


bool FindIATAtSecondSection() {	
	size_t imp_size;
	if (packer_type == "vmp") {
		imp_start_addr = obf_rdata_saddr;
		imp_end_addr = obf_rdata_eaddr;
	}
	else if (packer_type == "tmd3") {
		auto sec = main_img_info->sec_infos.at(1);
		imp_start_addr = sec->saddr;
		imp_end_addr = sec->eaddr;
	}
	
	*fout << "#!! IMP Start: " << toHex(imp_start_addr) << " IMP End: " << toHex(imp_end_addr) << endl;

	imp_size = imp_end_addr - imp_start_addr;
	UINT8* buf = (UINT8*)malloc(imp_size);
	// buf has executable memory image
	PIN_SafeCopy(buf, (VOID*)imp_start_addr, imp_size);

	// Check imports of vmp	
	ADDRINT iat_addr, i;
	ADDRINT iat_data, iat_data_prev, iat_data_next;

	iat_elem_by_addr.clear();

	// Find IAT End Address	
	iat_data_prev = 0;
	for (i = 0; i < imp_size - ADDRSIZE; i += ADDRSIZE) {		
		iat_data = TO_ADDRINT(buf + i);
		iat_addr = imp_start_addr + i;
		// Entry Address is a mark for end of import address table
		if (iat_data_prev == 0 && IsMainImageTextSection(iat_data)) {
			break;
		}
		iat_data_prev = iat_data;
	}
	imp_end_addr = iat_addr;

	iat_data = 0;
	iat_data_next = TO_ADDRINT(buf);
	for (i = 0; i < imp_end_addr - imp_start_addr - ADDRSIZE; i += ADDRSIZE) {				
		// end mark: 0 ; entry address (nullsub) ; 0
		iat_data_prev = iat_data;
		iat_data = iat_data_next;
		iat_data_next = TO_ADDRINT(buf + i + ADDRSIZE);

		iat_addr = imp_start_addr + i;								
		
		// Themida 3.x: IAT elements are obfuscated. 
		// obf_imports are after deobfuscated by run-until-API
		if (iat_data > imp_end_addr && iat_data < main_image_end_address) {
			*fout << "# " << toHex(iat_addr) << ' ' << toHex(iat_data);
			if (check_disasm(iat_data) != 0) {
				obf_iat_elems.push_back({iat_addr, iat_data});
				//obf_call_t obfcall = obf_call_t(0, iat_data, iat_addr, INDIRECT_CALL, "", 0);
				// obf_call_candidates.push_back(obfcall);
				*fout << "<= Obfuscated" << endl;
			}						
		}

		auto fn = GetFunctionInfo(iat_data);
		

		//if ((iat_addr & 0xffff) == 0x30c8) {
		//	*fout << "HERE " << toHex(iat_addr) << ' ' << toHex(iat_data) << ' ' << ((fn == NULL)? "No FN":fn->name) << endl;		
		//	*fout << "Symbol from Dbg Data " << GetDbgSymbol(iat_data) << endl;
		//}
		
		if (iat_data != 0 && fn == NULL) {
			ModuleInformation* mod = GetModuleInfo(iat_data);
			if (mod != NULL) {
				string symb = GetDbgSymbol(mod->name, mod->saddr, mod->eaddr, iat_data);
				*fout << "Symbol from Dbg Data " << toHex(iat_addr) << ' ' << toHex(iat_data) << ' ' << symb << ' ' << mod->name << endl;
				iat_elem_by_addr[iat_addr] = { iat_addr, iat_data, symb, mod->name };
			}
		}


		else if (iat_data == 0 || fn == NULL) {
			iat_elem_by_addr[iat_addr] = { iat_addr, 0, "", "" };				
			*fout << "# " << toHex(iat_addr) << ' ' << toHex(iat_data) << endl;

		}		
		else {
			auto mf = ResolveForwardedFunc(fn->module_name, fn->name);
			fn->name = mf.fn;
			fn->module_name = mf.dll;
			iat_elem_by_addr[iat_addr] = { iat_addr, fn->saddr, fn->name, fn->module_name };
			*fout << "# " << iat_elem_by_addr[iat_addr] << endl;
		}			
	}
	iat_addr += ADDRSIZE;
	iat_elem_by_addr[iat_addr] = { iat_addr, 0, "", "" };
	imp_end_addr = iat_addr;
	found_IAT = true;
	free(buf);	
	return found_IAT;
}


bool FindIAT()
{
	if (packer_type == "vmp" || packer_type == "tmd3")
	{
		return FindIATAtSecondSection();
	}

	size_t txtsize = main_text_section_end_address - main_text_section_start_address;
	if (packer_type == "enigma")
	{
		txtsize += 0x1000;
	}
	
	DLOG(LogType::kLOG_IAT_SEARCH, "Text Section Size: " << toHex(txtsize) << endl);
	
	UINT8* buf = (UINT8*)malloc(txtsize);	
	// buf has executable memory image
	PIN_SafeCopy(buf, (VOID*)main_text_section_start_address, txtsize);

	// Search for Imports
	size_t num_imp_fn = 0;
	size_t num_consecutive_not_imp_fn = 0;
	UINT8 *bufp;
	ADDRINT iat_data, iat_addr, i;
	ModuleInformation *mod;
	for (size_t blk = 0x2000; blk < txtsize; blk += 0x1000) {		
		DLOG(LogType::kLOG_IAT_SEARCH, "Searching in " << toHex(main_text_section_start_address + blk) << endl);
		iat_elem_by_addr.clear();	
		num_imp_fn = 0;


		for (i = 0; i < 0x1000; i += ADDRSIZE) {
			DLOG(LogType::kLOG_IAT_SEARCH, "i=" << toHex(i) << endl);
			bufp = buf + blk + i;
			iat_addr = main_text_section_start_address + blk + i;
			iat_data = TO_ADDRINT(bufp);	
			DLOG(LogType::kLOG_IAT_SEARCH, toHex(iat_addr) << ' ' << toHex(iat_data) << endl);

			// Entry Address is a mark for end of import address table
			if (IsMainImageTextSection(iat_data)) {
				DLOG(LogType::kLOG_IAT_SEARCH, "## End Mark\n");				
				fout->flush();
				break;
			}

#if TARGET_IA32
			auto it = obfaddr2fn.find(iat_data);

			// if target_addr is obfuscated function address
			if (it != obfaddr2fn.end())
			{
				DLOG(LogType::kLOG_IAT_SEARCH, "## IAT ENTRY: ");
				auto fn = it->second;
				if (fn == NULL) {
					DLOG(LogType::kLOG_IAT_SEARCH, "# NO FUNCTION\n");
					break;
				}
				addr2fnaddr[iat_data] = fn->saddr;
				auto mf = ResolveForwardedFunc(fn->module_name, fn->name);
				fn->name = mf.fn;
				fn->module_name = mf.dll;
				iat_elem_by_addr[iat_addr] = { iat_addr, fn->saddr, fn->name, fn->module_name };
				num_consecutive_not_imp_fn = 0;
				num_imp_fn++;
				
				DLOG(LogType::kLOG_IAT_SEARCH, toHex(iat_addr) << *it->second << endl);
				continue;
			}
#endif
			DLOG(LogType::kLOG_IAT_SEARCH, "## not obfuscated function\n");

			mod = GetModuleInfo(iat_data);		
			if (iat_data == 0 || mod == NULL) {
				if (mod == NULL) DLOG(LogType::kLOG_IAT_SEARCH, "## no module information\n");
				if (++num_consecutive_not_imp_fn > 1) {
					DLOG(LogType::kLOG_IAT_SEARCH, "## no not imp fn " << num_consecutive_not_imp_fn << endl);
					break;
				}
				iat_elem_by_addr[iat_addr] = { iat_addr, 0, "", "" };
				continue;
			}

			num_consecutive_not_imp_fn = 0;
			num_imp_fn++;

			auto fn = GetFunctionInfo(iat_data);
			if (fn == NULL) {
				*fout << toHex(iat_data) << endl;
				string symb = GetDbgSymbol(mod->name, mod->saddr, mod->eaddr, iat_data);
				if (symb == "") {
					DLOG(LogType::kLOG_IAT_SEARCH, "# NO FUNCTION\n");
					continue;
				}
				
				*fout << "Symbol from Dbg Data " << toHex(iat_addr) << ' ' << toHex(iat_data) << ' ' << symb << ' ' << mod->name << endl;
				iat_elem_by_addr[iat_addr] = { iat_addr, iat_data, symb, mod->name };									
			}
			else {
				*fout << fn->module_name << ' ' << fn->name << endl;
				auto mf = ResolveForwardedFunc(fn->module_name, fn->name);
				fn->name = mf.fn;
				fn->module_name = mf.dll;
				iat_elem_by_addr[iat_addr] = { iat_addr, fn->saddr, fn->name, fn->module_name };
			}

		}

		if (num_imp_fn > 3) {	// assumption: at least 3 import function
			DLOG(LogType::kLOG_IAT_SEARCH, "Found " << num_imp_fn << " imported function\n");
			imp_start_addr = main_text_section_start_address + blk;
			imp_end_addr = main_text_section_start_address + blk + i;
			found_IAT = true;
			goto free_buf;
		}
	}

	if (!found_IAT) {

	}
	DLOG(LogType::kLOG_IAT_SEARCH, "SEARCH IAT ENDED\n");


	// if we failed to find any IAT candidate, 
	// then make a new one in a cave area
	// which has a consecutive zeros with interval 0x1000
	if (imp_start_addr != 0) goto free_buf;
	imp_start_addr = 0;		
	for (size_t blk = 0; blk + obf_iat_elems.size() * ADDRSIZE < txtsize; blk += 0x1000) {
		found_zero_blk = true;
		for (size_t i = 0; i < obf_iat_elems.size() * ADDRSIZE; i++) {
			if (buf[blk + i] != 0) {
				found_zero_blk = false;
				break;
			}
		}
		if (found_zero_blk) {
			imp_start_addr = main_text_section_start_address + blk;
			*fout << "# iat candidate:" << toHex(imp_start_addr) << endl;
			goto free_buf;
		}
	}
	
	// find zero block with interval 0x100
	*fout << "# 2" << endl;
	for (size_t blk = 0; blk + obf_call_candidates.size() * ADDRSIZE < txtsize; blk += 0x100) {
		found_zero_blk = true;
		for (size_t i = 0; i < obf_call_candidates.size() * ADDRSIZE; i++) {
			if (buf[blk + i] != 0) {
				found_zero_blk = false;
				break;
			}
		}
		if (found_zero_blk) {
			imp_start_addr = main_text_section_start_address + blk;
			*fout << "# iat candidate:" << toHex(imp_start_addr) << endl;
			goto free_buf;
		}
	}
	
	// If there is no code cave, select idata 
	*fout << "# 3" << endl;	
	imp_start_addr = obf_idata_saddr;
	*fout << "# iat candidate:" << toHex(imp_start_addr) << endl;

free_buf:
	free(buf);

	// If IAT area is not found, make a new IAT area in the gap
	if (!found_IAT) {
		iat_elem_by_addr.clear();
		// Build sorted_api_map to gather functions per dll: function name -> fninfo. 
		map<string, FunctionInformation*> sorted_api_map;
		for (auto it = obfaddr2fn.begin(); it != obfaddr2fn.end(); it++) {
			FunctionInformation* fninfo = it->second;
			string key = fninfo->module_name + '.' + fninfo->name;
			sorted_api_map[key] = fninfo;
		}

		// Resolve obfuscated API call
		ADDRINT current_addr = imp_start_addr;
		ADDRINT rel_addr = 0;

		string prev_mod_name = "";
		for (auto it = sorted_api_map.begin(); it != sorted_api_map.end(); it++, current_addr += ADDRSIZE) {
			// assign resolved function address to candidate IAT area
			FunctionInformation* fn = it->second;
			if (prev_mod_name != "" && prev_mod_name != fn->module_name) {
				iat_elem_by_addr[iat_addr] = { iat_addr, 0, "", "" };
			}
			iat_elem_by_addr[iat_addr] = { iat_addr, fn->saddr, fn->name, fn->module_name };
			prev_mod_name = fn->module_name;
		}
		iat_elem_by_addr[iat_addr] = { iat_addr, 0, "", "" };
	}

	// *fout << toHex(addrZeroBlk) << endl;
	return found_IAT;
}


// reconstruct import list by resolved obfuscated calls
void ReconstructImpList() {

	*fout << "# Obfuscated Calls" << endl;	

	// Build sorted_api_map to gather functions per dll: function name -> fninfo. 
	map<string, FunctionInformation*> sorted_api_map;


	// add existing imports
	for (ADDRINT addr = imp_start_addr; addr < imp_end_addr; addr += ADDRSIZE) {

	}


	for (auto &e : obf_calls) {
		*fout << "# " << e << endl;
		FunctionInformation* fn = GetFunctionInfo(e.dst);		
		string m, f;
		m = fn->module_name;
		f = fn->name;		

		auto n = ResolveForwardedFunc(fn->module_name, fn->name);
		fn->module_name = n.dll;
		fn->name = n.fn;

		if (m != fn->module_name || f != fn->name) {
			*fout << "# " << fn->module_name << "." << fn->name << endl;
		}

		string key = fn->module_name + '.' + fn->name;
		sorted_api_map[key] = fn;
	}	

	// Resolve obfuscated API call
	ADDRINT iat_addr = imp_start_addr;
	size_t i = 0;
	ADDRINT rel_addr = 0;
	string prev_mod_name = "";
	FunctionInformation* fn;

	for (auto e : sorted_api_map) {
		fn = e.second;	
		if (prev_mod_name != "" && fn->module_name != prev_mod_name) {
			iat_elem_by_addr[i] = { iat_addr, 0, "", "" };
			i++;
			iat_addr += ADDRSIZE;
		}
		iat_elem_by_addr[i] = {
			iat_addr,
			fn->saddr, 
			fn->name,
			fn->module_name
		};		
		i++;
		iat_addr += ADDRSIZE;
		
		prev_mod_name = fn->module_name;
	}
	iat_elem_by_addr[i] = { iat_addr, 0, "", "" };
}


// Check External Reference from main image address
void PrintIATArea()
{
	// print IAT info
	*fout << "IAT START: " << toHex(imp_start_addr - main_image_start_address) << endl;
	ADDRINT addr;
	for (auto e : iat_elem_by_addr) {		
		addr = e.first;
		IAT_INFO& iat_info = e.second;
		if (iat_info.func_addr == 0) {
			*fout << toHex(addr - main_image_start_address) << "\taddr\t0\t0" << endl;
			
		}
		else {
			*fout << toHex(addr - main_image_start_address) << "\taddr\t" << iat_info.dll_name << '\t' << iat_info.func_name << endl;
		}
	}
	*fout << "IAT SIZE: " << toHex((imp_end_addr - imp_start_addr) / ADDRSIZE + 1) << endl;
}



///////////////////////////////////////////////////////////////////////////////////////////////////////
// Analysis Routines
///////////////////////////////////////////////////////////////////////////////////////////////////////

// API Detect executable trace analysis function
void Analysis_TRC_OEP(CONTEXT* ctxt, ADDRINT addr, bool is_ret, THREADID threadid)
{

	if (threadid != 0) return;

#if LOG_TRACE == 1
	if (IsMainImage(addr)) {
		*fout << "Trace:" << toHex(addr) << endl;
	}
#endif

	// Check OEP
	if (oep == 0)
	{
		// common for dll and exe
		SetMemoryPageExecute(addr);
		if (!is_dll_analysis && IsMainImageTextSection(addr))
		{
			NW::PBYTE p_oep_code = (NW::PBYTE)addr;
			NW::BYTE oep_code[2] = { *p_oep_code, *(p_oep_code + 1) };
			*fout << toHex1(oep_code[0]) << ' ' << toHex1(oep_code[1]) << endl;

			// vmp supports no packing. 20.5.4.
			if (GetMemoryPageWrite(addr) && GetMemoryPageExecute(addr) > 0 && !is_ret || packer_type == "vmp")
			{
				if (packer_type == "enigma") {
					UINT8 buf[6];
					PIN_SafeCopy(buf, (VOID*)addr, 6);
					if (buf[0] == 0xEB && buf[1] == 0x03 && buf[5] == 0xC3) {
						*fout << "# Fake OEP: ";
						for (auto pt : buf)
							*fout << toHex1(pt) << ' ';
						return;
					}
				}
				*fout << "OEP(va):" << toHex(addr) << endl;
				oep = addr - main_image_start_address;
				*fout << "OEP(rva):" << toHex(oep) << endl;

				PIN_SaveContext(ctxt, &ctx0);
				PIN_SemaphoreSet(&sem_oep_found);
			}
			return;
		}

		// if some problem occurs in dll
		if (is_dll_analysis && dll_is_unpack_started) {
			if (IsMainImageTextSection(addr)) {				
				oep = addr - main_image_start_address;
				*fout << "OEP:" << toHex(oep) << endl;
				PIN_SaveContext(ctxt, &ctx0);
				PIN_SemaphoreSet(&sem_oep_found);
			}
			//if (addr >= loader_saddr && addr < loader_eaddr) {
			//	// set fake oep
			//	oep = main_text_section_start_address - main_image_start_address;
			//	*fout << "OEP:" << toHex(oep) << endl;
			//	PIN_SaveContext(ctxt, &ctx0);
			//	PIN_SemaphoreSet(&sem_oep_found);
			//}
		}
	}
	else if (skip_until_oep) {
		if (addr == oep + main_image_start_address) {
			*fout << "OEP:" << toHex(oep) << endl;
			skip_until_oep = false;
			PIN_SaveContext(ctxt, &ctx0);
			PIN_SemaphoreSet(&sem_oep_found);
		}
		return;

	}
}


// thread control
void Analysis_Thread(THREADID threadid) {
	if (threadid != 0) {
		*fout << "thread: " << threadid << " suspend" << endl;
		fout->flush();
		PIN_Sleep(0);
		// PIN_ExitThread(0);
	}
}


void ToNextObfCall(CONTEXT* ctxt) {
	run_until_api_function_status = RunUntilAPIFunctionStatus::kCheckNextCall;

	// register context save & restore
	if (is_register_saved) {
		RestoreRegisters(ctxt);
	}
	else {
		SaveRegisters(ctxt);
		is_register_saved = true;
	}
	// Date: 23. 5. 12. 
	// clear gax first due to GAX-based API recovery			
	PIN_SetContextReg(ctxt, REG_GAX, 0);

	ADDRINT next_addr;

	// resolve obfuscated call
	// the result is stored at 'obf_calls'
	if (curr_obf_fn_pos < obf_call_candidates.size()) {
		DLOG(LogType::kLOG_CALL_CHECK, "FN-" << curr_obf_fn_pos << '/' << obf_call_candidates.size() << endl);
		curr_obf_call = &obf_call_candidates.at(curr_obf_fn_pos++);
		curr_obf_iat_elem = NULL;
		// currently call instruction is of the form 'E8 __ __ __ __' which is 5 bytes
		// but originally it is 'FF 15 __ __ __ __' or 'FF 25 __ __ __ __' which is 6 bytes
		// so next instruction address is addr + 6			

		// next address is caller
		// to check mov reg, ...
		next_addr = curr_obf_call->src;
		DLOG(LogType::kLOG_CALL_CHECK, "Checking Obfuscated Call: " <<
			toHex(curr_obf_call->src) << " -> " << toHex(curr_obf_call->dst) <<
			" (" << curr_obf_fn_pos << '/' << obf_call_candidates.size() << ")\n");
	}

	// resolve obfuscated IAT elements
	// the result updates 'iat_elem_by_addr'
	else if (curr_obf_iat_pos < obf_iat_elems.size()) {
		DLOG(LogType::kLOG_CALL_CHECK, "IAT-" << curr_obf_iat_pos << '/' << obf_iat_elems.size() << endl);
		curr_obf_iat_elem = &obf_iat_elems.at(curr_obf_iat_pos++);
		curr_obf_call = NULL;		
		next_addr = curr_obf_iat_elem->dst;		
		DLOG(LogType::kLOG_CALL_CHECK, "Checking Obfuscated IAT Element: " <<
			toHex(curr_obf_iat_elem->src) << " -> " << toHex(next_addr) <<
			" (" << curr_obf_iat_pos << '/' << obf_iat_elems.size() << ")\n");		
	}
	else {
		// when checking obfuscated call finished, prepare the end 				
		DLOG(LogType::kLOG_CALL_CHECK, "Checking End\n");
		run_until_api_function_status = RunUntilAPIFunctionStatus::kFinalize;
		DoFinalize();		
	}

	trace_address_sequence.clear();
	trace_stack_pointer_sequence.clear();
	register_to_value_API_function_name.clear();

	run_until_api_function_status = RunUntilAPIFunctionStatus::kCheckCurrentFunction;
	
	// testing call instruction
	if (curr_obf_call != NULL && curr_obf_call->ins_type == ObfuscatedCallType::kINDIRECT_CALL) {
		// jump to the call destination		
		fout->flush();
		ADDRINT dst = curr_obf_call->dst;
		ADDRINT ret_addr = curr_obf_call->src + 5;
		
		fout->flush();

		// push return address and go to the target address
		ADDRINT stktop = PIN_GetContextReg(ctxt, REG_STACK_PTR) + ADDRSIZE;
		if (IsMainImage(dst) && !IsMainImageTextSection(dst)) {
			*fout << "DEBUG: Directly go to call target " << toHex(dst) << endl;
			*fout << "RSP=" << toHex(stktop) << endl;
			*fout << "[RSP]=" << toHex(ret_addr) << endl;
			PIN_SetContextReg(ctxt, REG_STACK_PTR, stktop);
			*((ADDRINT*)stktop) = ret_addr;
			PIN_SetContextReg(ctxt, REG_INST_PTR, dst);
			PIN_ExecuteAt(ctxt);		
		}

	}
	PIN_SetContextReg(ctxt, REG_INST_PTR, next_addr);
	PIN_ExecuteAt(ctxt);	
}


// run until api
int DoRunUntilAPI(CONTEXT *ctxt, ADDRINT addr, bool is_ret) {	
	if (run_until_api_function_status == RunUntilAPIFunctionStatus::kCheckCurrentFunction) {
		// if obfuscated API checking is started and 
		// if the trace is in another section
		// then here is the obfuscated instructions that resolve 'call API_function'
		// These obfuscated instructions end by 'RET' instruction 
		// that jumps into API function code
		//
		// .text:     ...
		//   mov_obf_caller: call mov_obf_addr
		//                   db xx
		//   ret_addr      : ... 
		//                   ...
		//   obf_caller    : call REG 
		// 
		// .vmp0:             
		//                    ...
		//   mov_obf_addr  :  ...
		//                    ... (the effect of obfuscated code is equivalent to MOV REG, api_fn )
		//                    ret xx		

		ADDRINT stkptr = PIN_GetContextReg(ctxt, REG_STACK_PTR);
		ADDRINT stk_top_val;
		size_t copied_num = PIN_SafeCopy(&stk_top_val, reinterpret_cast<unsigned char*>(stkptr), ADDRSIZE);		
		trace_address_sequence.push_back(addr);
		trace_stack_pointer_sequence.push_back(stkptr);
		DLOG(LogType::kLOG_CALL_CHECK, "CheckAPI running " << toHex(addr) << ' ' << GetAddrInfo(addr) << ' ' << trace_address_sequence.size() << endl);
		fout->flush();

		FunctionInformation* fninfo;

		// check MOV reg, api_fn		
		if (curr_obf_call && (addr == curr_obf_call->src + 5 || addr == curr_obf_call->src + 6))
		{
			// check 'mov reg, [iat:api_function]'
			REG set_api_reg = GetRegisterAssignedWithAPIFunctionAddress(ctxt);
			if (set_api_reg != REG_INVALID_)
			{
				DLOG(LogType::kLOG_CALL_CHECK, "# MOV Caller address: " << curr_obf_call->src << endl);
				DLOG(LogType::kLOG_CALL_CHECK, "# MOV return address: " << addr << endl);
				DLOG(LogType::kLOG_CALL_CHECK, "# MOV next to Caller: " << trace_next_addr_m[curr_obf_call->src] << endl);
				DLOG(LogType::kLOG_CALL_CHECK, "# SP before mov call: " << trace_stack_pointer_sequence[0] << endl);
				DLOG(LogType::kLOG_CALL_CHECK, "# SP after mov call : " << stkptr << endl);

				ADDRINT adjusted_caller_addr = addr - 6;
				ADDRINT api_fn_addr = register_to_value_API_function_name[set_api_reg].first;
				fninfo = GetFunctionInfo(api_fn_addr);

				DLOG(LogType::kLOG_CALL_CHECK, toHex(adjusted_caller_addr - main_image_start_address) << "\tmov-" << REG_StringShort(set_api_reg) << '\t' << fninfo << endl);
				obfaddr2fn[curr_obf_call->dst] = fninfo;
				mov_obfaddr2fn[curr_obf_call->dst] = fninfo;
				obf_calls.push_back(ObfuscatedCall(adjusted_caller_addr, fninfo->saddr, 0, ObfuscatedCallType::kINDIRECT_MOV, REG_StringShort(set_api_reg), 0));
			}			
			ToNextObfCall(ctxt);
			// return 1; //  continue;
		}

		// because some text section has some illegal instructions
		// skip ip is at .text after the first call
		// CAUTION: some vmp has virtualized obfuscated call in IAT
		if (trace_address_sequence.size() > 1 && IsMainImageTextSection(addr) && !is_ret) {
			*fout << ".text section and not is_ret" << endl;
			ToNextObfCall(ctxt);			
			// return 1; //  continue;
		}

		if (trace_address_sequence.size() > 100 && !IsMainImageVMPSection(addr))
		{
			*fout << "obfuscated call too long" << endl;
			ToNextObfCall(ctxt);
			// return 1; // continue;
		}

		// Date: 23. 5. 12. 
		// themida 3.19 check
		// functions in kernel32.dll call Sleep and lstrlen first before the api function call. 
		// so, I check api function in RAX first. 
		if (packer_type == "tmd3" && curr_obf_iat_elem) {
			ADDRINT gax = PIN_GetContextReg(ctxt, REG_GAX);
			// *fout << "GAX:" << toHex(gax) << endl;
			fninfo = GetFunctionInfo(gax);
					
			if (fninfo != NULL) {
				*fout << "FN:" << *fninfo << endl;

				auto mf = ResolveForwardedFunc(fninfo->module_name, fninfo->name);
				fninfo->name = mf.fn;
				fninfo->module_name = mf.dll;

				*fout << "# --- " << fninfo->module_name << '\t' << fninfo->name << endl;
				iat_elem_by_addr[curr_obf_iat_elem->src] = { curr_obf_iat_elem->src, fninfo->saddr, fninfo->name, fninfo->module_name };

				obfaddr2fn[curr_obf_iat_elem->dst] = fninfo;

				ToNextObfCall(ctxt);
			}			
		}
		

		// if the trace in in API function
		// then the current address or return address is the API function. 		
		fninfo = GetFunctionInfo(addr);		

		if (fninfo == NULL) return 0; //  break;	

		// skip user exception by false positive find api calls
		if (fninfo->name.find("KiUserExceptionDispatcher") != string::npos)
		{
			*fout << "obfuscated call: Exception" << endl;
			ToNextObfCall(ctxt); 			
			// return 1; //  continue;
		}

		if (packer_type == "tmd2" || packer_type == "tmd3" || packer_type == "enigma")
		{
			if (curr_obf_call) {
				// Check the stack top value whether the value is next address of the call instruction. 
				ObfuscatedCallType ty;
				if (stk_top_val == curr_obf_call->next_addr) {
					ty = ObfuscatedCallType::kINDIRECT_CALL;
				}
				else {
					ty = ObfuscatedCallType::kINDIRECT_JMP;
				}

				*fout << "# --- " << fninfo->module_name << '\t' << fninfo->name << endl;
				obfaddr2fn[curr_obf_call->dst] = fninfo;
				*fout << "# --- " << toHex(curr_obf_call->src) << "->" << toHex(addr) << ' ' << ty << endl;
				auto obf_call = ObfuscatedCall(curr_obf_call->src, fninfo->saddr, curr_obf_call->ind_addr, ty, "", 0);
				*fout << "# " << obf_call << endl;
				obf_calls.push_back(obf_call);
			}
			else if (curr_obf_iat_elem) {
				auto mf = ResolveForwardedFunc(fninfo->module_name, fninfo->name);
				fninfo->name = mf.fn;
				fninfo->module_name = mf.dll;

				*fout << "# --- " << fninfo->module_name << '\t' << fninfo->name << endl;
				iat_elem_by_addr[curr_obf_iat_elem->src] = { curr_obf_iat_elem->src, fninfo->saddr, fninfo->name, fninfo->module_name };

				obfaddr2fn[curr_obf_iat_elem->dst] = fninfo;
			}

			ToNextObfCall(ctxt);			
			// return 1; // continue;
		}
		else if (packer_type == "vmp")
		{
			// cannot reach here
			*fout << "cannot reach here" << endl;

		}
		return 0; // break;
	}

	return 0;
}


// after checking obfuscated calls, dump and terminate.		
void DoFinalize() {
	PIN_SemaphoreSet(&sem_resolve_api_end);
	PIN_SemaphoreWait(&sem_dump_finished);
	((ofstream*)fout)->close();
	PIN_ExitProcess(-1);
}


// API Detect executable trace analysis function
void Analysis_TRC_API(CONTEXT *ctxt, ADDRINT addr, bool is_ret, THREADID threadid)
{	
	static int _trace = 0;
	if (threadid != 0) {
		*fout << "thread: " << threadid << " suspend" << endl;
		fout->flush();
		PIN_Sleep(0);		
		return;
	}	

	if (oep == 0) return;

	while (true) {
		*fout << "DEBUG: " << threadid << ' ' << toHex(addr) << ' ' << run_until_api_function_status << endl;
		fout->flush();

		if (run_until_api_function_status == RunUntilAPIFunctionStatus::kCheckCurrentFunction) {
			auto res = DoRunUntilAPI(ctxt, addr, is_ret);
			if (res == 0) break;
			else if (res == 1) continue;
		}

		else if (run_until_api_function_status == RunUntilAPIFunctionStatus::kCheckNextCall) {		
			PIN_RemoveInstrumentation();
			ToNextObfCall(ctxt);
		}

		if (run_until_api_function_status == RunUntilAPIFunctionStatus::kFinalize) {
			DoFinalize();			
		}

		break;
	}	// end of while loop	
}

// API Detect executable trace instrumentation function
void Instrument_TRC(TRACE trace, void *v)
{	
	ADDRINT addr = TRACE_Address(trace);

	INS last_ins = BBL_InsTail(TRACE_BblTail(trace));
	ADDRINT last_addr = INS_Address(last_ins);
	// bool is_ret = INS_IsRet(BBL_InsTail(TRACE_BblHead(trace)));	
	bool is_ret = INS_IsRet(last_ins);

	static int _trace = 0;
	if (addr == 0x00007ff7b991c67f) {
		_trace = 1;
	}

	if (_trace) {
		for (auto bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
		{
			*fout << " B " << toHex(BBL_Address(bbl)) << endl;
			fout->flush();
			for (auto ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
			{
				*fout << " I " << toHex(INS_Address(ins)) << ' ' << INS_Disassemble(ins) << endl;
				fout->flush();
				INS_InsertPredicatedCall(
					ins, IPOINT_BEFORE, (AFUNPTR)Analysis_INS,
					IARG_INST_PTR,
					IARG_END);
			}
		}
	}

	if (!oep) {
		TRACE_InsertCall(trace, IPOINT_BEFORE, (AFUNPTR)Analysis_TRC_OEP,
			IARG_CONTEXT,
			IARG_ADDRINT, addr,
			IARG_BOOL, is_ret,
			IARG_THREAD_ID,
			IARG_END);
	}
	else if (
		run_until_api_function_status == RunUntilAPIFunctionStatus::kCheckNextCall ||
		run_until_api_function_status == RunUntilAPIFunctionStatus::kCheckCurrentFunction) {

		if (is_ret && packer_type == "vmp") {			
			INS_InsertCall(last_ins, IPOINT_BEFORE, (AFUNPTR)Analysis_INS_API,
				IARG_CONTEXT, 
				IARG_ADDRINT, last_addr, 
				IARG_ADDRINT, InsType::kRET, 
				IARG_THREAD_ID,
				IARG_END);

		}
		else {

			//for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
			//	for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
			//		*fout << toHex(INS_Address(ins)) << ' ' << INS_Disassemble(ins) << endl;
			//	}
			//}
			//

			*fout << "TRACE " << toHex(addr) << endl;

			TRACE_InsertCall(trace, IPOINT_BEFORE, (AFUNPTR)Analysis_TRC_API,
				IARG_CONTEXT,
				IARG_ADDRINT, addr,
				IARG_BOOL, is_ret,
				IARG_THREAD_ID,
				IARG_END);	

		}
		//
		//if (curr_obf_fn_pos == 13) {
		//	BBL bbl;
		//	INS ins;
		//	for (bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
		//	{
		//		for (ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
		//		{
		//			*fout << " I " << toHex(INS_Address(ins)) << ' ' << INS_Disassemble(ins) << endl;
		//			InsType it = InsType::kOTHER;
		//			if (INS_Mnemonic(ins) == "POPFD" || INS_Mnemonic(ins) == "POPFQ") {
		//				it = InsType::kPOPF;
		//				*fout << "# POPF @ " << toHex(addr) << ' ' << INS_Disassemble(ins) << endl;
		//			}
		//			else if (INS_Mnemonic(ins) == "RET" || INS_Mnemonic(ins) == "RET_NEAR") {
		//				it = InsType::kRET;
		//				*fout << "# RET @ " << toHex(addr) << ' ' << INS_Disassemble(ins) << endl;
		//			}
		//		}
		//	}
		//}
		
	}

	trace_cache_m[addr] = new vector<ADDRINT>;
	trace_next_addr_m[addr] = addr + TRACE_Size(trace);
	
	if (is_dll_analysis)
	{
		if (addr == obf_dll_entry_addr) {
			dll_is_unpack_started = true;
			LOG("Unpack Started.\n");
		}
		if (!dll_is_unpack_started) return;
	}

	if (!IsMainImage(addr)) return;

	//// check invalid instructions
	//if (isCheckAPIStart) {
	//	if (check_disasm2(addr) == 0) {
	//		*fout << "invalid disassembly" << endl;
	//		isCheckAPIStart = true;
	//		isCheckAPIRunning = false;
	//	}
	//}

	// instrument each memory read/write instruction
	// and
	// check unsupported instructions
	if (!skip_until_oep) {
		BBL bbl;
		INS ins, prev_ins;
		for (bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
		{
			for (ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
			{
				prev_ins = ins;
				if (INS_IsFarRet(ins))
				{
					run_until_api_function_status = RunUntilAPIFunctionStatus::kCheckNextCall;
					*fout << "# Far Ret !!!" << endl;
				}
				if (INS_Mnemonic(ins) == "XRSTOR") continue;

				if (packer_type == "tmd2") {

					UINT32 memOperands = INS_MemoryOperandCount(ins);
					bool is_mem_write = false, is_mem_read = false;
					if (INS_Mnemonic(ins) == "XRSTOR") continue;

					for (size_t memOp = 0; memOp < memOperands; memOp++)
					{
						// Check each memory operand					
						if (INS_MemoryOperandIsRead(ins, memOp) && !INS_IsStackRead(ins))
						{
							is_mem_read = true;

						}
						if (INS_MemoryOperandIsWritten(ins, memOp) && !INS_IsStackWrite(ins))
						{
							is_mem_write = true;
						}
					}
					if (is_mem_read) {
						INS_InsertPredicatedCall(
							ins, IPOINT_BEFORE, (AFUNPTR)Analysis_INS_MR,
							IARG_MEMORYREAD_EA,
							IARG_END);
					}
					if (is_mem_write) {
						INS_InsertPredicatedCall(
							ins, IPOINT_BEFORE, (AFUNPTR)Analysis_INS_MW,
							IARG_INST_PTR,
							IARG_MEMORYWRITE_SIZE,
							IARG_MEMORYWRITE_EA,
							IARG_END);
					}
				}
				else {
					if (INS_IsMemoryWrite(ins) && !INS_IsStackWrite(ins))
					{
						// record write addresses to detect OEP
						INS_InsertPredicatedCall(
							ins, IPOINT_BEFORE, (AFUNPTR)Analysis_INS_MW,
							IARG_INST_PTR,
							IARG_MEMORYWRITE_SIZE,
							IARG_MEMORYWRITE_EA,
							IARG_END);
					}
				}
			}
		}

	}


	// check last ins
	BBL tail_bbs = TRACE_BblTail(trace);	
	string mne = INS_Mnemonic(last_ins);
	if (oep) {		
		if (!INS_IsControlFlow(last_ins) &&
			!INS_Stutters(last_ins) && 
			BBL_Size(tail_bbs) < 10 &&
			mne != "CPUID" &&
			mne != "INT" &&
			mne != "POPFD" 			
			) {			
			*fout << "Next!" << endl;
			*fout << INS_IsControlFlow(last_ins) << endl;
			*fout << INS_Stutters(last_ins) << endl;
			*fout << INS_Disassemble(last_ins) << endl;
			run_until_api_function_status = RunUntilAPIFunctionStatus::kCheckNextCall;
			return;
		}
	}	

	// Date: 23. 5. 12. 
	// This is ad-hoc method. I need to verify this code. 
	if (run_until_api_function_status == RunUntilAPIFunctionStatus::kCheckCurrentFunction && INS_IsCall(last_ins) && packer_type != "tmd3") {
		string asmcode = INS_Disassemble(last_ins);
		// *fout << asmcode << endl;
		auto pos = asmcode.rfind(' ');
		if (pos + 3 < asmcode.length()) {
			istringstream ss(&asmcode[pos + 3]);
			ADDRINT tgt;
			ss >> hex >> tgt;
			*fout << toHex(tgt) << endl;
			auto info = GetModuleInfo(tgt);
			if (info == NULL) {
				*fout << "skip" << endl;
				run_until_api_function_status = RunUntilAPIFunctionStatus::kCheckNextCall;
				return;
			}
		}
	}
}


////////////
// API deobfuscation instruction validity checking
////////////
void Analysis_INS_API(CONTEXT* ctxt, ADDRINT addr, ADDRINT it, THREADID tid)
{	
	if (tid != 0) return;
	*fout << "Analysis_INS_API " << toHex(addr) << endl;
	fout->flush();
	InsType ins_typ = (InsType)it;
	if (ins_typ == InsType::kOTHER) {
		return;
	}

	if (ins_typ == InsType::kPOPF) {		
		ADDRINT const stkptr = PIN_GetContextReg(ctxt, REG_STACK_PTR);
		ADDRINT stktop = *XED_STATIC_CAST(const ADDRINT*, stkptr);
		*fout << toHex(stkptr) << ' ' << toHex(stktop) << endl;
		if (stktop & 0b100000000) {
			*fout << "TF" << endl;
			run_until_api_function_status = RunUntilAPIFunctionStatus::kCheckNextCall;
			// TODO
		}
	}

	if (ins_typ == InsType::kRET) {
		*fout << "DEBUG: Checking RET" << endl;
		// Check call/jmp
		// Compare stack top to check the return address which points to the next to the caller instruction. 		
		ADDRINT adjusted_caller_addr;
		string call_type;
		ObfuscatedCallType ty;
		
		// return value has an API address
		ADDRINT stkptr = PIN_GetContextReg(ctxt, REG_STACK_PTR);
		ADDRINT stk_top_val = *((ADDRINT*)stkptr);
		stk_top_val = *((ADDRINT*)stkptr);
		
		auto fninfo = GetFunctionInfo(stk_top_val);		
		if (!fninfo) {
			ToNextObfCall(ctxt);
		}

		*fout << '[' << toHex(stkptr) << "]=" << toHex(stk_top_val) << ' ' << *fninfo << endl;

		// return value at the stack top
		stkptr += ADDRSIZE;
		stk_top_val = *((ADDRINT*)stkptr);

		*fout << '[' << toHex(stkptr) << "]=" << toHex(stk_top_val) << endl;

		INT32 stk_diff = trace_stack_pointer_sequence[0] - stkptr;		
		*fout << "Stack Difference = " << toHex(stk_diff) << endl;
		if (stk_diff != 0 && stk_diff != ADDRSIZE && stk_diff != -ADDRSIZE)
		{
			*fout << "Check call/jmp" << endl;
			*fout << *fninfo << endl;
			*fout << toHex(trace_stack_pointer_sequence[0]) << endl;
			*fout << toHex(stkptr) << endl;
			fout->flush();			
			ToNextObfCall(ctxt);
		}

		else if (stk_top_val == curr_obf_call->src + 5 || stk_top_val == curr_obf_call->src + 6) {
			call_type = "call";
			ty = ObfuscatedCallType::kINDIRECT_CALL;
			if (stk_top_val == curr_obf_call->src + 6)
			{
				adjusted_caller_addr = curr_obf_call->src;
			}
			else if (stk_top_val == curr_obf_call->src + 5)
			{
				adjusted_caller_addr = curr_obf_call->src - 1;
			}
			else
			{
				ToNextObfCall(ctxt);								
			}
		}
		else
		{
			call_type = "goto";
			ty = ObfuscatedCallType::kINDIRECT_JMP;
			if (stk_diff == 0)
			{
				adjusted_caller_addr = curr_obf_call->src;
			}
			else if (stk_diff == -ADDRSIZE)
			{
				adjusted_caller_addr = curr_obf_call->src - curr_obf_call->n_prev_pad_bytes;
			}
			else
			{
				ToNextObfCall(ctxt);
			}
		}

		DLOG(LogType::kLOG_CALL_CHECK, "# Caller address: " << toHex(curr_obf_call->src) << endl);
		DLOG(LogType::kLOG_CALL_CHECK, "# return address: " << toHex(stk_top_val) << endl);
		DLOG(LogType::kLOG_CALL_CHECK, "# next to Caller: " << trace_next_addr_m[curr_obf_call->src] << endl);
		DLOG(LogType::kLOG_CALL_CHECK, "# SP before call: " << trace_stack_pointer_sequence[0] << endl);
		DLOG(LogType::kLOG_CALL_CHECK, "# SP at API func: " << stkptr << endl);
		DLOG(LogType::kLOG_CALL_CHECK, "# call type     : " << call_type << endl);
		*fout << "ADDR:" << toHex(addr) << endl;
		if (addr != fninfo->saddr) DLOG(LogType::kLOG_CALL_CHECK, "branch into the middle of API function\n");

		DLOG(LogType::kLOG_CALL_CHECK,
			toHex(adjusted_caller_addr - main_image_start_address) << '\t' <<
			call_type << '\t' <<
			fninfo->module_name << '\t' <<
			fninfo->name << endl);

		obf_calls.push_back(ObfuscatedCall(adjusted_caller_addr, fninfo->saddr, 0, ty, "", 0));
		obfaddr2fn[curr_obf_call->src] = fninfo;

		ToNextObfCall(ctxt);
	}
}


void Analysis_INS_LOG(CONTEXT* ctxt, ADDRINT addr, THREADID tid)
{
	*fout << "# Analysis_INS_LOG " << toHex(tid) << ' ' << toHex(addr) << endl;
	string disasm = "";	
	size_t sz = get_disasm(addr, disasm);
	if (sz != 5) return;
	UINT8 opcode = *((UINT8*)addr);
	if (opcode != 0xe9) return;
	ADDRINT next = addr + sz;		
	INT64 diff = (INT64)*((INT32*)(addr + 1));
	*fout << "# DIFF: " << toHex(diff) << endl;
	ADDRINT dst = next + diff;
	*fout << "# JMP DEST: " << toHex(dst) << endl;
	*fout << disasm << endl;
	fout->flush();
	PIN_SetContextReg(ctxt, REG_INST_PTR, dst);	
	PIN_ExecuteAt(ctxt);
}


// ========================================================================================================================
// API Detection Functions for x86
// ========================================================================================================================

// Memory Protection Fix
void FixMemoryProtection()
{
	OS_RETURN_CODE rc;
	NATIVE_PID pid;
	rc = OS_GetPid(&pid);
	*fout << "# Fixing Memory Protection PID: " << pid << endl;
	
	OS_MEMORY_AT_ADDR_INFORMATION info;
	
	for (auto sec : main_img_info->sec_infos) {

		OS_QueryMemory(pid, (VOID*)sec->saddr, &info); 
		*fout << "# ADDR:" << toHex((ADDRINT)info.BaseAddress) << endl;
		*fout << "# SIZE:" << toHex(info.MapSize) << endl;
		*fout << "# Protection:" << toHex(info.Protection) << endl;
		*fout << "# Shared:" << toHex(info.Shared) << endl;
		*fout << "# Type:" << toHex(info.Type) << endl;

		rc = OS_ProtectMemory(pid, 
			(VOID*)sec->saddr, 
			sec->eaddr - sec->saddr, OS_PAGE_PROTECTION_TYPE_EXECUTE | 
			OS_PAGE_PROTECTION_TYPE_READ | OS_PAGE_PROTECTION_TYPE_WRITE);
		*fout << "# OS Return Code of ProtectMemory " << rc.generic_err << endl;;
	}
}


// IAT fixing
void FixIAT()
{	
	DLOG(LogType::kLOG_DUMP, "IAT Fixing\n");

	ADDRINT fnaddr;
	for (auto &[addr, imp] : iat_elem_by_addr) {				
		fnaddr = imp.func_addr;
		if (fnaddr == 0) {
			for (auto obf_call : obf_calls) {
				if (obf_call.ind_addr == 0) continue;
				if (addr == obf_call.ind_addr) {
					fnaddr = obf_call.dst;
					imp.func_addr = fnaddr;
					auto fn = GetFunctionInfo(fnaddr);
					auto n = ResolveForwardedFunc(fn->module_name, fn->name);
					fn->module_name = n.dll;
					fn->name = n.fn;
					imp.dll_name = fn->module_name;
					imp.func_name = fn->name;
					break;
				}
			}		
		}		      
		unsigned char* pc = reinterpret_cast<unsigned char*>(addr);
		PIN_SafeCopy(pc, &fnaddr, ADDRSIZE);
		DLOG(LogType::kLOG_DUMP, imp << endl);
	}
}

// call/goto fixing
void FixCall()
{
	DLOG(LogType::kLOG_DUMP, "# Call Fixing\n");
	UINT8 byts[16];
	size_t sz;
	unsigned char* pc;
	EXCEPTION_INFO pExinfo;

	for (auto obf_call: obf_calls)
	{	
		// skip obf_call from IAT
		if (obf_call.src == 0) continue;

		ADDRINT fn_addr = obf_call.dst;			
		for (auto &[_, iat_info] : iat_elem_by_addr) {
			if (iat_info.func_addr == obf_call.dst) {
				DLOG(LogType::kLOG_DUMP, toHex(obf_call.src) << ' ' << obf_call.GetMnem() << ' ' << iat_info.dll_name << ' ' << iat_info.func_name << endl);
				obf_call.ind_addr = iat_info.addr;
				pc = reinterpret_cast<unsigned char*>(obf_call.src);				
				sz = obf_call.ToBytes(byts);
				size_t num_copied = PIN_SafeCopyEx(pc, byts, sz, &pExinfo);
				DLOG(LogType::kLOG_DUMP, obf_call << endl);
				DLOG(LogType::kLOG_DUMP, "Patched:" << num_copied << endl);
				break;
			}
		}					
	}
}


////////////////////////////////////////////


// ----------------------------------------------------------------------------------------------------------
// Forwarding 된 api 함수 복원
// 
//  ucrt --> ms-win-crt-*
//	kernelbase --> ms-win-crt-*, kernel32
//	ntdll --> kernel32
//	gdi32full --> gdi32  : dll 이름만 바꿈(?)
//  * 계속 보완 해야 됨
//------------------------------------------------------------------------------------------------------------
void ResolveForwardedFunc(vector<IAT_INFO>& imp_list)
{
	
	for (auto &e : imp_list) {

		e.addr -= main_image_start_address;
		ResolveForwardedFunc(e.dll_name, e.func_name);
	}
	// remove themida iat(?)
	std::vector<IAT_INFO>::iterator it;
	for (it = imp_list.begin(); it != imp_list.end(); it++) {
		if (it->func_addr == (ADDRINT)(-1)) {
			break;
		}
	}
	imp_list.erase(it, imp_list.end());
}

FN_INFO ResolveForwardedFunc(string mod_name, string fn_name)
{
	if (mod_name.find("gdi32full.") != string::npos) {
		// 일단 무조건...
		mod_name = string("GDI32.DLL");
	}
	else if (mod_name.find("ucrtbase.") != string::npos) {
		const char* crt_dll_name = get_crt_dll_name(fn_name.c_str());
		if (crt_dll_name) {
			mod_name = string(crt_dll_name);
		}
	}
	else if (mod_name.find("kernelbase.") != string::npos) {

		const char* crt_dll_name = get_crt_dll_name(fn_name.c_str());
		if (crt_dll_name) {
			mod_name = string(crt_dll_name);
		}
		else {

			std::set<std::string>::iterator it = kernel32_funcs.find(fn_name);
			if (it != kernel32_funcs.end()) {
				mod_name = string("kernel32.dll");
			}
			else {
				// KERNELBASE 로 그냥 두자..
			}
		}
	}
	else if (mod_name.find("ntdll.") != string::npos) {

		// 전, 후 함수 확인해야되는데 ... 일단 무조건 바꾸는 걸로
		const char* kname = get_ntdll_to_kernel32_name(fn_name.c_str());

		if (kname) {
			mod_name = string("kernel32.dll");
			fn_name = string(kname);
		}
	}
	return { mod_name, fn_name };
}




void MakeDllList() {
	IAT_DLL_INFO dll_info;	

	DLOG(LogType::kLOG_DUMP, "# Making DLL List\n");

	bool is_first_fn = true;
	string prev_dll_name = "", curr_dll_name = "";
	for (auto &[_, iat_info] : iat_elem_by_addr) {
		DLOG(LogType::kLOG_DUMP, iat_info << endl);
		prev_dll_name = curr_dll_name;
		curr_dll_name = iat_info.dll_name;
		if (iat_info.func_addr == 0 || prev_dll_name != "" && curr_dll_name != "" && prev_dll_name != iat_info.dll_name) {
			// if zero address is repeated, 
			// we may have missed some api functions. 
			// The last few entries of IAT is fixed because the text section refers to those locations. 
			// Then we skip zeros before the last entries. 
			// TODO: fixed locations are in the middle of IAT...
			// 
			if (is_first_fn) continue;	
			dll_list.push_back(dll_info);	// vector push_back copies an object when the object is pushed.
			is_first_fn = true;
			if (iat_info.func_addr == 0) continue;
		}		
		if (is_first_fn) {
			dll_info.first_func = iat_info.addr - main_image_start_address;	// RVA
			dll_info.nfunc = 1;
			dll_info.name = iat_info.dll_name;
			is_first_fn = false;
			continue;
		}			
		dll_info.nfunc++;
	}

	*fout << "# DLL List" << endl;
	for (auto e : dll_list) {
		DLOG(LogType::kLOG_DUMP, e << endl);		
	}
	DLOG(LogType::kLOG_DUMP, "\n");	
}


// Make Import Section

void GetImportComponentSize(UINT32* iidsize0, UINT32* iltsize0, UINT32* iinsize0)
{
	UINT32 iidsize = 0;	// _IMAGE_IMPORT_DESCRIPTOR size
	UINT32 iltsize = 0;	// IAT Size
	UINT32 iinsize = 0;	// _IMAGE_IMPORT_BY_NAME size

	size_t n_dll = dll_list.size();
	size_t n_fn = iat_elem_by_addr.size();
	iidsize = (n_dll + 1) * 20;
	iltsize = (n_fn + 20) * ADDRSIZE;

	// iin dll name size
	for (auto e: dll_list) {
		int len = e.name.size() + 1;	// consider null termination			
		iinsize += Align(len, 2);
	}

	// iin func name size
	for (auto &[_, iat_info]: iat_elem_by_addr) {
		// ordinal functions do not have a name
		if (iat_info.func_name.find("Ordinal_") == string::npos) {
			int len = iat_info.func_name.size() + 1;
			iinsize += 2;
			iinsize += Align(len, 2);
		}
	}

	*iidsize0 = iidsize;
	*iltsize0 = iltsize;
	*iinsize0 = iinsize;
}

void* MakeImportSection(UINT32* size, UINT32 *idt_size, UINT32 vloc)
{
	DLOG(LogType::kLOG_DUMP, "Making Import Section\n");

	UINT32 iidsize;	// _IMAGE_IMPORT_DESCRIPTOR size
	UINT32 iltsize;	// IAT Size
	UINT32 iinsize;	// _IMAGE_IMPORT_BY_NAME size

	MakeDllList();
	GetImportComponentSize(&iidsize, &iltsize, &iinsize);

	UINT32 import_sec_size = Align((iidsize + iltsize + iinsize), 512) + 512;
	ADDRINT import_sec_buf = (ADDRINT)malloc(import_sec_size);
	int ndll = dll_list.size();
	
	// Make Import Directory Table
	NW::IMAGE_IMPORT_DESCRIPTOR* iid = (NW::IMAGE_IMPORT_DESCRIPTOR*)(import_sec_buf);

	ADDRINT ilt0 = import_sec_buf + iidsize;
	ADDRINT ilt = ilt0;

	int i = 0;

	for (auto &e: dll_list) {
		DLOG(LogType::kLOG_DUMP, "DLL " << e << ' ' << toHex(vloc + (ADDRINT)(&iid[i]) - import_sec_buf) << endl);
		iid[i].OriginalFirstThunk = ilt - import_sec_buf + vloc;
		iid[i].ForwarderChain = 0;
		iid[i].TimeDateStamp = 0;		
		iid[i].FirstThunk = e.first_func;  
		ilt += ADDRSIZE * (e.nfunc + 1); 
		i++;
	}
	memset(&iid[i], 0, sizeof(NW::IMAGE_IMPORT_DESCRIPTOR));  // last import directory entry

	// Make Import Names & IAT
	ADDRINT iin = ilt0 + iltsize;
	
	iid = (NW::IMAGE_IMPORT_DESCRIPTOR*)(import_sec_buf); // import names
	ilt = ilt0;	// IAT
	
	i = 0;
	string prev_dll_name;
	for (auto &[iat_elem_addr, iat_info]: iat_elem_by_addr) {
		ADDRINT func_addr = iat_info.func_addr;
		string dll_name = iat_info.dll_name;
		string func_name = iat_info.func_name;
		
		DLOG(LogType::kLOG_DUMP, iat_info << endl);
		// zero bytes between DLLs which means all function names are written and dll name should be written
		// if zero bytes are repeated, there are some missed functions				
		if (func_addr == 0 || prev_dll_name != "" && dll_name != "" && prev_dll_name != dll_name) {						
			// Write DLL Names in Image Import Names Table		
			DLOG(LogType::kLOG_DUMP, "DLL Name: \"" << prev_dll_name << "\" " << i << endl);
			if (prev_dll_name.length() > 0) {
				PutXWORD(ilt, 0);
				ilt += ADDRSIZE;

				DLOG(LogType::kLOG_DUMP, "IIN " << toHex(iin - import_sec_buf + vloc) << ' ' << prev_dll_name << endl);
	
				int len = prev_dll_name.length() + 1;
				PutBytes(iin, (ADDRINT)prev_dll_name.c_str(), len);
				iid[i].Name = iin - import_sec_buf + vloc;
				iin = iin + Align(len, 2);
				i++;
			}
		}

		// ordinal function		
		if (func_name.find("Ordinal_") != string::npos) {
			ADDRINT ilt_val;
			char* stopstr;
			string temp = func_name.substr(8);
			ilt_val = (ADDRINT)std::strtoul(temp.c_str(), &stopstr, 10);
			ilt_val |= IMAGE_ORDINAL_FLAG;

			PutXWORD(ilt, ilt_val);
			PIN_SafeCopy((void*)iat_elem_addr, (const void*)& ilt_val, ADDRSIZE);
			ilt += ADDRSIZE;

		}

		// name function
		else if (func_name != "") {
			ADDRINT ilt_val = iin - import_sec_buf + vloc;
			PutXWORD(ilt, ilt_val);			
			DLOG(LogType::kLOG_DUMP, "# ILT:" << toHex(ilt) << "  ILT_VAL:" << toHex(ilt_val) << endl);

			PIN_SafeCopy((void*)(iat_elem_addr + main_image_start_address), (const void*)& ilt_val, ADDRSIZE);
			ilt += ADDRSIZE;			

			PutWord(iin, 0);
			iin += 2;
			DLOG(LogType::kLOG_DUMP, "# IIN:" << toHex(iin - import_sec_buf + vloc) << ' ' << func_name << endl);

			int len1 = func_name.length() + 1;
			PutBytes(iin, (ADDRINT)func_name.c_str(), len1);						
			iin += Align(len1, 2);
		}

		prev_dll_name = dll_name;
	}

	*size = import_sec_size;
	*idt_size = iidsize;
	return (void*)import_sec_buf;
}

void* MakeImportSectionInRdata(UINT32* size, UINT32* idt_size, UINT32* vloc, UINT32 last_addr)
{
	DLOG(LogType::kLOG_DUMP, "Making Import Section\n");

	UINT32 iidsize;	// _IMAGE_IMPORT_DESCRIPTOR size
	UINT32 iltsize;	// IAT Size
	UINT32 iinsize;	// _IMAGE_IMPORT_BY_NAME size

	MakeDllList();
	GetImportComponentSize(&iidsize, &iltsize, &iinsize);
	*idt_size = iidsize;

	UINT32 import_sec_size = Align((iidsize + iltsize + iinsize), 512);
	*size = import_sec_size;
	
	*vloc = last_addr - import_sec_size;
	ADDRINT import_sec_buf = *vloc + main_image_start_address;

	DLOG(LogType::kLOG_DUMP, "IID Location:" << toHex(import_sec_buf) << endl);

	int ndll = dll_list.size();

	// Make Import Directory Table
	NW::IMAGE_IMPORT_DESCRIPTOR* iid = (NW::IMAGE_IMPORT_DESCRIPTOR*)(import_sec_buf);

	ADDRINT ilt0 = import_sec_buf + iidsize;
	ADDRINT ilt = ilt0;

	int i = 0;

	for (auto& e : dll_list) {
		DLOG(LogType::kLOG_DUMP, "DLL " << e << ' ' << toHex(*vloc + (ADDRINT)(&iid[i]) - import_sec_buf) << endl);
		iid[i].OriginalFirstThunk = ilt - import_sec_buf + *vloc;
		iid[i].ForwarderChain = 0;
		iid[i].TimeDateStamp = 0;
		iid[i].FirstThunk = e.first_func;
		ilt += ADDRSIZE * (e.nfunc + 1);
		i++;
	}
	memset(&iid[i], 0, sizeof(NW::IMAGE_IMPORT_DESCRIPTOR));  // last import directory entry

	// Make Import Names & IAT
	ADDRINT iin = ilt0 + iltsize;

	iid = (NW::IMAGE_IMPORT_DESCRIPTOR*)(import_sec_buf); // import names
	ilt = ilt0;	// IAT

	i = 0;
	string prev_dll_name;
	for (auto& [iat_elem_addr, iat_info] : iat_elem_by_addr) {		
		ADDRINT func_addr = iat_info.func_addr;
		string dll_name = iat_info.dll_name;
		string func_name = iat_info.func_name;

		DLOG(LogType::kLOG_DUMP, iat_info << endl);
		
		// zero bytes between DLLs which means all function names are written and dll name should be written
		// if zero bytes are repeated, there are some missed functions				
		if (func_addr == 0) {
			// Write DLL Names in Image Import Names Table		
			DLOG(LogType::kLOG_DUMP, "DLL Name:" << prev_dll_name << ' ' << i << endl);
			if (prev_dll_name.length() > 0) {
				PutXWORD(ilt, 0);
				ilt += ADDRSIZE;
				DLOG(LogType::kLOG_DUMP, "IIN:" << toHex(iin - import_sec_buf + *vloc) << ' ' << prev_dll_name << endl);

				int len = prev_dll_name.length() + 1;
				PutBytes(iin, (ADDRINT)prev_dll_name.c_str(), len);
				iid[i].Name = iin - import_sec_buf + *vloc;
				iin = iin + Align(len, 2);
				i++;
			}
		}

		// ordinal function		
		else if (func_name.find("Ordinal_") != string::npos) {
			ADDRINT ilt_val;
			char* stopstr;
			string temp = func_name.substr(8);
			ilt_val = (ADDRINT)std::strtoul(temp.c_str(), &stopstr, 10);
			ilt_val |= IMAGE_ORDINAL_FLAG;

			PutXWORD(ilt, ilt_val);
			PIN_SafeCopy((void*)iat_elem_addr, (const void*)&ilt_val, ADDRSIZE);
			ilt += ADDRSIZE;

		}

		// name function
		else {
			ADDRINT ilt_val = iin - import_sec_buf + *vloc;
			PutXWORD(ilt, ilt_val);
			DLOG(LogType::kLOG_DUMP, "ILT:" << toHex(ilt) << " ILT_VAL:" << toHex(ilt_val) << endl);

			PIN_SafeCopy((void*)(iat_elem_addr + main_image_start_address), (const void*)&ilt_val, ADDRSIZE);
			ilt += ADDRSIZE;

			PutWord(iin, 0);
			iin += 2;
			DLOG(LogType::kLOG_DUMP, "# IIN:" << toHex(iin - import_sec_buf + *vloc) << ' ' <<  func_name << endl);

			int len1 = func_name.length() + 1;
			PutBytes(iin, (ADDRINT)func_name.c_str(), len1);
			iin += Align(len1, 2);
		}

		prev_dll_name = dll_name;
	}

	return (void*)import_sec_buf;
}


void DumpData(const char* fname, ADDRINT start, UINT32 size)
{
	ofstream file1(fname, ios::out | ios::binary);
	file1.write((const char*)start, size);
	file1.close();
}

typedef void* (__stdcall* f_CheckSumMappedFile)(void*, NW::DWORD, NW::DWORD*, NW::DWORD*);
#undef INVALID_HANDLE_VALUE
#define INVALID_HANDLE_VALUE (NW::HANDLE)(-1)

ADDRINT Align(ADDRINT dwValue, ADDRINT dwAlign)
{
	if (dwAlign) {
		if (dwValue % dwAlign) {
			return (dwValue + dwAlign) - (dwValue % dwAlign);
		}
	}
	return dwValue;
}

void PutQWORD(ADDRINT addr, UINT64 val)
{
	UINT64* p = (UINT64*)addr;
	*p = val;
}
void PutDWORD(ADDRINT addr, UINT32 val)
{
	UINT32* p = (UINT32*)addr;
	*p = val;
}
void PutWord(ADDRINT addr, UINT16 val)
{
	UINT16* p = (UINT16*)addr;
	*p = val;

}

void PutXWORD(ADDRINT addr, ADDRINT val) {
	ADDRINT* p = (ADDRINT*)addr;
	*p = val;
}

void PutBytes(ADDRINT dst, ADDRINT src, int len)
{
	UINT8* psrc = (UINT8*)src;
	UINT8* pdst = (UINT8*)dst;
	for (int i = 0; i < len; i++) {
		*pdst++ = *psrc++;
	}
}

UINT64 GetQWORD(ADDRINT addr, ADDRINT* paddr)
{
	UINT64* p = (UINT64*)addr;
	if (paddr)* paddr += 8;
	return *p;
}
UINT32 GetDWORD(ADDRINT addr, ADDRINT* paddr)
{
	UINT32* p = (UINT32*)addr;
	if (paddr)* paddr += 4;
	return *p;

}
UINT16 GetWord(ADDRINT addr, ADDRINT* paddr)
{
	UINT16* p = (UINT16*)addr;
	if (paddr)* paddr += 2;

	return *p;;

}
void GetBytes(ADDRINT dst, ADDRINT src, int len)
{
	UINT8* psrc = (UINT8*)src;
	UINT8* pdst = (UINT8*)dst;
	for (int i = 0; i < len; i++) {
		*pdst++ = *psrc++;
	}
}

// dump image as hex text
void DumpHex()
{
	// dump as text file
	ModuleInformation* modinfo = GetModuleInfo(main_image_start_address);
	if (modinfo == NULL) return;

	size_t max_blk_size = 0;
	for (auto it = modinfo->sec_infos.begin(); it != modinfo->sec_infos.end(); it++)
	{
		SectionInformation* secinfo = *it;
		max_blk_size = max(max_blk_size, secinfo->eaddr - secinfo->saddr);
	}

	UINT8* mem_buf = (UINT8*)malloc(max_blk_size);

	for (auto it = modinfo->sec_infos.begin(); it != modinfo->sec_infos.end(); it++)
	{
		SectionInformation* secinfo = *it;
		size_t size = secinfo->eaddr - secinfo->saddr;
		*fout << "DUMP_START" << *secinfo << endl;
		PIN_SafeCopy(mem_buf, (VOID*)secinfo->saddr, size);

		for (size_t idx = 0; idx < size; idx++) {
			*fout << toHex1(mem_buf[idx]);
			if (idx % 64 == 63) *fout << endl;
		}
		if (size % 64 != 0) *fout << endl;
		*fout << "DUMP_END" << endl;
	}
}


// make a copy of original pe header when the image is loaded because themida break the headers from memory dump
void KeepHeader()
{
	hdr_at_load = malloc(4096);
	memcpy(hdr_at_load, (const void*)main_image_start_address, 4096);
}


// utility for calculating overlay offset

ADDRINT GetNextOffset(OFFSET_AND_SIZE o_s) 
{
	return o_s.offset + o_s.size;
}


OFFSET_AND_SIZE GetLargerWithinFile(
	OFFSET_AND_SIZE maxOffsetAndSize,
	OFFSET_AND_SIZE offsetAndSize)
{
	ADDRINT nextAddr = GetNextOffset(offsetAndSize);
	ADDRINT maxNextAddr = GetNextOffset(maxOffsetAndSize);
	if (nextAddr <= file_size && nextAddr > maxNextAddr) {
		return offsetAndSize;
	}
	return maxOffsetAndSize;
}

OFFSET_AND_SIZE GetOverlayDataStartOffsetAndSize(void* hdr)
{		
	ADDRINT loadBase0 = (ADDRINT)hdr;
	NW::IMAGE_DOS_HEADER* dos0 = (NW::IMAGE_DOS_HEADER*)loadBase0;
	NW::IMAGE_NT_HEADERS* nt0 = (NW::IMAGE_NT_HEADERS*)(loadBase0 + dos0->e_lfanew);
	NW::IMAGE_SECTION_HEADER* sect0 = (NW::IMAGE_SECTION_HEADER*)
		(loadBase0 +
			dos0->e_lfanew +
			sizeof(NW::DWORD) +
			sizeof(nt0->FileHeader) +
			nt0->FileHeader.SizeOfOptionalHeader);

	OFFSET_AND_SIZE maxOffsetAndSize = { 0, 0 }; 
	
	// optional header
	OFFSET_AND_SIZE ophdr_o_s = { 
		(ADDRINT) & (nt0->OptionalHeader) - loadBase0, 
		nt0->FileHeader.SizeOfOptionalHeader };
	maxOffsetAndSize = GetLargerWithinFile(maxOffsetAndSize, ophdr_o_s);

	// sections
	int nsec = nt0->FileHeader.NumberOfSections;

	for (auto i = 0; i < nsec; i++) {
		OFFSET_AND_SIZE sect_o_s = { sect0[i].PointerToRawData, sect0[i].SizeOfRawData };
		maxOffsetAndSize = GetLargerWithinFile(maxOffsetAndSize, sect_o_s);
	}

	// data directories

	for (auto e : nt0->OptionalHeader.DataDirectory) {
		// entry
		OFFSET_AND_SIZE de = { e.VirtualAddress, e.Size };
		maxOffsetAndSize = GetLargerWithinFile(maxOffsetAndSize, de);
	}

	if (file_size > GetNextOffset(maxOffsetAndSize)) {
		ADDRINT next_addr = GetNextOffset(maxOffsetAndSize);
		size_t sz = file_size - next_addr;
		return {next_addr, sz};
	}
	return { 0, 0 };
}


// dump memory of each section
void DumpUnpackedFile()
{	
	LOG("DUMP file");
	ADDRINT img_base = main_image_start_address;

	// use original header from loaded pe
	// because themida break the headers from memory dump
	void* hdr = hdr_at_load;
	ADDRINT loadBase0 = (ADDRINT)hdr;

	NW::IMAGE_DOS_HEADER* dos0 = (NW::IMAGE_DOS_HEADER*)loadBase0;
	NW::IMAGE_NT_HEADERS* nt0 = (NW::IMAGE_NT_HEADERS*)(loadBase0 + dos0->e_lfanew);
	NW::IMAGE_SECTION_HEADER* sect0 = (NW::IMAGE_SECTION_HEADER*)
		(loadBase0 + 
			dos0->e_lfanew + 
			sizeof(NW::DWORD) + 
			sizeof(nt0->FileHeader) + 
			nt0->FileHeader.SizeOfOptionalHeader);
	if (dos0->e_magic != 0x5A4D || nt0->Signature != 0x4550) {
		LOG("[Err] LoadExeFile: Invalid signatures");
		return;
	}

	// Check Overlay
	OFFSET_AND_SIZE overlay_os = GetOverlayDataStartOffsetAndSize(hdr);
	if (overlay_os.offset != 0) {
		*fout << "Overlay Data Detected. Offset:" << toHex(overlay_os.offset) << " Size:" << toHex(overlay_os.size) << endl;
		DumpUnpackedFile_Overlay();
		return;
	}

	// set OEP
	nt0->OptionalHeader.AddressOfEntryPoint = oep;

	// add one more section for import
	
	int nsec = nt0->FileHeader.NumberOfSections;
	nt0->FileHeader.NumberOfSections++;

	// Original Section that themida included in the packed binary
	UINT32 floc = 0x1000;
	for (int i = 0; i < nsec; i++) {
		UINT32 vsize = sect0[i].Misc.VirtualSize;
		UINT32 fsize_a = Align(vsize, nt0->OptionalHeader.FileAlignment);
		sect0[i].SizeOfRawData = fsize_a;
		sect0[i].PointerToRawData = floc;
		floc = floc + fsize_a;
	}

	nt0->OptionalHeader.ImageBase = img_base;

	// because themida deleted relocation
	nt0->FileHeader.Characteristics |= IMAGE_FILE_RELOCS_STRIPPED;

	// start of appended section
	UINT32 vloc = sect0[nsec - 1].VirtualAddress +
		Align(sect0[nsec - 1].Misc.VirtualSize, nt0->OptionalHeader.SectionAlignment);

	// import section	
	UINT32 vloc_imp = vloc;
	UINT32 idt_size;
	UINT32 vsize_imp;

	void* fdata_imp = MakeImportSection(&vsize_imp, &idt_size, vloc_imp);
	if (!fdata_imp) {
		return;
	}
	
	vsize_imp = Align(vsize_imp, nt0->OptionalHeader.SectionAlignment);
	UINT32 fsize_imp = Align(vsize_imp, nt0->OptionalHeader.FileAlignment);

	sect0[nsec].VirtualAddress = vloc_imp;
	sect0[nsec].Misc.VirtualSize = vsize_imp;
	sect0[nsec].SizeOfRawData = fsize_imp;
	sect0[nsec].PointerToRawData = floc;
	sect0[nsec].Characteristics = sect0[1].Characteristics;
	void* pp = &sect0[nsec].Name;
	strcpy((char*)pp, ".import");

	nt0->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = vloc_imp;
	nt0->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = idt_size;
	
	auto first_iat_element_addr = (*iat_elem_by_addr.begin()).first;
	auto last_iat_element_addr = (*iat_elem_by_addr.rbegin()).first;
	nt0->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = (UINT32)(first_iat_element_addr - main_image_start_address);
	nt0->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = (UINT32)(last_iat_element_addr - first_iat_element_addr + ADDRSIZE);

	// ----------------------------------------------------------------------------------------------------
	floc = floc + fsize_imp;
	vloc = vloc_imp + Align(vsize_imp, nt0->OptionalHeader.SectionAlignment);
	
	nt0->OptionalHeader.SizeOfImage = vloc;
	nt0->OptionalHeader.SizeOfHeaders = 0x400;

	string ext;
	if (is_dll_analysis) ext = "_dmp.dll";
	else ext = "_dmp.exe";
	string outfile;
	outfile = main_file_name; 
	FILE* fp = NULL;
	int cnt = 0;	
	while (fp == NULL) {
		outfile = main_file_name;
		if (cnt > 0) {
			outfile += "_" + toHex(cnt);
		}
		outfile += ext;
		fp = fopen(outfile.c_str(), "wb");
		cnt++;
	}
	UINT32 off = 0;;
	fwrite((const void*)hdr, 4096, 1, fp);

	off += 4096;

	for (int i = 0; i < nsec; i++) {
		UINT32 fsize = sect0[i].SizeOfRawData;
		ADDRINT addr = sect0[i].VirtualAddress + img_base;
		fwrite((const void*)addr, fsize, 1, fp);
		off += fsize;
	}

	fwrite((const void*)fdata_imp, fsize_imp, 1, fp);
	off += fsize_imp;

	free(hdr);
	free(fdata_imp);

	fclose(fp);		
}

/// =====================
// dump memory of each section and import section at 
void DumpUnpackedFile_Overlay()
{
	ADDRINT img_base = main_image_start_address;

	// use original header from loaded pe
	// because themida break the headers from memory dump
	void* hdr = hdr_at_load;
	ADDRINT loadBase0 = (ADDRINT)hdr;

	NW::IMAGE_DOS_HEADER* dos0 = (NW::IMAGE_DOS_HEADER*)loadBase0;
	NW::IMAGE_NT_HEADERS* nt0 = (NW::IMAGE_NT_HEADERS*)(loadBase0 + dos0->e_lfanew);
	NW::IMAGE_SECTION_HEADER* sect0 = (NW::IMAGE_SECTION_HEADER*)
		(loadBase0 +
			dos0->e_lfanew +
			sizeof(NW::DWORD) +
			sizeof(nt0->FileHeader) +
			nt0->FileHeader.SizeOfOptionalHeader);

	// set OEP
	nt0->OptionalHeader.AddressOfEntryPoint = oep;

	// add one more section for import

	int nsec = nt0->FileHeader.NumberOfSections;
	nt0->FileHeader.NumberOfSections++;

	// Original Section that themida included in the packed binary
	UINT32 floc = 0x1000;
	for (int i = 0; i < nsec; i++) {
		UINT32 vsize = sect0[i].Misc.VirtualSize;
		UINT32 fsize_a = Align(vsize, nt0->OptionalHeader.FileAlignment);
		sect0[i].SizeOfRawData = fsize_a;
		sect0[i].PointerToRawData = floc;
		floc = floc + fsize_a;
	}

	nt0->OptionalHeader.ImageBase = img_base;

	// because themida deleted relocation
	nt0->FileHeader.Characteristics |= IMAGE_FILE_RELOCS_STRIPPED;

	
	// import section	
	UINT32 vloc_imp;
	UINT32 idt_size;
	UINT32 vsize_imp;

	void* fdata_imp = MakeImportSectionInRdata(&vsize_imp, &idt_size, &vloc_imp, sect0[1].VirtualAddress + sect0[1].SizeOfRawData);
	if (!fdata_imp) {
		return;
	}

	vsize_imp = Align(vsize_imp, nt0->OptionalHeader.SectionAlignment);
	UINT32 fsize_imp = Align(vsize_imp, nt0->OptionalHeader.FileAlignment);

	// IDT, INT, Names
	UINT32 vloc = sect0[2].VirtualAddress - vsize_imp;


	//sect0[nsec].VirtualAddress = vloc_imp;
	//sect0[nsec].Misc.VirtualSize = vsize_imp;
	//sect0[nsec].SizeOfRawData = fsize_imp;
	//sect0[nsec].PointerToRawData = floc;
	//sect0[nsec].Characteristics = sect0[1].Characteristics;
	//void* pp = &sect0[nsec].Name;
	//strcpy((char*)pp, ".import");

	nt0->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = vloc_imp;
	nt0->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = idt_size;

	auto first_iat_element_addr = (*iat_elem_by_addr.begin()).first;
	auto last_iat_element_addr = (*iat_elem_by_addr.rbegin()).first;

	nt0->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = (UINT32)(first_iat_element_addr - main_image_start_address);
	nt0->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = (UINT32)(last_iat_element_addr - first_iat_element_addr + ADDRSIZE);


	// ----------------------------------------------------------------------------------------------------
	floc = floc + fsize_imp;
	vloc = vloc_imp + Align(vsize_imp, nt0->OptionalHeader.SectionAlignment);

	nt0->OptionalHeader.SizeOfImage = vloc;
	nt0->OptionalHeader.SizeOfHeaders = 0x400;

	string ext;
	if (is_dll_analysis) ext = "_dmp.dll";
	else ext = "_dmp.exe";
	string outfile;
	outfile = main_file_name;

	// read overlay data
	FILE* fp = NULL;
	fp = fopen(main_file_name.c_str(), "rb");
	
	OFFSET_AND_SIZE overlay_os = GetOverlayDataStartOffsetAndSize(hdr);
	void* overlay_data = malloc(overlay_os.size);
	fseek(fp, overlay_os.offset, SEEK_SET);
	fread(overlay_data, overlay_os.size, 1, fp);
	fclose(fp);
	fp = NULL;

	int cnt = 0;
	while (fp == NULL) {
		outfile = main_file_name;
		if (cnt > 0) {
			outfile += "_" + toHex(cnt);
		}
		outfile += ext;
		fp = fopen(outfile.c_str(), "wb");
		cnt++;
	}
	UINT32 off = 0;;
	fwrite((const void*)hdr, 4096, 1, fp);

	off += 4096;

	for (int i = 0; i < nsec; i++) {
		UINT32 fsize = sect0[i].SizeOfRawData;
		ADDRINT addr = sect0[i].VirtualAddress + img_base;
		fwrite((const void*)addr, fsize, 1, fp);
		off += fsize;
	}

	fwrite(overlay_data, overlay_os.size, 1, fp);
	fclose(fp);
	free(hdr);
}

/// =====================


// EXE INS memory write analysis function 
void Analysis_INS_MW(ADDRINT addr, size_t mSize, ADDRINT targetAddr)
{
	SetMemoryPageWrite(targetAddr);


	if (current_obf_fn == NULL) return;
	if (is_dll_analysis && IsMainImage(targetAddr)) return;

	if (IsMainImage(targetAddr)) return;
	if (targetAddr == 0) {
		current_obf_fn = 0;
		return;
	}
	if (GetModuleInfo(targetAddr) != NULL) return;

	for (size_t i = 0; i < mSize; i++)
	{
		obfaddr2fn[targetAddr + i] = current_obf_fn;
	}

	DLOG(LogType::kLOG_MEMORY_ACCESS, "MW: " << toHex(addr) << ' ' << toHex(targetAddr) << ' ' << mSize << endl);

}

// EXE INS memory read analysis function 
void Analysis_INS_MR(ADDRINT targetAddr)
{
	FunctionInformation *finfo = GetFunctionInfo(targetAddr);
	if (finfo == NULL) return;
	current_obf_fn = finfo;
	DLOG(LogType::kLOG_MEMORY_ACCESS, "API Read: " << toHex(targetAddr) << ' ' << *current_obf_fn << endl);
}

// debug
void Analysis_INS(ADDRINT addr) {
	*fout << "I " << toHex(addr) << endl;
	fout->flush();
}

// ========================================================================================================================
// Common Callbacks
// ========================================================================================================================

// IMG instrumentation function for EXE&DLL files
void Instrument_IMG(IMG img, void *v)
{

	// Trim image name
	string imgname = IMG_Name(img);
	size_t pos = imgname.rfind("\\") + 1;
	imgname = imgname.substr(pos);
	TO_LOWER(imgname);
	ModuleInformation *modinfo = NULL;
	if (module_info_m.find(imgname) != module_info_m.end()) return;
	
	bool kernel32 = false;
	TO_LOWER(imgname);
	if (imgname.find("kernel32.") != string::npos) kernel32 = true;

	// Record symbol information of a loaded image 
	ADDRINT img_saddr = IMG_LowAddress(img);
	ADDRINT img_eaddr = IMG_HighAddress(img);
	modinfo = new ModuleInformation(imgname, img_saddr, img_eaddr);
	module_info_m[imgname] = modinfo;	

	bool is_main = false;

	if (is_dll_analysis)
	{
		// obfuscated dll module is loaded
		if (imgname == obf_dll_name)
		{
			is_main = true;
			main_file_name = imgname;
			obf_dll_entry_addr = IMG_EntryAddress(img);
			main_image_start_address = img_saddr;
			main_image_end_address = img_eaddr;	
			main_img_info = modinfo;

			if (ir_file != "kdtir_0.txt") {
				AdjustLoadedAddress(main_image_start_address);
			}

			KeepHeader();
			ifstream in(main_file_name.c_str(), ifstream::ate | ifstream::binary);
			file_size = in.tellg();
		}

		// loader exe file is loaded
		if (IMG_IsMainExecutable(img))
		{			
			loader_saddr = img_saddr;
			loader_eaddr = img_eaddr;
		}
	}
	else
	{
		// EXE analysis
		if (IMG_IsMainExecutable(img))
		{
			is_main = true;
			main_file_name = imgname;
			main_image_start_address = img_saddr;
			main_image_end_address = img_eaddr;
			main_img_info = modinfo;

			if (ir_file != "kdtir_0.txt") AdjustLoadedAddress(main_image_start_address);

			KeepHeader();
			ifstream in(main_file_name.c_str(), ifstream::ate | ifstream::binary);
			file_size = in.tellg();
		}
	}

	if (is_main) {
		size_t cnt = 0;
		for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec), cnt++) {
			if (SEC_Name(sec) == ".text" || cnt == 0)
			{
				// by default, the first section is considered as .text section
				// if the executable file is compiled in debug mode, the first section is .textbss and the second section is .text
				main_text_section_start_address = SEC_Address(sec);
				main_text_section_end_address = main_text_section_start_address + SEC_Size(sec);
			}
			else if (SEC_Name(sec) == ".rdata") {
				obf_rdata_saddr = SEC_Address(sec);
				obf_rdata_eaddr = obf_rdata_saddr + SEC_Size(sec);
			}
			else if (packer_type == "vmp" && cnt == 1 && SEC_Name(sec) == ".data") {
				obf_rdata_saddr = SEC_Address(sec);
				obf_rdata_eaddr = obf_rdata_saddr + SEC_Size(sec);
			}
			else if (SEC_Name(sec) == ".idata")
			{
				obf_idata_saddr = SEC_Address(sec);
				obf_idata_eaddr = obf_idata_eaddr + SEC_Size(sec);
			}
			else if (SEC_Name(sec) == ".vmp0")
			{
				main_vmp_section_start_address = SEC_Address(sec);
				main_vmp_section_end_address = main_vmp_section_start_address + SEC_Size(sec);
			}
		}
	}
	
	*fout << "IMG:" << *modinfo << endl;

	// Record each section and function data
	size_t cnt = 0;
	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec), cnt++)
	{
		string secname = SEC_Name(sec);
		ADDRINT sec_saddr = SEC_Address(sec);
		ADDRINT sec_eaddr = sec_saddr + SEC_Size(sec);
		SectionInformation *secinfo = new SectionInformation(imgname, secname, sec_saddr, sec_eaddr);
		modinfo->sec_infos.push_back(secinfo);
		if (is_main) 
		{
			*fout << "SECTION:" << *secinfo << endl;
		}		
		
		// by default, the first section is considered as .text section
		// if the executable file is compiled in debug mode, the first section is .textbss and the second section is .text			
		if (SEC_Name(sec) == ".text" || cnt == 0)
		{			
			bool found_rtn = false;
			for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
			{
				string rtnname = RTN_Name(rtn);
				if (rtnname == ".text" || rtnname[0] == ' ') continue;

				ADDRINT rtn_saddr = RTN_Address(rtn);
				ADDRINT rtn_eaddr = rtn_saddr + RTN_Range(rtn);
				FunctionInformation *fninfo = new FunctionInformation(imgname, rtnname, rtn_saddr, rtn_eaddr);				
				fn_info_m[rtn_saddr] = fninfo;
				fn_str_2_fn_info[make_pair(imgname, rtnname)] = fninfo;
				module_info_m[imgname]->fn_infos.push_back(fninfo);

				if (kernel32) kernel32_funcs.insert(rtnname);

				found_rtn = true;
			}

			if (!found_rtn) {
				*fout << "PIN debugging information is not accessible.\n";
				// fout->flush();
				vector<ADDRINT> v_fn_addr;
				vector<string> v_fn_name;
				*fout << "Reading exports from the binary file in memory." << endl;
				// fout->flush();
				bool found_exports = read_exports(img_saddr, v_fn_addr, v_fn_name);
				*fout << "read_exports end " << found_exports << endl;
				// fout->flush();
				if (found_exports) {
					for (auto addr : v_fn_addr) {
						*fout << toHex(addr) << endl;
					}
					for (auto name : v_fn_name) {
						*fout << name << endl;
					}
					fout->flush();
					for (size_t i = 0; i < v_fn_name.size(); i++) {
						string rtnname = v_fn_name[i];
						ADDRINT rtn_saddr = v_fn_addr[i];
						ADDRINT rtn_eaddr = rtn_saddr + ADDRSIZE;	// we don't know the function size
						FunctionInformation* fninfo = new FunctionInformation(imgname, rtnname, rtn_saddr, rtn_eaddr);
						*fout << *fninfo << endl;
						fn_info_m[rtn_saddr] = fninfo;
						fn_str_2_fn_info[make_pair(imgname, rtnname)] = fninfo;
						module_info_m[imgname]->fn_infos.push_back(fninfo);
					}
				}
				
			}
		}
	}

}

// This routine is executed every time a thread is created.
VOID ThreadStart(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v)
{
	*fout << "Thread started " << threadid << endl;
	thr_cnt++;
	DLOG(LogType::kLOG_THREAD, "Starting Thread " << threadid << endl);
	thread_ids.insert(threadid);
	if (threadid == 0)
	{
		main_thread_uid = PIN_ThreadUid();
	}
}

// This routine is executed every time a thread is destroyed.
VOID ThreadFini(THREADID threadid, const CONTEXT *ctxt, INT32 code, VOID *v)
{
	thr_cnt--;
	DLOG(LogType::kLOG_THREAD, "# Ending Thread " << threadid << endl);
	thread_ids.erase(threadid);
}


/*!
 * Print out analysis results.
 * This function is called when the application exits.
 * @param[in]   code            exit code of the application
 * @param[in]   v               value specified by the tool in the
 *                              PIN_AddFiniFunction function call
 */
void Fini(INT32 code, void *v)
{
	((ofstream*)fout)->close();
}

/*!
 * Internal Thread
 */
VOID UnpackThread(VOID* arg)
{
	string msg_hdr = "Unpack Thread: ";

	if (no_stage == 2) {
		ReadIntermediateResult(ir_file);
	}
	else {
		// Wait until OEP is found.
		LOG(msg_hdr + "Waiting until OEP.\n");
		PIN_SemaphoreWait(&sem_oep_found);
	}
		
	// Fix Memory Protection for VMProtect 3.x and Themida 3.x
	if (packer_type == "vmp" && ADDRSIZE == 8 || packer_type == "tmd3") {
		LOG(msg_hdr + "Resetting Memory Protection\n");
		FixMemoryProtection();
	}

	// Date: 23. 5. 16. 
	// using dbghelp.dll
	InitDbgHelp();

	if (imp_start_addr == 0) {
		// Search for IAT area.		
		LOG(msg_hdr + "Searching for IAT Area.\n");
		bool isIAT = FindIAT();
		if (!isIAT)
		{
			LOG(msg_hdr + "Cannot find an IAT area candidate in the binary.\n");
		}
	}

	DLOG(LogType::kLOG_CALL_CHECK, "Obfuscated IAT element candidates: " << obf_iat_elems.size() << endl);
	if (1 /*obf_call_candidates.empty()*/) {
		// Search for obfuscated API calls.
		LOG(msg_hdr + "Searching for obfuscated calls.\n");
		FindObfuscatedAPICalls();
		DLOG(LogType::kLOG_CALL_CHECK, "Obfuscated Calls:\n");
		DLOG(LogType::kLOG_CALL_CHECK, "------------------------------\n");
		for (auto e : obf_calls) {
			DLOG(LogType::kLOG_CALL_CHECK, "# " << e << endl);
		}
		DLOG(LogType::kLOG_CALL_CHECK, "\n");	
	}


	if (no_stage == 1) {
		WriteIntermediateResult(ir_file);
		((ofstream*)fout)->close();
		PIN_ExitProcess(-1);
	}

	if (packer_type == "vmp" || packer_type == "tmd2" && ADDRSIZE == 8 || packer_type == "tmd3") {		
		// Resolve obfuscated API calls for vmp & Theamida64 2.x & Themida32/64 3.x
		LOG(msg_hdr + "Resolving obfuscated API Calls.\n");

		DLOG(LogType::kLOG_CALL_CHECK, "# Obfuscated Call Candidates\n");
		DLOG(LogType::kLOG_CALL_CHECK, "------------------------------\n");
		for (auto e : obf_call_candidates) {
			DLOG(LogType::kLOG_CALL_CHECK, e << endl);
		}

		run_until_api_function_status = RunUntilAPIFunctionStatus::kCheckNextCall;
		PIN_SemaphoreWait(&sem_resolve_api_end);
	}	
	LOG(msg_hdr + "Resolving obfuscated API Calls finished.\n");
	
	if (packer_type == "vmp") {
		LOG(msg_hdr + "Resolve forwarded functions.\n");
		ReconstructImpList();
	}
	

	PrintIATArea();

	LOG(msg_hdr + "Fixing IAT.\n");
	FixIAT();
	
	PrintIATArea();


	LOG(msg_hdr + "Fixing obfuscated calls.\n");
	FixCall();	
	
	LOG(msg_hdr + "Fixing obfuscated calls finished.\n");

	LOG(msg_hdr + "Dumping PE file.\n");
	DumpUnpackedFile();	

	LOG(msg_hdr + "Semaphore set\n");
	PIN_SemaphoreSet(&sem_dump_finished);	

	LOG(msg_hdr + "Semaphore set2\n");
	((ofstream*)fout)->close();
	PIN_ExitProcess(-1);

	LOG(msg_hdr + "exit\n");


}

static int hadException = FALSE;

// exception handler
static void OnException(THREADID threadIndex,
	CONTEXT_CHANGE_REASON reason,
	const CONTEXT* ctxtFrom,
	CONTEXT* ctxtTo,
	INT32 info,
	VOID* v)
{
	if (reason == CONTEXT_CHANGE_REASON_EXCEPTION)
	{
		UINT32 exceptionCode = info;
		// Depending on the system and CRT version, C++ exceptions can be implemented 
		// as kernel- or user-mode- exceptions.
		// This callback does not not intercept user mode exceptions, so we do not 
		// log C++ exceptions to avoid difference in output files.
		if (exceptionCode == 0xc0000096 || exceptionCode == 0xc000001d || exceptionCode == 0xc0000005) {
			*fout << "# Exception code *= " << toHex(exceptionCode) << endl;
			return;
		}
		if ((exceptionCode >= 0xc0000000) && (exceptionCode <= 0xcfffffff))
		{
			*fout << "# Exception code = " << toHex(exceptionCode) << endl;
			if (curr_obf_call) {
				*fout << "SKIP:" << toHex(curr_obf_call->src) << endl;
				*fout << "NO:" << curr_obf_fn_pos << endl;
				WriteIntermediateResult(ir_file);
			}
			else {
				*fout << "From:" << toHex(PIN_GetContextReg(ctxtFrom, REG_INST_PTR)) << endl;
				*fout << "From:" << toHex(PIN_GetContextReg(ctxtTo, REG_INST_PTR)) << endl;
			}
			LOG("Exception:" + hexstr(exceptionCode) + "\n");
			LOG("Continue-with " + ir_file);
			((ofstream*)fout)->close();
			PIN_ExitProcess(-1);
		}
	}
}


void ReadIntermediateResult(string filename)
{
	LOG("Reading Intermediate Result:" + filename + "\n");
	string line, data_ty;	
	ObfuscatedCall obfcall;
	string call_ty;	

	ifstream fin(filename.c_str());
	string current_status = "";
	while (fin.good()) {
		getline(fin, line);
		stringstream ss(line);
		if (line.find("OEP") != string::npos) {
			ss >> data_ty >> hex >> oep;
			continue;
		}
		else if (line.find("IMP") != string::npos) {
			ss >> data_ty >> hex >> imp_start_addr >> imp_end_addr;
			imp_start_addr += main_image_start_address;
			imp_end_addr += main_image_start_address;
			continue;
		}
		else if (line.find("OBFUSCATED CALL CANDIDATES") != string::npos) {
			current_status = "OBFUSCATED_CALL_CANDIDATES";
			continue;
		}
		else if (line.find("NEXT_POS") != string::npos) {
			ss >> data_ty >> curr_obf_fn_pos;
			continue;
		}
		else if (line.find("DEOBFUSCATED CALL") != string::npos) {
			current_status = "DEOBFUSCATED_CALL";
			continue;
		}

		if (current_status == "OBFUSCATED_CALL_CANDIDATES") {
			ss >> call_ty >> hex >> obfcall.src >> hex >> obfcall.dst >> obfcall.n_prev_pad_bytes;
			obfcall.ins_type = ParseObfuscatedCallType(call_ty);
			obf_call_candidates.push_back(obfcall);
		}
		else if (current_status == "DEOBFUSCATED_CALL") {
			ss >> call_ty >> hex >> obfcall.src >> hex >> obfcall.dst;
			obfcall.ins_type = ParseObfuscatedCallType(call_ty);
			obf_calls.push_back(obfcall);
		}
	}

	// so far obfuscated calls are in RVA
	// we will fix this after loading the main image

	fin.close();
	WriteIntermediateResult("test.txt");
	skip_until_oep = true;
}


void AdjustLoadedAddress(ADDRINT delta) {
	*fout << "# Adjusting Loaded Addresses\n";

	for (auto &e : obf_call_candidates) {
		*fout << "# e.src " << toHex(e.src) << "->";
		e.src += delta;
		*fout << toHex(e.src) << endl;
	}
	for (auto &e : obf_calls) {		
		*fout << "# e.src " << toHex(e.src) << "->";
		e.src += delta;
		*fout << toHex(e.src) << endl;
	}
	WriteIntermediateResult("test1.txt");

}

void WriteIntermediateResult(string filename)
{	
	*fout << "Writing intermediate result to " << filename << endl;
	ofstream ir_out(filename.c_str());
	
	ir_out << "OEP=" << toHex(oep) << endl;
	ir_out << "IMP_START=" << toHex(imp_start_addr - main_image_start_address) << endl;
	ir_out << "IMP_END=" << toHex(imp_end_addr - main_image_start_address) << endl;
	//ir_out << "IAT_ELEMENTS=[" << endl;
	//for (auto e : imp_list) {
	//	ir_out << "\t[";
	//	ir_out << toHex(e.addr - main_img_saddr) << ',';
	//	if (e.func_addr == 0) {
	//		ir_out << "0,\"\",\"\"";
	//		
	//	}
	//	else {
	//		ir_out << toHex(e.func_addr - main_img_saddr) << ',' << e.func_name << ',' << e.dll_name;
	//	}		
	//	ir_out  << "]," << endl;
	//}
	//ir_out << "]" << endl;


	ir_out << "OBFUSCATED_IAT_ELEMENTS=[" << endl;
	for (auto e : obf_iat_elems) {
		ir_out << "\t[" << toHex(e.src - main_image_start_address) << ',' << toHex(e.dst - main_image_start_address) << "]," << endl;
	}
	
	ir_out << "]" << endl;
	ir_out << "OBFUSCATED_CALL_CANDIDATES=[" << endl;
	for (auto e : obf_call_candidates) {
		ir_out << "\t[" << e.ins_type << ',' << toHex(e.src - main_image_start_address) << ' ' << toHex(e.dst - main_image_start_address) << ' ' << e.n_prev_pad_bytes << endl;
	}	
	ir_out << "]" << endl;
	ir_out << "DEOBFUSCATED CALLS" << endl;
	for (auto e : obf_calls) {
		ir_out << '\t' << e.ins_type << ' ' << toHex(e.src - main_image_start_address) << ' ' << toHex(e.dst - main_image_start_address) << endl;
	}
	ir_out << endl;
	ir_out.close();
}




/*!
 * The main procedure of the tool.
 * This function is called when the application image is loaded but not yet started.
 * @param[in]   argc            total number of elements in the argv array
 * @param[in]   argv            array of command line arguments, 
 *                              including pin -t <toolname> -- ...
 */
int main(int argc, char* argv[])
{
	// Initialize PIN library. Print help message if -h(elp) is specified
	// in the command line or the command line is invalid 
	if (PIN_Init(argc, argv))
	{
		return -1;
	}

	string outputFileName = KnobOutputFile.Value();
	if (outputFileName == "result.txt")
	{
		outputFileName = string(argv[argc - 1]);
		outputFileName += ".txt";
	}
	fout = new ofstream(outputFileName.c_str());

	is_mem_dump = KnobDump.Value();

	packer_type = KnobPackerType.Value();
	*fout << "PACKER:" << packer_type << endl;
	obf_dll_name = KnobDLLFile.Value();
	if (obf_dll_name != "") {
		is_dll_analysis = true;

		*fout << "TYPE:DLL" << endl;
		*fout << "NAME:" << obf_dll_name << endl;

		TO_LOWER(obf_dll_name);
		size_t pos = obf_dll_name.rfind("\\");
		if (pos != string::npos) obf_dll_name = obf_dll_name.substr(pos + 1);

	}
	else {
		*fout << "TYPE:EXE" << endl;
		*fout << "NAME:" << string(argv[argc - 1]) << endl;
	}

	is_direct_call = KnobDirectCall.Value();

	no_stage = KnobMultiStage.Value();

	// read previous result
	if (no_stage > 1) {
		stringstream ss;
		ss << "kdtir" << (no_stage - 1) << ".txt";
		ir_file = ss.str();
		*fout << "# reading intermediate result file:" << ir_file << endl;
		ReadIntermediateResult(ir_file);
	}

	// intermediate result output file
	if (no_stage > 0) {
		stringstream ss;
		ss << "kdtir" << no_stage << ".txt";
		ir_file = ss.str();
		*fout << "# intermediate result file:" << ir_file << endl;
	}		

	/////////////////////////////////////////////////////////////////////////////////////////////
	PIN_InitSymbols();
	
	// Register Analysis routines to be called when a thread begins/ends
	PIN_AddThreadStartFunction(ThreadStart, 0);
	PIN_AddThreadFiniFunction(ThreadFini, 0);

	// Image Instrumentation
	IMG_AddInstrumentFunction(Instrument_IMG, 0);

	// Register function to be called to instrument traces
	if (packer_type == "vmp" || packer_type == "tmd3" || packer_type == "tmd2" || packer_type == "enigma") {
		TRACE_AddInstrumentFunction(Instrument_TRC, 0);		
	}

	// exception handling
	// PIN_AddContextChangeFunction(OnException, 0);

	// Register function to be called when the application exits
	PIN_AddFiniFunction(Fini, 0);

	
	// Initialize semaphore
	PIN_SemaphoreInit(&sem_oep_found);
	PIN_SemaphoreInit(&sem_resolve_api_end);
	PIN_SemaphoreInit(&sem_unpack_finished);
	PIN_SemaphoreInit(&sem_dump_finished);
	
	// Spawn an internal thread
	PIN_SpawnInternalThread(UnpackThread, NULL, 0, &unpack_thread_uid);

	// Start the program, never returns    
	PIN_StartProgram();
	
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */

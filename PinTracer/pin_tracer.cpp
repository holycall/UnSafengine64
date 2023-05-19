#include "pin_tracer.h"
#include "internal_vm_analysis.h"

namespace NW {
#include <Windows.h>
}
#include <time.h>

using namespace std;

#define LOG_X64EXCEPTION_HANDLER 0


/* ===================================================================== */
// Command line switches
/* ===================================================================== */

KNOB<string> KnobConfigFile(KNOB_MODE_WRITEONCE, "pintool", "option", ".\\pintracer.cfg", "specify option file");

// KNOB related flags
bool is_dll_analysis = false;
string isMemTrace = "";
bool isMemReadTrace = false;
bool isMemWriteTrace = false;
bool isCount = false;
bool isGraph = false;
bool isInsTrace = false;
bool isWriteExecute = false;
bool isPrintBasicBlockHex = false;
bool isBlockTrace = false;
bool isBlockTracePT = false;
bool isDLLTrace = false;
bool isDynamicGeneratedCodeTrace = false;
bool isStringTrace = false;
bool isDumpCode = false;
bool isVMAnalysis = false;
bool isVMPVMAnalysis = false;
bool isInternalVMAnalysis = false;
bool isAntiAntiPin = false;
bool isAntiAntiVM = false;
bool isPrintSymbolInfo = false;


// VMP Analysis variables
bool isVMPChecking = false;

// obfuscated DLL name
string obf_dll_name = "";

// standard output & file output 
ostream* dot_out = NULL;	// dot output
ostream* dout = NULL;	// result output

// instruction count and basic block count per thread
map<THREADID, size_t> ins_cnt;
map<THREADID, size_t> bbl_cnt;


// =========================================================================
// memory section write & execute check by block
// =========================================================================
// memory write set
set<ADDRINT> mwaddrs;

// #define DEBUG 2
#define MAX_BLOCKS 100000	// Maximum File Size : 50MB assuming that default file alignment is 512 bytes (= 0.5kB)
#define BLOCK_SIZE 512
size_t mwblocks[MAX_BLOCKS];
size_t meblocks[MAX_BLOCKS];


// ===============
// for code cache
// ===============
map<ADDRINT, vector<ADDRINT>*> trace_cache_m;
set<ADDRINT> trace_visited_s;
UINT8 buf[1024];	// code cache buffer size is 1KB
char cbuf[256];	// character buffer


// obfuscated module information
ModuleInfo* main_img_info;
ADDRINT main_img_saddr = 0;	// section start address where EIP is changed into 
ADDRINT main_img_eaddr = 0;
ADDRINT main_txt_saddr = 0;	// section start address where EIP is changed into 
ADDRINT main_txt_eaddr = 0;
ADDRINT main_vm_saddr = 0;
ADDRINT main_vm_eaddr = 0;

// loader and dll information for obfuscated dll analysis
ADDRINT obf_dll_entry_addr;	// dll entry address of obfuscated dll
ADDRINT loader_saddr = 0;
ADDRINT loader_eaddr = 0;
bool dll_is_unpack_started = false;	// dll unpack started

// instruction trace start and end addresses
ADDRINT instrc_saddr = 0;
ADDRINT instrc_eaddr = 0;
bool isInsTrcWatchOn = false;
bool isInsTrcReady = false;
bool isInsTrcOn = false;
int analysis_step = 0;


// instruction trace start api sequence
vector<string> trc_start_apis, trc_end_apis;
size_t trc_start_apis_sz, trc_end_apis_sz;
string trc_start_api, trc_end_api;
map <THREADID, ADDRINT> thr_start_apis_index;	// api trace index in trc_start_apis 
map <THREADID, ADDRINT> thr_end_apis_index;	// api trace index in trc_end_apis 

bool isTrcOn = false;

// registers used for obfuscation
#ifdef TARGET_IA32
REG pin_regs[] = { REG_EAX, REG_EBX, REG_ECX, REG_EDX, REG_ESI, REG_EDI, REG_EBP, REG_ESP };
#elif TARGET_IA32E
REG pin_regs[] = {
	REG_RAX, REG_RBX, REG_RCX, REG_RDX, REG_RSI, REG_RDI, REG_RBP, REG_RSP,
	REG_R8, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15 };
#endif	

// special values to find register-memory mapping
ADDRINT special_values[] = {
	0xAAAAAADD, 0xBAAAAAAD, 0xCAAAAAFE, 0xDEAAAAAD,	0xEEEEEE66, 0xF000000D,
	0xADD12345, 0xBAADBABE, 0xCAFEBABE, 0xDEADBEEF, 0xE664F00D, 0xF00DCAFE
};

map<REG, ADDRINT> reg_2_special_value;
map<ADDRINT, REG> special_value_2_reg;

// VM information
ADDRINT vmenter_addr = 0;
ADDRINT vmexit_addr = 0;
SectionInfo* vmsec;
string vmsec_name = ".reloc";	// .reloc is Code Virtualizer's default section name

// handler table information
map<ADDRINT, ADDRINT> hdl_addr_m;
map<ADDRINT, ADDRINT> rev_hdl_addr_m;

// tracing helper
ModuleInfo* prevmod;
SectionInfo* prevsec;
map <THREADID, ADDRINT> thr_prev_addr;	// previous trace address
map <THREADID, ADDR_RANGE> stack_addr_range ;	// stack address range


// conditional branch target
// last_addr -> target_addr, next_addr
map <ADDRINT, pair<ADDRINT, ADDRINT>> bbl_cond_br_tgt;

// basic block that has indirect branch target
set <ADDRINT> bbl_has_indirect_br_tgt;

// a basic block's last call/ret instruction
#ifdef GEN_PT_PKT
set <ADDRINT> bbl_last_ins_ret;
#endif


// basic block last instruction branch type
enum BB_LAST_INS_TYPE {
	BB_JMP_DIRECT = 1,
	BB_JMP_INDIRECT,
	BB_JCC,
	BB_CALL_DIRECT,
	BB_CALL_INDIRECT,
	BB_RET,
	BB_OTHER,
};

string BB_LAST_INS_TYPE_STR[] = {
	"", "JD", "JI", "JC", "CD", "CI", "RE", ""
};

map <ADDRINT, BB_LAST_INS_TYPE> bbl_last_ins_type;


// OEP candidates
vector<ADDRINT> oep_candidates;


/// node: (address | code bytes) string
/// edge: node -> node map

map<string, set<string>> dcfg, tr_dcfg;
map<THREADID, string> prev_node;


// for checking user allocated memory region
vector<ADDR_RANGE> user_alloc_memory;



// ==========================


bool add_oep_candidate(ADDRINT a) {
	auto it = oep_candidates.begin();
	for (; it != oep_candidates.end(); it++) {
		if (*it == a) {
			return false;
		}
	}
	oep_candidates.push_back(a);
	return true;
}
bool remove_oep_candidate(ADDRINT a) {
	auto it = oep_candidates.begin();
	for (; it != oep_candidates.end(); it++) {
		if (*it == a) {
			oep_candidates.erase(it);
			return true;
		}
	}
	return false;
}




string get_memory_hex_str(ADDRINT addr, size_t size) {
	string ret_val = "";
	PIN_SafeCopy(buf, (VOID*)addr, size);

	for (size_t i = 0; i < size; i++)
	{
		ret_val += toHex1(buf[i]);
	}
	return ret_val;
}

string get_bb_str(ADDRINT addr, size_t size) {
	string ret_val = toHex(addr - main_img_saddr) + '_';
	PIN_SafeCopy(buf, (VOID*)addr, size);

	for (size_t i = 0; i < size; i++)
	{
		ret_val += toHex1(buf[i]);
	}
	return ret_val;
}


////////////////////////////////////////////
// memory read / write / execute helper
////////////////////////////////////////////

void clear_mwblocks()
{
	memset(mwblocks, 0, MAX_BLOCKS);
}

void clear_meblocks()
{
	memset(meblocks, 0, MAX_BLOCKS);
}

ADDRINT blk2addr(unsigned blk)
{
	return main_img_saddr + blk * BLOCK_SIZE;
}

// memory write check
bool set_mwblock(ADDRINT addr)
{
	size_t idx = (addr - main_img_saddr) / BLOCK_SIZE;
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

size_t get_mwblock(ADDRINT addr)
{
	size_t idx = (addr - main_img_saddr) / BLOCK_SIZE;
	if (idx > MAX_BLOCKS) return false;
	return mwblocks[idx];
}

// memory execute check
bool set_meblock(ADDRINT addr)
{
	size_t idx = (addr - main_img_saddr) / BLOCK_SIZE;
	if (idx > MAX_BLOCKS) return false;
	meblocks[idx]++;
	return true;
}

size_t get_meblock(ADDRINT addr)
{
	size_t idx = (addr - main_img_saddr) / BLOCK_SIZE;
	if (idx > MAX_BLOCKS) return false;
	return meblocks[idx];
}

typedef union _UNWIND_CODE {
	struct {
		UINT8 CodeOffset;
		UINT8 UnwindOP : 4;
		UINT8 OpInfo : 4;
	};
	UINT16 FrameOffset;
} UNWIND_CODE, * PUNWIND_CODE;

typedef struct _UNWIND_INFO_HDR {
	UINT8 Version : 3, Flags : 5;
	UINT8 SizeOfProlog;
	UINT8 CountOfCodes;
	UINT8 FrameRegister : 4, FrameOffset : 4;
	UNWIND_CODE UnwindCode[1];
} UNWIND_INFO_HDR, * PUNWIND_INFO_HDR;

ADDRINT get_exception_handler_jump_target(ADDRINT ex_va)
{
#if TARGET_IA32E
	ADDRINT img_base = main_img_saddr;
	ADDRINT ex_rva = ex_va - img_base;

	NW::PIMAGE_DOS_HEADER dos0 = (NW::PIMAGE_DOS_HEADER)img_base;
	NW::PIMAGE_NT_HEADERS nt0 = (NW::PIMAGE_NT_HEADERS)(img_base + dos0->e_lfanew);

	ADDRINT edir0 = nt0->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
	ADDRINT edir_size = nt0->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
	edir0 += img_base;


#if LOG_X64EXCEPTION_HANDLER == 1
	*fout << "EXC DIR:" << toHex(edir0) << endl;
	*fout << "ex_rva:" << toHex(ex_rva) << endl;
#endif
	// check ExceptionDir


	ADDRINT unwind_info_rva = 0;
	for (ADDRINT rfaddr = edir0; rfaddr < edir0 + edir_size; rfaddr += sizeof(NW::RUNTIME_FUNCTION)) {
		NW::PRUNTIME_FUNCTION rf = NW::PRUNTIME_FUNCTION(rfaddr);
#if LOG_X64EXCEPTION_HANDLER == 1
		*fout << toHex(rfaddr) << ' ' << toHex((ADDRINT)rf->BeginAddress) << ' ' << toHex((ADDRINT)rf->EndAddress) << endl;
#endif
		if (ex_rva >= rf->BeginAddress && ex_rva < rf->EndAddress) {
			unwind_info_rva = rf->UnwindInfoAddress;
			break;
		}
	}

#if LOG_X64EXCEPTION_HANDLER == 1
	*fout << "UNWIND_INFO " << toHex(unwind_info_rva) << endl;
#endif
	if (!unwind_info_rva) return 0;

	// skip UNWIND_INFO
	PUNWIND_INFO_HDR unwind_info_hdr0 = (PUNWIND_INFO_HDR)(unwind_info_rva + img_base);
#if LOG_X64EXCEPTION_HANDLER == 1
	*fout << "UNWIND_INFO_HDR " << toHex(unwind_info_hdr0) << endl;
	*fout << "SIZE UNWIND_CODE " << sizeof(UNWIND_CODE) << endl;
	*fout << "COUNT UNWIND_CODE " << (ADDRINT)unwind_info_hdr0->CountOfCodes << endl;
	*fout << "first UNWIND CODE " << toHex(unwind_info_hdr0->UnwindCode) << endl;
	*fout << unwind_info_hdr0->CountOfCodes * sizeof(UNWIND_CODE) << endl;
#endif
	ADDRINT addrExceptionInfo = (ADDRINT)(unwind_info_hdr0->UnwindCode + unwind_info_hdr0->CountOfCodes);
	if (unwind_info_hdr0->CountOfCodes % 2 == 1) {
		addrExceptionInfo += 2;	// alignment to DWORD
	}
	NW::PSCOPE_TABLE_AMD64 scope_table = (NW::PSCOPE_TABLE_AMD64)
		(addrExceptionInfo + 4);

#if LOG_X64EXCEPTION_HANDLER == 1
	*fout << "SCOPE_TABLE " << toHex(scope_table) << endl;
	*fout << "COUNT " << scope_table->Count << endl;
#endif

	// check C_SCOPE_TABLE
	for (size_t i = 0; i < scope_table->Count; i++) {
#if LOG_X64EXCEPTION_HANDLER == 1
		*fout << "BeginAddress:" << toHex((ADDRINT)scope_table->ScopeRecord[i].BeginAddress)
			<< " EndAddress:" << toHex((ADDRINT)scope_table->ScopeRecord[i].EndAddress)
			<< " JumpTarget:" << toHex((ADDRINT)scope_table->ScopeRecord[i].JumpTarget) << endl;
#endif
		if (ex_rva >= scope_table->ScopeRecord[i].BeginAddress && ex_rva < scope_table->ScopeRecord[i].EndAddress) {
#if LOG_X64EXCEPTION_HANDLER == 1
			*fout << "JumpTarget found " << toHex((ADDRINT)scope_table->ScopeRecord[i].JumpTarget) << endl;
#endif
			return scope_table->ScopeRecord[i].JumpTarget;
		}
	}

#endif

#if TARGET_IA32
	return ex_va + 0xe;
#endif
	// cannot reach here
	return 0;
}

ADDRINT get_x86_64_mod_change_skip_target(ADDRINT push_va) {
	return 0;
}


void INS_WriteExecuteTrace_MW(CONTEXT* ctxt, ADDRINT ip, size_t mSize, ADDRINT targetAddr, THREADID threadid)
{
	// *fout << toHex(ip) << " W:" << toHex(targetAddr) << endl;

	// Check only main image to detect OEP	

	if (!IS_MAIN_IMG(targetAddr)) return;

	if (get_meblock(targetAddr) > 1) {
		*fout << "Executed address " <<
			toHex(targetAddr - main_img_saddr) << '~' << toHex(targetAddr + mSize - main_img_saddr) <<
			" is rewritten at " << toHex(ip) << endl;
		remove_oep_candidate(targetAddr - main_img_saddr);
	}
	set_mwblock(targetAddr);


#if DEBUG == 1
	* fout << "# Write: " << toHex(targetAddr) << ' ' << *current_obf_fn << endl;
#endif
}

void TRC_WriteExecute(ADDRINT addr, THREADID tid)
{
	set_meblock(addr);
	if (IS_TEXT_SEC(addr))
	{
		if (get_mwblock(addr) && get_meblock(addr) == 1)
		{

			// ENIGMA 6.x x86: read 6 bytes and check whether this is Fake OEP
			// fake OEP pattern: EB 03 45 DC 9A C3
			// EB 03 __ __ __ C3 : jmp $+3; ... ; ret
			// Skip fake OEP

			UINT8 buf[6];
			PIN_SafeCopy(buf, (VOID*)addr, 6);
			for (auto pt : buf)
				*fout << toHex1(pt) << ' ';
			*fout << endl;
			if (buf[0] == 0xEB && buf[1] == 0x03 && buf[5] == 0xC3)
				return;

			ADDRINT oep = addr - main_img_saddr;
			add_oep_candidate(oep);
			*fout << "OEP Candidate:" << toHex(oep) << endl;
			if (oep_candidates.size() > 5) {
				*fout << "Final OEP Candidates" << endl;
				for (auto a : oep_candidates) {
					*fout << toHex(a) << endl;
				}
				((ofstream*)fout)->close();
				PIN_ExitProcess(-1);
			}
		}
		return;
	}
}



void TRC_Load(TRACE trc, void* v)
{
	ADDRINT addr = TRACE_Address(trc);

	bool is_main_or_dgc = false;
	if (IS_MAIN_IMG(addr)) {
		is_main_or_dgc = true;
	} 
	else if (!GetModuleInfo(addr)) {
		is_main_or_dgc = true;
	}

	if ((isAntiAntiPin || isAntiAntiVM) && is_main_or_dgc) {
		for (BBL bbl = TRACE_BblHead(trc); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
			ADDRINT bbl_addr = BBL_Address(bbl);
			size_t bbl_size = BBL_Size(bbl);
			INS ins = BBL_InsHead(bbl);
			if (isAntiAntiPin) {
#if TARGET_IA32E
				if (INS_Mnemonic(ins) == "POPFQ") {
					ADDRINT jmptgt = get_exception_handler_jump_target(bbl_addr);
					if (jmptgt != 0) {
						*fout << "# POPFQ Exception Handler @" << toHex(bbl_addr) << ": Jump Target: " << toHex(jmptgt) << endl;
						INS_InsertPredicatedCall(
							ins, IPOINT_BEFORE, (AFUNPTR)BBL_Skip_ExeptionHandler,
							IARG_CONTEXT,
							IARG_INST_PTR,
							IARG_ADDRINT, jmptgt + main_img_saddr,
							IARG_THREAD_ID,
							IARG_END);
					}
				}
#elif TARGET_IA32
				
				if (INS_Mnemonic(ins) == "POPFD" && bbl_size == 1) {
					ADDRINT jmptgt = get_exception_handler_jump_target(bbl_addr);
					if (jmptgt != 0) {
						*fout << toHex(bbl_addr) << " POPFD" << endl;
						*fout << "# POPFQ Exception Handler @" << toHex(bbl_addr) << ": Jump Target: " << toHex(jmptgt) << endl;
						BBL_InsertCall(
							bbl, IPOINT_BEFORE, (AFUNPTR)BBL_Skip_ExeptionHandler,
							IARG_CONTEXT,
							IARG_ADDRINT, bbl_addr,
							IARG_ADDRINT, jmptgt + main_img_saddr,
							IARG_THREAD_ID,
							IARG_END);
					}
				}				
				
				INS nextins = INS_Next(ins);
				if (INS_Valid(nextins) && INS_IsFarRet(nextins)) {					
					*fout << toHex(bbl_addr) << "# Checking Far Ret - X86-64 Mode Change" << endl;
					BBL_InsertCall(
						bbl, IPOINT_BEFORE, (AFUNPTR)BBL_Skip_X86_64_Mode_Change,
						IARG_CONTEXT,
						IARG_ADDRINT, bbl_addr,
						IARG_THREAD_ID,
						IARG_END);
				}


#endif		
			}

			if (isAntiAntiVM) {
				if (INS_Mnemonic(ins) == "CPUID") {
					*fout << "found cpuid instruction\n";
					fout->flush();
					ADDRINT insaddr = INS_Address(ins);
					ADDRINT nextaddr = insaddr + INS_Size(ins);
					INS_InsertCall(
						ins, IPOINT_BEFORE, (AFUNPTR)INS_Fake_CPUID,
						IARG_CONTEXT,
						IARG_INST_PTR,
						IARG_ADDRINT, nextaddr,
						IARG_THREAD_ID,
						IARG_END);
				}

			}
		}	// end of for bbl
	}

	if (isCount) {
		for (BBL bbl = TRACE_BblHead(trc); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
			ADDRINT bbl_addr = BBL_Address(bbl);
			size_t bbl_size = BBL_Size(bbl);
			ADDRINT num_ins = 0;
			for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
				num_ins++;
			}
			BBL_InsertCall(bbl, IPOINT_BEFORE,
				(AFUNPTR)BBL_Count,
				IARG_ADDRINT, bbl_addr,
				IARG_ADDRINT, bbl_size,
				IARG_ADDRINT, num_ins,
				IARG_THREAD_ID,
				IARG_END);
		}
		return;
	}

	if (isInsTrace) {
		for (BBL bbl = TRACE_BblHead(trc); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
			ADDRINT bbl_addr = BBL_Address(bbl);
			if (IS_MAIN_IMG(bbl_addr)) {
				for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
					INS_InsertPredicatedCall(
						ins, IPOINT_BEFORE, (AFUNPTR)INS_Hook,
						IARG_CONTEXT,
						IARG_INST_PTR,
						IARG_THREAD_ID,
						IARG_END);
				}
			}
		}
	}

	// API Trace
	TRACE_InsertCall(trc, IPOINT_BEFORE, (AFUNPTR)TRC_APIOutput_Handler,
		IARG_CONTEXT, 
		IARG_INST_PTR, 
		IARG_THREAD_ID,
		IARG_END);
	

	if ((isMemWriteTrace || isMemReadTrace) && is_main_or_dgc) {
		for (BBL bbl = TRACE_BblHead(trc); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
			for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
				if (isMemWriteTrace) {
					if (INS_IsMemoryWrite(ins) && !INS_IsStackWrite(ins)) {
						INS_InsertPredicatedCall(
							ins, IPOINT_BEFORE, (AFUNPTR)INS_Memtrace_MW_before,
							IARG_CONTEXT,
							IARG_INST_PTR,
							IARG_MEMORYWRITE_SIZE,
							IARG_MEMORYWRITE_EA,
							IARG_THREAD_ID,
							IARG_END);
						INS_InsertPredicatedCall(
							ins, IPOINT_AFTER, (AFUNPTR)INS_Memtrace_MW_after,
							IARG_CONTEXT,
							IARG_MEMORYWRITE_SIZE,
							IARG_THREAD_ID,
							IARG_END);
					}
				}
				
				if (isMemReadTrace) {
					if (INS_IsMemoryRead(ins) && !INS_IsStackRead(ins)) {
						INS_InsertPredicatedCall(
							ins, IPOINT_BEFORE, (AFUNPTR)INS_Memtrace_MR,
							IARG_CONTEXT,
							IARG_INST_PTR,
							IARG_MEMORYREAD_SIZE,
							IARG_MEMORYREAD_EA,
							IARG_THREAD_ID,
							IARG_END);
					}
				}				
			}
		}
	}

	if (isBlockTracePT) {
		// pt trace, do not skip dll module 
		for (BBL bbl = TRACE_BblHead(trc); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
			ADDRINT bbl_addr = BBL_Address(bbl);
			size_t bbl_size = BBL_Size(bbl);

			INS lastins = BBL_InsTail(bbl);
			ADDRINT lastaddr = INS_Address(lastins);

			*fout << INS_Disassemble(lastins) << endl;

			if (INS_Category(lastins) == XED_CATEGORY_CALL) {
				if (INS_IsIndirectControlFlow(lastins)) {
					bbl_last_ins_type[bbl_addr] = BB_CALL_INDIRECT;
				}
				else {
					bbl_last_ins_type[bbl_addr] = BB_CALL_DIRECT;
				}
			}
			else if (INS_Category(lastins) == XED_CATEGORY_RET) {
				bbl_last_ins_type[bbl_addr] = BB_RET;
			}
			else if (INS_Category(lastins) == XED_CATEGORY_COND_BR) {
				bbl_last_ins_type[bbl_addr] = BB_JCC;
				bbl_cond_br_tgt[bbl_addr] = make_pair(INS_DirectControlFlowTargetAddress(lastins), INS_NextAddress(lastins));
			}
			else if (INS_Category(lastins) == XED_CATEGORY_UNCOND_BR) {
				if (INS_IsIndirectControlFlow(lastins)) {
					bbl_last_ins_type[bbl_addr] = BB_JMP_INDIRECT;
				}
				else {
					bbl_last_ins_type[bbl_addr] = BB_JMP_DIRECT;
				}
			}

			if (INS_IsIndirectControlFlow(lastins)) {
				bbl_has_indirect_br_tgt.insert(bbl_addr);
			}

			BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)BBL_PT_CodeExecuted,
				IARG_ADDRINT, bbl_addr,
				IARG_ADDRINT, lastaddr,
				IARG_THREAD_ID,
				IARG_END);


			PIN_SafeCopy(buf, (VOID*)bbl_addr, bbl_size);

			
			stringstream ss;			

			//ss << "C ";
			// auto mod = GetModuleInfo(bbl_addr);
			//if (mod) {
			//	ss << mod->name << ' ' << toHex(bbl_addr - mod->saddr) << ' ';
			//}
			//else {
			//	ss << "? " << toHex(bbl_addr) << ' ';
			//}

			ss << "C " << toHex(bbl_addr) << ' ';
			for (size_t i = 0; i < bbl_size; i++)
			{
				ss << toHex1(buf[i]);
			}
			ss << endl;

			PIN_GetLock(&lock, 1);									
			*fout << ss.str();
			PIN_ReleaseLock(&lock);

			for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
				if (INS_IsMemoryWrite(ins) && !INS_IsStackWrite(ins)) {
					INS_InsertPredicatedCall(
						ins, IPOINT_BEFORE, (AFUNPTR)INS_PT_WriteExecute,
						IARG_MEMORYWRITE_EA,
						IARG_END);
				}
			}
		}
	}


	// internal vm analysis
	if (isInternalVMAnalysis) {
		for (BBL bbl = TRACE_BblHead(trc); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
			for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {

				ADDRINT ins_addr = INS_Address(ins);
				size_t ins_size = INS_Size(ins);
				PIN_SafeCopy(buf, (VOID*)ins_addr, ins_size);

				string disasm_code = INS_Disassemble(ins);
				asmcode_m[ins_addr] = disasm_code + " # " + get_memory_hex_str(ins_addr, ins_size);
				INS_InsertPredicatedCall(
					ins, IPOINT_BEFORE, (AFUNPTR)INS_InternalVMAnalysis,
					IARG_INST_PTR,
					IARG_BOOL, INS_IsIndirectBranchOrCall(ins),
					IARG_THREAD_ID,
					IARG_END);

				if (INS_IsMemoryRead(ins) && !INS_IsStackRead(ins)) {
					INS_InsertPredicatedCall(
						ins, IPOINT_BEFORE, (AFUNPTR)INS_InternalVMAnalysis_MR,
						IARG_CONTEXT,
						IARG_INST_PTR,
						IARG_MEMORYREAD_SIZE,
						IARG_MEMORYREAD_EA,
						IARG_THREAD_ID,
						IARG_END);
				}

			}
		}
	}

	// vmp analysis
	if (isVMPVMAnalysis) {

		ModuleInfo* mod_info = GetModuleInfo(addr);

		// OEP Detection
		if (IS_MAIN_IMG(addr)) {
			TRACE_InsertCall(trc, IPOINT_BEFORE, (AFUNPTR)TRC_WriteExecute,
				IARG_ADDRINT, addr,
				IARG_THREAD_ID,
				IARG_END);

			for (BBL bbl = TRACE_BblHead(trc); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
				for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
					if (INS_IsMemoryWrite(ins) && !INS_IsStackWrite(ins)) {
						INS_InsertPredicatedCall(
							ins, IPOINT_BEFORE, (AFUNPTR)INS_WriteExecuteTrace_MW,
							IARG_CONTEXT,
							IARG_INST_PTR,
							IARG_MEMORYWRITE_SIZE,
							IARG_MEMORYWRITE_EA,
							IARG_THREAD_ID,
							IARG_END);
					}
				}
			}
		}

		if (mod_info != NULL) {
			auto fn = GetFunctionInfo(addr);
			if (fn != NULL && fn->name == "ZwMapViewOfSection") {
				isVMPChecking = true;
				*fout << "# VMP Memory Checking Started" << endl;
			}
			if (fn != NULL && fn->name == "ZwUnmapViewOfSection") {
				isVMPChecking = false;
				*fout << "# VMP Memory Checking Ended" << endl;
			}

		}
		if (isVMPChecking) {
			if (IS_MAIN_IMG(addr) || mod_info == NULL) {
				for (BBL bbl = TRACE_BblHead(trc); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
					INS ins = BBL_InsTail(bbl);
					if (IS_VM_SEC(addr) && INS_IsIndirectControlFlow(ins))
					{
						ADDRINT ins_addr = INS_Address(ins);
						string disasm_code = INS_Disassemble(ins);
						asmcode_m[ins_addr] = disasm_code;

						INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)INS_HandlerExit_Handler,
							IARG_ADDRINT, ins_addr,
							IARG_THREAD_ID,
							IARG_END);
					}
				}
			}
		}
	}

	if (isWriteExecute && is_main_or_dgc) {
		TRACE_InsertCall(trc, IPOINT_BEFORE, (AFUNPTR)TRC_WriteExecute,
			IARG_ADDRINT, addr,
			IARG_THREAD_ID,
			IARG_END);

		for (BBL bbl = TRACE_BblHead(trc); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
			ADDRINT bbl_addr = BBL_Address(bbl);
			size_t bbl_size = BBL_Size(bbl);

			for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
			{
				if (INS_IsMemoryWrite(ins) && !INS_IsStackWrite(ins)) {					
					INS_InsertPredicatedCall(
						ins, IPOINT_BEFORE, (AFUNPTR)INS_WriteExecuteTrace_MW,
						IARG_CONTEXT,
						IARG_INST_PTR,
						IARG_MEMORYWRITE_SIZE,
						IARG_MEMORYWRITE_EA,
						IARG_THREAD_ID,
						IARG_END);
				}
			}
		}
	}
	
	if (isVMAnalysis) {
		for (BBL bbl = TRACE_BblHead(trc); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
			ADDRINT bbl_addr = BBL_Address(bbl);
			size_t bbl_size = BBL_Size(bbl);

			// log jmp dword ptr [...] instruction
			// log jmp exx instruction
			// log ret instruction in vm section	

			for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
			{
				if (IS_VM_SEC(addr) && (INS_IsRet(ins) || INS_IsIndirectBranchOrCall(ins)))
				{
					ADDRINT ins_addr = INS_Address(ins);
					string disasm_code = INS_Disassemble(ins);
					asmcode_m[ins_addr] = disasm_code;

					INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)INS_HandlerExit_Handler,
						IARG_ADDRINT, ins_addr,
						IARG_THREAD_ID,
						IARG_END);
				}

				// Memory Read and Write
				UINT32 memOperands = INS_MemoryOperandCount(ins);
				for (UINT32 memOp = 0; memOp < memOperands; memOp++)
				{
					if (INS_MemoryOperandIsRead(ins, memOp) && !INS_IsStackRead(ins))
					{
						INS_InsertPredicatedCall(
							ins, IPOINT_BEFORE, (AFUNPTR)INS_Memtrace_MR_Handler,
							IARG_CONTEXT,
							IARG_INST_PTR,
							IARG_MEMORYREAD_SIZE,
							IARG_MEMORYREAD_EA,
							IARG_THREAD_ID,
							IARG_BOOL, INS_IsStackRead(ins),
							IARG_END);
					}
					if (INS_MemoryOperandIsWritten(ins, memOp) && !INS_IsStackWrite(ins))
					{
						INS_InsertPredicatedCall(
							ins, IPOINT_BEFORE, (AFUNPTR)INS_Memtrace_MW_Handler,
							IARG_CONTEXT,
							IARG_INST_PTR,
							IARG_MEMORYWRITE_SIZE,
							IARG_MEMORYWRITE_EA,
							IARG_THREAD_ID,
							IARG_BOOL, INS_IsStackWrite(ins),
							IARG_END);
						INS_InsertPredicatedCall(
							ins, IPOINT_AFTER, (AFUNPTR)INS_Memtrace_MWAfter_Handler,
							IARG_CONTEXT,
							IARG_MEMORYWRITE_SIZE,
							IARG_THREAD_ID,
							IARG_BOOL, INS_IsStackWrite(ins),
							IARG_END);
					}
				}
				
			}
		}
	}

	if (isPrintBasicBlockHex) {
		for (BBL bbl = TRACE_BblHead(trc); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
			ADDRINT bbl_addr = BBL_Address(bbl);
			size_t bbl_size = BBL_Size(bbl);
						
			bool is_trace = false;
			if (IS_MAIN_IMG(bbl_addr)) is_trace = true;
			else if (!GetModuleInfo(bbl_addr)) is_trace = true;
			else if (isDLLTrace) is_trace = true;

			if (is_trace) {
				PIN_SafeCopy(buf, (VOID*)bbl_addr, bbl_size);
				stringstream ss;								
				ss << "C " << toHex(bbl_addr) << ' ';
				for (size_t i = 0; i < bbl_size; i++)
				{
					ss << toHex1(buf[i]);
				}
				ss << endl;
				PIN_GetLock(&lock, 1);
				*fout << ss.str();
				PIN_ReleaseLock(&lock);
				
			}
		}
	}

	if (isBlockTrace) {
		for (BBL bbl = TRACE_BblHead(trc); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
			ADDRINT bbl_addr = BBL_Address(bbl);
			size_t bbl_size = BBL_Size(bbl);

			bool is_trace = false;
			if (IS_MAIN_IMG(bbl_addr)) is_trace = true;
			else if (!GetModuleInfo(bbl_addr)) is_trace = true;
			else if (isDLLTrace) is_trace = true;
			
			if (is_trace) {
				BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)BBL_CodeExecuted,
					IARG_CONTEXT, 
					IARG_ADDRINT, bbl_addr,
					IARG_THREAD_ID,
					IARG_END);
			}			
		}                                                                                      
	}

	if (isStringTrace) {
		for (BBL bbl = TRACE_BblHead(trc); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
			ADDRINT bbl_addr = BBL_Address(bbl);
			size_t bbl_size = BBL_Size(bbl); bool is_trace = false;
			if (IS_MAIN_IMG(bbl_addr)) is_trace = true;
			else if (!GetModuleInfo(bbl_addr)) is_trace = true;
			else if (isDLLTrace) is_trace = true;
			if (is_trace) {
				INS ins = BBL_InsTail(bbl);
				INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)BBL_String,
					IARG_CONTEXT,
					IARG_ADDRINT, bbl_addr,
					IARG_THREAD_ID,
					IARG_END);				
			}
		}
	}



}


bool add_user_alloc_memory(ADDRINT start_addr, ADDRINT end_addr) {
	for (ADDR_RANGE &r : user_alloc_memory) {
		if (r.in(start_addr)) {
			if (end_addr <= r.end_addr) {
				continue;
			}
			r.end_addr = end_addr;
			return true;
		}
		if (r.in(end_addr)) {
			if (start_addr >= r.start_addr) {
				continue;
			}
			r.start_addr = start_addr;
			return true;
		}
	}
	return false;
}

bool is_user_alloc_memory(ADDRINT addr) {
	for (ADDR_RANGE r : user_alloc_memory) {
		if (r.in(addr)) {
			return true;
		}
	}
	return false;
}

ADDR_RANGE get_user_alloc_memory_info(ADDRINT addr)
{
	for (ADDR_RANGE &r : user_alloc_memory) {
		if (r.in(addr)) {
			return r;
		}
	}	
	return {};
}

bool is_stack_memory(ADDRINT addr, THREADID tid) {
	auto match = stack_addr_range.find(tid);
	if (match == stack_addr_range.end()) return false;
	auto ar = match->second;
	return ar.in(addr);	
}

void RTN_AllocVirtualMemory(CONTEXT *ctxt, THREADID tid)
{

	//NTSTATUS ZwAllocateVirtualMemory(
	//	_In_    HANDLE    ProcessHandle,
	//	_Inout_ PVOID * BaseAddress,
	//	_In_    ULONG_PTR ZeroBits,
	//	_Inout_ PSIZE_T   RegionSize,
	//	_In_    ULONG     AllocationType,
	//	_In_    ULONG     Protect
	//);

	ADDRINT* pbase_address;
	size_t* pregion_size;
	ADDRINT start_addr, end_addr;

	auto gax = PIN_GetContextReg(ctxt, REG_GAX);
	if (gax != 0) return;	// STATUS_SUCCESS: 0

#ifdef TARGET_IA32
	auto rsp = PIN_GetContextReg(ctxt, REG_STACK_PTR);
	PIN_SafeCopy(buf, (VOID*)(rsp + ADDRSIZE * 2), ADDRSIZE * 3);
	pbase_address = (ADDRINT*)TO_ADDRINT(buf);
	pregion_size = (ADDRINT*)TO_ADDRINT(buf + ADDRSIZE * 2);
#elif TARGET_IA32E
	pbase_address = (ADDRINT*)PIN_GetContextReg(ctxt, REG_GDX);;
	pregion_size = (ADDRINT*)PIN_GetContextReg(ctxt, REG_R9);
#endif
	
	if (pbase_address == 0 || pregion_size == 0) return;

	PIN_GetLock(&lock, tid + 1);
	* fout << "allocated memory " << toHex((ADDRINT)pbase_address) << ' ' << toHex((ADDRINT)pregion_size) << endl;
	fout->flush();
	PIN_ReleaseLock(&lock);
	start_addr = *pbase_address;
	end_addr = start_addr + *pregion_size;
	add_user_alloc_memory(start_addr, end_addr);
}


void BBL_Count(ADDRINT addr, ADDRINT bbl_size, ADDRINT num_ins, THREADID tid)
{
	ins_cnt[tid] += num_ins;
	bbl_cnt[tid]++;
	set_meblock(addr);

	string bb_str = get_bb_str(addr, bbl_size);
	string prev_bb_str;
	if (prev_node.find(tid) != prev_node.end()) {
		prev_bb_str = prev_node[tid];
		if (dcfg.find(prev_bb_str) == dcfg.end()) {
			dcfg[prev_bb_str] = set<string>();
		}
		dcfg[prev_bb_str].insert(bb_str);

		if (tr_dcfg.find(bb_str) == tr_dcfg.end()) {
			tr_dcfg[bb_str] = set<string>();
		}
		tr_dcfg[bb_str].insert(prev_bb_str);
	}

	prev_node[tid] = bb_str;


	if (IS_TEXT_SEC(addr) && get_mwblock(addr) > 0 || addr == instrc_eaddr) {
		*fout << "OEP: " << toHex(addr) << endl;
		*fout << endl;
		for (auto i : ins_cnt) {
			*fout << "Thread:" << i.first << " Number of Executed Instructions:" << i.second << endl;
		}
		*fout << endl;
		for (auto i : bbl_cnt) {
			*fout << "Thread:" << i.first << " Number of Executed Basic Blocks:" << i.second << endl;
		}
		((ofstream*)fout)->close();

		if (isGraph) {
			for (auto n1 : dcfg) {
				for (auto n2 : n1.second) {
					string fr = n1.first;
					auto pos = fr.find("_");
					fr = fr.substr(0, pos + 5);
					string to = n2;
					pos = to.find("_");
					to = to.substr(0, pos + 5);
					*dot_out << "bb_" + fr << " -> " << "bb_" + to << ';' << endl;
				}
			}
			*dot_out << "}" << endl;
			((ofstream*)dot_out)->close();
		}

		PIN_ExitApplication(0);
	}
}

void BBL_CodeExecuted(CONTEXT* ctxt, ADDRINT addr, THREADID tid)
{		
	if (!isTrcOn) return;
	PIN_GetLock(&lock, tid + 1);
	*fout << "B " << tid << ' ' << toHex(addr) << endl;
	PIN_ReleaseLock(&lock);	
}


// get string from address
bool get_string(ADDRINT addr, string& res, THREADID tid) {
	/*NATIVE_PID current_pid;
	OS_GetPid(&current_pid);
	OS_MEMORY_AT_ADDR_INFORMATION info;
	OS_QueryMemory(current_pid, (VOID*)addr, &info);
	info.BaseAddress*/

	if (!IS_MAIN_IMG(addr) && !is_user_alloc_memory(addr) && !is_stack_memory(addr, tid)) {
		return false;
	}

	size_t sz = PIN_SafeCopy(buf, (VOID*)addr, 128);
	if (sz == 0) return false;

	// check ASCII string at addr
	size_t i = 0;
	for (; i < sz; i++) {
		if (buf[i] == 0) break;
		if (buf[i] < 32 || buf[i] >= 127) return false;
	}

	// minimun length of a string
	if (i < 8) return false;
	res.assign(buf, buf + i);
	
	return true;
}

bool get_wstring(ADDRINT addr, wstring& res, THREADID tid) {
	/*NATIVE_PID current_pid;
	OS_GetPid(&current_pid);
	OS_MEMORY_AT_ADDR_INFORMATION info;
	OS_QueryMemory(current_pid, (VOID*)addr, &info);
	info.BaseAddress*/

	//if (!IS_MAIN_IMG(addr) && !is_user_alloc_memory(addr) && !is_stack_memory(addr, tid)) {
	//	return false;
	//}

	size_t sz = PIN_SafeCopy(buf, (VOID*)addr, 256);
	if (sz == 0) return false;

	// check wchar string at addr
	size_t i = 0;
	for (; i < sz; i+=2) {
		if (buf[i] == 0 && buf[i+1] == 0) break;
	}
	
	if (i == 0) return false;
	res.assign(buf, buf + i);
	return true;
}




void BBL_String(CONTEXT* ctxt, ADDRINT addr, THREADID tid)
{
	if (!isTrcOn) return;	

	auto rsp = PIN_GetContextReg(ctxt, REG_STACK_PTR);
	PIN_SafeCopy(buf, (VOID*)rsp, ADDRSIZE);
	auto stktop = TO_ADDRINT(buf);
		
	string stkstr = "";	
	bool hasstkstr = get_string(stktop, stkstr, tid);

	string gaxstr = "";
	auto gax = PIN_GetContextReg(ctxt, REG_GAX);
	bool hasgaxstr = get_string(gax, gaxstr, tid);

	if (hasstkstr || hasgaxstr) {		
		*fout << "B " << tid << ' ' << toHex(addr);
		if (hasstkstr) {
			*fout << " RSP:" << toHex(rsp) << ", [RSP]:" << toHex(stktop) << ", str@[RSP]=" << stkstr;
		}
		if (hasgaxstr) {
			*fout << ", GAX:" << toHex(gax) << ", str@GAX=" << gaxstr;
		}
		*fout << endl;
	}	
}


// packet count
size_t packet_no = 0;

// process PT TNT packet
char tntss[7];
size_t tntss_ptr = 0;
#define PUT_TNT_PACKET(x, s) \
	tntss[tntss_ptr++] = x; \
	if (tntss_ptr == 6) { \
		PIN_GetLock(&lock, tid + 1); \
		s << toHex4(packet_no++) << " tnt.8 " << tntss << endl; \
		PIN_ReleaseLock(&lock); \
		tntss_ptr = 0; \
	} 
#define PRINT_TNT_STR(s) \
	if (tntss_ptr > 0) { \
		tntss[tntss_ptr] = 0; \
		PIN_GetLock(&lock, tid + 1); \
		s << toHex4(packet_no++) << " tnt.8 " << tntss << endl; \
		PIN_ReleaseLock(&lock); \
		tntss_ptr = 0; \
	}

// bbl count
size_t bbl_no = 0;

void BBL_PT_CodeExecuted(ADDRINT addr, ADDRINT lastaddr, THREADID tid)
{
	ADDRINT prevaddr;
	string tnt_str;

	if (tid != 0) return;
	prevaddr = thr_prev_addr[tid];
	thr_prev_addr[tid] = addr;


	stringstream ss;
	ss << toHex(addr) << ' ' << BB_LAST_INS_TYPE_STR[bbl_last_ins_type[addr]] << ' ';

	set_meblock(addr);

	/*
	BB_JMP_DIRECT,
	BB_JMP_INDIRECT,
	BB_JCC,
	BB_CALL_DIRECT,
	BB_CALL_INDIRECT,
	BB_RET,
	*/

	ss << toHex(prevaddr) << ' ' << bbl_cond_br_tgt.count(prevaddr) << ' ';
	if (bbl_cond_br_tgt.count(prevaddr)) {
		if (bbl_cond_br_tgt[prevaddr].first == addr) {
			ss << '!';
#ifdef GEN_PT_PKT
			PUT_TNT_PACKET('!', ss);
#endif
		}
		else {
			ss << '.';
#ifdef GEN_PT_PKT
			PUT_TNT_PACKET('.', ss);
#endif
		}
	}
	ss << endl;

#ifdef GEN_PT_PKT
	if (bbl_has_indirect_br_tgt.count(prevaddr)) {
		PRINT_TNT_STR(ss);
		string is_ret = "";
		if (bbl_last_ins_ret.count(prevaddr)) is_ret = "ret";
		ss << toHex4(packet_no++) << " tip " << toHex(addr) << ' ' << is_ret << endl;
	}

	if (bbl_cond_br_tgt.count(prevaddr)) {
		if (bbl_cond_br_tgt[prevaddr].first == addr) {
			PUT_TNT_PACKET('!', ss);
		}
		else {
			PUT_TNT_PACKET('.', ss);
		}
	}
#endif

	PIN_GetLock(&lock, tid + 1);
	*fout << ss.str();
	PIN_ReleaseLock(&lock);
}


void INS_PT_WriteExecute(ADDRINT addr)
{
	set_mwblock(addr);
}

string current_api = "";
void TRC_APIOutput_Handler(CONTEXT* ctxt, ADDRINT addr, THREADID tid)
{
	ADDRINT prevaddr = thr_prev_addr[tid];
	thr_prev_addr[tid] = addr;
	
	FunctionInfo* fn_info = GetFunctionInfo(addr);
	if (fn_info == NULL) {
		REG_AH;
		
		if (current_api == "VirtualProtect") {
			auto rax = PIN_GetContextReg(ctxt, REG_GAX);
			*fout << "return: " << toHex(rax) << endl;
		}
		current_api = "";
		return;
	}
	
	
	if (IS_MAIN_IMG(prevaddr) || !IS_MAIN_IMG(prevaddr) && !GetModuleInfo(addr)) {
		auto& fn_name = fn_info->name;
		current_api = fn_name;
		PIN_GetLock(&lock, tid + 1);
		*fout << "API " << tid << ' ' << fn_name;
		
#if TARGET_IA32E

		if (fn_name == "VirtualProtect") {
			auto rcx = PIN_GetContextReg(ctxt, REG_RCX);
			auto rdx = PIN_GetContextReg(ctxt, REG_RDX);
			auto r8 = PIN_GetContextReg(ctxt, REG_R8);
			auto r9 = PIN_GetContextReg(ctxt, REG_R9);
			*fout << "(lpAddress=" << toHex(rcx);
			*fout << ", dwSize=" << toHex(rdx);
			*fout << ", flNewProtect=" << toHex(r8);
			*fout << ", lpflOldProtect=" << toHex(r9) << ")"; 
			if (rcx == 0x0000000140158e70) {
				isTrcOn = true;
			}
		}

		if (fn_name.find("MessageBox") != string::npos) {
			auto rdx = PIN_GetContextReg(ctxt, REG_RDX);
			auto r8 = PIN_GetContextReg(ctxt, REG_R8);
			*fout << ' ' << toHex(rdx) << ' ' << toHex(r8) << ' ';
				
			string pText, pCaption;
			if (fn_name == "MessageBoxW") {
				wstring pwText, pwCaption;
				if (!get_wstring(rdx, pwText, tid)) {
					*fout << "\nfailed to get wstring at rdx\n";
				}
				if (!get_wstring(r8, pwCaption, tid)) {
					*fout << "\nfailed to get wstring at r8\n";
				}
				pText.assign(pwText.begin(), pwText.end());
				pCaption.assign(pwCaption.begin(), pwCaption.end());					
			}	
			else if (fn_name == "MessageBoxA") {					
				get_string(rdx, pText, tid);
				get_string(r8, pCaption, tid);					
			}				
			*fout << ' ' << pText << ' ' << pCaption;
		}
#endif
		* fout << endl;
		PIN_ReleaseLock(&lock);
		if (fn_name == trc_start_api) {
			isInternalVMLog = true;
		}

		if (fn_name == trc_end_api) {
			PIN_ExitProcess(0);
		}

		// trace start apis check
		if (!isTrcOn) {				

			// debug:
			if (fn_name == "RtlAllocateHeap") {
				static int cnt = 0;
				cnt++;
				*fout << fn_name << ' ' << cnt << endl;
				if (cnt == 12) isTrcOn = true;
			}

			auto &sidx = thr_start_apis_index[tid];
			if (sidx < trc_start_apis_sz) {
				if (trc_start_apis[sidx] == fn_name) {										
					thr_start_apis_index[tid]++;
					if (sidx + 1 == trc_start_apis_sz) {
						isTrcOn = true;
					}
				}
				else {					
					thr_start_apis_index[tid] = 0;
				}
			}				
		}			
		else {
			// trace start apis and end apis check
			auto &eidx = thr_end_apis_index[tid];
			if (eidx < trc_end_apis_sz) {
				if (trc_end_apis[eidx] == fn_name) {
					eidx++;
					if (eidx == trc_end_apis_sz) {
						isTrcOn = false;
						fout->flush();
						PIN_ExitProcess(0);
					}
				}
			}
				
		}

	}
	
	// if (fn_info->saddr == addr) *fout << "# tid:" << tid << ' ' << toHex(prevaddr) << ' ' << GetAddrInfo(prevaddr) << " -> " << toHex(addr) << ' ' << GetAddrInfo(addr) << endl;

}

void INS_Hook(CONTEXT* ctxt, ADDRINT addr, THREADID tid)
{
	if (!isTrcOn) return;
	string code;
	get_disasm(addr, code);
	PIN_GetLock(&lock, tid + 1);
	*fout << "I " << tid << ' ' << toHex(addr) << ' ' << code << endl;
	PIN_ReleaseLock(&lock);
}


void INS_Fake_CPUID(CONTEXT* ctxt, ADDRINT addr, ADDRINT nextaddr, THREADID tid) {
	auto cpuid_gax = PIN_GetContextReg(ctxt, REG_GAX);
	*fout << "cpuid with eax:" << toHex(cpuid_gax) << endl;

	//eax:1 -> eax : 50654 ebx : 2400800 ecx : FEFAF387 edx : BFEBFBFF
	//eax:40000000 -> eax : 4000000B ebx : 7263694D ecx : 666F736F edx : 76482074
	//eax:40000003 -> eax : BFFF ebx : 2BB9FF ecx : 2 edx : 3DFFFBF6

	ADDRINT eax1, ebx1, ecx1, edx1;

	switch (cpuid_gax) {
	case 1:
		// CPU Identification
		eax1 = 0x50654;
		ebx1 = 0x2400800;
		ecx1 = 0xFEFAF387;
		edx1 = 0xBFEBFBFF;
		break;
	case 0x40000000:
		// Hypervisor CPUID Leaf Range
		eax1 = 0x4000000B;
		ebx1 = 0x7263694D;
		ecx1 = 0x666F736F;
		edx1 = 0x76482074;
		break;
	case 0x40000003:
		// Hypervisor Feature Identification
		eax1 = 0xBFFF;
		ebx1 = 0x2BB9FF;
		ecx1 = 2;
		edx1 = 0x3DFFFBF6;
		break;
	default:
		return;
	}

	PIN_SetContextReg(ctxt, REG_GAX, eax1);
	PIN_SetContextReg(ctxt, REG_GBX, ebx1);
	PIN_SetContextReg(ctxt, REG_GCX, ecx1);
	PIN_SetContextReg(ctxt, REG_GDX, edx1);		
	PIN_SetContextReg(ctxt, REG_INST_PTR, nextaddr);	
	PIN_ExecuteAt(ctxt);
}

void BBL_Skip_ExeptionHandler(CONTEXT* ctxt, ADDRINT addr, ADDRINT toaddr, THREADID tid)
{
	ADDRINT rsp, stktop;

	// get stack top value
	rsp = PIN_GetContextReg(ctxt, REG_STACK_PTR);
	PIN_SafeCopy(buf, (VOID*)rsp, ADDRSIZE);
	stktop = TO_ADDRINT(buf);
	*fout << tid << " EFLAGS:" << toHex(stktop) << endl;

	// get trap flag and if TF==0, do not skip
	if ((stktop & 0x100) == 0) return;

	PIN_GetLock(&lock, tid + 1);
	*fout << "# Skipping Exception handler " << tid << ' ' << toHex(addr) << "->" << toHex(toaddr) << endl;
	PIN_ReleaseLock(&lock);

	PIN_SetContextReg(ctxt, REG_STACK_PTR, rsp + ADDRSIZE);
	PIN_SetContextReg(ctxt, REG_INST_PTR, toaddr);
	PIN_ExecuteAt(ctxt);
}

void BBL_Skip_X86_64_Mode_Change(CONTEXT* ctxt, ADDRINT addr, THREADID tid) {
	// Check [esp] and [esp+4]
	ADDRINT rsp, top, next;
	rsp = PIN_GetContextReg(ctxt, REG_STACK_PTR);
	PIN_SafeCopy(buf, (VOID*)rsp, ADDRSIZE);
	top = TO_ADDRINT(buf);
	PIN_SafeCopy(buf, (VOID*)(rsp + ADDRSIZE), ADDRSIZE);
	next = TO_ADDRINT(buf);
	*fout << "[esp]:" << toHex(top) << endl;
	*fout << "[esp+4]:" << toHex(next) << endl;

	if (top != addr || next != 0x33) {
		*fout << "# No Mode Change" << endl;
		return;
	}

	// disassemble 0x60 bytes and search for 'ret far' instruction	
	ADDRINT ea = addr + 5;
	string asmstr;
	size_t len; 
	bool found = false;
	while (ea < addr + 0x60) {
		len = get_disasm64(ea, asmstr);
		if (len == 0) {
			*fout << "# No Mode Change - disassembly error" << endl;
			return;
		}
		*fout << toHex(ea) << ' ' << asmstr << endl;
		if (asmstr == "ret far ") {
			found = true;
			break;
		}
		ea += len;
	}

	if (found) {
		// modify esp and eip
		*fout << "# Skipping Mode Change" << endl;
		PIN_SetContextReg(ctxt, REG_STACK_PTR, rsp + ADDRSIZE + ADDRSIZE);
		PIN_SetContextReg(ctxt, REG_INST_PTR, ea + len);
		PIN_ExecuteAt(ctxt);

		return;
	}
	
	*fout << "# No Mode Change" << endl;
	return;


}


void INS_HandlerExit_Handler(ADDRINT addr, THREADID tid)
{
	PIN_GetLock(&lock, tid + 1);
	*fout << "HE " << tid << ' ' << toHex(addr) << ' ' << asmcode_m[addr] << endl;
	PIN_ReleaseLock(&lock);
}


// ========================================================================================================================
// Memory Trace Functions 
// ========================================================================================================================

// shared global variable across memory read before and after
ADDRINT mem_write_addr, mem_read_addr;
stringstream delayed_msg;

void INS_Memtrace_MR(CONTEXT* ctxt, ADDRINT ip, size_t mSize, ADDRINT targetAddr, THREADID threadid)
{
	// skip stack write
	if (PIN_GetContextReg(ctxt, REG_STACK_PTR) / 0x1000 == targetAddr / 0x1000) return;
	PIN_SafeCopy(buf, (VOID*)targetAddr, mSize);
	ADDRINT mem_value = buf2val(buf, mSize);
	*fout << "R " << threadid << ' ' << toHex(ip) << ' ' << toHex(targetAddr) << ' ' << StringHex(mem_value, mSize * 2, false) << endl;;
}


void INS_Memtrace_MW_before(CONTEXT* ctxt, ADDRINT ip, size_t mSize, ADDRINT targetAddr, THREADID threadid)
{
	mem_write_addr = targetAddr;
	delayed_msg.str("");
	delayed_msg.clear();

	// skip stack write
	if (PIN_GetContextReg(ctxt, REG_STACK_PTR) / 0x1000 == targetAddr / 0x1000) return;

	delayed_msg << "W " << threadid << ' ' << toHex(ip) << ' ' << toHex(targetAddr) << ' ';
	//if (isFound) delayed_msg << " HDL";
	//delayed_msg << ' ';
}

// memory trace memory write analysis function
void INS_Memtrace_MW_after(CONTEXT* ctxt, size_t mSize, THREADID threadid)
{
	if (mem_write_addr < main_img_saddr || mem_write_addr >= main_img_eaddr) return;
	// skip stack write
	if (PIN_GetContextReg(ctxt, REG_STACK_PTR) / 0x1000 == mem_write_addr / 0x1000) return;

	string msg = "";
	PIN_SafeCopy(buf, (VOID*)mem_write_addr, mSize);
	ADDRINT mem_value = buf2val(buf, mSize);
	delayed_msg << StringHex(mem_value, mSize * 2, false);
	PIN_GetLock(&lock, threadid + 1);
	*fout << delayed_msg.str() << endl;
	PIN_ReleaseLock(&lock);
}


// memory trace memory write analysis function
void INS_Memtrace_MW_Handler(CONTEXT* ctxt, ADDRINT ip, size_t mSize, ADDRINT targetAddr, THREADID threadid, BOOL is_stack)
{
	mem_write_addr = targetAddr;
	if (is_stack || !IS_MAIN_IMG(targetAddr)) {
		return;
	}

	delayed_msg.str("");
	delayed_msg.clear();

	delayed_msg << "W " << threadid << ' ' << toHex(ip) << ' ' << toHex(targetAddr) << ' ' << mSize;
	//if (isFound) delayed_msg << " HDL";
	delayed_msg << ' ';
}

// memory trace memory write analysis function
void INS_Memtrace_MWAfter_Handler(CONTEXT* ctxt, size_t mSize, THREADID threadid, BOOL is_stack)
{
	if (is_stack && (mem_write_addr < main_img_saddr || mem_write_addr >= main_img_eaddr)) return;

	string msg = "";
	PIN_SafeCopy(buf, (VOID*)mem_write_addr, mSize);
	ADDRINT mem_value = buf2val(buf, mSize);

	delayed_msg << StringHex(mem_value, mSize * 2, false);

	ADDRINT ebp_val = PIN_GetContextReg(ctxt, REG_EBP);

	ADDRDELTA diff = mem_write_addr - ebp_val;
	if (ebp_val >= main_img_saddr && ebp_val < main_img_eaddr && diff >= 0 && diff <= 0xFF) {
		// *fout << "EBP:" << toHex(ebp_val) << " DIFF:" << toHex1(diff) << ' ';
		delayed_msg << " # EBP:" << toHex(ebp_val) << " DIFF:" << toHex1(diff) << ' ';
	}


	// *fout << "V:" << StringHex(mem_value, mSize * 2, false);

	PIN_GetLock(&lock, threadid + 1);
	*fout << delayed_msg.str() << endl;
	PIN_ReleaseLock(&lock);
}


// memory trace memory read analysis function
void INS_Memtrace_MR_Handler(CONTEXT* ctxt, ADDRINT ip, size_t mSize, ADDRINT targetAddr, THREADID threadid, BOOL is_stack)
{
	if (is_stack || !IS_MAIN_IMG(targetAddr)) return;

	string msg = "";
	if (hdl_addr_m.find(targetAddr) != hdl_addr_m.end()) {
		msg = " # HDL:" + toHex(hdl_addr_m[targetAddr]) + ' ';
		// msg += " EBP:" + toHex(PIN_GetContextReg(ctxt, REG_STACK_PTR));
	}

	// UINT8 buf[ADDRSIZE];	

	PIN_SafeCopy(buf, (VOID*)targetAddr, mSize);
	ADDRINT mem_value = buf2val(buf, mSize);
	ADDRINT ebp_val = PIN_GetContextReg(ctxt, REG_EBP);
	ADDRDELTA diff = targetAddr - ebp_val;

	if (ebp_val >= main_img_saddr && ebp_val < main_img_eaddr && diff >= 0 && diff <= 0xFF) {
		// msg += "\tEBP:" + toHex(ebp_val) + "\tdiff:" + toHex1(diff);
		msg += " # EBP:" + toHex(ebp_val) + " DIFF:" + toHex1(diff) + ' ';
	}

	PIN_GetLock(&lock, threadid + 1);
	*fout << "R " << threadid << ' ' << toHex(ip) << ' ' << toHex(targetAddr) << ' '
		<< mSize << ' ' << StringHex(mem_value, mSize * 2, false) << msg << endl;

	PIN_ReleaseLock(&lock);
}

// ========================================================================================================================
// Common Callbacks
// ========================================================================================================================

// IMG instrumentation function for EXE files
void IMG_Load(IMG img, void* v)
{
	string imgname = IMG_Name(img);
	size_t pos = imgname.rfind("\\") + 1;
	imgname = imgname.substr(pos);
	TO_LOWER(imgname);
	ModuleInfo* modinfo = NULL;
	if (GetModuleInfo(imgname)) return;

	// Record symbol information of a loaded image 
	ADDRINT saddr = IMG_LowAddress(img);
	ADDRINT eaddr = IMG_HighAddress(img);
	modinfo = new ModuleInfo(imgname, saddr, eaddr);	

	stringstream ss;

#if LOG_IMAGE_INFO == 1
	ss << "IMAGE:" << *modinfo << endl;
#endif

	if (/* isStringTrace && */ imgname == "ntdll.dll") {
		RTN rtn_mem_alloc = RTN_FindByName(img, "RtlAllocateHeap");
		if (RTN_Valid(rtn_mem_alloc)) {			
			RTN_Open(rtn_mem_alloc);
			RTN_InsertCall(rtn_mem_alloc, IPOINT_AFTER, (AFUNPTR)RTN_AllocVirtualMemory, IARG_CONTEXT, IARG_END);
			RTN_Close(rtn_mem_alloc);
		}		
	}

	if (is_dll_analysis)
	{
		// obfuscated dll module is loaded
		ss << imgname << ' ' << obf_dll_name << endl;
		if (imgname == obf_dll_name)
		{
			obf_dll_entry_addr = IMG_EntryAddress(img);
			main_img_saddr = saddr;
			main_img_eaddr = eaddr;
			main_img_info = modinfo;

			SEC sec = IMG_SecHead(img);
			main_txt_saddr = SEC_Address(sec);
			main_txt_eaddr = main_txt_saddr + SEC_Size(sec);
		}

		// loader exe file is loaded
		if (IMG_IsMainExecutable(img))
		{
			loader_saddr = saddr;
			loader_eaddr = eaddr;
		}
	}
	else
	{
		// EXE analysis
		if (IMG_IsMainExecutable(img))
		{
			main_img_saddr = saddr;
			main_img_eaddr = eaddr;

			// modify tracing start address according to memory loaded address of the executable file
			if (instrc_saddr != 0) instrc_saddr += main_img_saddr;
			if (instrc_eaddr != 0) instrc_eaddr += main_img_saddr;

			SEC sec = IMG_SecHead(img);
			main_txt_saddr = SEC_Address(sec);
			main_txt_eaddr = main_txt_saddr + SEC_Size(sec);			
		}
	}

	// collect symbol information
	size_t cnt = 0;
	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec), cnt++)
	{
		string secname = SEC_Name(sec);
		ADDRINT saddr = SEC_Address(sec);
		ADDRINT eaddr = saddr + SEC_Size(sec);
		SectionInfo* secinfo = new SectionInfo(imgname, secname, saddr, eaddr);
		modinfo->sec_infos.push_back(secinfo);
#if LOG_SECTION_INFO == 1
		ss << "SECTION:" << *secinfo << endl;
#endif
		if (SEC_Name(sec) == ".text")
		{

			if (IS_MAIN_IMG(saddr))
			{
				main_txt_saddr = SEC_Address(sec);
				main_txt_eaddr = main_txt_saddr + SEC_Size(sec);
			}

			for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn))
			{
				string rtnname = RTN_Name(rtn);
				ADDRINT saddr = RTN_Address(rtn);
				ADDRINT eaddr = saddr + RTN_Range(rtn);
				FunctionInfo* fninfo = new FunctionInfo(imgname, rtnname, saddr, eaddr);

				if (isPrintSymbolInfo) {
					ss << "FN:" << fninfo->name << '[' << toHex(fninfo->saddr) << ',' << toHex(fninfo->eaddr) << ']' << endl;
				}
			}
		}
		else if (IS_MAIN_IMG(saddr) && SEC_Name(sec) == vmsec_name)
		{
			vmsec = secinfo;
			main_vm_saddr = vmsec->saddr;
			main_vm_eaddr = vmsec->eaddr;
			ss << "VM Section:" << *vmsec << endl;
		}
	}
	PIN_GetLock(&lock, 1);
	*fout << ss.str();
	PIN_ReleaseLock(&lock);
}



// This routine is executed every time a thread is created.
VOID ThreadStart(THREADID threadid, CONTEXT* ctxt, INT32 flags, VOID* v)
{
	ADDRINT inst_ptr = PIN_GetContextReg(ctxt, REG_INST_PTR);
	thr_prev_addr[threadid] = inst_ptr;
	thr_start_apis_index[threadid] = 0;
	thr_end_apis_index[threadid] = 0;

	ADDRINT stack_ptr = PIN_GetContextReg(ctxt, REG_STACK_PTR);
	OS_MEMORY_AT_ADDR_INFORMATION meminfo;
	NATIVE_PID pid;
	OS_GetPid(&pid);
	OS_QueryMemory(pid, (VOID*)stack_ptr, &meminfo);
	ADDRINT baseaddr = (ADDRINT)meminfo.BaseAddress;
	stack_addr_range[threadid] = { baseaddr, baseaddr + meminfo.MapSize };
	*fout << "Stack Range of tid " << threadid << " :" << toHex(baseaddr) << ' ' << toHex(baseaddr + meminfo.MapSize) << endl;

#if LOG_THREAD == 1
	* fout << "Starting Thread " << threadid << endl;
#endif
}

// This routine is executed every time a thread is destroyed.
VOID ThreadFini(THREADID threadid, const CONTEXT* ctxt, INT32 code, VOID* v)
{
#if LOG_THREAD == 1
	* fout << "Ending Thread " << threadid << endl;
#endif
}

/*!
* Print out analysis results.
* This function is called when the application exits.
* @param[in]   code            exit code of the application
* @param[in]   v               value specified by the tool in the
*                              PIN_AddFiniFunction function call
*/
void Fini(INT32 code, void* v)
{
	((ofstream*)fout)->close();
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
	std::map<std::string, std::string> config;

	string config_file = KnobConfigFile.Value();	
	LOG("CONFIG FILE:" + config_file + "\n");
	read_config_file(config_file);

	string inputFileName;
	for (int i = 5; i < argc - 1; i++) {
		string arg = string(argv[i]);
		if (arg == "--") {
			inputFileName = string(argv[i + 1]);
		}
	}

	string outputFileName = get_config_str("output_file");
	if (outputFileName == "")
	{
		outputFileName = inputFileName;
		for (int i = 5; i < argc - 1; i++) {
			string arg = string(argv[i]);
			if (arg == "--") break;
			outputFileName += '_' + arg;
		}

		time_t rawtime;
		struct tm* timeinfo;
		char buffer[80];
		time(&rawtime);
		timeinfo = localtime(&rawtime);
		strftime(buffer, 80, "_%y%m%d_%H%M%S", timeinfo);

		outputFileName += string(buffer) + ".txt";
	}



	LOG("OUTPUT FILE:" + outputFileName + "\n");


	fout = new ofstream(outputFileName.c_str());

	string dot_outputFileName;
	if (isGraph) {
		dot_out = new ofstream(dot_outputFileName.c_str());
		*dot_out << "digraph G {\n" << endl;
	}

	if (isGraph) {
		size_t pos = outputFileName.rfind(".txt");
		if (pos + 4 == outputFileName.size()) {
			dot_outputFileName = outputFileName.substr(0, pos) + ".dot";
		}
	}

	isMemTrace = get_config_str("trace_memory");

	if (isMemTrace == "r") isMemReadTrace = true;
	else if (isMemTrace == "w") isMemWriteTrace = true;
	else if (isMemTrace == "rw")
	{
		isMemReadTrace = true;
		isMemWriteTrace = true;
	}

	obf_dll_name = get_config_str("dll_file");

	isCount = get_config_bool("count");
	isGraph = get_config_bool("graph");

	isInsTrace = get_config_bool("trace_ins");
	isWriteExecute = get_config_bool("trace_write_execute");
	isPrintBasicBlockHex = get_config_bool("trace_basic_block_hex");
	isBlockTrace = get_config_bool("trace_basic_block");
	isBlockTracePT = get_config_bool("trace_basic_block_pt");	
	isDLLTrace = get_config_bool("trace_dll");	
	isStringTrace = get_config_bool("trace_string");

	isDumpCode = get_config_bool("dump_code");
	instrc_saddr = get_config_hex("trace_start_address");
	instrc_eaddr = get_config_hex("trace_end_address");
	string start_apis = get_config_str("trace_start_api_sequence");
	string end_apis = get_config_str("trace_end_api_sequence");
	trc_start_api = get_config_str("trace_start_api");
	trc_end_api = get_config_str("trace_end_api");

	isAntiAntiPin = get_config_bool("anti_anti_dbi");
	isAntiAntiVM = get_config_bool("anti_anti_vm");
	isPrintSymbolInfo = get_config_bool("print_symbol_information");

	// tracing start when trc_end_api exists and trc_start_api not exists
	if (trc_end_api != "" && trc_start_api == "") {
		isInternalVMLog = true;
	}

	// api sequence where logging api starts and ends
	if (start_apis != "") {
		for (size_t pos = 0, next_pos;;)
		{
			next_pos = start_apis.find(" ", pos);			
			trc_start_apis.push_back(start_apis.substr(pos, next_pos - pos));
			pos = next_pos;
			if (pos == string::npos) break;
			pos++;
		}		
		trc_start_apis_sz = trc_start_apis.size();
	}
	else {		
		// isTrcOn = true;
	}
	if (end_apis != "") {
		for (size_t pos = 0, next_pos;;)
		{
			next_pos = end_apis.find(" ", pos);
			trc_end_apis.push_back(end_apis.substr(pos, next_pos - pos));
			pos = next_pos;
			if (pos == string::npos) break;
			pos++;
		}
		trc_end_apis_sz = trc_end_apis.size();
	}

	isVMPVMAnalysis = get_config_bool("vmp_vm_analysis");
	isInternalVMAnalysis = get_config_bool("internal_vm_analysis");
	if (get_config_bool("vm_find_handlers")) analysis_step = 1;
	if (get_config_bool("vm_analysis"))
	{
		isVMAnalysis = true;
	}
	vmsec_name = get_config_str("vmp_section");

	PIN_InitSymbols();

	// Register Analysis routines to be called when a thread begins/ends
	PIN_AddThreadStartFunction(ThreadStart, 0);
	PIN_AddThreadFiniFunction(ThreadFini, 0);
	TRACE_AddInstrumentFunction(TRC_Load, 0);
	IMG_AddInstrumentFunction(IMG_Load, 0);

	// Register function to be called when the application exits
	PIN_AddFiniFunction(Fini, 0);

	// Start the program, never returns
	PIN_StartProgram();

	return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */

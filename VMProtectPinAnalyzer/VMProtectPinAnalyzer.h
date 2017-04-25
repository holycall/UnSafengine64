#include "pin.H"
#include <iostream>
#include <fstream>
#include <map>
#include <set>
#include "StrUtil.h"
#include "PinSymbolInfoUtil.h"

// obfuscated module information
ADDRINT obf_img_saddr = 0;	// section start address where eip is changed into 
ADDRINT obf_img_eaddr = 0;
ADDRINT obf_txt_saddr = 0;	// section start address where eip is changed into 
ADDRINT obf_txt_eaddr = 0;

ADDRINT obf_rdata_saddr = 0;	// section start address after .text section
ADDRINT obf_rdata_eaddr = 0;	

ADDRINT oep = 0;	// oep of VMProtect unpacked executable

/* ================================================================== */
// Global variables 
/* ================================================================== */

bool isDetach = false;

// thread count
size_t thr_cnt;
set<size_t> thread_ids;
PIN_THREAD_UID mainThreadUid;


// ===============
// for debugging
// ===============
map<ADDRINT, string> asmcode_m;
map<ADDRINT, vector<ADDRINT>*> trace_cache_m;
map<ADDRINT, ADDRINT> trace_next_addr_m;
UINT8 memory_buffer[1024*1024];	// code cache buffer size is 1MB


ADDRINT obf_entry_addr;	// VMProtect dll entry address

// dll loader information for obfuscated dll analysis
ADDRINT loader_saddr = 0;
ADDRINT loader_eaddr = 0;

bool is_unpack_started = false;	// dll unpack started

// trace related variables
ADDRINT prevaddr;	// previous trace address
int obfCallLevel = 0;	// flag for recording 1-level obfuscated call instructions

mod_info_t *prevmod;	// previous module

// KNOB related flags
bool isMemTrace = false;
bool isAPIDetect = false;
bool isDLLAnalysis = false;
bool isOEPDetect = false;
bool isDebug = false;

// obfuscated DLL name
string dll_name = "";

// standard output & file output 
ostream * fout = &cerr;	// result output
ostream * dout = NULL;	// result output

// number of seconds to wait until a debugger to attach at OEP
UINT32 debugger_attach_wait_time = 0;

// instruction trace start and end addresses
ADDRINT instrc_saddr = 0;
ADDRINT instrc_eaddr = 0;
bool isInsTrcWatchOn = false;
bool isInsTrcReady = false;
bool isInsTrcOn = false;

// anti-attach write addresses
set<ADDRINT> anti_attach_address_set;

// lock serializes access to the output file.
PIN_LOCK lock;

// region info 
vector<reg_info_t*> region_info_v;

// module info 
map<string, mod_info_t*> module_info_m;

// function info
map<ADDRINT, fn_info_t*> fn_info_m;
map<pair<string, string>, fn_info_t*> fn_str_2_fn_info;

// runtime function info
fn_info_t *current_obf_fn = NULL;

// map from obfuscated function into original function
map<ADDRINT, fn_info_t*> obfaddr2fn;

// map from obfuscated address to original address in IAT
map<ADDRINT, ADDRINT> iataddr2obffnaddr;


// obfuscated call information struct
struct call_info_t {
	bool is_push_before_call;	
	ADDRINT caller_addr;
	ADDRINT target_addr;
	call_info_t(bool chk1, ADDRINT caller, ADDRINT target) :
		is_push_before_call(chk1), caller_addr(caller), target_addr(target) {};
};

// obfuscated call instruction address and target address
vector<call_info_t*> obfuscated_call_candidate_addrs;


// flags for current status 
bool isCheckAPIStart = false;
bool isCheckAPIRunning = false;
size_t current_obf_fn_pos = 0;

vector<ADDRINT> traceAddrSeq;
vector<ADDRINT> traceSPSeq;
map<REG, pair<ADDRINT, string>> movRegApiFnAddrs;

// ADDRINT caller_addr = 0;
call_info_t *current_obfuscated_call;

ADDRINT current_callstkaddr = 0;
bool isMovRegCallReg = false;
bool isCheckAPIEnd = false;

// current obfuscated function address for x64
ADDRINT current_obf_fn_addr;

// 64bit export block candidate
ADDRINT addrZeroBlk = 0;


#define MakeDWORD(buf) (buf[3] | (buf[2] << 8) | (buf[1] << 16) | (buf[0] << 24))
#define MakeADDR(buf) (buf[0] | (buf[1] << 8) | (buf[2] << 16) | (buf[3] << 24))
#define MakeADDR1(buf) (buf[1] | (buf[2] << 8) | (buf[3] << 16) | (buf[4] << 24))

ADDRINT toADDRINT(UINT8 *buf) { 
	int n = sizeof(ADDRINT);
	ADDRINT addr = buf[n-1];
	for (int i = n-2; i >= 0; i--) {
		addr = (addr << 8) | buf[i];
	}
	return addr; 
}

ADDRINT toADDRINT1(UINT8 *buf) { 
	int n = sizeof(ADDRINT);
	ADDRINT addr = buf[n];
	for (int i = n - 1; i >= 1; i--) {
		addr = (addr << 8) | buf[i];
	}
	return addr;
}

#define RECORDTRACE 1

// registers used for obfuscation
#ifdef TARGET_IA32
REG regs_for_obfuscation[] = { REG_EAX, REG_EBX, REG_ECX, REG_EDX, REG_ESI, REG_EDI };
#elif TARGET_IA32E
REG regs_for_obfuscation[] = { REG_RAX, REG_RBX, REG_RCX, REG_RDX, REG_RSI, REG_RDI };
#endif	


void clear_mwblocks();
void clear_meblocks();
ADDRINT blk2addr(unsigned blk);
bool set_mwblock(ADDRINT addr);
size_t get_mwblock(ADDRINT addr);
bool set_meblock(ADDRINT addr);
size_t get_meblock(ADDRINT addr);

void FindAPICalls();
bool FindGap();
void EXE_IMG_inst(IMG img, void *v);
void DLL_IMG_inst(IMG img, void *v);
void ThreadStart(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v);
void ThreadFini(THREADID threadid, const CONTEXT *ctxt, INT32 code, VOID *v);
void EXE_TRC_Memtrc_analysis(ADDRINT addr, THREADID threadid);
void EXE_TRC_inst(TRACE trace, void *v);
void DLL_TRC_APIDetectinst(TRACE trace, void *v);
void EXE_INS_Memtrace_MW_analysis(ADDRINT ip, size_t mSize, ADDRINT targetAddr, THREADID threadid);
void EXE_INS_Memtrace_MR_analysis(ADDRINT ip, size_t mSize, ADDRINT targetAddr, THREADID threadid);

void EXE_TRC_OEPDetect_inst(TRACE trace, void *v);
void EXE_TRC_OEPDetect_analysis(ADDRINT addr, THREADID threadid);
void EXE_INS_OEPDetect_MW_analysis(CONTEXT *ctxt, ADDRINT ip, ADDRINT nextip, size_t mSize, ADDRINT targetAddr, THREADID threadid);

void EXE_TRC_APIDetect_inst(TRACE trace, void *v);
void TRC_APIDetect_analysis(CONTEXT *ctxt, ADDRINT addr, UINT32 size, THREADID threadid);
void restore_regs(LEVEL_VM::CONTEXT * ctxt);
REG check_api_fn_assignment_to_register(LEVEL_VM::CONTEXT * ctxt);
REG check_reg_call_ins(std::string &disasm);
bool check_abnormal_ins(std::string &disasm);
void INS_APIDetect_MW_analysis(ADDRINT targetAddr, ADDRINT insaddr);
// Pin Tracer
// 2015.04.25. ~
// seogu.choi@gmail.com

#include "config.h"
#include "pin.H"
#include "pin_helper.h"

#include <iostream>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <string>


// for address range
struct ADDR_RANGE {
	ADDRINT start_addr;
	ADDRINT end_addr;
	bool in(ADDRINT addr) {
		return addr >= start_addr && addr < end_addr;
	}
};


bool add_oep_candidate(ADDRINT a);
bool remove_oep_candidate(ADDRINT a);

bool add_user_alloc_memory(ADDRINT start_addr, ADDRINT end_addr);
bool is_user_alloc_memory(ADDRINT addr);
ADDR_RANGE get_user_alloc_memory_info(ADDRINT addr);

// Instrumentation and analysis functions
void IMG_Load(IMG img, void* v);
void TRC_Load(TRACE trace, void* v);

void RTN_AllocVirtualMemory(CONTEXT* ctxt, THREADID tid);

void BBL_Count(ADDRINT addr, ADDRINT bbl_size, ADDRINT num_ins, THREADID tid);
void BBL_CodeExecuted(CONTEXT* ctxt, ADDRINT addr, THREADID threadid);
void BBL_PT_CodeExecuted(ADDRINT addr, ADDRINT lastaddr, THREADID tid);
void BBL_String(CONTEXT* ctxt, ADDRINT addr, THREADID threadid);

void INS_PT_WriteExecute(ADDRINT addr);
void INS_HandlerExit_Handler(ADDRINT addr, THREADID tid);
void TRC_APIOutput_Handler(CONTEXT *ctxt, ADDRINT addr, THREADID tid);

void INS_Hook(CONTEXT* ctxt, ADDRINT addr, THREADID tid);
void BBL_Skip_ExeptionHandler(CONTEXT* ctxt, ADDRINT addr, ADDRINT toaddr, THREADID tid);
void BBL_Skip_X86_64_Mode_Change(CONTEXT* ctxt, ADDRINT addr, THREADID tid);

void INS_Fake_CPUID(CONTEXT* ctxt, ADDRINT addr, ADDRINT nextaddr, THREADID tid);

// Memory Trace Instrumentation

void INS_Memtrace_MR(CONTEXT* ctxt, ADDRINT ip, size_t mSize, ADDRINT targetAddr, THREADID threadid);
void INS_Memtrace_MW_before(CONTEXT* ctxt, ADDRINT ip, size_t mSize, ADDRINT targetAddr, THREADID threadid);
void INS_Memtrace_MW_after(CONTEXT* ctxt, size_t mSize, THREADID threadid);

void INS_Memtrace_MW_Handler(CONTEXT *ctxt, ADDRINT ip, size_t mSize, ADDRINT targetAddr, THREADID threadid, BOOL is_stack);
void INS_Memtrace_MWAfter_Handler(CONTEXT *ctxt, size_t mSize, THREADID threadid, BOOL is_stack);
void INS_Memtrace_MR_Handler(CONTEXT *ctxt, ADDRINT ip, size_t mSize, ADDRINT targetAddr, THREADID threadid, BOOL is_stack);

void INS_WriteExecuteTrace_MW(CONTEXT* ctxt, ADDRINT ip, size_t mSize, ADDRINT targetAddr, THREADID threadid);


// string trace
bool get_string(ADDRINT addr, string& res, THREADID tid);
bool get_wstring(ADDRINT addr, std::wstring& res, THREADID tid);

// Memory Read Write Helper
void clear_mwblocks();
void clear_meblocks();
ADDRINT blk2addr(unsigned blk);
bool set_mwblock(ADDRINT addr);
size_t get_mwblock(ADDRINT addr);
bool set_meblock(ADDRINT addr);
size_t get_meblock(ADDRINT addr);

// PE Header Information
ADDRINT get_exception_handler_jump_target(ADDRINT ex_va);
ADDRINT get_x86_64_mod_change_skip_target(ADDRINT push_va);


template<typename T>
constexpr auto IS_MAIN_IMG(T addr) { return (addr >= main_img_saddr && addr < main_img_eaddr); }

template<typename T>
constexpr auto IS_VM_SEC(T addr) { return(addr >= main_vm_saddr && addr < main_vm_eaddr); }

template<typename T>
constexpr auto IS_TEXT_SEC(T addr) { return(addr >= main_txt_saddr && addr < main_txt_eaddr); }


/// md5 hash
string get_bb_str(ADDRINT addr, size_t size);

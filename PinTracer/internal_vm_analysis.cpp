#include "internal_vm_analysis.h"

bool isInternalVMLog = false;

void INS_InternalVMAnalysis(ADDRINT addr, BOOL is_indirect_branch, THREADID tid)
{
	if (!isInternalVMLog) return;
	PIN_GetLock(&lock, tid + 1);
	*fout << "I " << tid << ' ' << toHex(addr) << ' ' << asmcode_m[addr] << endl;
	if (is_indirect_branch) {
		*fout << "==============================================" << endl;
	}
	PIN_ReleaseLock(&lock);
}

void BBL_InternalVMAnalysis(ADDRINT addr, THREADID tid)
{
	*fout << "B " << tid << ' ' << toHex(addr) << endl;
}

void INS_InternalVMAnalysis_MR(CONTEXT* ctxt, ADDRINT ip, size_t mSize, ADDRINT targetAddr, THREADID threadid)
{
	if (!isInternalVMLog) return;

	// skip stack write
	if (PIN_GetContextReg(ctxt, REG_STACK_PTR) / 0x1000 == targetAddr / 0x1000) return;
	// if (mSize != 1) return;
	UINT8 buf[8];
	PIN_SafeCopy(buf, (VOID*)targetAddr, mSize);
	ADDRINT mem_value = buf2val(buf, mSize);
	*fout << "R " << hexstr(ip) << ' ' << hexstr(targetAddr) << ' ' << StringHex(mem_value, mSize * 2, false) << endl;;
}

#pragma once
#include "pin.H"
#include "pin_helper.h"

extern bool isInternalVMLog;

void INS_InternalVMAnalysis(ADDRINT addr, BOOL is_indirect_branch, THREADID tid);
void BBL_InternalVMAnalysis(ADDRINT addr, THREADID threadid);
void INS_InternalVMAnalysis_MR(CONTEXT* ctxt, ADDRINT ip, size_t mSize, ADDRINT targetAddr, THREADID threadid);


/*
 * Copyright (C) 2004-2021 Intel Corporation.
 * SPDX-License-Identifier: MIT
 */

/*! @file
 *  This file contains an ISA-portable PIN tool for counting dynamic instructions
 */

#include "pin.H"
#include <iostream>
#include "branchcount.h"
#include <string>
#include <deque>
#include <map>

using std::cerr;
using std::endl;

bool  started = true;
FILE* trace_file;
FILE* trace_file_e;
FILE* trace_file_t;
UINT64 branch_count = 0;
int64_t inst_count = 0;

static std::deque<LEVEL_BASE::REG> last20regs;
static int isdependency = 0;
std::map<ADDRINT, ADDRINT> lastBranchTarget;

KNOB<std::string> KnobTraceFile(KNOB_MODE_WRITEONCE, "pintool", "trace_out_file", "",
                           "specify branch trace output file name");
KNOB<std::string> KnobCompressorPath(KNOB_MODE_WRITEONCE, "pintool", "compressor",
                                "/usr/bin/bzip2", "Path to compressor program");
KNOB<int64_t> KnobWarmupInstructions(
  KNOB_MODE_WRITEONCE, "pintool", "warmup_instructions", "20000000",
  "Number of warmup instructions before tracing and/or branch predicting.");
KNOB<int64_t> KnobRedirectPCAtStart(
  KNOB_MODE_WRITEONCE, "pintool", "redirect_pc_at_start", "0",
  "If not zero, redirect the program to this PC.");
KNOB<int64_t> KnobMaxInstructions(
  KNOB_MODE_WRITEONCE, "pintool", "max_instructions", "200000000",
  "Save 200000000 trace of instructions by default");

BR_TYPE get_br_type(const INS& inst) {
  switch(INS_Category(inst)) {
    case XED_CATEGORY_COND_BR:
      return INS_IsDirectBranch(inst) ? BR_TYPE::COND_DIRECT :
                                        BR_TYPE::COND_INDIRECT;
    case XED_CATEGORY_UNCOND_BR:
      return INS_IsDirectBranch(inst) ? BR_TYPE::UNCOND_DIRECT :
                                        BR_TYPE::UNCOND_INDIRECT;
    case XED_CATEGORY_CALL:
      return BR_TYPE::CALL;
    case XED_CATEGORY_RET:
      return BR_TYPE::RET;
    default:
      return BR_TYPE::NOT_BR;
  }
}

INT32 Usage()
{
    cerr << "This tool prints out the number of dynamic instructions executed to stderr.\n"
            "\n";

    cerr << KNOB_BASE::StringKnobSummary();

    cerr << endl;

    return -1;
}

/* ===================================================================== */

VOID doinstcount() 
{ 
  inst_count++;
  if (inst_count > KnobMaxInstructions.Value())
  {
    cerr << "Count " << branch_count << endl;
    fclose(trace_file);
    //fclose(trace_file_e);
    //fclose(trace_file_t);
    PIN_ExitApplication(0);
  }
    
}

void dump_br(const ADDRINT fetch_addr, const BOOL resolve_dir,
             const ADDRINT branch_target, UINT32 br_type,const CONTEXT *ctxt) {
    if(!started)
        return;
    int i = 0;
    HistElt current_hist_elt;
    current_hist_elt.pc        = fetch_addr;
    current_hist_elt.target    = branch_target;
    current_hist_elt.direction = resolve_dir ? 1 : 0;
    current_hist_elt.type      = static_cast<BR_TYPE>(br_type);
    current_hist_elt.dependency = isdependency;
    isdependency = 0;

    for (; i < 8; i++)
    {
      current_hist_elt.regs[i] = (uint32_t)PIN_GetContextReg(ctxt,static_cast<LEVEL_BASE::REG>(REG_RDI+(i*2)));
    }
    
    for (;i < 16;i++)
    {
      current_hist_elt.regs[i] = (uint32_t)PIN_GetContextReg(ctxt,static_cast<LEVEL_BASE::REG>(REG_R8+ (i - 8)));
    }
    current_hist_elt.regs[16] = (uint32_t)PIN_GetContextReg(ctxt,static_cast<LEVEL_BASE::REG>(REG_RIP));
    current_hist_elt.regs[17] = (uint32_t)PIN_GetContextReg(ctxt,static_cast<LEVEL_BASE::REG>(REG_RFLAGS));


    static_assert(sizeof(ADDRINT) == sizeof(current_hist_elt.pc));

    //if (inst_count < KnobMaxInstructions.Value() * 0.9)
      //{
        auto elements_written = fwrite(&current_hist_elt, sizeof(current_hist_elt), 1,
                                    trace_file);
        assert(elements_written == 1);
      //}
      /*
    else if (inst_count < KnobMaxInstructions.Value() * 0.95 && inst_count >= KnobMaxInstructions.Value() * 0.90)
      {
        auto elements_written = fwrite(&current_hist_elt, sizeof(current_hist_elt), 1,
                                    trace_file_e);
        assert(elements_written == 1);
      }
    else 
    {
      auto elements_written = fwrite(&current_hist_elt, sizeof(current_hist_elt), 1,
                                    trace_file_t);
      assert(elements_written == 1);
    }*/
    branch_count++;
    //inst_count++;
}

VOID redirect_to_pc(CONTEXT* ctx) {
  started     = true;
  ADDRINT rip = KnobRedirectPCAtStart.Value();
  PIN_SetContextRegval(ctx, REG_INST_PTR, (const UINT8*)(&rip));
  PIN_RemoveInstrumentation();
  PIN_ExecuteAt(ctx);
}

static int dependency_count = 0;
VOID Instruction(INS ins, VOID* v) { 

  //if(KnobRedirectPCAtStart.Value() != 0 && !started) {
  //  INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)redirect_to_pc, IARG_CONTEXT,
  //                 IARG_END);
  //  return;
  //}
  
  if (isdependency == 1)
  {
    dependency_count++;
    if (dependency_count == 5)
    {
      isdependency = 0;
      dependency_count = 0;
    }
  }
  else 
  {
    dependency_count = 0;
  }

  int i;

  if (INS_Opcode(ins) == XED_ICLASS_CMP) 
  {
    
    REG reg1 = INS_OperandReg(ins, 0);
    REG reg2 = INS_OperandReg(ins, 1);
    //printf("test\n");

    for (i = 0; i < (int)last20regs.size(); i++)
    {
      if (last20regs[i] == reg1 || last20regs[i] == reg2)
      {
        isdependency = 1;
        //printf("dependency\n");
        break;
      }
    }
  }
  else if (INS_Opcode(ins) == XED_ICLASS_TEST) 
  {
      
      REG reg1 = INS_OperandReg(ins, 0);
      REG reg2 = INS_OperandReg(ins, 1);

      for (int i = 0; i < (int)last20regs.size(); i++)
      {
          if (last20regs[i] == reg1 || last20regs[i] == reg2)
          {
              isdependency = 1;
              break;
          }
      }
  }

  LEVEL_BASE::REG rd = INS_RegW(ins,0);

  if (last20regs.size() < 100)
  {
    last20regs.push_back(rd);
  }
  else
  {
    last20regs.pop_front();
    last20regs.push_back(rd);
  }


  BR_TYPE br_type = get_br_type(ins);

  if(br_type != BR_TYPE::NOT_BR) {
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)dump_br, IARG_INST_PTR,
                   IARG_BRANCH_TAKEN, IARG_BRANCH_TARGET_ADDR, IARG_UINT32,
                   static_cast<uint32_t>(br_type),IARG_CONTEXT, IARG_END);
  }
  //else 
  //{
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)doinstcount, IARG_END);
  //}
    
    }

/* ===================================================================== */

VOID Fini(INT32 code, VOID* v) { 
    cerr << "Count " << branch_count << endl; 
    fclose(trace_file);
    //fclose(trace_file_e);
    //fclose(trace_file_t);
    
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int main(int argc, char* argv[])
{
    if (PIN_Init(argc, argv))
    {
        return Usage();
    }

    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);

    if(KnobCompressorPath.Value().empty()) {
        trace_file = fopen(KnobTraceFile.Value().c_str(), "w");
    } else {
        cerr << "print to file " << KnobTraceFile.Value().c_str() << endl;
        char bzip2_pipe_cmd[1024];
        sprintf(bzip2_pipe_cmd, "%s > %s", KnobCompressorPath.Value().c_str(),
                KnobTraceFile.Value().c_str());
        trace_file = popen(bzip2_pipe_cmd, "w");
    }
    /*
    if(KnobCompressorPath.Value().empty()) {
        trace_file_e = fopen(KnobTraceFile.Value().c_str(), "w");
    } else {
        cerr << "print to file " << KnobTraceFile.Value().c_str() << "_e" << endl;
        char bzip2_pipe_cmd_e[1024];
        sprintf(bzip2_pipe_cmd_e, "%s > %s%s", KnobCompressorPath.Value().c_str(),
                KnobTraceFile.Value().c_str(), "_e");
        trace_file_e = popen(bzip2_pipe_cmd_e, "w");
    }

    if(KnobCompressorPath.Value().empty()) {
        trace_file_t = fopen(KnobTraceFile.Value().c_str(), "w");
    } else {
        cerr << "print to file " << KnobTraceFile.Value().c_str() << "_t " << endl;
        char bzip2_pipe_cmd_t[1024];
        sprintf(bzip2_pipe_cmd_t, "%s > %s%s", KnobCompressorPath.Value().c_str(),
                KnobTraceFile.Value().c_str(), "_t");
        trace_file_t = popen(bzip2_pipe_cmd_t, "w");
    }*/

    // Never returns
    PIN_StartProgram();

    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */

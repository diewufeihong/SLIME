/*
   american fuzzy lop - LLVM-mode instrumentation pass
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres. C bits copied-and-pasted
   from afl-as.c are Michal's fault.

   Copyright 2015, 2016 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This library is plugged into LLVM when invoking clang through afl-clang-fast.
   It tells the compiler to add code roughly equivalent to the bits discussed
   in ../afl-as.h.

 */

#define AFL_LLVM_PASS

#include "../config.h"
#include "../debug.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
/* Added by LH. */
#include "llvm/IR/CFG.h"
#include "llvm/Analysis/Interval.h"
/* For SplitEdge. */
#include "llvm/Transforms/Utils/BasicBlockUtils.h"


using namespace llvm;

namespace {

  class AFLCoverage : public ModulePass {

    public:

      static char ID;
      AFLCoverage() : ModulePass(ID) {
        char *afl_lto_edge_ptr;
        char *afl_lto_bb_ptr;

        if ((afl_lto_edge_ptr= getenv("AFL_LLVM_LTO_STARTID_EDGE")) != NULL)
          if ((afl_global_edge_id = (uint32_t)atoi(afl_lto_edge_ptr)) < 0 ||
            afl_global_edge_id >= MAP_SIZE)
            FATAL("AFL_LLVM_LTO_STARTID_EDGE value of \"%s\" is not between 0 and %u\n",
              afl_lto_edge_ptr, MAP_SIZE - 1); 
        if ((afl_lto_bb_ptr = getenv("AFL_LLVM_LTO_STARTID_BB")) != NULL)
          if ((afl_global_bb_id = (uint32_t)atoi(afl_lto_bb_ptr)) < 0 ||
            afl_global_bb_id >= MAP_SIZE)
            FATAL("AFL_LLVM_LTO_STARTID_BB value of \"%s\" is not between 0 and %u\n",
              afl_lto_bb_ptr, MAP_SIZE - 1); 
      }

      bool runOnModule(Module &M) override;

      // StringRef getPassName() const override {
      //  return "American Fuzzy Lop Instrumentation";
      // }
      protected:
        uint32_t     afl_global_edge_id = 1;
        uint32_t     afl_global_bb_id = 1;

  };

}


char AFLCoverage::ID = 0;

/* Globals used to record basic block and branch information. 
   Record which branches reach the current basic block.
    Created by LH.*/
struct bb_suc{
	unsigned int bb_id;                           /* Successor basic block id                    */
  uint32_t edge_id;                             /* Edge id from previous bb to this successor  */
	struct bb_suc *next;                   	      /* Next element, if any                        */
};

struct bb_cmp_suc{
  BasicBlock* cmp_suc;                          /* Successor bb pointer for cmp with const     */
  struct bb_cmp_suc *next;                   	  /* Next element, if any                        */
};

struct bb{    
  u8 instrument;                                /* Flag to mark whether to instrument          */  
  BasicBlock* bb_p;                             /* Basic block pointer                         */
	unsigned int bb_id;                           /* Basic block id                              */
  unsigned int bb_mem_num;                      /* The number of memory accesses of the basic block */
  unsigned int bb_func_num;                     /* The number of syscall of the basic block    */
  unsigned int bb_global_num;                   /* The number of global variables of the basic block */
  unsigned int bb_global_assign_num;            /* The number of global variable assignments of the basic block */
  
  struct bb_suc *suc_queue;                     /* Successor basic blocks queue (linked list)  */
  struct bb_suc *suc_last;                      /* Last successor basic block                  */    
  struct bb_suc *cmp_suc_id_queue;              /* Cmp successor basic blocks id queue (linked list) */
  struct bb_suc *cmp_suc_id_last;               /* Last cmp successor basic block id           */
  struct bb_cmp_suc *cmp_suc_queue;             /* Cmp successor basic blocks queue (linked list)  */
  struct bb_cmp_suc *cmp_suc_last;              /* Last cmp successor basic block                  */
	struct bb *next;                   	        	/* Next element, if any                        */
};

static struct bb *bb_queue;                     /* Basic blocks queue (linked list)            */

std::vector<std::string> syscall_routines = {
  // memory allocation
  "calloc",  "malloc",   "realloc",  "free",
  // memory operation
  "memcpy",  "memmove",  "memchr",   "memset",  
  "memcmp",
  // string operation
  "strcpy",  "strncpy",  "strerror", "strlen",
  "strcat",  "strncat",  "strcmp",   "strspn",
  "strcoll", "strncmp",  "strxfrm",  "strstr",
  "strchr",  "strcspn",  "strpbrk",  "strrchr", 
  "strtok",
  // TODO... add more interesting functions
};

bool is_syscall(llvm::StringRef fn_name){
  for(std::vector<std::string>::size_type i = 0; i < syscall_routines.size(); i++){
    if(fn_name.compare(syscall_routines[i]) == 0)
      return true;
  }
  return false;
}


/* Function that we never instrument or analyze */
/* Note: this ignore check is also called in isInInstrumentList() */
bool isIgnoreFunction(const llvm::Function *F) {

  // Starting from "LLVMFuzzer" these are functions used in libfuzzer based
  // fuzzing campaign installations, e.g. oss-fuzz

  static constexpr const char *ignoreList[] = {

      "asan.",
      "llvm.",
      "sancov.",
      "__ubsan",
      "ign.",
      "__afl",
      "_fini",
      "__libc_",
      "__asan",
      "__msan",
      "__cmplog",
      "__sancov",
      "__san",
      "__cxx_",
      "__decide_deferred",
      "_GLOBAL",
      "_ZZN6__asan",
      "_ZZN6__lsan",
      "msan.",
      "LLVMFuzzerM",
      "LLVMFuzzerC",
      "LLVMFuzzerI",
      "maybe_duplicate_stderr",
      "discard_output",
      "close_stdout",
      "dup_and_close_stderr",
      "maybe_close_fd_mask",
      "ExecuteFilesOnyByOne"

  };

  for (auto const &ignoreListFunc : ignoreList) {

    if (F->getName().startswith(ignoreListFunc)) { return true; }

  }

  static constexpr const char *ignoreSubstringList[] = {

      "__asan", "__msan",       "__ubsan",    "__lsan",  "__san", "__sanitize",
      "__cxx",  "DebugCounter", "DwarfDebug", "DebugLoc"

  };

  for (auto const &ignoreListFunc : ignoreSubstringList) {

    // hexcoder: F->getName().contains() not avaiilable in llvm 3.8.0
    if (StringRef::npos != F->getName().find(ignoreListFunc)) { return true; }

  }

  return false;

}

bool AFLCoverage::runOnModule(Module &M) {
  LLVMContext &C = M.getContext();

  IntegerType *Int8Ty  = IntegerType::getInt8Ty(C);
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);

  /* Show a banner */

  char be_quiet = 0;

  if (isatty(2) && !getenv("AFL_QUIET")) {

    SAYF(cCYA "afl-llvm-pass " cBRI VERSION cRST " by <lszekeres@google.com>\n");

  } else be_quiet = 1;

  /* Decide instrumentation ratio */

  char* inst_ratio_str = getenv("AFL_INST_RATIO");
  unsigned int inst_ratio = 100;

  if (inst_ratio_str) {

    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
        inst_ratio > 100)
      FATAL("Bad value of AFL_INST_RATIO (must be between 1 and 100)");

  }

  /* Get globals for the SHM region and the previous location. */

  GlobalVariable *AFLMapPtr =
      new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__afl_area_ptr");

  /* Instrument all the things! */

  int inst_blocks = 0;
  
  /* Added by LH. */
  bool bb_first = true;
	struct bb *bb_cur = NULL; 
  for (auto &F : M){
    /* added by LH */

    if (F.size() < 1) continue;
    if (isIgnoreFunction(&F)) continue;

    // the instrument file list check
    AttributeList Attrs = F.getAttributes();
    if (Attrs.hasAttribute(-1, StringRef("skipinstrument"))) {
      continue;
    }

    for (auto &BB : F) {  
      struct bb *bb_now = (struct bb *)malloc(sizeof(struct bb));
      bb_now->instrument = 1;
      bb_now->bb_mem_num = 0;
      bb_now->bb_func_num = 0;
      bb_now->bb_global_num = 0;
      bb_now->bb_global_assign_num = 0;

      /* Determine some static analysis information for each basic block. Added by LH. */ 
      for (BasicBlock::iterator inst = BB.begin(); inst != BB.end(); ++inst){
        bool global_flag = 0;
        for(Use &U:(&*inst)->operands()){      
          if(GlobalVariable *GV = dyn_cast<GlobalVariable>(U)){
            bb_now->bb_global_num++;
            if(!global_flag) global_flag = 1;
          }
          else if(GEPOperator * gepo = dyn_cast<GEPOperator>(&U)){
            if(GlobalVariable *gv = dyn_cast<GlobalVariable>(gepo->getPointerOperand())){
              bb_now->bb_global_num++;
              if(!global_flag) global_flag = 1;
            }
            for(auto it = gepo->idx_begin(), et = gepo->idx_end(); it != et; ++it){
              if(GlobalVariable* gv = dyn_cast<GlobalVariable>(*it)){
                bb_now->bb_global_num++;
                if(!global_flag) global_flag = 1;
              }
            }
          }
        }
        
        if(isa<StoreInst>(inst)){
          if(global_flag) bb_now->bb_global_assign_num++;
        }

        if(inst->mayReadFromMemory()){
          bb_now->bb_mem_num++;
        }
        
        if(inst->mayWriteToMemory()){
          bb_now->bb_mem_num++;
        }

        Instruction &bb_inst = *inst;

        if(CallInst* call_inst = dyn_cast<CallInst>(&bb_inst)) {
          Function* fn = call_inst->getCalledFunction();
          if(fn == NULL){
            Value *v = call_inst->getCalledOperand();
            fn = dyn_cast<Function>(v->stripPointerCasts());
            if(fn == NULL)
              continue;
          }
          llvm::StringRef fn_name = fn->getName();
          llvm::StringRef fn_name_start = fn_name.slice(0,5);
          if(fn_name_start.compare("llvm.") == 0)
            continue;
          
          if(is_syscall(fn_name)){
            bb_now->bb_func_num++;
          }
        }
      }
      
      /* Build a list of basic blocks, added by LH. */
      bb_now->bb_id = afl_global_bb_id;
      afl_global_bb_id++;
      bb_now->bb_p = &BB;
      bb_now->suc_queue = NULL;
      bb_now->suc_last = NULL;
      bb_now->cmp_suc_queue = NULL;
      bb_now->cmp_suc_last = NULL;
      bb_now->cmp_suc_id_queue = NULL;
      bb_now->cmp_suc_id_last = NULL;
			bb_now->next = NULL;
      if(bb_first) {
        bb_first = false;
        bb_queue = bb_now;
        bb_cur = bb_now;
      }else{  
			  bb_cur->next = bb_now;
			  bb_cur = bb_now;
      }
      
      if(BranchInst *BI = dyn_cast<BranchInst>(BB.getTerminator())){
        if(BI->isConditional()){
          if(CmpInst *CI = dyn_cast<CmpInst>(BI->getCondition())){
            if (CI && isa<Instruction>(CI->getOperand(0)) && isa<Constant>(CI->getOperand(1))){
              struct bb_cmp_suc *cmp_suc_now = (struct bb_cmp_suc *)malloc(sizeof(struct bb_cmp_suc));
              cmp_suc_now->cmp_suc = BI->getSuccessor(0);
              cmp_suc_now->next = NULL;
              if(bb_now->cmp_suc_queue){
                bb_now->cmp_suc_last->next =  cmp_suc_now;
                bb_now->cmp_suc_last = cmp_suc_now;
              }else{
                bb_now->cmp_suc_queue = cmp_suc_now;
                bb_now->cmp_suc_last = cmp_suc_now;
              }
            }
          }
        }
      }
    }
  }
  /* Build a list of subsequent basic blocks, added by LH. */  
	struct bb *b = bb_queue;
  while(b){
    if(b->instrument){
      for (auto it = succ_begin(b->bb_p), et = succ_end(b->bb_p); it != et; ++it){
        BasicBlock *  newBB = NULL;
        BasicBlock *succ = *it;
        newBB = llvm::SplitEdge(b->bb_p, succ);
        BasicBlock::iterator IP = newBB->getFirstInsertionPt();
        IRBuilder<>          IRB(&(*IP));
        /* Set the ID of the inserted basic block */
        ConstantInt *CurLoc = ConstantInt::get(Int32Ty, afl_global_edge_id);
        /* Load SHM pointer */
        Value *MapPtrIdx;
        LoadInst *MapPtr = IRB.CreateLoad(AFLMapPtr);
        MapPtr->setMetadata(M.getMDKindID("nosanitize"),
                              MDNode::get(C, None));
        MapPtrIdx = IRB.CreateGEP(MapPtr, CurLoc);
        /* Update bitmap */
        LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
            Counter->setMetadata(M.getMDKindID("nosanitize"),

                                 MDNode::get(C, None));                  
        ConstantInt *One = ConstantInt::get(Int8Ty, 1);
        Value *Incr = IRB.CreateAdd(Counter, One);
        IRB.CreateStore(Incr, MapPtrIdx)
                ->setMetadata(M.getMDKindID("nosanitize"),
                              MDNode::get(C, None));
        inst_blocks++;
	      struct bb *b_suc = bb_queue;
        while(b_suc){
          if(b_suc->bb_p == succ){
            struct bb_suc *suc_now = (struct bb_suc *)malloc(sizeof(struct bb_suc));
            suc_now->bb_id = b_suc->bb_id;
            suc_now->edge_id = afl_global_edge_id;
            suc_now->next = NULL;
            if(b->suc_queue){
              b->suc_last->next = suc_now;
              b->suc_last = suc_now;
            }else{
              b->suc_queue = suc_now;
              b->suc_last = suc_now;
            }
            struct bb_cmp_suc* b_cmp_suc = b->cmp_suc_queue;
            while(b_cmp_suc){
              if(b_cmp_suc->cmp_suc == succ){
                struct bb_suc *cmp_suc_id_now = (struct bb_suc *)malloc(sizeof(struct bb_suc));
                cmp_suc_id_now->bb_id = b_suc->bb_id;
                cmp_suc_id_now->edge_id = afl_global_edge_id;
                cmp_suc_id_now->next = NULL;
                if(b->cmp_suc_id_queue){
                  b->cmp_suc_id_last->next = cmp_suc_id_now;
                  b->cmp_suc_id_last = cmp_suc_id_now;
                }else{
                  b->cmp_suc_id_queue = cmp_suc_id_now;
                  b->cmp_suc_id_last = cmp_suc_id_now;
                }
                break;
              }
              b_cmp_suc = b_cmp_suc->next;  
            } 
            break;
          }
          b_suc = b_suc->next;
        }
        afl_global_edge_id++;
      } 
    }
    b = b->next;
  }


  /* Say something nice. */

  if (!be_quiet) {

    if (!inst_blocks) WARNF("No instrumentation targets found.");
    else OKF("Instrumented %u locations (%s mode, ratio %u%%).",
             inst_blocks, getenv("AFL_HARDEN") ? "hardened" :
             ((getenv("AFL_USE_ASAN") || getenv("AFL_USE_MSAN")) ?
              "ASAN/MSAN" : "non-hardened"), inst_ratio);

  }

   /*  Print the queue, added by LH. */
  FILE * bb_file = NULL;
  char * bb_file_ptr = getenv("SLIME_BB_NAME");  
  if(bb_file_ptr == NULL){
    bb_file = fopen("./result.bb", "w");
  } else if ((bb_file = fopen(bb_file_ptr, "w")) == NULL){
      WARNF("Cannot access document file.");
  }  
	b = bb_queue;

  uint32_t afl_global_id = (afl_global_bb_id > afl_global_edge_id) ? afl_global_bb_id : afl_global_edge_id;

#ifdef __x86_64__
  fprintf(bb_file, "%u\n", ((afl_global_id>>3)+1)<<3);
#else
  fprintf(bb_file, "%u\n", ((afl_global_id>>2)+1)<<2);
#endif /* ^__x86_64__ */


  while(b){
    fprintf(bb_file,"b%u\t",b->bb_id);
    fprintf(bb_file,"%u\t",b->bb_mem_num);
    fprintf(bb_file,"%u\t",b->bb_func_num);
    fprintf(bb_file,"%u\t",b->bb_global_num);
    fprintf(bb_file,"%u\ns",b->bb_global_assign_num);
    struct bb_suc * b_suc = b->suc_queue;
    while(b_suc){
      fprintf(bb_file,"%u\t",b_suc->bb_id);
      fprintf(bb_file,"%u\t",b_suc->edge_id);
      b_suc = b_suc->next;
    }
    fprintf(bb_file,"\nc");
    struct bb_suc * b_cmp_suc = b->cmp_suc_id_queue;
    while(b_cmp_suc){
      fprintf(bb_file,"%u\t",b_cmp_suc->bb_id);
      b_cmp_suc = b_cmp_suc->next;
    }
    fprintf(bb_file,"\n");
    b = b->next;
  }
  fprintf(bb_file,"e\n");
  free(bb_queue);
  fclose(bb_file);

  return true;

}


static void registerAFLPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {

  PM.add(new AFLCoverage());

}


static RegisterPass<AFLCoverage> X("afl-llvm-pass", "afl++ LTO instrumentation pass",
                                  false, false);

static RegisterStandardPasses RegisterAFLPass(
    PassManagerBuilder::EP_FullLinkTimeOptimizationLast, registerAFLPass);

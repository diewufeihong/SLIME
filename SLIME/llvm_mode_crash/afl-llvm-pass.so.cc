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
        char *afl_lto_ptr;

        if ((afl_lto_ptr = getenv("AFL_LLVM_LTO_STARTID")) != NULL)
          if ((afl_global_edge_id = (uint32_t)atoi(afl_lto_ptr)) < 0 ||
            afl_global_edge_id >= MAP_SIZE)
            FATAL("AFL_LLVM_LTO_STARTID value of \"%s\" is not between 0 and %u\n",
              afl_lto_ptr, MAP_SIZE - 1); 
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

struct bb{    
  u8 instrument;                                /* Flag to mark whether to instrument          */ 
  BasicBlock* bb_p;                             /* Basic block pointer                         */
	struct bb *next;                   	        	/* Next element, if any                        */
};

static struct bb *bb_queue;                     /* Basic blocks queue (linked list)            */

char AFLCoverage::ID = 0;


bool AFLCoverage::runOnModule(Module &M) {

  LLVMContext &C = M.getContext();

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

  /* Created by LH. */
  GlobalVariable *AFLBBPtr =
      new GlobalVariable(M, PointerType::get(Int32Ty, 0), false,
                         GlobalValue::ExternalLinkage, 0, "__afl_bb_ptr");

  bool bb_first = true;
	struct bb *bb_cur = NULL; 
  for (auto &F : M)
    for (auto &BB : F) {
      struct bb *bb_now = (struct bb *)malloc(sizeof(struct bb));
      bb_now->bb_p = &BB;
			bb_now->next = NULL;
      bb_now->instrument = 1;
      if(bb_first) {
        bb_first = false;
        bb_queue = bb_now;
        bb_cur = bb_now;
      }else{  
			  bb_cur->next = bb_now;
			  bb_cur = bb_now;
      }
      afl_global_bb_id++;
    }

  /* Instrument all the things! */
	struct bb *b = bb_queue;
  int inst_blocks = 0;
  while(b){
    if(b->instrument) {
      for (auto it = succ_begin(b->bb_p), et = succ_end(b->bb_p); it != et; ++it){
        BasicBlock *  newBB = NULL;
        BasicBlock *succ = *it;
        newBB = llvm::SplitEdge(b->bb_p, succ);
        BasicBlock::iterator IP = newBB->getFirstInsertionPt();
        IRBuilder<>          IRB(&(*IP));
         /* Set the ID of the inserted basic block */
        ConstantInt *CurLoc = ConstantInt::get(Int32Ty, afl_global_edge_id++);
        /* Load SHM bb pointer, added by LH. */
        LoadInst *BBPtr = IRB.CreateLoad(AFLBBPtr);
        BBPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
        Value *BBPtrIdx =
            IRB.CreateGEP(BBPtr,ConstantInt::get(Int32Ty, 0));
        /* Update last_bb, added by LH.  */
        IRB.CreateStore(CurLoc, BBPtrIdx);
        inst_blocks++;
      }
    }
    b = b->next;
  }


  /*  Print the queue, added by LH. */
  FILE * bb_file = NULL;
  char * bb_file_ptr;  
  u32 record_map_size = 0;
  u32 now_map_size = 0;
  if((bb_file_ptr = getenv("AFL_LLVM_DOCUMENT_IDS")) != NULL){
    if ((bb_file = fopen(bb_file_ptr, "r+")) == NULL){
      if((bb_file = fopen(bb_file_ptr, "w")) == NULL){
        FATAL("Cannot access document file.");
      }
    }else if(fscanf(bb_file,"%u",&record_map_size)==-1) {
     FATAL("Error in fscanf function.\n");
    }  
  }

  uint32_t afl_global_id = (afl_global_bb_id > afl_global_edge_id) ? afl_global_bb_id : afl_global_edge_id;

#ifdef __x86_64__
  now_map_size = ((afl_global_id>>3)+1)<<3;
  if(record_map_size < now_map_size){
    fseek(bb_file, 0, SEEK_SET);
    fprintf(bb_file, "%u\n", now_map_size);
  }
#else
  now_map_size = ((afl_global_id>>2)+1)<<2;
  if(record_map_size < now_map_size){
    fseek(bb_file, 0, SEEK_SET);
    fprintf(bb_file, "%u\n", now_map_size);
  }
#endif /* ^__x86_64__ */

  fclose(bb_file);

  /* Say something nice. */

  if (!be_quiet) {

    if (!inst_blocks) WARNF("No instrumentation targets found.");
    else OKF("Instrumented %u locations (%s mode, ratio %u%%).",
             inst_blocks, getenv("AFL_HARDEN") ? "hardened" :
             ((getenv("AFL_USE_ASAN") || getenv("AFL_USE_MSAN")) ?
              "ASAN/MSAN" : "non-hardened"), inst_ratio);

  }

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


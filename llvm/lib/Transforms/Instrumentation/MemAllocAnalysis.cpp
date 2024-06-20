//===- MemAllocAnalysis.cpp - Example code from "Writing an LLVM Pass" ---------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements two versions of the LLVM "MemAllocAnalysis World" pass described
// in docs/WritingAnLLVMPass.html
//
//===----------------------------------------------------------------------===//
#include "llvm/Transforms/Instrumentation/MemAllocAnalysis.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/Pass.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/InitializePasses.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/LoopUtils.h"
using namespace llvm;

#define DEBUG_TYPE "memory-alloc"

STATISTIC(MemAllocAnalysisCounter, "Counts number of functions greeted");

/*
cl::opt<bool> ClMemAllocAnalysis(
    "memAllocAnalysis",
    cl::desc("Mem Alloc Analysis"),
    cl::init(true));
*/
bool
MemAllocAnalysis::runOnFunction(Function &F) {
    LLVMContext &Context = F.getContext();
    Module *M = F.getParent();

    errs() << "running memAlloc Analysis!" << "\n";
    /*

    // Declare or get the logMalloc function
    Type *VoidTy = Type::getVoidTy(Context);
    Type *SizeTy = Type::getInt64Ty(Context);  // Assuming size_t is 64 bits
    Type *PtrTy = Type::getInt8PtrTy(Context);
    FunctionType *LogMallocTy = FunctionType::get(VoidTy, {SizeTy, PtrTy}, false);
    FunctionCallee LogMalloc = M->getOrInsertFunction("logMemAccess", LogMallocTy);

    */

    // Declare or get the logMalloc function
    Type *NewVoidTy = Type::getVoidTy(Context);
    Type *NewSizeTy = Type::getInt64Ty(Context);  // Assuming size_t is 64 bits
    Type *NewElementTy = Type::getInt64Ty(Context);  // Assuming size_t is 64 bits
    Type *OpTypeTy = Type::getInt64Ty(Context);  // Assuming size_t is 64 bits
    Type *NewPtrTy  = Type::getInt8PtrTy(Context);
    FunctionType *LogNewTy = FunctionType::get(NewVoidTy, {NewSizeTy,NewElementTy, OpTypeTy, NewPtrTy}, false);
    //FunctionType *LogNewTy = FunctionType::get(NewVoidTy, {NewSizeTy,NewPtrTy}, false);
    FunctionCallee LogNew = M->getOrInsertFunction("logNewAllocation", LogNewTy);

    ++MemAllocAnalysisCounter;

    const DataLayout &DL = F.getParent()->getDataLayout();


    /*
     * 1 malloc
     * 2 calloc
     * 3 realloc
     * 4 free
     * 5 new
     * 6 new []
     * 7 delete
     * 8 malloc fortran
     * 9 dealloc fortran
     * 10 xalloc
     */
    uint64_t memOp = 0;

    for (Function::iterator bb= F.begin(), bbe= F.end(); bb != bbe; ++bb) {
        for (BasicBlock::iterator i = bb->begin(), ie=bb->end(); i != ie; ++i) {
            Instruction *Inst = &*i;

            //errs() << "Instruction: " << *Inst << "\n";

            IRBuilder<> builder(Inst);

            if (auto *BitCast = dyn_cast<BitCastInst>(Inst)) {
                Instruction *PrevInst = Inst->getPrevNode();

                if (PrevInst) {
                    if ( auto *Call = dyn_cast<CallInst>(PrevInst)) {

                        /*
                        if (DILocation *Loc = PrevInst->getDebugLoc()) {
                            unsigned Line = Loc->getLine();
                            StringRef File = Loc->getFilename();
                            StringRef Dir = Loc->getDirectory();
                            errs() << "check allocation at " << Dir << "/" << File << ":" << Line << "\n";
                        }
                        */


                        Function *CalledFunc = Call->getCalledFunction();

                        if (!CalledFunc)
                            continue;

                        StringRef FuncName = CalledFunc->getName();
                        Type *DestType = BitCast->getDestTy();
                        Value *funcRet = Call;
                        if (FuncName.equals("malloc") || FuncName.equals("calloc") || FuncName.equals("xmalloc")
                            || FuncName.startswith("_gfortran_internal_malloc")) {
                            if (PointerType *PtrType = dyn_cast<PointerType>(DestType)) {
                                Type *ElementType = PtrType->getElementType();

                                // ElementType->isFloatTy()
                                // ElementType->isInt()

                                uint64_t ElementSize = DL.getTypeAllocSize(ElementType);
                                Value *Arg0 = Call->getArgOperand(0);

                                // malloc arg0 is allocate bytes
                                // get return type with  for size of each element
                                // calloc arg0 is number of elements
                                //        arg1 is size of each element

                                if (FuncName.equals("malloc")) {
                                    memOp = 1;
                                } else if (FuncName.equals("calloc")) {
                                    memOp = 2;
                                } else if (FuncName.startswith("_gfortran_internal_malloc")) {
                                    memOp = 8;
                                } else if (FuncName.equals("xmalloc")) {
                                    memOp = 10;
                                }

                                if (memOp == 2) {
                                    Value *Arg1 = Call->getArgOperand(1);
                                    builder.CreateCall(LogNew, {Arg0, Arg1, builder.getInt64(memOp), funcRet});
                                } else {
                                    builder.CreateCall(LogNew, {Arg0, builder.getInt64(ElementSize), builder.getInt64(memOp), funcRet});
                                }

                            }
                        } else if (FuncName.startswith("_Znwm") || FuncName.startswith("_Znam") || FuncName.startswith("_gfortran_internal_free")) {
                            // single and array
                            if (PointerType *PtrType = dyn_cast<PointerType>(DestType)) {
                                Type *ElementType = PtrType->getElementType();

                                // ElementType->isFloatTy()
                                // ElementType->isInt()

                                uint64_t ElementSize = DL.getTypeAllocSize(ElementType);
                                Value *SizeArg = Call->getArgOperand(0);

                                if (FuncName.startswith("_Znwm")) {
                                    memOp = 5;
                                } else if (FuncName.startswith("_Znwm") || FuncName.startswith("_Znam")){
                                    memOp = 6;
                                } else if (FuncName.startswith("_gfortran_internal_free")) {
                                    memOp = 9;
                                }

                                builder.CreateCall(LogNew, {SizeArg, builder.getInt64(ElementSize), builder.getInt64(memOp), funcRet});
                            }
                        }
                    }
                }
            } else if (auto *Call = dyn_cast<CallInst>(Inst)) {

                /*
                if (DILocation *Loc = Inst->getDebugLoc()) {
                    unsigned Line = Loc->getLine();
                    StringRef File = Loc->getFilename();
                    StringRef Dir = Loc->getDirectory();
                    errs() << "check deallocation at " << Dir << "/" << File << ":" << Line << "\n";
                }
                */

                Function *CalledFunc = Call->getCalledFunction();

                if (!CalledFunc)
                    continue;

                StringRef FuncName = CalledFunc->getName();
                if (FuncName.startswith("_ZdlPv") || FuncName.startswith("_ZdaPv") || FuncName == "free" || FuncName.startswith("_gfortran_internal_free")) {
                    // _ZdlPv -> operator delete(void*)
                    // _ZdaPv -> operator delete[](void*)
                    if (FuncName == "free")
                        memOp = 4;
                    else
                        memOp = 7;

                    Value *SizeArg = Call->getArgOperand(0);

                    Type *ptrType = SizeArg->getType()->getPointerElementType();

                    // Get the size of the object type
                    uint64_t size = DL.getTypeAllocSize(ptrType);

                    builder.CreateCall(LogNew, {builder.getInt64(size), builder.getInt64(0), builder.getInt64(memOp), SizeArg});
                }
            }
            }
        }

        return true;
      }

char MemAllocAnalysis::ID = 0;

INITIALIZE_PASS(MemAllocAnalysis, "memory-alloc",
                    "MemAllocAnalysis for size and pointer", false, false)

FunctionPass *llvm::createMemAllocAnalysis() {
  return new MemAllocAnalysis();
}

PreservedAnalyses MemAllocAnalysisNoLegacy::run(Function &F,
                                             FunctionAnalysisManager &AM) {

    errs() << "Now Memory Alloc Analysis Runs! " << "\n";

    return PreservedAnalyses::all();
}

// Register the pass with a pass manager
llvm::PassPluginLibraryInfo getMemAllocAnalysisNoLegacyInfo() {
  return {LLVM_PLUGIN_API_VERSION, "MemAllocAnalysis", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager &FPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "memory-alloc") {
                    FPM.addPass(MemAllocAnalysisNoLegacy());
                    return true;
                  }
                  return false;
                });
          }};
}

// Export the pass registration function
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return getMemAllocAnalysisNoLegacyInfo();
}


//===- NewAllocAnalysis.cpp - Example code from "Writing an LLVM Pass" ---------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements two versions of the LLVM "NewAllocAnalysis World" pass described
// in docs/WritingAnLLVMPass.html
//
//===----------------------------------------------------------------------===//

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

#define DEBUG_TYPE "newAllocAnalysis"

STATISTIC(NewAllocAnalysisCounter, "Counts number of functions greeted");

namespace {

// NewAllocAnalysis - The first implementation, without getAnalysisUsage.
struct NewAllocAnalysis : public FunctionPass {
    static char ID; // Pass identification, replacement for typeid
    NewAllocAnalysis() : FunctionPass(ID) {}

    bool runOnFunction(Function &F) override {
    LLVMContext &Context = F.getContext();
    Module *M = F.getParent();

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

    ++NewAllocAnalysisCounter;

    const DataLayout &DL = F.getParent()->getDataLayout();


    /*
     * 1 malloc
     * 2 calloc
     * 3 realloc
     * 4 free
     * 5 new
     * 6 new []
     * 7 delete
     */
    uint64_t memOp = 0;

    for (Function::iterator bb= F.begin(), bbe= F.end(); bb != bbe; ++bb) {
        for (BasicBlock::iterator i = bb->begin(), ie=bb->end(); i != ie; ++i) {
            Instruction *Inst = &*i;

            errs() << "Instruction: " << *Inst << "\n";

            IRBuilder<> builder(Inst);

            if (auto *BitCast = dyn_cast<BitCastInst>(Inst)) {
                Instruction *PrevInst = Inst->getPrevNode();

                if (PrevInst) {
                    if ( auto *Call = dyn_cast<CallInst>(PrevInst)) {
                        Function *CalledFunc = Call->getCalledFunction();
                        StringRef FuncName = CalledFunc->getName();
                        Type *DestType = BitCast->getDestTy();
                        Value *funcRet = Call;
                        if (FuncName.equals("malloc") || FuncName.equals("calloc")) {
                            if (PointerType *PtrType = dyn_cast<PointerType>(DestType)) {
                                Type *ElementType = PtrType->getElementType();

                                // ElementType->isFloatTy()
                                // ElementType->isInt()

                                uint64_t ElementSize = DL.getTypeAllocSize(ElementType);
                                Value *SizeArg = Call->getArgOperand(0);


                                if (FuncName.equals("malloc")) {
                                    memOp = 1;
                                } else {
                                    memOp = 2;
                                }

                                builder.CreateCall(LogNew, {SizeArg, builder.getInt64(ElementSize), builder.getInt64(memOp), funcRet});
                            }
                        } else if (FuncName.startswith("_Znwm") || FuncName.startswith("_Znam")) {
                            // single and array
                            if (PointerType *PtrType = dyn_cast<PointerType>(DestType)) {
                                Type *ElementType = PtrType->getElementType();

                                // ElementType->isFloatTy()
                                // ElementType->isInt()

                                uint64_t ElementSize = DL.getTypeAllocSize(ElementType);
                                Value *SizeArg = Call->getArgOperand(0);

                                if (FuncName.startswith("_Znwm")) {
                                    memOp = 5;
                                } else {
                                    memOp = 6;
                                }

                                builder.CreateCall(LogNew, {SizeArg, builder.getInt64(ElementSize), builder.getInt64(memOp), funcRet});
                            }
                        }
                    }
                }
            } else if (auto *Call = dyn_cast<CallInst>(Inst)) {
                Function *CalledFunc = Call->getCalledFunction();
                StringRef FuncName = CalledFunc->getName();
                if (FuncName.startswith("_ZdlPv") || FuncName.startswith("_ZdaPv") || FuncName == "free") {
                    // _ZdlPv -> operator delete(void*)
                    // _ZdaPv -> operator delete[](void*)
                    if (FuncName == "free")
                        memOp = 4;
                    else
                        memOp = 7;

                    Value *SizeArg = Call->getArgOperand(0);
                    builder.CreateCall(LogNew, {builder.getInt64(0), builder.getInt64(0), builder.getInt64(memOp), SizeArg});
                }
            }
            /*
            else if (auto *Call = dyn_cast<CallInst>(Inst)) {
                Function *CalledFunc = Call->getCalledFunction();
                StringRef FuncName = CalledFunc->getName();
                //outs() << FuncName << "\n";
                if (FuncName.equals("malloc") || FuncName.equals("calloc")) {
                    Value *SizeArg = Call->getArgOperand(0);
                    Value *MallocRet = Call;
                    builder.CreateCall(LogMalloc, {SizeArg, MallocRet});
                } else if (FuncName.startswith("_ZdlPv") || FuncName.startswith("_ZdaPv")) {
                    // _ZdlPv -> operator delete(void*)
                    // _ZdaPv -> operator delete[](void*)
                    if (FuncName.startswith("_ZdaPv")) {
                    } else {
                    }
                } else if (FuncName == "free") {
                    // free function
                }
            }
            */
            }
        }

        return true;
      }
};

}

char NewAllocAnalysis::ID = 0;
static RegisterPass<NewAllocAnalysis> X("newAllocAnalysis", "NewAllocAnalysis for size and pointer");

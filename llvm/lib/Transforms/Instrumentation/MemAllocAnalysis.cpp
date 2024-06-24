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
#include "llvm/Demangle/Demangle.h"

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
MemAllocAnalysis::containsOperatorNewInMiddle(const std::string& str, bool isNew) {
    size_t pos;
    if (isNew)
        pos = str.find("operator new(");
    else
        pos = str.find("operator delete(");

    return (pos != std::string::npos) && (pos != 0);
}

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
     * 1    malloc
     * 2    calloc
     * 3    realloc
     * 4    free
     * 5    new
     * 6    new [] char
     * 7    delete
     * 8    malloc fortran
     * 9    dealloc fortran
     * 10   xalloc
     * 11   new [] int
     * 12   delete []
     * 13   operator new
     * 14   operator delete
     */

    std::unordered_set<Instruction *> instDone;

    uint64_t memOp = 0;

    for (Function::iterator bb= F.begin(), bbe= F.end(); bb != bbe; ++bb) {
        for (BasicBlock::iterator i = bb->begin(), ie=bb->end(); i != ie; ++i) {
            Instruction *Inst = &*i;

            //errs() << "Instruction: " << *Inst << "\n";

            if (auto *BitCast = dyn_cast<BitCastInst>(Inst)) {

                IRBuilder<> builder(Inst);

                Instruction *PrevInst = Inst->getPrevNode();

                if (PrevInst) {
                    if ( auto *Call = dyn_cast<CallInst>(PrevInst)) {

                        Function *CalledFunc = Call->getCalledFunction();

                        if (!CalledFunc)
                            continue;

                        StringRef FuncName = CalledFunc->getName();
                        Type *DestType = BitCast->getDestTy();
                        Value *funcRet = Call;


                        errs() << "bit cast previous node 0----" << "\n";
                        std::string demangledName = demangle(FuncName.str().c_str());
                        errs() << "bit cast previous node 0 Found invoke function call: " << demangledName << "\n";

                        if (DILocation *Loc = Inst->getDebugLoc()) {
                          unsigned Line = Loc->getLine();
                          unsigned Col = Loc->getColumn();
                          StringRef File = Loc->getFilename();
                          StringRef Dir = Loc->getDirectory();
                          errs() << "0 Found invoke function call: " << demangledName << " at "
                                 << Dir << "/" << File << ":" << Line << ":" << Col << "\n";
                        }

                        if (instDone.count(PrevInst) != 0)
                            continue;

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

                                instDone.insert(PrevInst);

                            }
                        } else if (FuncName.startswith("_Znwm") || FuncName.startswith("_Znam") || FuncName.startswith("_Znaj")) {

                            // single and array
                            if (PointerType *PtrType = dyn_cast<PointerType>(DestType)) {
                                Type *ElementType = PtrType->getElementType();

                                // ElementType->isFloatTy()
                                // ElementType->isInt()

                                uint64_t ElementSize = DL.getTypeAllocSize(ElementType);
                                Value *SizeArg = Call->getArgOperand(0);

                                if ( FuncName.startswith("_Znam")){
                                    memOp = 6;
                                } else if (FuncName.startswith("_Znwm")) {
                                    memOp = 5;
                                } else if ( FuncName.startswith("_Znaj")){
                                    memOp = 11;
                                }

                                builder.CreateCall(LogNew, {SizeArg, builder.getInt64(ElementSize), builder.getInt64(memOp), funcRet});
                                instDone.insert(PrevInst);
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

                if (instDone.count(Inst) != 0)
                    continue;

                Function *CalledFunc = Call->getCalledFunction();

                if (!CalledFunc)
                    continue;

                StringRef FuncName = CalledFunc->getName();

                errs() << "1----" << "\n";
                std::string demangledName = demangle(FuncName.str().c_str());
                errs() << "1 Found pure function call: " << demangledName << "\n";

                if (DILocation *Loc = Inst->getDebugLoc()) {
                  unsigned Line = Loc->getLine();
                  unsigned Col = Loc->getColumn();
                  StringRef File = Loc->getFilename();
                  StringRef Dir = Loc->getDirectory();
                  errs() << "1 Found pure function call: " << demangledName << " at "
                         << Dir << "/" << File << ":" << Line << ":" << Col << "\n";
                }

                bool isOperatorDelete = false;

                if ( containsOperatorNewInMiddle(demangledName,false)) {
                    isOperatorDelete = true;
                    errs() << "1 Found pure diy delete: " << demangledName << "\n";
                    Inst->print(errs());
                }

                bool isOperatorNew = false;
                if ( containsOperatorNewInMiddle(demangledName,true)) {
                    isOperatorNew = true;
                    errs() << "1 Found pure diy new: " << demangledName << "\n";
                    Inst->print(errs());
                }

                if (isOperatorDelete || FuncName.startswith("_ZdlPv") || FuncName.startswith("_ZdaPv") || FuncName == "free" || FuncName.startswith("_gfortran_internal_free")) {

                    IRBuilder<> builder(Inst);

                    // operator delete
                    if (isOperatorDelete)
                        memOp = 14;
                    // _ZdlPv -> operator delete(void*)
                    // _ZdaPv -> operator delete[](void*)
                    else if (FuncName == "free")
                        memOp = 4;
                    else if (FuncName.startswith("_gfortran_internal_free"))
                        memOp = 9;
                    else if (FuncName.startswith("_ZdlPv"))
                        memOp = 7;
                    else if (FuncName.startswith("_ZdaPv"))
                        memOp = 12;

                    Value *SizeArg = Call->getArgOperand(0);

                    Type *ptrType = SizeArg->getType()->getPointerElementType();

                    // Get the size of the object type
                    uint64_t size = DL.getTypeAllocSize(ptrType);

                    builder.CreateCall(LogNew, {builder.getInt64(size), builder.getInt64(0), builder.getInt64(memOp), SizeArg});

                    instDone.insert(Inst);
                } else if (isOperatorNew || FuncName.startswith("_Znwm") || FuncName.startswith("_Znam") || FuncName.startswith("_Znaj")) {

                    IRBuilder<> builder(Context);

                    if (Instruction *nextInst = Inst->getNextNode()) {
                        builder.SetInsertPoint(nextInst);
                        errs() << "1 Found function call get next node: " << demangledName << "\n";
                    } else {
                        // This is to solve MemoryManagerArrayImpl.cpp
                        // memptr = new char[size];
                        //   %call = invoke noalias nonnull i8* @_Znam(i64 %size) #9
                        //   to label %if.then unwind label %invoke.cont3, !dbg !705, !heapallocsite !420
                        // If callInst is the last instruction, insert before the terminator
                        builder.SetInsertPoint(&(*i));
                        errs() << "1 Found function call insert to end: " << demangledName << "\n";
                    }

                    if (DILocation *Loc = Inst->getDebugLoc()) {
                      unsigned Line = Loc->getLine();
                      unsigned Col = Loc->getColumn();
                      StringRef File = Loc->getFilename();
                      StringRef Dir = Loc->getDirectory();
                      errs() << "Found new memory allocation (call): " << demangledName << " at "
                             << Dir << "/" << File << ":" << Line << ":" << Col << "\n";
                    }

                    // Get the return value (pointer to allocated memory)
                    Value *returnValue = Inst;

                    uint64_t ElementSize = 0;

                    if (isOperatorNew) {
                        memOp = 13;

                        ElementSize = 4;

                        if (Call->getNumArgOperands() == 0) {

                            builder.CreateCall(LogNew, {builder.getInt64(1), builder.getInt64(ElementSize), builder.getInt64(memOp), returnValue});

                        } else {

                            Value *SizeArg = Call->getArgOperand(0);
                            builder.CreateCall(LogNew, {SizeArg, builder.getInt64(ElementSize), builder.getInt64(memOp), returnValue});

                        }

                    } else if ( FuncName.startswith("_Znam")){
                        Value *SizeArg = Call->getArgOperand(0);
                        //operator new char [](unsigned long)
                        memOp = 6;
                        ElementSize = 1;
                        builder.CreateCall(LogNew, {SizeArg, builder.getInt64(ElementSize), builder.getInt64(memOp), returnValue});
                    } else if (FuncName.startswith("_Znwm")) {
                        // This is for Base64.cpp in xalanbmk
                        // Avoid bug:
                        // Instruction does not dominate all uses!
                        // %call15 = invoke noalias nonnull dereferenceable(16) i8* @_Znwm(i64 16) #15
                        // to label %invoke.cont14 unwind label %lpad13, !dbg !1265, !heapallocsite !265
                        // call void @logNewAllocation(i64 0, i64 4, i64 5, i8* nonnull %call15), !dbg !1265
                        // in function _ZNK11xercesc_2_711DOMNodeImpl13getChildNodesEv
                        // fatal error: error in backend: Broken function found, compilation aborted!
                        //operator new int
                        memOp = 5;
                        ElementSize = 4;

                        if (Call->getNumArgOperands() == 0) {

                            builder.CreateCall(LogNew, {builder.getInt64(1), builder.getInt64(ElementSize), builder.getInt64(memOp), returnValue});

                        } else {

                            Value *SizeArg = Call->getArgOperand(0);
                            builder.CreateCall(LogNew, {SizeArg, builder.getInt64(ElementSize), builder.getInt64(memOp), returnValue});

                        }

                    } else if (FuncName.startswith("_Znaj")) {
                        Value *SizeArg = Call->getArgOperand(0);
                        //operator new int [](unsigned long)
                        memOp = 11;
                        ElementSize = 4;
                        builder.CreateCall(LogNew, {SizeArg, builder.getInt64(ElementSize), builder.getInt64(memOp), returnValue});
                    }

                    instDone.insert(Inst);
                }

            } else if (InvokeInst *invokeInst = dyn_cast<InvokeInst>(Inst)) {

                Function *CalledFunc = invokeInst->getCalledFunction();

                // Get the return value (pointer to allocated memory)
                Value *returnValue = invokeInst;

                if (!CalledFunc)
                    continue;

                StringRef FuncName = CalledFunc->getName();

                errs() << "2----" << "\n";
                std::string demangledName = demangle(FuncName.str().c_str());
                errs() << "2 Found invoke function call: " << demangledName << "\n";

                if (DILocation *Loc = Inst->getDebugLoc()) {
                  unsigned Line = Loc->getLine();
                  unsigned Col = Loc->getColumn();
                  StringRef File = Loc->getFilename();
                  StringRef Dir = Loc->getDirectory();
                  errs() << "2 Found invoke function call: " << demangledName << " at "
                         << Dir << "/" << File << ":" << Line << ":" << Col << "\n";
                }

                bool isOperatorNew = false;
                if ( containsOperatorNewInMiddle(demangledName,true)) {
                    isOperatorNew = true;
                    errs() << "1 Found pure diy new: " << demangledName << "\n";
                    Inst->print(errs());
                }

                if (instDone.count(Inst) != 0 )
                    continue;

                if (isOperatorNew || FuncName.startswith("_Znwm") || FuncName.startswith("_Znam") || FuncName.startswith("_Znaj")) {

                    if (instDone.count(Inst) != 0)
                        continue;

                    instDone.insert(Inst);

                    // 1) new(unsigned long)
                    // 2) new[](unsigned long)
                    // 3) new[](unsinged int)

                    //IRBuilder<> builder(invokeInst->getNextNode());

                    uint64_t ElementSize = 0;


                    IRBuilder<> builder(Context);

                    if (Instruction *nextInst = invokeInst->getNextNode()) {
                        builder.SetInsertPoint(nextInst);
                        errs() << "2 Found function call get next node: " << demangledName << "\n";
                    } else {
                        BasicBlock *currentBB = invokeInst->getParent();

                        // If callInst is the last instruction, insert before the terminator
                        //builder.SetInsertPoint(&(*i));
                        errs() << "2 Found function call insert to end: " << demangledName << "\n";



                        for (auto *succ : successors(currentBB)) {
                            BasicBlock *newBB = SplitEdge(currentBB, succ);

                            // Insert the instrumentation call at the start of the new block
                            IRBuilder<> builder(&newBB->front());

                            errs() << "create a new block " << demangledName << "\n";

                            if ( FuncName.startswith("_Znam")){
                                Value *SizeArg = invokeInst->getArgOperand(0);
                                //operator new char [](unsigned long)
                                memOp = 6;
                                ElementSize = 1;
                                builder.CreateCall(LogNew, {SizeArg, builder.getInt64(ElementSize), builder.getInt64(memOp), returnValue});
                            } else if (FuncName.startswith("_Znwm")) {
                                //operator new int
                                memOp = 5;
                                ElementSize = 4;

                                if (invokeInst->getNumArgOperands() == 0) {

                                    builder.CreateCall(LogNew, {builder.getInt64(1), builder.getInt64(ElementSize), builder.getInt64(memOp), returnValue});

                                } else {

                                    Value *SizeArg = invokeInst->getArgOperand(0);
                                    builder.CreateCall(LogNew, {SizeArg, builder.getInt64(ElementSize), builder.getInt64(memOp), returnValue});

                                }
                            }  else if (FuncName.startswith("_Znaj")) {
                                Value *SizeArg = invokeInst->getArgOperand(0);
                                //operator new int [](unsigned long)
                                memOp = 11;
                                ElementSize = 4;
                                builder.CreateCall(LogNew, {SizeArg, builder.getInt64(ElementSize), builder.getInt64(memOp), returnValue});
                            }

                            break;
                        }

                        continue;
                    }

                    if (isOperatorNew) {
                        memOp = 13;

                        ElementSize = 4;

                        if (Call->getNumArgOperands() == 0) {

                            builder.CreateCall(LogNew, {builder.getInt64(1), builder.getInt64(ElementSize), builder.getInt64(memOp), returnValue});

                        } else {

                            Value *SizeArg = Call->getArgOperand(0);
                            builder.CreateCall(LogNew, {SizeArg, builder.getInt64(ElementSize), builder.getInt64(memOp), returnValue});

                        }
                    } else if ( FuncName.startswith("_Znam")){
                        Value *SizeArg = invokeInst->getArgOperand(0);
                        //operator new char [](unsigned long)
                        memOp = 6;
                        ElementSize = 1;
                        builder.CreateCall(LogNew, {SizeArg, builder.getInt64(ElementSize), builder.getInt64(memOp), returnValue});
                    } else if (FuncName.startswith("_Znwm")) {
                        //operator new int
                        memOp = 5;
                        ElementSize = 4;

                        if (invokeInst->getNumArgOperands() == 0) {

                            builder.CreateCall(LogNew, {builder.getInt64(1), builder.getInt64(ElementSize), builder.getInt64(memOp), returnValue});

                        } else {

                            Value *SizeArg = invokeInst->getArgOperand(0);
                            builder.CreateCall(LogNew, {SizeArg, builder.getInt64(ElementSize), builder.getInt64(memOp), returnValue});

                        }


                    } else if (FuncName.startswith("_Znaj")) {
                        Value *SizeArg = invokeInst->getArgOperand(0);
                        //operator new int [](unsigned long)
                        memOp = 11;
                        ElementSize = 4;
                        builder.CreateCall(LogNew, {SizeArg, builder.getInt64(ElementSize), builder.getInt64(memOp), returnValue});
                    }


                    //if (SizeArg == nullptr)
                    //    builder.CreateCall(LogNew, {builder.getInt64(0), builder.getInt64(ElementSize), builder.getInt64(memOp), returnValue});
                    //else
                    //    builder.CreateCall(LogNew, {SizeArg, builder.getInt64(ElementSize), builder.getInt64(memOp), returnValue});
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


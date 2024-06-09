//===- ObjFirstInsert.cpp - Example code from "Writing an LLVM Pass" ---------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements two versions of the LLVM "ObjFirstInsert World" pass described
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
#include "llvm/Support/raw_ostream.h"

using namespace llvm;

#define DEBUG_TYPE "objFirstInsert"

STATISTIC(ObjFirstInsertCounter, "Counts number of functions greeted");

namespace {
  // ObjFirstInsert - The first implementation, without getAnalysisUsage.
  struct ObjFirstInsert : public FunctionPass {
    static char ID; // Pass identification, replacement for typeid
    ObjFirstInsert() : FunctionPass(ID) {}

    bool isClassOrStructType(Type *Ty) {
        //Type *Ty = V->getType();

        // errs() << "Ptr: " << *Ty << " " << Ty->isPointerTy() << "\n";

        // Check if the type is a pointer
        if (!Ty->isPointerTy()) {
            return false;
        }

        // Get the element type if it's a pointer
        Ty = Ty->getPointerElementType();


        // errs() << " Struct: " << *Ty << " " << Ty->isStructTy()  << " " << Ty->isPointerTy() << "\n";

        if (!Ty->isPointerTy()) {
            return false;
        }

        Type *ElementType = Ty->getPointerElementType();

        // Check if the element type is a struct or class
        return ElementType->isStructTy();
    }

    uint32_t getStructSize(AllocaInst* I) {
        /*
        Type *type = I->getType();

        type = type->getPointerElementType();

        Type *ElementType = type->getPointerElementType();
        */

        const DataLayout &DL = I->getModule()->getDataLayout();

        uint32_t size = DL.getTypeAllocSize(I->getAllocatedType());

        errs() << "pointer size: " << size << "\n";


        Type *type = I->getType();

        if (type->isPointerTy()) {
            type = type->getPointerElementType();
            if (type->isPointerTy()) {
                type = type->getPointerElementType();
                if (type->isStructTy()) {
                    uint32_t struct_size = DL.getTypeAllocSize(type);
                    errs() << "struct size: " << struct_size << "\n";
                }
            }
        }

        return size;
    }

    bool runOnFunction(Function &F) override {
      ++ObjFirstInsertCounter;
      errs() << "ObjFirstInsert: ";
      errs().write_escaped(F.getName()) << '\n';

      unsigned objectAllocCount = 0; // Counter for object allocations

      unsigned instCount = 0;   // Counter for instructions

        for (Function::iterator bb= F.begin(), bbe= F.end(); bb != bbe; ++bb) {
            for (BasicBlock::iterator i = bb->begin(), ie=bb->end(); i != ie; ++i) {
                instCount++;
                Instruction *Inst = &*i;

                // errs() << "Instruction: " << *Inst << "\n";

                /*
                // Iterate over the operands of the instruction
                for (Use &U : Inst->operands()) {
                    Value *Op = U.get();
                    // Dump the operand
                    errs() << "Operand: " << *Op << "\n";
                }
                */

                IRBuilder<> builder(Inst);

                if (AllocaInst *AI = dyn_cast<AllocaInst>(Inst)) {
                    /*
                    Value *Operand = AI->getOperand(0);
                    errs() << "Operand: " << *Operand<< "\n";
                    if (isClassOrStructType(Operand)) {
                       objectAllocCount++;
                    }
                    */

                    Type *type = AI->getType();
                    uint32_t size = getStructSize(AI);
                    errs() << "Type: " << *type<< " Size: " << size << "\n";
                    if (isClassOrStructType(type)) {

                        objectAllocCount++;

                        /*
                        builder.CreateInlineAsm(
                            Type::getVoidTy(F.getContext()), // result type
                            "asm volatile(\"allocMem %0, %1\" : : \"i\"(immediate1), \"i\"(immediate2))", // Assembly template
                            true,   // Has side effects,
                            false,  // Is Align Stack
                        );
                        */

                        /*
                        StringRef asmTemplate = "allocMem %[immediate1], %[immediate2]";

                        // Create the InlineAsm instruction
                        InlineAsm *asmInst = InlineAsm::get(
                            FunctionType::get(Type::getVoidTy(F.getContext()), false), // Function type
                            asmTemplate,                                               //
                            "i, i",                                                    // Constraints for the immediate operands
                            true,                                                      // Has side effects
                            false                                                      // Is align stack
                        );

                        builder.Insert(asmInst);

                        Instruction *insertionPoint = Inst;

                        bb->insert(insertionPoint, asmInst);
                        */


                        //Type *VoidTy = Type::getVoidTy(F.getContext());
                        //Value *Nop = builder.CreateBitCast(Constant::getNullValue(VoidTy), VoidTy);

                        /*
                        Instruction *NopInst = builder.CreateIntrinsic(
                            Intrinsic::dbg_value, // Use dbg_value as a no-op instruction
                            {}, // No arguments
                            {}  // No function
                        );
                        */

                        // Instruction *NopInst = dyn_cast<Expression>(Nop);

                        // Add attributes to indicate side effects
                        // NopInst->addAttribute(Attribute::NoUnwind);
                        // NopInst->addAttribute(Attribute::NoReturn);

                        // Attach metadata to the nop instruction
                        // LLVMContext &Ctx = F.getContext();
                        // MDString *CustomMDString = MDString::get(Ctx, "Custom metadata value");
                        // Metadata *CustomMDArgs[] = { CustomMDString };
                        // MDNode *CustomMDNode = MDNode::get(Ctx, CustomMDArgs);
                        // NopInst->setMetadata("custom_metadata", CustomMDNode);

                        // NopInst->moveAfter(Inst);
                    }
                }
            }
        }

      outs() << "Number of object allocations: " << objectAllocCount<< "\n";
      outs() << "Number of instructions: " << instCount << "\n";

      return true;
    }
  };
}

char ObjFirstInsert::ID = 0;
static RegisterPass<ObjFirstInsert> X("objFirstInsert", "ObjFirstInsert World Pass");

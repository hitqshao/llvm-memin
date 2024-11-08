#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/Pass.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Support/raw_ostream.h"
#include <set>

using namespace llvm;

namespace {
    struct ObjectPass : public FunctionPass {
        static char ID;

        ObjectPass() : FunctionPass(ID) {}

        bool runOnFunction(Function &F) override {
         //   std::set<const Type*> classes; // Set to store unique class types
         unsigned objectCount = 0; // Counter for object allocations
         unsigned instCount = 0; // Counter for object allocations

         //   // Traverse global variables to identify class definitions
         //   for (GlobalVariable &GV : M.globals()) {
         //       if (GV.getType()->isStructTy()) {
         //           // This is a global variable representing a class structure
         //           classes.insert(GV.getType());
         //       }
         //   }

         // Traverse instructions to identify object allocations
         /*
         for (Function &F : M) {
             for (BasicBlock &BB : F) {
                 for (Instruction &I : BB) {
                     if (AllocaInst *AI = dyn_cast<AllocaInst>(&I)) {
                         // This instruction represents object allocation
                         objectCount++;
                     }
                     instCount++;
                 }
             }
         }
        */


        for (Function::iterator bb= F.begin(), bbe= F.end(); bb != bbe; ++bb) {
            for (BasicBlock::iterator i = bb->begin(), ie=bb->end(); i != ie; ++i) {
                /*
                instCount++;
                Instruction *I = &*i;
                if (AllocaInst *AI = dyn_cast<AllocaInst>(I)) {
                     objectCount++;
                }
                */
            }
        }

        //for (Module::iterator F = M.begin() , FEnd = M.end(); F != FEnd; F++) {

        //    //outs() << "module: " << F->getName() << "\n";


        //    for (Function::iterator FI= F->begin(), FIEnd = F->end(); FI!= FIEnd; FI++) {
        //            //outs() << "function: " << FI->getName() << "\n";

        //            for (BasicBlock::iterator BBI = FI->begin(), BBIEnd = FI->end(); BBI != BBIEnd; BBI++) {
        //                //outs() << "block: " << BBI->getName() << "\n";

        //                /*
        //                Instruction *I = &(*BBI);
        //                if (AllocaInst *AI = dyn_cast<AllocaInst>(I)) {
        //                     objectCount++;
        //                }
        //                instCount++;
        //                */
        //            }
        //    }
        //}
         //   // Print the results
         //   outs() << "Number of unique classes: " << classes.size() << "\n";
         //   outs() << "Number of object allocations: " << objectCount << "\n";
         //outs() << "Number of instructions: " << instCount << "\n";
         //outs() << "hello......" << "\n";
         return false; // Pass does not modify the module
        }
    };
} // namespace

char ObjectPass::ID = 0;
static RegisterPass<ObjectPass> X("insert-custom-instruction", "Insert custom instruction before object references");

//extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
//llvmGetPassPluginInfo() {
//    return {
//        .APIVersion = LLVM_PLUGIN_API_VERSION,
//        .PluginName = "Object pass",
//        .PluginVersion = "v0.1",
//        .RegisterPassBuilderCallbacks = [](PassBuilder &PB) {
//            PB.registerPipelineStartEPCallback(
//                [](ModulePassManager &MPM, OptimizationLevel Level) {
//                    MPM.addPass(ObjectPass());
//                });
//        }
//    };
//}

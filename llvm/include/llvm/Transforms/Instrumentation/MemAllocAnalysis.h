//===--------- Definition of the MemAlloc class --------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file declares the MemAlloc class.
//
//===----------------------------------------------------------------------===//
#ifndef LLVM_TRANSFORMS_INSTRUMENTATION_MEMALLOC_H
#define LLVM_TRANSFORMS_INSTRUMENTATION_MEMALLOC_H

#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/InitializePasses.h"

using namespace llvm;

namespace llvm {

/// Public interface to the memory profiler pass for instrumenting code to
/// profile memory accesses.
///
/// The profiler itself is a function pass that works by inserting various
/// calls to the MemAlloc runtime library functions. The runtime library
/// essentially replaces malloc() and free() with custom implementations that
/// record data about the allocations.
class MemAllocAnalysis: public FunctionPass {
public:
  static char ID; // Pass identification, replacement for typeid

  MemAllocAnalysis() : FunctionPass(ID) {
    initializeMemAllocAnalysisPass(*PassRegistry::getPassRegistry());
  }

  StringRef getPassName() const override { return "MemAllocAnalysis"; }

  static bool isRequired() { return true; }

  bool runOnFunction(Function &F) override;

  bool containsOperatorNewInMiddle(const std::string& str, bool isNew);
};

// Insert MemAlloc instrumentation
FunctionPass *createMemAllocAnalysis();


class MemAllocAnalysisNoLegacy: public PassInfoMixin<MemAllocAnalysisNoLegacy> {
public:
    explicit MemAllocAnalysisNoLegacy() {};
    PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);
    static bool isRequired() { return true; }
};

} // namespace llvm

#endif

add_llvm_library( LLVMObjectPass MODULE BUILDTREE_ONLY
  ObjectPass.cpp

  ADDITIONAL_HEADER_DIRS
  ${LLVM_MAIN_INCLUDE_DIR}/llvm/Transforms
  ${LLVM_MAIN_INCLUDE_DIR}/llvm/Transforms/ObjectPass

  DEPENDS
  intrinsics_gen
  omp_gen

  COMPONENT_NAME
  IPO

  LINK_COMPONENTS
  AggressiveInstCombine
  Analysis
  BitReader
  BitWriter
  Core
  FrontendOpenMP
  InstCombine
  IRReader
  Linker
  Object
  ProfileData
  Scalar
  Support
  TargetParser
  TransformUtils
  Vectorize
  Instrumentation

  opt
  )

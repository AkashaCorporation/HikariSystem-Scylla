{
  "targets": [
    {
      "target_name": "hexcore_rellic",
      "cflags!": [
        "-fno-exceptions"
      ],
      "cflags_cc!": [
        "-fno-exceptions"
      ],
      "sources": [
        "src/main.cpp",
        "src/rellic_wrapper.cpp"
      ],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")",
        "deps/llvm/include",
        "deps/clang/include",
        "deps/z3/include",
        "deps/rellic/include"
      ],
      "defines": [
        "NAPI_VERSION=8",
        "NAPI_DISABLE_CPP_EXCEPTIONS"
      ],
      "conditions": [
        [
          "OS=='win'",
          {
            "libraries": [
              "<(module_root_dir)/deps/rellic/lib/rellic.lib",
              "<(module_root_dir)/deps/clang/lib/clangAST.lib",
              "<(module_root_dir)/deps/clang/lib/clangBasic.lib",
              "<(module_root_dir)/deps/clang/lib/clangLex.lib",
              "<(module_root_dir)/deps/clang/lib/clangSema.lib",
              "<(module_root_dir)/deps/clang/lib/clangFrontend.lib",
              "<(module_root_dir)/deps/clang/lib/clangSerialization.lib",
              "<(module_root_dir)/deps/clang/lib/clangDriver.lib",
              "<(module_root_dir)/deps/clang/lib/clangParse.lib",
              "<(module_root_dir)/deps/clang/lib/clangEdit.lib",
              "<(module_root_dir)/deps/clang/lib/clangAnalysis.lib",
              "<(module_root_dir)/deps/z3/lib/libz3.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMCore.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMSupport.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMIRReader.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMAsmParser.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMBitReader.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMBitWriter.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMBitstreamReader.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMAnalysis.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMTransformUtils.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMScalarOpts.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMInstCombine.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMAggressiveInstCombine.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMPasses.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMipo.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMVectorize.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMLinker.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMIRPrinter.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMCodeGen.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMCodeGenTypes.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMTarget.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMTargetParser.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMObject.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMBinaryFormat.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMMC.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMMCParser.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMProfileData.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMRemarks.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMDemangle.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMTextAPI.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMFrontendOpenMP.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMCoroutines.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMObjCARCOpts.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMGlobalISel.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMSelectionDAG.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMExtensions.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMCFGuard.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMX86CodeGen.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMX86Desc.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMX86Info.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMX86AsmParser.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMX86Disassembler.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMAArch64CodeGen.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMAArch64Desc.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMAArch64Info.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMAArch64AsmParser.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMAArch64Disassembler.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMAArch64Utils.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMAsmPrinter.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMDebugInfoDWARF.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMDebugInfoCodeView.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMDebugInfoMSF.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMDebugInfoPDB.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMSymbolize.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMWindowsDriver.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMWindowsManifest.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMMCDisassembler.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMOption.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMFrontendDriver.lib",
              "<(module_root_dir)/deps/llvm/lib/LLVMFrontendHLSL.lib"
            ],
            "msvs_settings": {
              "VCCLCompilerTool": {
                "ExceptionHandling": 1,
                "RuntimeLibrary": 0,
                "AdditionalOptions": [
                  "/EHsc",
                  "/std:c++17",
                  "/bigobj"
                ]
              },
              "VCLinkerTool": {
                "AdditionalDependencies": [
                  "Advapi32.lib",
                  "Shell32.lib",
                  "Ole32.lib",
                  "Uuid.lib",
                  "ws2_32.lib",
                  "psapi.lib",
                  "dbghelp.lib",
                  "version.lib",
                  "ntdll.lib",
                  "synchronization.lib",
                  "bcrypt.lib",
                  "Shlwapi.lib"
                ]
              }
            },
            "defines": [
              "_CRT_SECURE_NO_WARNINGS",
              "_SCL_SECURE_NO_WARNINGS",
              "_SILENCE_CXX17_ITERATOR_BASE_CLASS_DEPRECATION_WARNING",
              "NOMINMAX"
            ]
          }
        ],
        [
          "OS=='linux'",
          {
            "libraries": [
              "-lpthread",
              "-ldl",
              "-lz"
            ],
            "cflags": [
              "-fPIC"
            ],
            "cflags_cc": [
              "-fPIC",
              "-std=c++17",
              "-fexceptions"
            ]
          }
        ],
        [
          "OS=='mac'",
          {
            "xcode_settings": {
              "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
              "CLANG_CXX_LIBRARY": "libc++",
              "MACOSX_DEPLOYMENT_TARGET": "10.15",
              "OTHER_CPLUSPLUSFLAGS": [
                "-std=c++17"
              ]
            }
          }
        ]
      ]
    }
  ]
}

///
/// Copyright (C) 2016, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
///
/// Permission is hereby granted, free of charge, to any person obtaining a copy
/// of this software and associated documentation files (the "Software"), to deal
/// in the Software without restriction, including without limitation the rights
/// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
/// copies of the Software, and to permit persons to whom the Software is
/// furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in all
/// copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
/// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
/// SOFTWARE.
///

#include <lib/Utils/Utils.h>
#include <llvm/ADT/DenseSet.h>
#include <llvm/Bitcode/BitcodeReader.h>
#include <llvm/Bitcode/BitcodeWriter.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Transforms/IPO.h>
#include <llvm/Transforms/IPO/AlwaysInliner.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include <llvm/Transforms/Scalar.h>
#include <llvm/Transforms/Utils.h>

#include <fstream>
#include <lib/Utils/BinaryCFGReader.h>

// #include <lib/Utils/cfg.pb.h>

#include <nlohmann/json.hpp>

#include "InstructionLabeling.h"
#include "MemoryWrapperElimination.h"
#include "RegisterPromotion.h"
#include "RevGen.h"

using namespace llvm;
using namespace s2etools;

LogKey RevGen::TAG = LogKey("RevGen");

namespace {
cl::opt<std::string> BitcodeLibary("bitcodelib", cl::desc("Path to the bitcode library"), cl::Required);

cl::opt<std::string> BinaryFile("binary", cl::desc("The binary file to translate"), cl::Required);

cl::opt<std::string> OutputFile("output", cl::desc("Output bitcode file"), cl::Required);

cl::opt<std::string> ExternalCfg("external-cfg", cl::desc("CFG in JSON"), cl::Required);
} // namespace

RevGen::~RevGen() {
    if (m_translator) {
        delete m_translator;
    }
}

bool RevGen::initialize(void) {
    m_fp = vmi::FileSystemFileProvider::get(m_binaryFile, false);
    if (!m_fp) {
        llvm::errs() << "Can't open " << m_binaryFile << "\n";
        return false;
    }

    m_binary = vmi::ExecutableFile::get(m_fp, false, 0);
    if (!m_binary) {
        llvm::errs() << "Can't parse " << m_binaryFile << "\n";
        return false;
    }

    LOGINFO("ImageBase: " << hexval(m_binary->getImageBase()) << "\n");

    m_translator = new X86Translator(m_bitcodeLibrary, m_binary);

    return true;
}

TranslatedBlock *RevGen::translate(uint64_t start, uint64_t end) {
    LOGDEBUG("========================================\n");
    LOGDEBUG("Translating: " << hexval(start) << " to " << hexval(end) << "\n");

    TranslatedBlock *tb = m_translator->translate(start, end);
    if (!tb) {
        LOGERROR("Could not translate block\n");
        return NULL;
    }

    if (tb->getType() == BB_EXCP) {
        LOGERROR("BB contains invalid instruction\n");
    }

    LOGDEBUG(*tb->getFunction() << "\n");
    return tb;
}

void RevGen::exploreCfg(const std::string &cfgJson) {
    m_translator->exploreCfg(m_tbs, cfgJson);
}

void RevGen::translate(const llvm::BinaryFunctions &functions, const llvm::BinaryBasicBlocks &bbs) {
    m_functions = functions;
    m_bbs = bbs;

    std::unordered_map<uint64_t, BinaryFunction *> fcnMap;
    for (auto fcn : functions) {
        fcnMap[fcn->getEntryBlock()->getStartPc()] = fcn;
    }

    for (auto const &bb : m_bbs) {
        TranslatedBlock *tb = translate(bb->getStartPc(), bb->getEndPc());
        if (tb) {
            m_tbs[tb->getAddress()] = tb;
        }
    }

    // Create dummy functions if there are calls to functions that are
    // not in the input CFG.
    for (const auto &p : m_tbs) {
        auto tb = p.second;

        if (tb->getType() != BB_CALL) {
            continue;
        }

        uint64_t target = tb->getSuccessor(0);
        if (fcnMap.find(target) != fcnMap.end()) {
            continue;
        }

        const auto tit = m_tbs.find(target);
        if (tit == m_tbs.end()) {
            LOGWARNING("Could not find entry point " << hexval(target) << " for unknown function");
            continue;
        }

        auto ttb = tit->second;

        std::stringstream ss;
        ss << "__unk_fcn_" << hexval(target);
        BinaryFunction *newFcn = new BinaryFunction(ss.str());

        auto start = ttb->getAddress();
        auto end = ttb->getLastAddress();
        auto size = ttb->getSize();
        BinaryBasicBlock *newBb = new BinaryBasicBlock(start, end, size);
        newFcn->add(newBb);
        newFcn->setEntryBlock(newBb);
        m_functions.insert(newFcn);
        fcnMap[target] = newFcn;
    }
}

void RevGen::writeBitcodeFile(const std::string &bitcodeFile) {
    std::error_code EC;
    llvm::raw_fd_ostream o(bitcodeFile, EC, llvm::sys::fs::OF_None);

    llvm::Module *module = m_translator->getModule();

    // Output the bitcode file to stdout
    llvm::WriteBitcodeToFile(*module, o);
}

// This function can be called from GDB for debugging
void PrintValue(llvm::Value *v) {
    llvm::outs() << *v << "\n";
}

int main(int argc, char **argv) {
    cl::ParseCommandLineOptions(argc, (char **) argv, " analysis");
    // GOOGLE_PROTOBUF_VERIFY_VERSION;

    if (!llvm::sys::fs::exists(BinaryFile)) {
        llvm::errs() << BinaryFile << " does not exist\n";
        return -1;
    }

    if (!llvm::sys::fs::exists(BitcodeLibary)) {
        llvm::errs() << BitcodeLibary << " does not exist\n";
        return -1;
    }

    RevGen translator(BinaryFile, BitcodeLibary);

    if (!translator.initialize()) {
        llvm::errs() << "Could not initialize translator\n";
        return -1;
    }

    BinaryBasicBlocks toTranslate;
    BinaryFunctions functions;

    if (llvm::sys::fs::exists(ExternalCfg)) {
        ParseExternalCfgFile(ExternalCfg, toTranslate, functions);
    } else {
        llvm::errs() << ExternalCfg << " does not exist\n";
        return -1;
    }

    if (!functions.size()) {
        llvm::errs() << "No functions to translate. Check the CFG file\n";
        return -1;
    }

    if (!toTranslate.size()) {
        llvm::errs() << "No basic blocks to translate. Check the CFG file\n";
        return -1;
    }

    translator.translate(functions, toTranslate);
    translator.exploreCfg(ExternalCfg);
    translator.writeBitcodeFile(OutputFile);

    return 0;
}

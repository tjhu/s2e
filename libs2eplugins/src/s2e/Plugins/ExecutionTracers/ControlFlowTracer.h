///
/// Copyright (C) 2022, sylvie
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

#ifndef S2E_PLUGINS_CONTROLFLOWTRACER_H
#define S2E_PLUGINS_CONTROLFLOWTRACER_H

#include <s2e/Plugin.h>
#include <stdio.h>
#include <string.h>
#include <utility>
#include <nlohmann/json.hpp>

#include <s2e/Plugins/Core/BaseInstructions.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>
#include <s2e/Plugins/OSMonitors/ModuleDescriptor.h>
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/DenseMap.h"

namespace s2e {
namespace plugins {

// do not delete
enum S2E_CONTROLFLOWTRACER_COMMANDS {
    // TODO: customize list of commands here
    COMMAND_1
};

struct S2E_CONTROLFLOWTRACER_COMMAND {
    S2E_CONTROLFLOWTRACER_COMMANDS Command;
    union {
        // Command parameters go here
        uint64_t param;
    };
};

struct TB {
    uint64_t start;
    uint32_t size;
    uint64_t end;
    llvm::DenseMap<uint64_t, uint32_t> succs;
    llvm::DenseMap<uint64_t, uint32_t> call_succs;
    llvm::DenseMap<uint64_t, uint32_t> other_succs;
    uint32_t block_type;
    uint32_t is_ret;
};

class ControlFlowTracer : public Plugin, IPluginInvoker {

    S2E_PLUGIN

public:
    ControlFlowTracer(S2E *s2e) : Plugin(s2e) {}
    void initialize();

private:
    std::string m_fileName;
    FILE* m_traceFile;
    ModuleExecutionDetector* m_detector;
    OSMonitor* m_monitor;
    uint64_t m_prevTB;     // {TB, TB_Type}

    llvm::DenseMap<uint64_t, TB*> TBs;
    std::unordered_map<std::string, std::vector<std::pair<uint64_t, uint64_t>>> m_modules;

    void onModuleTranslateBlockStart(ExecutionSignal* signal, S2EExecutionState* state, const ModuleDescriptor& module, TranslationBlock* tb, uint64_t pc);
    void onModuleBlockExecutionStart(S2EExecutionState* state, uint64_t pc);
    void onModuleTranslateBlockComplete(S2EExecutionState* state, const ModuleDescriptor& module, TranslationBlock* tb, uint64_t lastPc);
    //void onModuleTranslateBlockEnd(ExecutionSignal* signal, S2EExecutionState* state, const ModuleDescriptor& module, TranslationBlock* tb,
    //                               uint64_t endPc, bool isValid, uint64_t targetPc);
    void onExternalTbTransition(ExecutionSignal* signal, S2EExecutionState* state, TranslationBlock* tb,
                                uint64_t endPc, bool isValid, uint64_t targetPc, bool exit);
    void onModuleTransition(S2EExecutionState* state, ModuleDescriptorConstPtr prev, ModuleDescriptorConstPtr next);
    void onModuleLoad(S2EExecutionState* state, const ModuleDescriptor& module);
    void onEngineShutdown();

    // writer methods
    void generateTraceInfoJsonFile();       // generates traceInfo.json
    void writeTraceInfoJson();
    void writeTBs(nlohmann::json& tbJson);
    void writeModules(nlohmann::json& moduleJson);
    nlohmann::json writeSuccessors(llvm::DenseMap<uint64_t, uint32_t> map);

    // Allow the guest to communicate with this plugin using s2e_invoke_plugin. do not delete.
    virtual void handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_CONTROLFLOWTRACER_H
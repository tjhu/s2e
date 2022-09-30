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

#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleMap.h>
#include <cpu/tb.h>

#include <stdlib.h>
#include <iostream>
#include <numeric>
#include <functional>
#include <nlohmann/json.hpp>

#include "ControlFlowTracer.h"

using json = nlohmann::json;

namespace s2e {
namespace plugins {

/*namespace {

//
// This class can optionally be used to store per-state plugin data.
//
// Use it as follows:
// void ControlFlowTracer::onEvent(S2EExecutionState *state, ...) {
//     DECLARE_PLUGINSTATE(ControlFlowTracerState, state);
//     plgState->...
// }
//
class ControlFlowTracerState: public PluginState {
    // Declare any methods and fields you need here

public:
    static PluginState *factory(Plugin *p, S2EExecutionState *s) {
        return new ControlFlowTracerState();
    }

    virtual ~ControlFlowTracerState() {
        // Destroy any object if needed
    }

    virtual ControlFlowTracerState *clone() const {
        return new ControlFlowTracerState(*this);
    }
};

}*/


S2E_DEFINE_PLUGIN(ControlFlowTracer, "Tracer for control flow of translation blocks", "", );

void ControlFlowTracer::initialize() {
    // initialize member variables
    m_fileName = "traceInfo.json";
    m_detector = s2e()->getPlugin<ModuleExecutionDetector>();
    m_monitor = static_cast<OSMonitor*>(s2e()->getPlugin("OSMonitor"));
    m_prevTB = 0;

    // initialize traceInfo.json
    generateTraceInfoJsonFile();

    // register to execute whenever a tb of target module is executed
    m_detector->onModuleTranslateBlockStart.connect(sigc::mem_fun(*this, &ControlFlowTracer::onModuleTranslateBlockStart));

    // register to record ending address of tb
    m_detector->onModuleTranslateBlockComplete.connect(sigc::mem_fun(*this, &ControlFlowTracer::onModuleTranslateBlockComplete));

    //
    m_detector->onExternalTbTransition.connect(sigc::mem_fun(*this, &ControlFlowTracer::onExternalTbTransition));

    // register on module transitions involving the target module
    m_detector->onModuleTransition.connect(sigc::mem_fun(*this, &ControlFlowTracer::onModuleTransition));

    // register to record module info
    m_monitor->onModuleLoad.connect(sigc::mem_fun(*this, &ControlFlowTracer::onModuleLoad));

    // clean up on s2e shutdown
    s2e()->getCorePlugin()->onEngineShutdown.connect(sigc::mem_fun(*this, &ControlFlowTracer::onEngineShutdown));
}

void ControlFlowTracer::generateTraceInfoJsonFile() {
    m_fileName = s2e()->getOutputFilename(m_fileName);
    m_traceFile = fopen(m_fileName.c_str(), "a");
}

void ControlFlowTracer::onEngineShutdown() {
    writeTraceInfoJson();
    fclose(m_traceFile);
}

void ControlFlowTracer::onModuleTranslateBlockStart(ExecutionSignal* signal, S2EExecutionState* state, const ModuleDescriptor& module,
                                              TranslationBlock* tb, uint64_t pc)
{
    signal->connect(sigc::mem_fun(*this, &ControlFlowTracer::onModuleBlockExecutionStart));
    // construct new TB entry
    TB* newTB = new TB;
    newTB->start = pc;
    TBs.insert(std::pair<uint64_t, TB*>{pc, newTB});
}

void ControlFlowTracer::onModuleBlockExecutionStart(S2EExecutionState* state, uint64_t pc)
{
     if (m_prevTB != 0) {
         uint32_t prev_type = TBs[m_prevTB]->block_type;
         uint32_t curr_type = TBs[pc]->block_type;
         if (prev_type >= 1 && prev_type <= 4) {   // JMP
             // add pc to normal succs as TB_JMP
             (TBs[m_prevTB]->succs).insert(std::pair<uint64_t, uint32_t>{pc, prev_type});
         }
         else if (prev_type == 5 || prev_type == 6) {  // CALL
             // add pc to call succs as TB_CALL
             (TBs[m_prevTB]->call_succs).insert(std::pair<uint64_t, uint32_t>{pc, prev_type});
         }
         else if (curr_type == 0 || curr_type == 8 || curr_type == 9) {    // RET
             // add pc to normal succs
             (TBs[m_prevTB]->succs).insert(std::pair<uint64_t, uint32_t>{pc, curr_type});
         }
         if (curr_type == 7 || curr_type == 10 || curr_type == 11 || curr_type == 12) {   // OTHER
             // add pc to other_succs
             (TBs[m_prevTB]->other_succs).insert(std::pair<uint64_t, uint32_t>{pc, curr_type});
         }
     }
     m_prevTB = pc;
}

void ControlFlowTracer::onModuleTranslateBlockComplete(S2EExecutionState* state, const ModuleDescriptor& module, TranslationBlock* tb, uint64_t lastPc)
{
    // set attribute of current block
    uint64_t pc = (uint64_t)tb->pc;
    TB* current = TBs.lookup(pc);
    current->size = tb->size;
    current->end = lastPc;
    current->block_type = tb->se_tb_type;
    current->is_ret = (current->block_type == 8 || current->block_type == 9) ? current->block_type : 0;
}

//void ControlFlowTracer::onModuleTranslateBlockEnd(ExecutionSignal* signal, S2EExecutionState* state, const ModuleDescriptor& module,
//                                                  TranslationBlock* tb, uint64_t endPc, bool isValid, uint64_t targetPc)
//{
//    fprintf(m_traceFile, "regs()->getPc(): %lx\n", state->regs()->getPc());
//    fprintf(m_traceFile, "endPc: %lx\n", endPc);
//    fprintf(m_traceFile, "curr module: %s\n", m_detector->getModule(state, state->regs()->getPc())->Name.c_str());
//      fprintf(m_traceFile, "targetPc: %lx\n", targetPc);
//
//    auto targetModule = m_detector->getModule(state, targetPc);
//    if (targetModule == nullptr) {
//        fprintf(m_traceFile, "target module: nullptr\n");
//    } else {
//        fprintf(m_traceFile, "target module: %s\n", targetModule->Name.c_str());
//    }
//    fprintf(m_traceFile, "-----------------\n");
//}

void ControlFlowTracer::onExternalTbTransition(ExecutionSignal* signal, S2EExecutionState* state, TranslationBlock* tb,
                                               uint64_t endPc, bool isValid, uint64_t targetPc, bool exit)
{
//    fprintf(m_traceFile, "endPc: %lx\n", endPc);
//    fprintf(m_traceFile, "state pc: %lx\n", state->regs()->getPc());
//    fprintf(m_traceFile, "targetPc: %lx\n", targetPc);
//    fprintf(m_traceFile, "exiting target: %d\n---------------\n", exit);
}

void ControlFlowTracer::onModuleTransition(S2EExecutionState* state, ModuleDescriptorConstPtr prev, ModuleDescriptorConstPtr next)
{
    if (prev != nullptr) {      // exiting target module
        m_prevTB = 0;
        //fprintf(m_traceFile, "onModuleTransition: exiting target %s, %lx\n", prev->Name.c_str(), state->regs()->getPc());
    }
    else if (next != nullptr) {
        //fprintf(m_traceFile, "onModuleTransition: entering target %s, %lx\n", next->Name.c_str(), state->regs()->getPc());
    }
}

void ControlFlowTracer::onModuleLoad(S2EExecutionState* state, const ModuleDescriptor& module)
{
    for (const auto &section : module.Sections) {
//        fprintf(m_traceFile, "Module = %s, start = %lx, end = %lx\n", module.Name.c_str(), section.runtimeLoadBase,
//                section.runtimeLoadBase+section.size);
        m_modules[module.Name.c_str()].push_back(std::pair<uint64_t, uint64_t>{section.runtimeLoadBase, section.size});
    }
    // create map of address ranges that are mapped to module names

}

void ControlFlowTracer::writeTraceInfoJson()
{
    json tbJson;
    json moduleJson;
    writeTBs(tbJson);
    writeModules(moduleJson);

    // write to file
    json finalJson = json{
            {"TBs", tbJson},
            {"modules", moduleJson}
    };
    const auto jsonStr = finalJson.dump(2);
    fprintf(m_traceFile, "%s\n", jsonStr.c_str());
}

void ControlFlowTracer::writeTBs(nlohmann::json& tbJson)
{
    for (auto const& pair : TBs) {
        const TB* tb = pair.second;
        // normal successor json
        json succs = writeSuccessors(tb->succs);
        json call_succs = writeSuccessors(tb->call_succs);
        json other_succs = writeSuccessors(tb->other_succs);

        json add = json{
                {"start", tb->start},
                {"size", tb->size},
                {"end", tb->end},
                {"succs", succs},
                {"call_succs", call_succs},
                {"other_succs", other_succs},
                {"block_type", tb->block_type},
                {"is_ret", tb->is_ret}
        };
        tbJson.push_back(add);
    }
}

json ControlFlowTracer::writeSuccessors(llvm::DenseMap<uint64_t, uint32_t> map)
{
    if (map.empty()) {
        return json::array();
    }
    json res;
    for (auto const& succ : map) {
        res.push_back(json{
            {"addr", succ.first},
            {"type", succ.second}
        });
    }
    return res;
}


void ControlFlowTracer::writeModules(nlohmann::json& moduleJson)
{
    for (auto const& module : m_modules) {
        json sections;
        for (auto const& section : module.second) {
            sections.push_back(json{
                {"lb", section.first},
                {"size", section.second}
            });
        }
        moduleJson.push_back(json{
                {"name", module.first},
                {"sections", sections}
        });
    }
}


 // don't need this but do not delete
void ControlFlowTracer::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize)
{
    S2E_CONTROLFLOWTRACER_COMMAND command;

    if (guestDataSize != sizeof(command)) {
        getWarningsStream(state) << "mismatched S2E_CONTROLFLOWTRACER_COMMAND size\n";
        return;
    }

    if (!state->mem()->read(guestDataPtr, &command, guestDataSize)) {
        getWarningsStream(state) << "could not read transmitted data\n";
        return;
    }

    switch (command.Command) {
        // TODO: add custom commands here
        case COMMAND_1:
            break;
        default:
            getWarningsStream(state) << "Unknown command " << command.Command << "\n";
            break;
    }
}



} // namespace plugins
} // namespace s2e
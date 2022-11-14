#include "ControlFlowTracer.h"
#include <cpu/tb.h>
#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/S2E.h>

using json = nlohmann::json;

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(ControlFlowTracer, "Tracer for control flow of translation blocks", "ModuleExecutionDetector",
                  "OSMonitor");

void ControlFlowTracer::initialize() {
    // initialize member variables
    m_fileName = "traceInfo.json";
    m_detector = s2e()->getPlugin<ModuleExecutionDetector>();
    m_monitor = static_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));
    m_prevTB = 0;

    // initialize traceInfo.json
    generateTraceInfoJsonFile();

    // register to execute whenever a tb of target module is executed
    m_detector->onModuleTranslateBlockStart.connect(
        sigc::mem_fun(*this, &ControlFlowTracer::onModuleTranslateBlockStart));

    // register to record ending address of tb
    m_detector->onModuleTranslateBlockComplete.connect(
        sigc::mem_fun(*this, &ControlFlowTracer::onModuleTranslateBlockComplete));

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

void ControlFlowTracer::onModuleTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state,
                                                    const ModuleDescriptor &module, TranslationBlock *tb, uint64_t pc) {
    signal->connect(sigc::mem_fun(*this, &ControlFlowTracer::onModuleBlockExecutionStart));
    // construct new TB entry
    TB *newTB = new TB;
    newTB->start = pc;
    m_tbs.insert({pc, newTB});
}

void ControlFlowTracer::onModuleBlockExecutionStart(S2EExecutionState *state, uint64_t pc) {
    if (m_prevTB != 0) {
        auto prev_type = static_cast<ETranslationBlockType>(m_tbs[m_prevTB]->block_type);
        auto curr_type = static_cast<ETranslationBlockType>(m_tbs[pc]->block_type);
        switch (prev_type) {
            case TB_JMP:
            case TB_JMP_IND:
            case TB_COND_JMP:
            case TB_COND_JMP_IND:
                m_tbs[m_prevTB]->succs.insert({pc, prev_type});
                break;
            case TB_CALL:
            case TB_CALL_IND:
                m_tbs[m_prevTB]->call_succs.insert({pc, prev_type});
                break;
            case TB_DEFAULT:
            case TB_RET:
            case TB_IRET:
                m_tbs[m_prevTB]->succs.insert({pc, curr_type});
                break;
            case TB_REP:
            case TB_EXCP:
            case TB_SYSENTER:
            case TB_INTERRUPT:
                m_tbs[m_prevTB]->other_succs.insert({pc, curr_type});
                break;
            default:
                getInfoStream(state) << "Unhandled TB predecessor " << prev_type << "\n";
                abort();
                break;
        }
    }
    m_prevTB = pc;
}

void ControlFlowTracer::onModuleTranslateBlockComplete(S2EExecutionState *state, const ModuleDescriptor &module,
                                                       TranslationBlock *tb, uint64_t lastPc) {
    // set attribute of current block
    TB *current = m_tbs.lookup(tb->pc);
    current->size = tb->size;
    current->end = lastPc;
    current->block_type = tb->se_tb_type;
    current->is_ret = (current->block_type == TB_RET || current->block_type == TB_IRET) ? current->block_type : 0;
}

void ControlFlowTracer::onModuleTransition(S2EExecutionState *state, ModuleDescriptorConstPtr prev,
                                           ModuleDescriptorConstPtr next) {
    if (prev != nullptr) { // exiting target module
        m_prevTB = 0;
    }
}

void ControlFlowTracer::onModuleLoad(S2EExecutionState *state, const ModuleDescriptor &module) {
    for (const auto &section : module.Sections) {
        m_modules[module.Name.c_str()].push_back(std::pair<uint64_t, uint64_t>{section.runtimeLoadBase, section.size});
    }
    // create map of address ranges that are mapped to module names
}

void ControlFlowTracer::writeTraceInfoJson() {
    json tbJson;
    json moduleJson;
    writeTBs(tbJson);
    writeModules(moduleJson);

    // write to file
    json finalJson = json{{"TBs", tbJson}, {"modules", moduleJson}};
    const auto jsonStr = finalJson.dump(2);
    fprintf(m_traceFile, "%s\n", jsonStr.c_str());
}

void ControlFlowTracer::writeTBs(nlohmann::json &tbJson) {
    for (auto const &pair : m_tbs) {
        const TB *tb = pair.second;
        // normal successor json
        json succs = writeSuccessors(tb->succs);
        json call_succs = writeSuccessors(tb->call_succs);
        json other_succs = writeSuccessors(tb->other_succs);

        json add = json{{"start", tb->start},
                        {"size", tb->size},
                        {"end", tb->end},
                        {"succs", succs},
                        {"call_succs", call_succs},
                        {"other_succs", other_succs},
                        {"block_type", tb->block_type},
                        {"is_ret", tb->is_ret}};
        tbJson.push_back(add);
    }
}

json ControlFlowTracer::writeSuccessors(llvm::DenseMap<uint64_t, uint32_t> map) {
    if (map.empty()) {
        return json::array();
    }
    json res;
    for (auto const &succ : map) {
        res.push_back(json{{"addr", succ.first}, {"type", succ.second}});
    }
    return res;
}

void ControlFlowTracer::writeModules(nlohmann::json &moduleJson) {
    for (auto const &module : m_modules) {
        json sections;
        for (auto const &section : module.second) {
            sections.push_back(json{{"lb", section.first}, {"size", section.second}});
        }
        moduleJson.push_back(json{{"name", module.first}, {"sections", sections}});
    }
}

} // namespace plugins
} // namespace s2e

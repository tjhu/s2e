#ifndef S2E_PLUGINS_CONTROLFLOWTRACER_H
#define S2E_PLUGINS_CONTROLFLOWTRACER_H

#include <llvm/ADT/DenseMap.h>
#include <nlohmann/json.hpp>
#include <s2e/Plugin.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>

namespace s2e {
namespace plugins {

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

class ControlFlowTracer : public Plugin {
    S2E_PLUGIN

public:
    ControlFlowTracer(S2E *s2e) : Plugin(s2e) {
    }

    void initialize();

private:
    std::string m_fileName;
    FILE *m_traceFile;
    ModuleExecutionDetector *m_detector;
    OSMonitor *m_monitor;
    target_ulong m_prevTB;

    llvm::DenseMap<target_ulong, TB *> m_tbs;
    std::unordered_map<std::string, std::vector<std::pair<uint64_t, uint64_t>>> m_modules;

    void onModuleTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, const ModuleDescriptor &module,
                                     TranslationBlock *tb, uint64_t pc);

    void onModuleBlockExecutionStart(S2EExecutionState *state, uint64_t pc);

    void onModuleTranslateBlockComplete(S2EExecutionState *state, const ModuleDescriptor &module, TranslationBlock *tb,
                                        uint64_t lastPc);

    void onModuleTransition(S2EExecutionState *state, ModuleDescriptorConstPtr prev, ModuleDescriptorConstPtr next);

    void onModuleLoad(S2EExecutionState *state, const ModuleDescriptor &module);

    void onEngineShutdown();

    // writer methods
    void generateTraceInfoJsonFile(); // generates traceInfo.json
    void writeTraceInfoJson();

    void writeTBs(nlohmann::json &tbJson);

    void writeModules(nlohmann::json &moduleJson);

    nlohmann::json writeSuccessors(llvm::DenseMap<uint64_t, uint32_t> map);
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_CONTROLFLOWTRACER_H

#include "ControlFlowTracer.h"

#include <fstream>
#include <limits>
#include <nlohmann/json.hpp>

#include <cpu/tb.h>
#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/S2E.h>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(ControlFlowTracer, "Tracer for control flow of translation blocks", "", "ModuleExecutionDetector",
                  "OSMonitor", "ProcessExecutionDetector");

namespace {
class CFTState final : public PluginState {
public:
    auto getLastBlockAddress() const -> Address {
        return m_lastBlockAddress;
    }

    void setLastBlockAddress(const Address value) {
        m_lastBlockAddress = value;
        m_external = false;
    }

    auto isExternal() const -> bool {
        return m_external;
    }

    void leaveModule() {
        m_external = true;
    }

    auto clone() const -> CFTState * override {
        return new CFTState{*this};
    }

    static auto factory(Plugin *const p, S2EExecutionState *const s) -> PluginState * {
        return new CFTState{};
    }

private:
    Address m_lastBlockAddress = 0;
    bool m_external = true;
};

auto toCFType(const ETranslationBlockType tbType) -> CFType {
    switch (tbType) {
        case TB_DEFAULT:
        case TB_JMP:
        case TB_COND_JMP:
        case TB_REP:
            return CFType::Jump;
        case TB_JMP_IND:
        case TB_COND_JMP_IND:
            return CFType::IndJump;
        case TB_CALL:
            return CFType::Call;
        case TB_CALL_IND:
            return CFType::IndCall;
        case TB_RET:
            return CFType::Return;
            break;
        case TB_IRET:
        case TB_EXCP:
        case TB_SYSENTER:
        case TB_INTERRUPT:
            return CFType::Special;
            break;
        default:
            assert(false && "Unhandled ETranslationBlockType");
            break;
    }
}
} // namespace

TracedBlock::TracedBlock(const Address address) : address{address} {
}

void TracedBlock::update(const Address lastPc, const uint64_t size, const CFType cfType) {
    this->lastPc = lastPc;
    this->size = size;
    this->cfType = cfType;
}

void to_json(nlohmann::json &j, const MappedSegment &ms) {
    j = {{"moduleName", ms.moduleName}, {"loadAddress", ms.loadAddress}, {"size", ms.size}};
}

void to_json(nlohmann::json &j, const TracedBlock &tb) {
    j = {{"address", tb.address},       {"size", tb.size},
         {"lastPc", tb.lastPc},         {"cfType", tb.cfType},
         {"successors", tb.successors}, {"instructions", tb.instructions}};
}

void to_json(nlohmann::json &j, const TraceInfo &ti) {
    j = {{"segments", ti.segments}, {"entries", ti.entries}, {"blocks", ti.blocks}};
}

auto TraceInfoGen::getTraceInfo() const -> const TraceInfo & {
    return m_traceInfo;
}

void TraceInfoGen::registerBlock(const Address address) {
    assert(address != 0 && "Cannot register block at address 0");
    const bool isNew = m_blockIndex.insert({address, IndexedBlock{m_traceInfo.blocks.size()}}).second;
    if (isNew) {
        m_traceInfo.blocks.emplace_back(address);
    }
}

void TraceInfoGen::updateBlock(const Address address, const Address lastPc, const uint64_t size, const CFType cfType) {
    assert(address != 0 && "Cannot register block at address 0");
    assert(size > 0 && "Block cannot be of size 0");
    assert(m_blockIndex.count(address) == 1 && "Block not registered");
    m_traceInfo.blocks[m_blockIndex.lookup(address).block_index].update(lastPc, size, cfType);
}

void TraceInfoGen::registerInstruction(const Address block, const Address pc) {
    assert(block != 0 && "Cannot register instruction to zero-block");
    assert(pc - block < std::numeric_limits<uint16_t>::max() && "Block shouldn't be larger than 65KB");
    assert(m_blockIndex.count(block) == 1 && "Block not registered");
    m_traceInfo.blocks[m_blockIndex.lookup(block).block_index].instructions.emplace_back(pc - block);
}

void TraceInfoGen::recordTransfer(const Address from, const Address to) {
    const auto fromIt = m_blockIndex.find(from);
    assert(fromIt != m_blockIndex.end() && "from-block not found");
    auto &succs = fromIt->second.succs;
    const auto succsIt = succs.find(to);
    if (succsIt == succs.end()) {
        succs.insert(to);
        m_traceInfo.blocks[fromIt->second.block_index].successors.push_back(to);
    }
}

void TraceInfoGen::recordEntry(const Address addr) {
    assert(addr != 0 && "Address 0 cannot be an entry");
    if (!m_entryIndex.contains(addr)) {
        m_entryIndex.insert(addr);
        m_traceInfo.entries.push_back(addr);
    }
}

void TraceInfoGen::registerSegment(std::string name, const Address loadAddress, const uint64_t size) {
    m_traceInfo.segments.push_back({std::move(name), loadAddress, size});
}

ControlFlowTracer::ControlFlowTracer(S2E *const s2e) : Plugin(s2e) {
}

void ControlFlowTracer::initialize() {
    m_monitor = static_cast<OSMonitor *>(s2e()->getPlugin("OSMonitor"));
    m_pDetector = s2e()->getPlugin<ProcessExecutionDetector>();
    m_monitor->onModuleLoad.connect(sigc::mem_fun(*this, &ControlFlowTracer::onModuleLoad));

    m_detector = s2e()->getPlugin<ModuleExecutionDetector>();

    m_detector->onModuleTranslateBlockStart.connect(
        sigc::mem_fun(*this, &ControlFlowTracer::onModuleTranslateBlockStart));
    m_detector->onModuleTranslateBlockEnd.connect(sigc::mem_fun(*this, &ControlFlowTracer::onModuleTranslateBlockEnd));
    m_detector->onModuleTranslateBlockComplete.connect(
        sigc::mem_fun(*this, &ControlFlowTracer::onModuleTranslateBlockComplete));

    s2e()->getCorePlugin()->onTranslateInstructionStart.connect(
        sigc::mem_fun(*this, &ControlFlowTracer::onTranslateInstructionStart));
    m_detector->onModuleTransition.connect(sigc::mem_fun(*this, &ControlFlowTracer::onModuleTransition));

    s2e()->getCorePlugin()->onEngineShutdown.connect(sigc::mem_fun(*this, &ControlFlowTracer::onEngineShutdown));
}

void ControlFlowTracer::onEngineShutdown() {
    nlohmann::json json = m_gen.getTraceInfo();
    std::ofstream out{s2e()->getOutputFilename(TraceInfo::filename)};
    out << json.dump();
}

void ControlFlowTracer::onModuleTranslateBlockStart(ExecutionSignal *const signal, S2EExecutionState *const state,
                                                    const ModuleDescriptor &module, TranslationBlock *const tb,
                                                    const uint64_t pc) {
    m_gen.registerBlock(tb->pc);
    signal->connect(sigc::mem_fun(*this, &ControlFlowTracer::onModuleBlockExecutionStart));
}

void ControlFlowTracer::onModuleTranslateBlockEnd(ExecutionSignal *const signal, S2EExecutionState *const state,
                                                  const ModuleDescriptor &module, TranslationBlock *const tb,
                                                  const uint64_t endPc, const bool staticTarget,
                                                  const uint64_t targetPc) {
    if (staticTarget) {
        const bool targetInModule = m_detector->getDescriptor(state, targetPc) != nullptr;
        if (targetInModule) {
            // Register block so translator can pick it up later even if it is not executed.
            m_gen.registerBlock(targetPc);
            m_gen.recordTransfer(tb->pc, targetPc);
        }
    } else {
        signal->connect(sigc::mem_fun(*this, &ControlFlowTracer::onModuleBlockExecutionEnd));
    }
}

void ControlFlowTracer::onModuleTranslateBlockComplete(S2EExecutionState *const state, const ModuleDescriptor &module,
                                                       TranslationBlock *const tb, const uint64_t lastPc) {
    m_gen.updateBlock(tb->pc, lastPc, tb->size, toCFType(tb->se_tb_type));
}

void ControlFlowTracer::onModuleBlockExecutionStart(S2EExecutionState *const state, const uint64_t pc) {
    DECLARE_PLUGINSTATE(CFTState, state);
    if (plgState->isExternal()) {
        m_gen.recordEntry(pc);
    }
    plgState->setLastBlockAddress(pc);
}

void ControlFlowTracer::onModuleBlockExecutionEnd(S2EExecutionState *const state, const uint64_t pc) {
    DECLARE_PLUGINSTATE(CFTState, state);

    const uint64_t targetPc = state->regs()->getPc();
    const bool targetInModule = m_detector->getDescriptor(state, targetPc) != nullptr;
    if (targetInModule) {
        m_gen.recordTransfer(plgState->getLastBlockAddress(), targetPc);
    }
}

void ControlFlowTracer::onTranslateInstructionStart(ExecutionSignal *const signal, S2EExecutionState *const state,
                                                    TranslationBlock *const tb, const uint64_t pc) {
    const ModuleDescriptorConstPtr currentModule = m_detector->getDescriptor(state, pc);
    if (!currentModule) {
        return;
    }

    m_gen.registerInstruction(tb->pc, pc);
}

void ControlFlowTracer::onModuleTransition(S2EExecutionState *const state, const ModuleDescriptorConstPtr prev,
                                           const ModuleDescriptorConstPtr next) {
    DECLARE_PLUGINSTATE(CFTState, state);
    if (!next) {
        plgState->leaveModule();
    }
}

void ControlFlowTracer::onModuleLoad(S2EExecutionState *const state, const ModuleDescriptor &module) {
    if (m_pDetector->isTrackedPid(state, module.Pid)) {
        for (const SectionDescriptor &section : module.Sections) {
            m_gen.registerSegment(module.Name, section.runtimeLoadBase, section.size);
        }
    }
}

} // namespace plugins
} // namespace s2e

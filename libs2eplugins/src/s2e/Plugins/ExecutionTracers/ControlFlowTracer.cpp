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

    void setLastBlockAddress(Address value) {
        m_lastBlockAddress = value;
    }

    auto isExternal() const -> bool {
        return m_lastBlockAddress == 0;
    }

    void leaveModule() {
        m_lastBlockAddress = 0;
    }

    auto clone() const -> CFTState * override {
        return new CFTState{*this};
    }

    static auto factory(Plugin *p, S2EExecutionState *s) -> PluginState * {
        return new CFTState;
    }

private:
    Address m_lastBlockAddress = 0;
};

auto toCFType(ETranslationBlockType tbType) -> CFType {
    switch (tbType) {
        case TB_DEFAULT:
        case TB_JMP:
        case TB_JMP_IND:
        case TB_COND_JMP:
        case TB_COND_JMP_IND:
        case TB_REP:
            return CFType::Jump;
        case TB_CALL:
        case TB_CALL_IND:
            return CFType::Call;
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

TracedBlock::TracedBlock(Address address) : address{address} {
}

void TracedBlock::update(Address lastPc, uint64_t size, CFType cfType) {
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

void TraceInfoGen::registerBlock(Address address) {
    assert(address != 0 && "Cannot register block at address 0");
    const auto isNew = m_blockIndex.insert({address, IndexedBlock{m_traceInfo.blocks.size()}}).second;
    if (isNew) {
        m_traceInfo.blocks.emplace_back(address);
    }
}

void TraceInfoGen::updateBlock(Address address, Address lastPc, uint64_t size, CFType cfType) {
    assert(address != 0 && "Cannot register block at address 0");
    assert(size > 0 && "Block cannot be of size 0");
    assert(m_blockIndex.count(address) == 1 && "Block not registered");
    m_traceInfo.blocks[m_blockIndex.lookup(address).block_index].update(lastPc, size, cfType);
}

void TraceInfoGen::registerInstruction(Address block, Address pc) {
    assert(block != 0 && "Cannot register instruction to zero-block");
    assert(pc - block < std::numeric_limits<uint16_t>::max() && "Block shouldn't be larger than 65KB");
    assert(m_blockIndex.count(block) == 1 && "Block not registered");
    m_traceInfo.blocks[m_blockIndex.lookup(block).block_index].instructions.emplace_back(pc - block);
}

void TraceInfoGen::recordTransfer(Address from, Address to) {
    const auto fromIt = m_blockIndex.find(from);
    assert(fromIt != m_blockIndex.end() && "from-block not found");
    auto &succs = fromIt->second.succs;
    const auto succsIt = succs.find(to);
    if (succsIt == succs.end()) {
        succs.insert(to);
        m_traceInfo.blocks[fromIt->second.block_index].successors.push_back(to);
    }
}

void TraceInfoGen::recordEntry(Address addr) {
    assert(addr != 0 && "Address 0 cannot be an entry");
    if (!m_entryIndex.contains(addr)) {
        m_entryIndex.insert(addr);
        m_traceInfo.entries.push_back(addr);
    }
}

void TraceInfoGen::registerSegment(std::string name, Address loadAddress, uint64_t size) {
    m_traceInfo.segments.push_back({std::move(name), loadAddress, size});
}

ControlFlowTracer::ControlFlowTracer(S2E *s2e) : Plugin(s2e) {
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

void ControlFlowTracer::onModuleTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state,
                                                    const ModuleDescriptor &module, TranslationBlock *tb, uint64_t pc) {
    m_gen.registerBlock(tb->pc);
    signal->connect(sigc::mem_fun(*this, &ControlFlowTracer::onModuleBlockExecutionStart));
}

void ControlFlowTracer::onModuleTranslateBlockEnd(ExecutionSignal *signal, S2EExecutionState *state,
                                                  const ModuleDescriptor &module, TranslationBlock *tb, uint64_t endPc,
                                                  bool staticTarget, uint64_t targetPc) {
    if (staticTarget) {
        const auto &targetModule = m_detector->getDescriptor(state, targetPc);
        m_gen.registerBlock(targetPc);
        if (targetModule) {
            m_gen.recordTransfer(tb->pc, targetPc);
            return;
        }
    }
    signal->connect(sigc::mem_fun(*this, &ControlFlowTracer::onModuleBlockExecutionEnd));
}

void ControlFlowTracer::onModuleTranslateBlockComplete(S2EExecutionState *state, const ModuleDescriptor &module,
                                                       TranslationBlock *tb, uint64_t lastPc) {
    m_gen.updateBlock(tb->pc, lastPc, tb->size, toCFType(tb->se_tb_type));
}

void ControlFlowTracer::onModuleBlockExecutionStart(S2EExecutionState *state, uint64_t pc) {
    DECLARE_PLUGINSTATE(CFTState, state);
    if (plgState->isExternal()) {
        m_gen.recordEntry(pc);
    }
    plgState->setLastBlockAddress(pc);
}

void ControlFlowTracer::onModuleBlockExecutionEnd(S2EExecutionState *state, uint64_t pc) {
    DECLARE_PLUGINSTATE(CFTState, state);

    const auto &targetPc = state->regs()->getPc();
    const auto &targetModule = m_detector->getDescriptor(state, targetPc);
    if (!targetModule) {
        return;
    }

    m_gen.recordTransfer(plgState->getLastBlockAddress(), targetPc);
}

void ControlFlowTracer::onTranslateInstructionStart(ExecutionSignal *signal, S2EExecutionState *state,
                                                    TranslationBlock *tb, uint64_t pc) {
    const auto &currentModule = m_detector->getDescriptor(state, pc);
    if (!currentModule) {
        return;
    }

    m_gen.registerInstruction(tb->pc, pc);
}

void ControlFlowTracer::onModuleTransition(S2EExecutionState *state, ModuleDescriptorConstPtr prev,
                                           ModuleDescriptorConstPtr next) {
    DECLARE_PLUGINSTATE(CFTState, state);
    if (!next) {
        plgState->leaveModule();
    }
}

void ControlFlowTracer::onModuleLoad(S2EExecutionState *state, const ModuleDescriptor &module) {
    if (m_pDetector->isTracked(state, module.Pid)) {
        for (const auto &section : module.Sections)
            m_gen.registerSegment(module.Name, section.runtimeLoadBase, section.size);
    }
}

} // namespace plugins
} // namespace s2e

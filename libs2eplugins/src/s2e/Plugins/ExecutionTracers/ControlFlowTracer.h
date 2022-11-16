#ifndef S2E_PLUGINS_CONTROLFLOWTRACER_H
#define S2E_PLUGINS_CONTROLFLOWTRACER_H

#include <llvm/ADT/DenseMap.h>
#include <s2e/Plugin.h>
#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/Plugins/OSMonitors/Support/ModuleExecutionDetector.h>
#include <s2e/Plugins/OSMonitors/Support/ProcessExecutionDetector.h>

namespace s2e {
namespace plugins {

using Address = uint64_t;

struct MappedSegment {
    std::string moduleName;
    Address loadAddress;
    uint64_t size;
};

enum class CFType {
    /// Direct jumps, indirect jumps, tail calls, rep prefix and fallthroughs.
    Jump,
    /// Direct and indirect calls.
    Call,
    /// Returning with a return instruction.
    Return,
    /// Everything that we can't easily model: interrupts, iret, exceptions, and sysenter.
    Special
};

struct TracedBlock {
    TracedBlock() = default;
    TracedBlock(Address address, uint64_t size, CFType cfType);

    /// The virtual address of the block in this trace. This could be different across multiple traces if the target
    /// binary is position independent and ASLR is enabled.
    Address address;
    /// This size of the block, in bytes.
    uint64_t size;
    /// How this block is terminated.
    CFType cfType;
    /// All observed successors of this block. If it ends on a direct jump or call, this should have a size of 1.
    std::vector<uint64_t> successors;
};

struct TraceInfo {
    static constexpr const char *filename = "traceInfo.json";

    std::vector<MappedSegment> segments;
    std::vector<Address> entries;
    std::vector<TracedBlock> blocks;
};

class TraceInfoGen {
public:
    auto getTraceInfo() const -> const TraceInfo &;
    void registerBlock(Address address, uint64_t size, CFType cfType);
    void recordTransfer(Address from, Address to);
    void recordEntry(Address addr);
    void registerSegment(std::string name, Address loadAddress, uint64_t size);

private:
    struct IndexedBlock {
        size_t block_index;
        llvm::DenseSet<Address> succs;
    };

    TraceInfo m_traceInfo;
    llvm::DenseMap<Address, IndexedBlock> m_blockIndex;
    llvm::DenseSet<Address> m_entryIndex;
};

class ControlFlowTracer final : public Plugin {
    S2E_PLUGIN

public:
    ControlFlowTracer(S2E *s2e);
    void initialize();

private:
    void onModuleTranslateBlockStart(ExecutionSignal *signal, S2EExecutionState *state, const ModuleDescriptor &module,
                                     TranslationBlock *tb, uint64_t pc);
    void onModuleTranslateBlockComplete(S2EExecutionState *state, const ModuleDescriptor &module, TranslationBlock *tb,
                                        uint64_t last_pc);
    void onModuleBlockExecutionStart(S2EExecutionState *state, uint64_t pc);
    void onModuleTransition(S2EExecutionState *state, ModuleDescriptorConstPtr prev, ModuleDescriptorConstPtr next);
    void onModuleLoad(S2EExecutionState *state, const ModuleDescriptor &module);
    void onEngineShutdown();

    OSMonitor *m_monitor = nullptr;
    ModuleExecutionDetector *m_detector = nullptr;
    ProcessExecutionDetector *m_pDetector = nullptr;
    TraceInfoGen m_gen;
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_CONTROLFLOWTRACER_H

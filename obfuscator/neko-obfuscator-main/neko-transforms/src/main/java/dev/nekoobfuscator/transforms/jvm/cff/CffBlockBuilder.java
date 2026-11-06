package dev.nekoobfuscator.transforms.jvm.cff;

import static dev.nekoobfuscator.transforms.jvm.cff.ControlFlowFlatteningLr.*;
import static dev.nekoobfuscator.transforms.jvm.cff.ControlFlowFlatteningVerify.*;

import dev.nekoobfuscator.api.transform.IRLevel;
import dev.nekoobfuscator.api.transform.TransformContext;
import dev.nekoobfuscator.api.transform.TransformPass;
import dev.nekoobfuscator.api.transform.TransformPhase;
import dev.nekoobfuscator.core.ir.l1.L1Class;
import dev.nekoobfuscator.core.ir.l1.L1Method;
import dev.nekoobfuscator.core.pipeline.PipelineContext;
import dev.nekoobfuscator.transforms.util.JvmObfuscationCoverage;
import dev.nekoobfuscator.transforms.util.TransformGuards;
import dev.nekoobfuscator.transforms.jvm.internal.JvmCodeSizeEstimator;
import dev.nekoobfuscator.transforms.jvm.internal.JvmPassBytecode;
import dev.nekoobfuscator.transforms.jvm.key.JvmKeyDispatchPass;
import dev.nekoobfuscator.transforms.jvm.strings.JvmStringObfuscationPass;
import dev.nekoobfuscator.transforms.jvm.constants.JvmConstantObfuscationPass;
import dev.nekoobfuscator.transforms.jvm.parameters.JvmMethodParameterObfuscationPass;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import org.objectweb.asm.Type;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.tree.analysis.BasicValue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


abstract class CffBlockBuilder extends CffIslandMaterial {

    protected AbstractInsnNode constructorInitInsn(L1Class clazz, MethodNode mn) {
        for (
            AbstractInsnNode insn = mn.instructions.getFirst();
            insn != null;
            insn = insn.getNext()
        ) {
            if (
                insn instanceof MethodInsnNode call &&
                call.getOpcode() == Opcodes.INVOKESPECIAL &&
                "<init>".equals(call.name) &&
                (clazz.name().equals(call.owner) ||
                    clazz.superName().equals(call.owner))
            ) {
                return insn;
            }
        }
        return null;
    }

    protected Map<LabelNode, String> handlerReachableDomains(
        MethodNode mn,
        List<Block> blocks,
        Map<LabelNode, LabelNode> aliases,
        Set<LabelNode> handlerBodies
    ) {
        Set<LabelNode> blockLabels = Collections.newSetFromMap(
            new IdentityHashMap<>()
        );
        Map<LabelNode, Block> byLabel = new IdentityHashMap<>();
        Map<LabelNode, LabelNode> nextByLabel = new IdentityHashMap<>();
        LabelNode normalEntry = null;
        for (int i = 0; i < blocks.size(); i++) {
            Block block = blocks.get(i);
            if (!block.handler() && normalEntry == null) {
                normalEntry = block.label();
            }
            blockLabels.add(block.label());
            byLabel.put(block.label(), block);
            if (i + 1 < blocks.size()) {
                nextByLabel.put(block.label(), blocks.get(i + 1).label());
            }
        }
        Set<LabelNode> normalReachable = reachableFrom(
            mn,
            normalEntry,
            blockLabels,
            byLabel,
            nextByLabel,
            aliases
        );

        Map<LabelNode, String> domains = new IdentityHashMap<>();
        List<LabelNode> bodies = new ArrayList<>(handlerBodies);
        for (
            int handlerIndex = 0;
            handlerIndex < bodies.size();
            handlerIndex++
        ) {
            String token = "H" + handlerIndex;
            Set<LabelNode> reachable = Collections.newSetFromMap(
                new IdentityHashMap<>()
            );
            List<LabelNode> work = new ArrayList<>();
            LabelNode canonical = canonicalLabel(
                bodies.get(handlerIndex),
                aliases
            );
            if (blockLabels.contains(canonical) && reachable.add(canonical)) {
                addHandlerDomain(domains, canonical, token);
                work.add(canonical);
            }
            for (int i = 0; i < work.size(); i++) {
                LabelNode label = work.get(i);
                Block block = byLabel.get(label);
                if (block == null) continue;
                for (LabelNode successor : blockSuccessors(mn, block, nextByLabel)) {
                    canonical = canonicalLabel(successor, aliases);
                    if (
                        blockLabels.contains(canonical) &&
                        !normalReachable.contains(canonical) &&
                        reachable.add(canonical)
                    ) {
                        addHandlerDomain(domains, canonical, token);
                        work.add(canonical);
                    }
                }
            }
        }
        return domains;
    }

    protected void addHandlerDomain(
        Map<LabelNode, String> domains,
        LabelNode label,
        String token
    ) {
        String existing = domains.get(label);
        domains.put(label, existing == null ? token : existing + "," + token);
    }

    protected Set<LabelNode> reachableFrom(
        MethodNode mn,
        LabelNode start,
        Set<LabelNode> blockLabels,
        Map<LabelNode, Block> byLabel,
        Map<LabelNode, LabelNode> nextByLabel,
        Map<LabelNode, LabelNode> aliases
    ) {
        Set<LabelNode> reachable = Collections.newSetFromMap(
            new IdentityHashMap<>()
        );
        if (start == null) return reachable;
        List<LabelNode> work = new ArrayList<>();
        LabelNode canonicalStart = canonicalLabel(start, aliases);
        if (
            blockLabels.contains(canonicalStart) &&
            reachable.add(canonicalStart)
        ) {
            work.add(canonicalStart);
        }
        for (int i = 0; i < work.size(); i++) {
            LabelNode label = work.get(i);
            Block block = byLabel.get(label);
            if (block == null) continue;
            for (LabelNode successor : blockSuccessors(mn, block, nextByLabel)) {
                LabelNode canonical = canonicalLabel(successor, aliases);
                if (
                    blockLabels.contains(canonical) &&
                    reachable.add(canonical)
                ) {
                    work.add(canonical);
                }
            }
        }
        return reachable;
    }

    protected List<LabelNode> blockSuccessors(
        MethodNode mn,
        Block block,
        Map<LabelNode, LabelNode> nextByLabel
    ) {
        AbstractInsnNode last = lastRealBefore(mn, block.endExclusive());
        if (last == null || terminates(last.getOpcode())) {
            return Collections.emptyList();
        }
        List<LabelNode> successors = new ArrayList<>();
        if (last instanceof JumpInsnNode jump) {
            successors.add(jump.label);
            if (last.getOpcode() != Opcodes.GOTO) {
                LabelNode next = nextByLabel.get(block.label());
                if (next != null) successors.add(next);
            }
        } else if (last instanceof LookupSwitchInsnNode ls) {
            successors.add(ls.dflt);
            successors.addAll(ls.labels);
        } else if (last instanceof TableSwitchInsnNode ts) {
            successors.add(ts.dflt);
            successors.addAll(ts.labels);
        } else {
            LabelNode next = nextByLabel.get(block.label());
            if (next != null) successors.add(next);
        }
        return successors;
    }

    protected LabelNode canonicalLabel(
        LabelNode label,
        Map<LabelNode, LabelNode> aliases
    ) {
        LabelNode current = label;
        Set<LabelNode> seen = Collections.newSetFromMap(new IdentityHashMap<>());
        while (current != null && seen.add(current)) {
            LabelNode next = aliases.get(current);
            if (next == null || next == current) break;
            current = next;
        }
        return current == null ? label : current;
    }

    protected void completeBlockLabelAliases(
        MethodNode mn,
        LabelNode start,
        List<Block> blocks,
        Map<LabelNode, LabelNode> aliases
    ) {
        Set<LabelNode> blockLabels = Collections.newSetFromMap(
            new IdentityHashMap<>()
        );
        Map<AbstractInsnNode, LabelNode> firstRealOwners = new IdentityHashMap<>();
        for (Block block : blocks) {
            blockLabels.add(block.label());
            AbstractInsnNode first = nextReal(block.label());
            if (first != null) firstRealOwners.put(first, block.label());
        }
        for (Block block : blocks) {
            for (
                AbstractInsnNode scan = block.label();
                scan != null && scan.getOpcode() < 0;
                scan = scan.getPrevious()
            ) {
                if (scan instanceof LabelNode label && label != block.label()) {
                    aliases.put(label, block.label());
                }
            }
            for (
                AbstractInsnNode scan = block.label();
                scan != null && scan.getOpcode() < 0;
                scan = scan.getNext()
            ) {
                if (scan instanceof LabelNode label && label != block.label()) {
                    aliases.put(label, block.label());
                }
            }
        }
        for (AbstractInsnNode scan = start; scan != null; scan = scan.getNext()) {
            if (!(scan instanceof LabelNode label) || blockLabels.contains(label)) {
                continue;
            }
            if (aliases.containsKey(label)) continue;
            AbstractInsnNode first = nextReal(label.getNext());
            LabelNode owner = first == null ? null : firstRealOwners.get(first);
            if (owner != null) aliases.put(label, owner);
        }
        for (Map.Entry<LabelNode, LabelNode> alias : new ArrayList<>(aliases.entrySet())) {
            LabelNode canonical = canonicalLabel(alias.getValue(), aliases);
            if (canonical != null && canonical != alias.getKey()) {
                aliases.put(alias.getKey(), canonical);
            }
        }
    }

    protected boolean isZeroStackLabel(
        LabelNode label,
        Set<LabelNode> zeroStackLabels
    ) {
        if (zeroStackLabels.contains(label)) return true;
        for (
            AbstractInsnNode scan = label.getPrevious();
            scan != null && scan.getOpcode() < 0;
            scan = scan.getPrevious()
        ) {
            if (scan instanceof LabelNode alias && zeroStackLabels.contains(alias)) {
                return true;
            }
        }
        for (
            AbstractInsnNode scan = label.getNext();
            scan != null && scan.getOpcode() < 0;
            scan = scan.getNext()
        ) {
            if (scan instanceof LabelNode alias && zeroStackLabels.contains(alias)) {
                return true;
            }
        }
        return false;
    }

    protected BlockPlan buildBlocks(
        MethodNode mn,
        LabelNode start,
        Set<LabelNode> extraLeaders,
        Set<LabelNode> zeroStackLabels,
        Set<LabelNode> linearLeaders,
        CffFrameAnalysis frames
    ) {
        Set<AbstractInsnNode> leaders = new HashSet<>();
        leaders.add(start);
        leaders.addAll(extraLeaders);
        leaders.addAll(linearLeaders);
        Set<LabelNode> handlerLabels = new HashSet<>();
        if (mn.tryCatchBlocks != null) {
            for (TryCatchBlockNode tcb : mn.tryCatchBlocks) {
                if (frames.isZeroStack(tcb.start)) {
                    leaders.add(tcb.start);
                }
                leaders.add(tcb.handler);
                handlerLabels.add(tcb.handler);
            }
        }
        for (
            AbstractInsnNode insn = start;
            insn != null;
            insn = insn.getNext()
        ) {
            if (insn instanceof JumpInsnNode jump) {
                AbstractInsnNode next = nextReal(insn.getNext());
                boolean targetZero = isZeroStackLabel(jump.label, zeroStackLabels);
                if (jump.getOpcode() == Opcodes.GOTO) {
                    if (targetZero) leaders.add(jump.label);
                } else if (
                    targetZero && frames.isZeroStack(next)
                ) {
                    leaders.add(jump.label);
                    leaders.add(ensureLabelBefore(mn, next));
                }
            } else if (insn instanceof TableSwitchInsnNode ts) {
                if (allSwitchTargetsZero(ts.dflt, ts.labels, zeroStackLabels)) {
                    leaders.add(ts.dflt);
                    leaders.addAll(ts.labels);
                }
            } else if (insn instanceof LookupSwitchInsnNode ls) {
                if (allSwitchTargetsZero(ls.dflt, ls.labels, zeroStackLabels)) {
                    leaders.add(ls.dflt);
                    leaders.addAll(ls.labels);
                }
            } else if (terminates(insn.getOpcode())) {
                AbstractInsnNode next = nextReal(insn.getNext());
                if (frames.isZeroStack(next)) leaders.add(
                    ensureLabelBefore(mn, next)
                );
            }
        }
        List<LabelNode> ordered = new ArrayList<>();
        for (
            AbstractInsnNode insn = start;
            insn != null;
            insn = insn.getNext()
        ) {
            if (insn instanceof LabelNode label && leaders.contains(label)) {
                ordered.add(label);
            }
        }
        List<Block> blocks = new ArrayList<>();
        Map<LabelNode, LabelNode> aliases = new IdentityHashMap<>();
        Map<Integer, LabelNode> canonicalByIndex = new HashMap<>();
        for (int i = 0; i < ordered.size(); i++) {
            LabelNode label = ordered.get(i);
            AbstractInsnNode endExclusive =
                i + 1 < ordered.size() ? ordered.get(i + 1) : null;
            if (hasRealInstruction(label, endExclusive)) {
                blocks.add(
                    new Block(
                        label,
                        endExclusive,
                        handlerLabels.contains(label)
                    )
                );
                canonicalByIndex.put(i, label);
            }
        }
        LabelNode nextCanonical = null;
        for (int i = ordered.size() - 1; i >= 0; i--) {
            LabelNode label = ordered.get(i);
            LabelNode canonical = canonicalByIndex.get(i);
            if (canonical != null) {
                nextCanonical = canonical;
            } else if (nextCanonical != null) {
                aliases.put(label, nextCanonical);
            }
        }
        return new BlockPlan(blocks, aliases);
    }

    protected boolean hasRealInstruction(
        LabelNode label,
        AbstractInsnNode endExclusive
    ) {
        for (
            AbstractInsnNode insn = label;
            insn != null && insn != endExclusive;
            insn = insn.getNext()
        ) {
            if (insn.getOpcode() >= 0) return true;
        }
        return false;
    }

    protected boolean useSubdispatcherOutliner(
        MethodNode mn,
        List<Block> blocks,
        List<HandlerBridge> handlerBridges
    ) {
        return useOutliner(
            mn,
            blocks,
            handlerBridges,
            DISPATCH_OUTLINER_BLOCK_THRESHOLD,
            DISPATCH_OUTLINER_EDGE_THRESHOLD,
            DISPATCH_OUTLINER_HANDLER_THRESHOLD,
            DISPATCH_OUTLINER_ESTIMATED_CODE_PRESSURE
        );
    }

    protected boolean useTransitionOutliner(
        MethodNode mn,
        List<Block> blocks,
        List<HandlerBridge> handlerBridges
    ) {
        if (hasBackwardBlockEdge(mn, blocks)) {
            int outlinerPressure = estimatedOutlinerCodePressure(
                mn,
                blocks,
                handlerBridges
            );
            if (outlinerPressure >= DISPATCH_OUTLINER_ESTIMATED_CODE_PRESSURE) {
                return true;
            }
            if (
                estimatedJitMethodBytes(mn, blocks, handlerBridges) >=
                    JIT_BUDGET_METHOD_BYTES
            ) {
                return true;
            }
        }
        return useOutliner(
            mn,
            blocks,
            handlerBridges,
            TRANSITION_OUTLINER_BLOCK_THRESHOLD,
            TRANSITION_OUTLINER_EDGE_THRESHOLD,
            TRANSITION_OUTLINER_HANDLER_THRESHOLD,
            TRANSITION_OUTLINER_ESTIMATED_CODE_PRESSURE
        );
    }

    protected boolean useOutliner(
        MethodNode mn,
        List<Block> blocks,
        List<HandlerBridge> handlerBridges,
        int blockThreshold,
        int edgeThreshold,
        int handlerThreshold,
        int codePressureThreshold
    ) {
        int nonHandlerBlocks = 0;
        int estimatedEdges = 0;
        for (int i = 0; i < blocks.size(); i++) {
            Block block = blocks.get(i);
            if (block.handler()) continue;
            nonHandlerBlocks++;
            AbstractInsnNode last = lastRealBefore(mn, block.endExclusive());
            if (last instanceof LookupSwitchInsnNode ls) {
                estimatedEdges += 1 + ls.labels.size();
            } else if (last instanceof TableSwitchInsnNode ts) {
                estimatedEdges += 1 + ts.labels.size();
            } else if (last instanceof JumpInsnNode jump) {
                estimatedEdges += jump.getOpcode() == Opcodes.GOTO ? 1 : 2;
            } else if (last != null && !terminates(last.getOpcode()) && i + 1 < blocks.size()) {
                estimatedEdges++;
            }
        }
        int protectedHandlerCost = handlerBridges.size() * 3;
        int codeBytes = JvmCodeSizeEstimator.estimateMethodBytes(mn);
        int sizePressure = codeBytes + estimatedEdges * 220 + protectedHandlerCost * 180;
        return nonHandlerBlocks >= blockThreshold ||
            estimatedEdges >= edgeThreshold ||
            handlerBridges.size() >= handlerThreshold ||
            sizePressure >= codePressureThreshold;
    }

    protected int estimatedOutlinerCodePressure(
        MethodNode mn,
        List<Block> blocks,
        List<HandlerBridge> handlerBridges
    ) {
        int estimatedEdges = 0;
        for (int i = 0; i < blocks.size(); i++) {
            Block block = blocks.get(i);
            if (block.handler()) continue;
            AbstractInsnNode last = lastRealBefore(mn, block.endExclusive());
            if (last instanceof LookupSwitchInsnNode ls) {
                estimatedEdges += 1 + ls.labels.size();
            } else if (last instanceof TableSwitchInsnNode ts) {
                estimatedEdges += 1 + ts.labels.size();
            } else if (last instanceof JumpInsnNode jump) {
                estimatedEdges += jump.getOpcode() == Opcodes.GOTO ? 1 : 2;
            } else if (last != null && !terminates(last.getOpcode()) && i + 1 < blocks.size()) {
                estimatedEdges++;
            }
        }
        return JvmCodeSizeEstimator.estimateMethodBytes(mn) +
            estimatedEdges * 220 +
            handlerBridges.size() * 3 * 180;
    }

    protected int smallTokenDispatchCaseLimit(
        MethodNode mn,
        List<Block> blocks,
        List<HandlerBridge> handlerBridges
    ) {
        int codePressure = estimatedOutlinerCodePressure(
            mn,
            blocks,
            handlerBridges
        );
        if (codePressure >= LARGE_METHOD_TOKEN_DISPATCH_CODE_PRESSURE) {
            return LARGE_METHOD_SMALL_TOKEN_DISPATCH_CASES;
        }
        if (useJitBudgetTokenDispatchEncoding(mn, blocks, handlerBridges)) {
            return JIT_BUDGET_TOKEN_DISPATCH_CASES;
        }
        return SMALL_TOKEN_DISPATCH_CASES;
    }

    protected boolean useCompactTransitionWrappers(
        int outlinerCodePressure,
        MethodNode mn,
        List<Block> blocks,
        List<HandlerBridge> handlerBridges
    ) {
        return outlinerCodePressure >= COMPACT_TRANSITION_WRAPPER_CODE_PRESSURE ||
            useJitBudgetTokenDispatchEncoding(mn, blocks, handlerBridges);
    }

    protected boolean useJitBudgetTokenDispatchEncoding(
        MethodNode mn,
        List<Block> blocks,
        List<HandlerBridge> handlerBridges
    ) {
        return hasBackwardBlockEdge(mn, blocks) &&
            estimatedJitMethodBytes(mn, blocks, handlerBridges) >=
                JIT_BUDGET_METHOD_BYTES;
    }

    protected int estimatedJitMethodBytes(
        MethodNode mn,
        List<Block> blocks,
        List<HandlerBridge> handlerBridges
    ) {
        int estimatedEdges = 0;
        int nonHandlerBlocks = 0;
        for (int i = 0; i < blocks.size(); i++) {
            Block block = blocks.get(i);
            if (block.handler()) continue;
            nonHandlerBlocks++;
            AbstractInsnNode last = lastRealBefore(mn, block.endExclusive());
            if (last instanceof LookupSwitchInsnNode ls) {
                estimatedEdges += 1 + ls.labels.size();
            } else if (last instanceof TableSwitchInsnNode ts) {
                estimatedEdges += 1 + ts.labels.size();
            } else if (last instanceof JumpInsnNode jump) {
                estimatedEdges += jump.getOpcode() == Opcodes.GOTO ? 1 : 2;
            } else if (last != null && !terminates(last.getOpcode()) && i + 1 < blocks.size()) {
                estimatedEdges++;
            }
        }
        int estimated = JvmCodeSizeEstimator.estimateMethodBytes(mn) +
            nonHandlerBlocks * JIT_BUDGET_BLOCK_BYTES +
            estimatedEdges * JIT_BUDGET_EDGE_BYTES +
            handlerBridges.size() * JIT_BUDGET_HANDLER_BYTES;
        return Math.min(estimated, HOTSPOT_HUGE_METHOD_LIMIT_BYTES);
    }

    protected int inlineDirectTransitionBudgetBytes(
        MethodNode mn,
        List<Block> blocks,
        List<HandlerBridge> handlerBridges,
        boolean outlineTransitions
    ) {
        if (!outlineTransitions) return 0;
        if (!useJitBudgetTokenDispatchEncoding(mn, blocks, handlerBridges)) return 0;
        int projectedOutlinedBytes = estimatedOutlinedJitMethodBytes(
            mn,
            blocks,
            handlerBridges
        );
        return inlineDirectTransitionBudgetBytesForProjectedSize(
            mn,
            projectedOutlinedBytes
        );
    }

    static int inlineDirectTransitionBudgetBytesForProjectedSize(
        MethodNode mn,
        int projectedOutlinedBytes
    ) {
        return Math.max(
            0,
            HOTSPOT_HUGE_METHOD_LIMIT_BYTES -
                adaptivePostCffReserveBytes(mn) -
                projectedOutlinedBytes
        );
    }

    static int adaptivePostCffReserveBytes(MethodNode mn) {
        if (mn == null || mn.instructions == null) {
            return JIT_BUDGET_POST_CFF_RESERVE_BYTES;
        }
        int pressure = 0;
        for (
            AbstractInsnNode insn = mn.instructions.getFirst();
            insn != null;
            insn = insn.getNext()
        ) {
            pressure += postCffSiteReservePressure(insn);
            if (
                pressure >=
                    JIT_BUDGET_POST_CFF_RESERVE_BYTES -
                        JIT_BUDGET_MIN_POST_CFF_RESERVE_BYTES
            ) {
                return JIT_BUDGET_POST_CFF_RESERVE_BYTES;
            }
        }
        return Math.min(
            JIT_BUDGET_POST_CFF_RESERVE_BYTES,
            JIT_BUDGET_MIN_POST_CFF_RESERVE_BYTES + Math.max(0, pressure)
        );
    }

    private static int postCffSiteReservePressure(AbstractInsnNode insn) {
        if (insn instanceof InvokeDynamicInsnNode indy) {
            return isStringConcatWithConstants(indy) ? 220 : 160;
        }
        if (insn instanceof LdcInsnNode ldc) {
            Object cst = ldc.cst;
            if (cst instanceof String value) {
                return 96 + Math.min(96, value.length() / 8);
            }
            if (cst instanceof Number) {
                return 32;
            }
            if (cst instanceof Type || cst instanceof Handle) {
                return 48;
            }
            return 16;
        }
        if (insn instanceof IntInsnNode intInsn) {
            if (intInsn.getOpcode() == Opcodes.NEWARRAY) {
                return 160;
            }
            if (
                intInsn.getOpcode() == Opcodes.BIPUSH ||
                    intInsn.getOpcode() == Opcodes.SIPUSH
            ) {
                return 24;
            }
        }
        int opcode = insn.getOpcode();
        if (
            opcode >= Opcodes.ICONST_M1 && opcode <= Opcodes.ICONST_5 ||
                opcode == Opcodes.LCONST_0 ||
                opcode == Opcodes.LCONST_1 ||
                opcode == Opcodes.FCONST_0 ||
                opcode == Opcodes.FCONST_1 ||
                opcode == Opcodes.FCONST_2 ||
                opcode == Opcodes.DCONST_0 ||
                opcode == Opcodes.DCONST_1
        ) {
            return 4;
        }
        return 0;
    }

    private static boolean isStringConcatWithConstants(InvokeDynamicInsnNode indy) {
        return indy.bsm != null &&
            "java/lang/invoke/StringConcatFactory".equals(indy.bsm.getOwner()) &&
            "makeConcatWithConstants".equals(indy.bsm.getName());
    }

    protected int estimatedOutlinedJitMethodBytes(
        MethodNode mn,
        List<Block> blocks,
        List<HandlerBridge> handlerBridges
    ) {
        int estimatedEdges = 0;
        int nonHandlerBlocks = 0;
        for (int i = 0; i < blocks.size(); i++) {
            Block block = blocks.get(i);
            if (block.handler()) continue;
            nonHandlerBlocks++;
            AbstractInsnNode last = lastRealBefore(mn, block.endExclusive());
            if (last instanceof LookupSwitchInsnNode ls) {
                estimatedEdges += 1 + ls.labels.size();
            } else if (last instanceof TableSwitchInsnNode ts) {
                estimatedEdges += 1 + ts.labels.size();
            } else if (last instanceof JumpInsnNode jump) {
                estimatedEdges += jump.getOpcode() == Opcodes.GOTO ? 1 : 2;
            } else if (last != null && !terminates(last.getOpcode()) && i + 1 < blocks.size()) {
                estimatedEdges++;
            }
        }
        return JvmCodeSizeEstimator.estimateMethodBytes(mn) +
            nonHandlerBlocks * JIT_BUDGET_OUTLINED_BLOCK_BYTES +
            estimatedEdges * JIT_BUDGET_OUTLINED_EDGE_BYTES +
            handlerBridges.size() * JIT_BUDGET_OUTLINED_HANDLER_BYTES;
    }

    protected boolean hasBackwardBlockEdge(MethodNode mn, List<Block> blocks) {
        Map<LabelNode, Integer> blockIndex = new IdentityHashMap<>();
        for (int i = 0; i < blocks.size(); i++) {
            blockIndex.put(blocks.get(i).label(), i);
        }
        for (int i = 0; i < blocks.size(); i++) {
            Block block = blocks.get(i);
            if (block.handler()) continue;
            AbstractInsnNode last = lastRealBefore(mn, block.endExclusive());
            if (last instanceof JumpInsnNode jump) {
                if (isBackwardBlockTarget(blockIndex, i, jump.label)) return true;
            } else if (last instanceof LookupSwitchInsnNode lookup) {
                if (isBackwardBlockTarget(blockIndex, i, lookup.dflt)) return true;
                for (LabelNode label : lookup.labels) {
                    if (isBackwardBlockTarget(blockIndex, i, label)) return true;
                }
            } else if (last instanceof TableSwitchInsnNode table) {
                if (isBackwardBlockTarget(blockIndex, i, table.dflt)) return true;
                for (LabelNode label : table.labels) {
                    if (isBackwardBlockTarget(blockIndex, i, label)) return true;
                }
            }
        }
        return false;
    }

    protected boolean isBackwardBlockTarget(
        Map<LabelNode, Integer> blockIndex,
        int sourceIndex,
        LabelNode target
    ) {
        Integer targetIndex = blockIndex.get(target);
        return targetIndex != null && targetIndex <= sourceIndex;
    }

    protected Set<LabelNode> linearZeroStackLeaders(
        MethodNode mn,
        LabelNode start,
        CffFrameAnalysis frames
    ) {
        Set<LabelNode> leaders = new HashSet<>();
        boolean active = false;
        for (
            AbstractInsnNode insn = mn.instructions.getFirst();
            insn != null;
            insn = insn.getNext()
        ) {
            if (insn == start) active = true;
            if (!active || insn.getOpcode() < 0 || isControlTransfer(insn)) {
                continue;
            }
            AbstractInsnNode next = nextReal(insn.getNext());
            if (frames.isZeroStack(next)) {
                leaders.add(ensureLabelBefore(mn, next));
            }
        }
        return leaders;
    }

    protected boolean normalizeNonZeroStackControlTargets(
        PipelineContext pctx,
        MethodNode mn,
        LabelNode start,
        CffFrameAnalysis frames
    ) {
        Map<LabelNode, StackSpill> spills = new IdentityHashMap<>();
        Map<String, StackSpill> spillsByShape = new LinkedHashMap<>();
        Map<AbstractInsnNode, EdgeStackSpill> outgoingSpills = new IdentityHashMap<>();

        for (
            AbstractInsnNode insn = start;
            insn != null;
            insn = insn.getNext()
        ) {
            EdgeTargets targets = controlEdgeTargets(mn, insn);
            if (targets.labels().isEmpty()) continue;
            StackSpill edgeSpill = null;
            for (EdgeTarget edgeTarget : targets.labels()) {
                List<BasicValue> stack = frames.stackValues(edgeTarget.framePoint());
                if (stack.isEmpty()) continue;
                StackSpill spill = spillForStackShape(mn, stack, spillsByShape);
                spills.put(edgeTarget.label(), spill);
                if (edgeSpill == null) {
                    edgeSpill = spill;
                } else if (edgeSpill != spill) {
                    throw new IllegalStateException(
                        "CFF cannot normalize divergent non-empty stack edge shapes in " +
                            mn.name +
                            mn.desc
                    );
                }
            }
            if (edgeSpill != null) {
                outgoingSpills.put(
                    insn,
                    new EdgeStackSpill(edgeSpill, targets.consumedValues())
                );
            }
        }

        if (spills.isEmpty()) {
            return false;
        }

        InsnList defaults = spillDefaults(spills);
        if (defaults.size() > 0) {
            JvmKeyDispatchPass.markGenerated(pctx, defaults);
            mn.instructions.insertBefore(start, defaults);
        }

        for (
            AbstractInsnNode insn = start;
            insn != null;
            insn = insn.getNext()
        ) {
            EdgeStackSpill edgeSpill = outgoingSpills.get(insn);
            if (edgeSpill == null) continue;
            InsnList stores = spillStoresBeforeControl(
                mn,
                insn,
                edgeSpill.spill(),
                edgeSpill.consumedValues()
            );
            JvmKeyDispatchPass.markGenerated(pctx, stores);
            mn.instructions.insertBefore(insn, stores);
        }

        for (Map.Entry<LabelNode, StackSpill> entry : spills.entrySet()) {
            LabelNode target = entry.getKey();
            StackSpill spill = entry.getValue();
            AbstractInsnNode previous = previousReal(target.getPrevious());
            if (previous != null && !isControlTransfer(previous)) {
                InsnList stores = spillStores(spill);
                JvmKeyDispatchPass.markGenerated(pctx, stores);
                mn.instructions.insertBefore(target, stores);
            }
            InsnList loads = spillLoads(spill);
            JvmKeyDispatchPass.markGenerated(pctx, loads);
            AbstractInsnNode real = nextReal(target.getNext());
            if (real == null) {
                mn.instructions.add(loads);
            } else {
                mn.instructions.insertBefore(real, loads);
            }
        }
        mn.maxStack += Math.max(1, maxSpillSlots(spills));
        return true;
    }

    protected InsnList spillDefaults(Map<LabelNode, StackSpill> spills) {
        InsnList insns = new InsnList();
        Set<StackSpill> seen = Collections.newSetFromMap(new IdentityHashMap<StackSpill, Boolean>());
        for (StackSpill spill : spills.values()) {
            if (!seen.add(spill)) continue;
            for (int i = 0; i < spill.values().size(); i++) {
                emitSpillDefault(insns, spill.values().get(i), spill.locals()[i]);
            }
        }
        return insns;
    }

    protected void emitSpillDefault(InsnList insns, BasicValue value, int local) {
        Type type = value.getType();
        if (type == null) {
            insns.add(new InsnNode(Opcodes.ICONST_0));
            insns.add(new VarInsnNode(Opcodes.ISTORE, local));
            return;
        }
        switch (type.getSort()) {
            case Type.LONG -> {
                insns.add(new InsnNode(Opcodes.LCONST_0));
                insns.add(new VarInsnNode(Opcodes.LSTORE, local));
            }
            case Type.FLOAT -> {
                insns.add(new InsnNode(Opcodes.FCONST_0));
                insns.add(new VarInsnNode(Opcodes.FSTORE, local));
            }
            case Type.DOUBLE -> {
                insns.add(new InsnNode(Opcodes.DCONST_0));
                insns.add(new VarInsnNode(Opcodes.DSTORE, local));
            }
            case Type.ARRAY, Type.OBJECT -> {
                insns.add(new InsnNode(Opcodes.ACONST_NULL));
                insns.add(new VarInsnNode(Opcodes.ASTORE, local));
            }
            default -> {
                insns.add(new InsnNode(Opcodes.ICONST_0));
                insns.add(new VarInsnNode(Opcodes.ISTORE, local));
            }
        }
    }

    protected EdgeTargets controlEdgeTargets(
        MethodNode mn,
        AbstractInsnNode insn
    ) {
        int opcode = insn.getOpcode();
        if (insn instanceof JumpInsnNode jump) {
            List<EdgeTarget> labels = new ArrayList<>();
            labels.add(new EdgeTarget(jump.label, jump.label));
            if (opcode != Opcodes.GOTO) {
                AbstractInsnNode next = nextReal(insn.getNext());
                if (next != null) {
                    labels.add(new EdgeTarget(ensureLabelBefore(mn, next), next));
                }
            }
            return new EdgeTargets(labels, consumedStackValueCount(opcode));
        }
        if (insn instanceof LookupSwitchInsnNode ls) {
            List<EdgeTarget> labels = new ArrayList<>();
            labels.add(new EdgeTarget(ls.dflt, ls.dflt));
            for (LabelNode label : ls.labels) {
                labels.add(new EdgeTarget(label, label));
            }
            return new EdgeTargets(labels, 1);
        }
        if (insn instanceof TableSwitchInsnNode ts) {
            List<EdgeTarget> labels = new ArrayList<>();
            labels.add(new EdgeTarget(ts.dflt, ts.dflt));
            for (LabelNode label : ts.labels) {
                labels.add(new EdgeTarget(label, label));
            }
            return new EdgeTargets(labels, 1);
        }
        return new EdgeTargets(List.of(), 0);
    }

    protected int consumedStackValueCount(int opcode) {
        return switch (opcode) {
            case Opcodes.GOTO -> 0;
            case Opcodes.IFEQ,
                Opcodes.IFNE,
                Opcodes.IFLT,
                Opcodes.IFGE,
                Opcodes.IFGT,
                Opcodes.IFLE,
                Opcodes.IFNULL,
                Opcodes.IFNONNULL -> 1;
            case Opcodes.IF_ICMPEQ,
                Opcodes.IF_ICMPNE,
                Opcodes.IF_ICMPLT,
                Opcodes.IF_ICMPGE,
                Opcodes.IF_ICMPGT,
                Opcodes.IF_ICMPLE,
                Opcodes.IF_ACMPEQ,
                Opcodes.IF_ACMPNE -> 2;
            default -> 0;
        };
    }

    protected StackSpill spillForStackShape(
        MethodNode mn,
        List<BasicValue> stack,
        Map<String, StackSpill> spillsByShape
    ) {
        String signature = stackShapeSignature(stack);
        StackSpill existing = spillsByShape.get(signature);
        if (existing != null) return existing;
        StackSpill spill = allocateStackSpill(mn, stack);
        spillsByShape.put(signature, spill);
        return spill;
    }

    protected String stackShapeSignature(List<BasicValue> stack) {
        StringBuilder signature = new StringBuilder();
        for (BasicValue value : stack) {
            Type type = value.getType();
            signature
                .append(value.getSize())
                .append(':')
                .append(type == null ? "?" : type.getDescriptor())
                .append(';');
        }
        return signature.toString();
    }

    protected InsnList spillStoresBeforeControl(
        MethodNode mn,
        AbstractInsnNode control,
        StackSpill spill,
        int consumedValues
    ) {
        BranchOperand[] operands = branchOperands(control, consumedValues);
        int[] operandLocals = allocateOperandLocals(mn, operands);
        InsnList insns = new InsnList();
        for (int i = operands.length - 1; i >= 0; i--) {
            insns.add(new VarInsnNode(operands[i].storeOpcode(), operandLocals[i]));
        }
        insns.add(spillStores(spill));
        for (int i = 0; i < operands.length; i++) {
            insns.add(new VarInsnNode(operands[i].loadOpcode(), operandLocals[i]));
        }
        return insns;
    }

    protected BranchOperand[] branchOperands(AbstractInsnNode control, int consumedValues) {
        int opcode = control.getOpcode();
        if (consumedValues == 0) return new BranchOperand[0];
        if (control instanceof LookupSwitchInsnNode || control instanceof TableSwitchInsnNode) {
            return new BranchOperand[] { BranchOperand.INT };
        }
        return switch (opcode) {
            case Opcodes.IFEQ,
                Opcodes.IFNE,
                Opcodes.IFLT,
                Opcodes.IFGE,
                Opcodes.IFGT,
                Opcodes.IFLE -> new BranchOperand[] { BranchOperand.INT };
            case Opcodes.IFNULL,
                Opcodes.IFNONNULL -> new BranchOperand[] { BranchOperand.REF };
            case Opcodes.IF_ICMPEQ,
                Opcodes.IF_ICMPNE,
                Opcodes.IF_ICMPLT,
                Opcodes.IF_ICMPGE,
                Opcodes.IF_ICMPGT,
                Opcodes.IF_ICMPLE -> new BranchOperand[] {
                    BranchOperand.INT,
                    BranchOperand.INT,
                };
            case Opcodes.IF_ACMPEQ,
                Opcodes.IF_ACMPNE -> new BranchOperand[] {
                    BranchOperand.REF,
                    BranchOperand.REF,
                };
            default -> throw new IllegalStateException(
                "CFF cannot normalize unsupported non-empty stack branch opcode: " +
                    opcode
            );
        };
    }

    protected int[] allocateOperandLocals(MethodNode mn, BranchOperand[] operands) {
        int[] locals = new int[operands.length];
        int nextLocal = mn.maxLocals;
        for (int i = 0; i < operands.length; i++) {
            locals[i] = nextLocal;
            nextLocal += operands[i].size();
        }
        mn.maxLocals = Math.max(mn.maxLocals, nextLocal);
        return locals;
    }

    protected StackSpill allocateStackSpill(MethodNode mn, List<BasicValue> stack) {
        int[] locals = new int[stack.size()];
        int nextLocal = mn.maxLocals;
        for (int i = 0; i < stack.size(); i++) {
            BasicValue value = stack.get(i);
            locals[i] = nextLocal;
            nextLocal += Math.max(1, value.getSize());
        }
        mn.maxLocals = Math.max(mn.maxLocals, nextLocal);
        return new StackSpill(List.copyOf(stack), locals);
    }

    protected InsnList spillStores(StackSpill spill) {
        InsnList insns = new InsnList();
        for (int i = spill.values().size() - 1; i >= 0; i--) {
            insns.add(new VarInsnNode(storeOpcode(spill.values().get(i)), spill.locals()[i]));
        }
        return insns;
    }

    protected InsnList spillLoads(StackSpill spill) {
        InsnList insns = new InsnList();
        for (int i = 0; i < spill.values().size(); i++) {
            insns.add(new VarInsnNode(loadOpcode(spill.values().get(i)), spill.locals()[i]));
        }
        return insns;
    }

    protected int maxSpillSlots(Map<LabelNode, StackSpill> spills) {
        int max = 0;
        Set<StackSpill> seen = Collections.newSetFromMap(new IdentityHashMap<StackSpill, Boolean>());
        for (StackSpill spill : spills.values()) {
            if (!seen.add(spill)) continue;
            int slots = 0;
            for (BasicValue value : spill.values()) {
                slots += Math.max(1, value.getSize());
            }
            max = Math.max(max, slots);
        }
        return max;
    }

    protected int storeOpcode(BasicValue value) {
        return typedOpcode(value, Opcodes.ISTORE);
    }

    protected int loadOpcode(BasicValue value) {
        return typedOpcode(value, Opcodes.ILOAD);
    }

    protected int typedOpcode(BasicValue value, int baseOpcode) {
        Type type = value.getType();
        if (type == null) {
            return baseOpcode;
        }
        return type.getOpcode(baseOpcode);
    }

    protected boolean allSwitchTargetsZero(
        LabelNode dflt,
        List<LabelNode> labels,
        Set<LabelNode> zeroStackLabels
    ) {
        if (!isZeroStackLabel(dflt, zeroStackLabels)) return false;
        for (LabelNode label : labels) {
            if (!isZeroStackLabel(label, zeroStackLabels)) return false;
        }
        return true;
    }

    protected void insertHandlerBridges(
        MethodNode mn,
        List<HandlerBridge> handlerBridges,
        int exceptionLocal,
        int keyLocal,
        int guardLocal,
        int pathKeyLocal,
        int blockKeyLocal,
        int pcLocal,
        int domainLocal,
        int dataLocal,
        int keyTmpLocal,
        int methodSeedLocal,
        Map<LabelNode, Integer> stateByLabel,
        Map<LabelNode, CffBlockKeyState> keyStateByLabel,
        Map<LabelNode, DispatchTarget> dispatchByLabel,
        Map<DispatchTarget, Long> dispatchSeedByTarget,
        Set<LabelNode> runtimeKeyLabels,
        long methodSeed,
        long salt,
        CffTransitionOutliner.TransitionOutliner dispatcherOutliner,
        CffTransitionOutliner.TransitionOutliner transitionOutliner
    ) {
        if (handlerBridges.isEmpty()) return;
        for (HandlerBridge bridge : handlerBridges) {
            LabelNode handler = bridge.handler();
            LabelNode body = bridge.body();
            Integer bodyState = labelValue(stateByLabel, body);
            DispatchTarget bodyTarget = requireTarget(body, labelValue(dispatchByLabel, body));
            long edgeSeed = edgeSeed(salt, handler, body, 0x45584348414E444CL);
            InsnList prefix = new InsnList();
            prefix.add(new VarInsnNode(Opcodes.ASTORE, exceptionLocal));
            prefix.add(new VarInsnNode(Opcodes.LLOAD, methodSeedLocal));
            prefix.add(new VarInsnNode(Opcodes.LSTORE, keyLocal));
            emitInitKeys(
                prefix,
                guardLocal,
                pathKeyLocal,
                blockKeyLocal,
                keyLocal,
                methodSeed ^ salt,
                keyTmpLocal
            );
            CffBlockKeyState initialHandlerKeys = initialKeyState(methodSeed, methodSeed ^ salt);
            emitEncryptedToken(
                prefix,
                initialHandlerKeys.pcToken(),
                initialHandlerKeys,
                guardLocal,
                pathKeyLocal,
                blockKeyLocal,
                edgeSeed ^ 0x48494E4954504331L,
                keyTmpLocal
            );
            prefix.add(new VarInsnNode(Opcodes.ISTORE, pcLocal));
            emitStoreMethodKey(
                prefix,
                keyLocal,
                guardLocal,
                pathKeyLocal,
                blockKeyLocal,
                pcLocal,
                initialHandlerKeys
            );
            CffBlockKeyState handlerSourceKeys = syntheticHandlerSourceKey(
                methodSeed,
                salt,
                bridge.handler()
            );
            emitDecodeBlockKeys(
                prefix,
                keyLocal,
                guardLocal,
                pathKeyLocal,
                blockKeyLocal,
                pcLocal,
                keyTmpLocal,
                keyTmpLocal + 3,
                initialHandlerKeys,
                handlerSourceKeys,
                methodSeed,
                edgeSeed ^ 0x48414E444C455249L,
                EdgeRole.HANDLER
            );
            emitEncryptedToken(
                prefix,
                handlerSourceKeys.pcToken(),
                handlerSourceKeys,
                guardLocal,
                pathKeyLocal,
                blockKeyLocal,
                edgeSeed ^ 0x48414E44504331L,
                keyTmpLocal
            );
            prefix.add(new VarInsnNode(Opcodes.ISTORE, pcLocal));
            emitStoreMethodKey(
                prefix,
                keyLocal,
                guardLocal,
                pathKeyLocal,
                blockKeyLocal,
                pcLocal,
                handlerSourceKeys
            );
            if (bridge.catchLocal() >= 0) {
                prefix.add(new VarInsnNode(Opcodes.ALOAD, exceptionLocal));
                prefix.add(new VarInsnNode(Opcodes.ASTORE, bridge.catchLocal()));
            }
            emitStoreDomain(
                prefix,
                domainLocal,
                guardLocal,
                pathKeyLocal,
                blockKeyLocal,
                keyLocal,
                bodyTarget.island(),
                bodyTarget.domainToken(),
                handlerSourceKeys,
                methodSeed,
                bodyTarget.domainSeed(),
                keyTmpLocal
            );
            if (dispatcherOutliner != null) {
                emitInitTransitionOut(prefix, dispatcherOutliner.outLocal());
            }
            prefix.add(
                transition(
                    requireState(body, bodyState),
                    bodyTarget,
                    keyLocal,
                    guardLocal,
                    pathKeyLocal,
                    blockKeyLocal,
                    pcLocal,
                    domainLocal,
                    dataLocal,
                    keyTmpLocal,
                    requireDispatchSeed(bodyTarget, dispatchSeedByTarget),
                    handlerSourceKeys,
                    requireBlockKey(body, labelValue(keyStateByLabel, body)),
                    methodSeed,
                    edgeSeed,
                    runtimeKeyLabels.contains(body),
                    EdgeRole.HANDLER,
                    transitionOutliner
                )
            );
            mn.instructions.insert(handler, prefix);
        }
    }
}

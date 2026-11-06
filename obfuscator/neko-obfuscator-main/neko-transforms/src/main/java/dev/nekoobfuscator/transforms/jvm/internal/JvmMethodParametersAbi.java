package dev.nekoobfuscator.transforms.jvm.internal;

import dev.nekoobfuscator.core.ir.l1.L1Class;
import dev.nekoobfuscator.core.ir.l1.L1Method;
import dev.nekoobfuscator.core.pipeline.PipelineContext;
import dev.nekoobfuscator.transforms.util.TransformGuards;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.AnalyzerException;
import org.objectweb.asm.tree.analysis.Frame;
import org.objectweb.asm.tree.analysis.SourceInterpreter;
import org.objectweb.asm.tree.analysis.SourceValue;

import java.util.LinkedHashSet;
import java.util.Set;

public final class JvmMethodParametersAbi {
    private static final String OBSERVED_METHODS = "jvm.methodParametersAbi.observedMethods";
    private static final int SOURCE_ANALYSIS_MIN_MAX_STACK = 64;
    private static final int SOURCE_ANALYSIS_MAX_MAX_STACK = 4096;

    private JvmMethodParametersAbi() {
    }

    public static boolean isObservedMethodParametersMethod(PipelineContext pctx, L1Class clazz, L1Method method) {
        if (pctx == null || clazz == null || method == null) return false;
        if (method.asmNode().parameters == null || method.asmNode().parameters.isEmpty()) return false;
        return observedMethods(pctx).contains(key(clazz.name(), method.name(), method.descriptor()));
    }

    public static boolean isObservedMethodParametersLookup(
        PipelineContext pctx,
        String owner,
        String name,
        Type[] parameterTypes,
        boolean publicLookup
    ) {
        if (pctx == null || owner == null || name == null || parameterTypes == null) return false;
        L1Class targetClass = pctx.classMap().get(owner);
        if (targetClass == null) return false;
        Set<String> observed = observedMethods(pctx);
        for (L1Method candidate : targetClass.methods()) {
            MethodNode node = candidate.asmNode();
            if (!name.equals(candidate.name())) continue;
            if (publicLookup && (node.access & Opcodes.ACC_PUBLIC) == 0) continue;
            if (!sameTypes(Type.getArgumentTypes(candidate.descriptor()), parameterTypes)) continue;
            if (observed.contains(key(targetClass.name(), candidate.name(), candidate.descriptor()))) return true;
        }
        return false;
    }

    public static boolean isMethodParametersObserverLookup(
        PipelineContext pctx,
        MethodNode observer,
        String owner,
        String name,
        Type[] parameterTypes,
        boolean publicLookup
    ) {
        if (!callsGetParameters(observer)) return false;
        return targetsMethodWithParameterMetadata(pctx, owner, name, parameterTypes, publicLookup);
    }

    private static Set<String> observedMethods(PipelineContext pctx) {
        Set<String> cached = pctx.getPassData(OBSERVED_METHODS);
        if (cached != null) return cached;
        Set<String> observed = new LinkedHashSet<>();
        for (L1Class clazz : pctx.classMap().values()) {
            if (TransformGuards.isRuntimeClass(clazz)) continue;
            for (L1Method method : clazz.methods()) {
                MethodNode mn = method.asmNode();
                if (!method.hasCode() || TransformGuards.isGeneratedMethod(method) || !callsGetParameters(mn)) {
                    continue;
                }
                collectObservedMethods(pctx, clazz, mn, observed);
            }
        }
        Set<String> immutable = Set.copyOf(observed);
        pctx.putPassData(OBSERVED_METHODS, immutable);
        return immutable;
    }

    private static boolean callsGetParameters(MethodNode mn) {
        if (mn == null || mn.instructions == null) return false;
        for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof MethodInsnNode call && isGetParameters(call)) return true;
        }
        return false;
    }

    private static boolean targetsMethodWithParameterMetadata(
        PipelineContext pctx,
        String owner,
        String name,
        Type[] parameterTypes,
        boolean publicLookup
    ) {
        if (pctx == null || owner == null || name == null) return false;
        L1Class targetClass = pctx.classMap().get(owner);
        if (targetClass == null) return false;
        boolean matchedUnknownParameters = false;
        for (L1Method candidate : targetClass.methods()) {
            MethodNode node = candidate.asmNode();
            if (!name.equals(candidate.name())) continue;
            if (publicLookup && (node.access & Opcodes.ACC_PUBLIC) == 0) continue;
            if (node.parameters == null || node.parameters.isEmpty()) continue;
            if (parameterTypes == null) {
                if (matchedUnknownParameters) return false;
                matchedUnknownParameters = true;
                continue;
            }
            if (sameTypes(Type.getArgumentTypes(candidate.descriptor()), parameterTypes)) return true;
        }
        return matchedUnknownParameters;
    }

    private static void collectObservedMethods(
        PipelineContext pctx,
        L1Class observerClass,
        MethodNode mn,
        Set<String> observed
    ) {
        try {
            Frame<SourceValue>[] frames = analyzeSourceValues(observerClass.name(), mn);
            for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (!(insn instanceof MethodInsnNode call) || !isGetParameters(call)) continue;
                int index = mn.instructions.indexOf(call);
                if (index < 0 || index >= frames.length) continue;
                Frame<SourceValue> frame = frames[index];
                if (frame == null || frame.getStackSize() == 0) continue;
                ExecutableLookup lookup = sourceExecutableLookupTarget(
                    pctx,
                    mn,
                    frames,
                    frame.getStack(frame.getStackSize() - 1),
                    0
                );
                addObservedTarget(pctx, lookup, observed);
            }
            collectSameMethodLookupTargets(pctx, mn, frames, observed);
        } catch (AnalyzerException | RuntimeException ignored) {
            // Unknown provenance is intentionally not promoted to an ABI exemption.
        }
    }

    private static void collectSameMethodLookupTargets(
        PipelineContext pctx,
        MethodNode mn,
        Frame<SourceValue>[] frames,
        Set<String> observed
    ) {
        for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (!(insn instanceof MethodInsnNode call)) continue;
            if (isReflectionMethodLookup(call)) {
                addObservedTarget(pctx, sourceReflectiveMethodLookup(pctx, mn, frames, call), observed);
            } else if (isReflectionConstructorLookup(call)) {
                addObservedTarget(pctx, sourceReflectiveConstructorLookup(pctx, mn, frames, call), observed);
            }
        }
    }

    private static void addObservedTarget(PipelineContext pctx, ExecutableLookup lookup, Set<String> observed) {
        if (lookup == null || lookup.owner() == null || lookup.name() == null) {
            return;
        }
        L1Class targetClass = pctx.classMap().get(lookup.owner());
        if (targetClass == null) return;
        String matched = null;
        for (L1Method candidate : targetClass.methods()) {
            if (!lookup.name().equals(candidate.name())) continue;
            if (candidate.asmNode().parameters == null || candidate.asmNode().parameters.isEmpty()) continue;
            if (lookup.parameterTypes() != null) {
                Type[] candidateArgs = Type.getArgumentTypes(candidate.descriptor());
                if (!sameTypes(candidateArgs, lookup.parameterTypes())) continue;
            }
            String candidateKey = key(targetClass.name(), candidate.name(), candidate.descriptor());
            if (lookup.parameterTypes() != null) {
                observed.add(candidateKey);
                continue;
            }
            if (matched != null) return;
            matched = candidateKey;
        }
        if (matched != null) {
            observed.add(matched);
        }
    }

    private static ExecutableLookup sourceExecutableLookupTarget(
        PipelineContext pctx,
        MethodNode mn,
        Frame<SourceValue>[] frames,
        SourceValue value,
        int depth
    ) {
        if (value == null || depth > 6) return null;
        ExecutableLookup result = null;
        for (AbstractInsnNode insn : value.insns) {
            ExecutableLookup sourced = null;
            if (insn instanceof MethodInsnNode call) {
                if (isReflectionMethodLookup(call)) {
                    sourced = sourceReflectiveMethodLookup(pctx, mn, frames, call);
                } else if (isReflectionConstructorLookup(call)) {
                    sourced = sourceReflectiveConstructorLookup(pctx, mn, frames, call);
                }
            } else if (insn instanceof VarInsnNode var && var.getOpcode() == Opcodes.ALOAD) {
                sourced = sourceExecutableLookupTarget(
                    pctx,
                    mn,
                    frames,
                    storedLocalValue(mn, frames, var),
                    depth + 1
                );
            } else if (insn instanceof TypeInsnNode type && type.getOpcode() == Opcodes.CHECKCAST) {
                int index = mn.instructions.indexOf(type);
                if (index >= 0 && index < frames.length) {
                    Frame<SourceValue> frame = frames[index];
                    if (frame != null && frame.getStackSize() > 0) {
                        sourced = sourceExecutableLookupTarget(
                            pctx,
                            mn,
                            frames,
                            frame.getStack(frame.getStackSize() - 1),
                            depth + 1
                        );
                    }
                }
            }
            if (sourced == null) return null;
            if (result != null && !result.equals(sourced)) return null;
            result = sourced;
        }
        return result;
    }

    private static ExecutableLookup sourceReflectiveMethodLookup(
        PipelineContext pctx,
        MethodNode mn,
        Frame<SourceValue>[] frames,
        MethodInsnNode call
    ) {
        int index = mn.instructions.indexOf(call);
        if (index < 0 || index >= frames.length) return null;
        Frame<SourceValue> frame = frames[index];
        if (frame == null || frame.getStackSize() < 3) return null;
        int top = frame.getStackSize();
        String owner = sourceClassObjectOwner(pctx, mn, frames, frame.getStack(top - 3), 0);
        String name = literalString(mn, frames, frame.getStack(top - 2), 0);
        Type[] params = sourceClassArrayParameterTypes(pctx, mn, frames, call, frame.getStack(top - 1), 0);
        return owner == null || name == null ? null : new ExecutableLookup(owner, name, params);
    }

    private static ExecutableLookup sourceReflectiveConstructorLookup(
        PipelineContext pctx,
        MethodNode mn,
        Frame<SourceValue>[] frames,
        MethodInsnNode call
    ) {
        int index = mn.instructions.indexOf(call);
        if (index < 0 || index >= frames.length) return null;
        Frame<SourceValue> frame = frames[index];
        if (frame == null || frame.getStackSize() < 2) return null;
        int top = frame.getStackSize();
        String owner = sourceClassObjectOwner(pctx, mn, frames, frame.getStack(top - 2), 0);
        Type[] params = sourceClassArrayParameterTypes(pctx, mn, frames, call, frame.getStack(top - 1), 0);
        return owner == null ? null : new ExecutableLookup(owner, "<init>", params);
    }

    private static Type[] sourceClassArrayParameterTypes(
        PipelineContext pctx,
        MethodNode mn,
        Frame<SourceValue>[] frames,
        MethodInsnNode consumerCall,
        SourceValue arrayValue,
        int depth
    ) {
        if (arrayValue == null || depth > 6) return null;
        Type[] result = null;
        for (AbstractInsnNode insn : arrayValue.insns) {
            Type[] sourced = null;
            if (insn.getOpcode() == Opcodes.ACONST_NULL) {
                sourced = new Type[0];
            } else if (insn instanceof TypeInsnNode type
                && type.getOpcode() == Opcodes.ANEWARRAY
                && "java/lang/Class".equals(type.desc)) {
                sourced = sourceClassArrayParameterTypesFromAllocation(
                    pctx,
                    mn,
                    frames,
                    consumerCall,
                    type
                );
            } else if (insn instanceof VarInsnNode var && var.getOpcode() == Opcodes.ALOAD) {
                sourced = sourceClassArrayParameterTypes(
                    pctx,
                    mn,
                    frames,
                    consumerCall,
                    storedLocalValue(mn, frames, var),
                    depth + 1
                );
            } else if (insn instanceof TypeInsnNode type && type.getOpcode() == Opcodes.CHECKCAST) {
                int index = mn.instructions.indexOf(type);
                if (index >= 0 && index < frames.length) {
                    Frame<SourceValue> frame = frames[index];
                    if (frame != null && frame.getStackSize() > 0) {
                        sourced = sourceClassArrayParameterTypes(
                            pctx,
                            mn,
                            frames,
                            consumerCall,
                            frame.getStack(frame.getStackSize() - 1),
                            depth + 1
                        );
                    }
                }
            } else if (insn.getOpcode() == Opcodes.DUP) {
                int index = mn.instructions.indexOf(insn);
                if (index >= 0 && index < frames.length) {
                    Frame<SourceValue> frame = frames[index];
                    if (frame != null && frame.getStackSize() > 0) {
                        sourced = sourceClassArrayParameterTypes(
                            pctx,
                            mn,
                            frames,
                            consumerCall,
                            frame.getStack(frame.getStackSize() - 1),
                            depth + 1
                        );
                    }
                }
            } else if (isClassArraySourceBookkeeping(insn)) {
                continue;
            }
            if (sourced == null) return null;
            if (result != null && !sameTypes(result, sourced)) return null;
            result = sourced;
        }
        return result;
    }

    private static Type[] sourceClassArrayParameterTypesFromAllocation(
        PipelineContext pctx,
        MethodNode mn,
        Frame<SourceValue>[] frames,
        MethodInsnNode consumerCall,
        TypeInsnNode allocation
    ) {
        int allocationIndex = mn.instructions.indexOf(allocation);
        int consumerIndex = mn.instructions.indexOf(consumerCall);
        if (allocationIndex < 0 || consumerIndex <= allocationIndex || allocationIndex >= frames.length) {
            return null;
        }
        Frame<SourceValue> allocationFrame = frames[allocationIndex];
        if (allocationFrame == null || allocationFrame.getStackSize() == 0) return null;
        Integer length = literalInt(
            mn,
            frames,
            allocationFrame.getStack(allocationFrame.getStackSize() - 1),
            0
        );
        if (length == null || length < 0 || length > 256) return null;
        Type[] types = new Type[length];
        boolean[] seen = new boolean[length];
        for (AbstractInsnNode scan = allocation.getNext(); scan != null && scan != consumerCall; scan = scan.getNext()) {
            if (!(scan instanceof InsnNode store) || store.getOpcode() != Opcodes.AASTORE) continue;
            int storeIndex = mn.instructions.indexOf(store);
            if (storeIndex < 0 || storeIndex >= frames.length) return null;
            Frame<SourceValue> frame = frames[storeIndex];
            if (frame == null || frame.getStackSize() < 3) return null;
            SourceValue arrayRef = frame.getStack(frame.getStackSize() - 3);
            if (!sourceMayAliasInstruction(mn, frames, arrayRef, allocation, 0)) continue;
            Integer slot = literalInt(mn, frames, frame.getStack(frame.getStackSize() - 2), 0);
            Type type = literalClassType(mn, frames, frame.getStack(frame.getStackSize() - 1), 0);
            if (slot == null || slot < 0 || slot >= types.length || type == null) return null;
            if (seen[slot] && !types[slot].equals(type)) return null;
            types[slot] = type;
            seen[slot] = true;
        }
        for (boolean slotSeen : seen) {
            if (!slotSeen) return null;
        }
        return types;
    }

    private static String sourceClassObjectOwner(
        PipelineContext pctx,
        MethodNode mn,
        Frame<SourceValue>[] frames,
        SourceValue value,
        int depth
    ) {
        if (value == null || depth > 6) return null;
        String owner = null;
        for (AbstractInsnNode insn : value.insns) {
            String sourced = null;
            if (insn instanceof LdcInsnNode ldc &&
                ldc.cst instanceof Type type &&
                type.getSort() == Type.OBJECT) {
                sourced = type.getInternalName();
            } else if (insn instanceof MethodInsnNode call && returnsClassObject(call)) {
                sourced = sourceClassObjectOwnerFromProducingCall(pctx, mn, frames, call, depth + 1);
            } else if (insn instanceof VarInsnNode var && var.getOpcode() == Opcodes.ALOAD) {
                sourced = sourceClassObjectOwner(pctx, mn, frames, storedLocalValue(mn, frames, var), depth + 1);
            } else if (insn instanceof TypeInsnNode type && type.getOpcode() == Opcodes.CHECKCAST) {
                int index = mn.instructions.indexOf(type);
                if (index >= 0 && index < frames.length) {
                    Frame<SourceValue> frame = frames[index];
                    if (frame != null && frame.getStackSize() > 0) {
                        sourced = sourceClassObjectOwner(
                            pctx,
                            mn,
                            frames,
                            frame.getStack(frame.getStackSize() - 1),
                            depth + 1
                        );
                    }
                }
            }
            if (sourced == null) return null;
            if (owner != null && !owner.equals(sourced)) return null;
            owner = sourced;
        }
        return owner;
    }

    private static String sourceClassObjectOwnerFromProducingCall(
        PipelineContext pctx,
        MethodNode mn,
        Frame<SourceValue>[] frames,
        MethodInsnNode call,
        int depth
    ) {
        int index = mn.instructions.indexOf(call);
        if (index < 0 || index >= frames.length) return null;
        Frame<SourceValue> frame = frames[index];
        Type[] args = Type.getArgumentTypes(call.desc);
        int receiverSlots = call.getOpcode() == Opcodes.INVOKESTATIC ? 0 : 1;
        int base = frame == null ? -1 : frame.getStackSize() - args.length - receiverSlots;
        if (base < 0) return null;
        if ("java/lang/Class".equals(call.owner)
            && "forName".equals(call.name)
            && call.desc.startsWith("(Ljava/lang/String;")) {
            return normalizedClassName(pctx, literalString(mn, frames, frame.getStack(base), depth + 1));
        }
        if (args.length == 1
            && "Ljava/lang/String;".equals(args[0].getDescriptor())
            && ("loadClass".equals(call.name) || "findClass".equals(call.name))) {
            return normalizedClassName(
                pctx,
                literalString(mn, frames, frame.getStack(base + receiverSlots), depth + 1)
            );
        }
        return null;
    }

    private static Type literalClassType(
        MethodNode mn,
        Frame<SourceValue>[] frames,
        SourceValue value,
        int depth
    ) {
        if (value == null || depth > 4) return null;
        Type result = null;
        for (AbstractInsnNode insn : value.insns) {
            Type sourced = classConstant(insn);
            if (insn instanceof VarInsnNode var && var.getOpcode() == Opcodes.ALOAD) {
                sourced = literalClassType(mn, frames, storedLocalValue(mn, frames, var), depth + 1);
            }
            if (sourced == null) return null;
            if (result != null && !result.equals(sourced)) return null;
            result = sourced;
        }
        return result;
    }

    private static String literalString(
        MethodNode mn,
        Frame<SourceValue>[] frames,
        SourceValue value,
        int depth
    ) {
        if (value == null || depth > 4) return null;
        String string = null;
        for (AbstractInsnNode insn : value.insns) {
            String sourced = null;
            if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof String valueString) {
                sourced = valueString;
            } else if (insn instanceof VarInsnNode var && var.getOpcode() == Opcodes.ALOAD) {
                sourced = literalString(mn, frames, storedLocalValue(mn, frames, var), depth + 1);
            }
            if (sourced == null) return null;
            if (string != null && !string.equals(sourced)) return null;
            string = sourced;
        }
        return string;
    }

    private static Integer literalInt(
        MethodNode mn,
        Frame<SourceValue>[] frames,
        SourceValue value,
        int depth
    ) {
        if (value == null || depth > 4) return null;
        Integer result = null;
        for (AbstractInsnNode insn : value.insns) {
            Integer sourced = intConstant(insn);
            if (insn instanceof VarInsnNode var && var.getOpcode() == Opcodes.ILOAD) {
                sourced = literalInt(mn, frames, storedLocalValue(mn, frames, var), depth + 1);
            }
            if (sourced == null) return null;
            if (result != null && !result.equals(sourced)) return null;
            result = sourced;
        }
        return result;
    }

    private static SourceValue storedLocalValue(
        MethodNode mn,
        Frame<SourceValue>[] frames,
        VarInsnNode load
    ) {
        int loadIndex = mn.instructions.indexOf(load);
        if (loadIndex < 0 || loadIndex >= frames.length) return null;
        Frame<SourceValue> frame = frames[loadIndex];
        if (frame == null || load.var < 0 || load.var >= frame.getLocals()) return null;
        SourceValue local = frame.getLocal(load.var);
        return storedLocalValueFromFrame(mn, frames, local, storeOpcodeForLoad(load.getOpcode()), 0);
    }

    private static SourceValue storedLocalValueFromFrame(
        MethodNode mn,
        Frame<SourceValue>[] frames,
        SourceValue local,
        int storeOpcode,
        int depth
    ) {
        if (local == null || depth > 4) return null;
        if (storeOpcode < 0) return local;
        Set<AbstractInsnNode> merged = new LinkedHashSet<>();
        boolean sawStore = false;
        for (AbstractInsnNode insn : local.insns) {
            if (insn instanceof VarInsnNode store && store.getOpcode() == storeOpcode) {
                int storeIndex = mn.instructions.indexOf(store);
                if (storeIndex < 0 || storeIndex >= frames.length) return null;
                Frame<SourceValue> storeFrame = frames[storeIndex];
                if (storeFrame == null || storeFrame.getStackSize() == 0) return null;
                SourceValue stored = storeFrame.getStack(storeFrame.getStackSize() - 1);
                SourceValue resolved = storedLocalValueFromFrame(
                    mn,
                    frames,
                    stored,
                    storeOpcode,
                    depth + 1
                );
                if (resolved == null) return null;
                merged.addAll(resolved.insns);
                sawStore = true;
            } else {
                merged.add(insn);
            }
        }
        return sawStore ? new SourceValue(local.getSize(), merged) : local;
    }

    private static boolean sourceMayAliasInstruction(
        MethodNode mn,
        Frame<SourceValue>[] frames,
        SourceValue value,
        AbstractInsnNode target,
        int depth
    ) {
        if (value == null || depth > 12) return false;
        for (AbstractInsnNode insn : value.insns) {
            if (insn == target) return true;
            if (insn instanceof VarInsnNode var && var.getOpcode() == Opcodes.ALOAD) {
                if (sourceMayAliasInstruction(
                    mn,
                    frames,
                    storedLocalValue(mn, frames, var),
                    target,
                    depth + 1
                )) {
                    return true;
                }
            } else if (insn instanceof TypeInsnNode type && type.getOpcode() == Opcodes.CHECKCAST) {
                int index = mn.instructions.indexOf(type);
                if (index >= 0 && index < frames.length) {
                    Frame<SourceValue> frame = frames[index];
                    if (frame != null && frame.getStackSize() > 0 &&
                        sourceMayAliasInstruction(
                            mn,
                            frames,
                            frame.getStack(frame.getStackSize() - 1),
                            target,
                            depth + 1
                        )) {
                        return true;
                    }
                }
            } else if (insn.getOpcode() == Opcodes.DUP) {
                int index = mn.instructions.indexOf(insn);
                if (index >= 0 && index < frames.length) {
                    Frame<SourceValue> frame = frames[index];
                    if (frame != null && frame.getStackSize() > 0 &&
                        sourceMayAliasInstruction(
                            mn,
                            frames,
                            frame.getStack(frame.getStackSize() - 1),
                            target,
                            depth + 1
                        )) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private static Frame<SourceValue>[] analyzeSourceValues(String owner, MethodNode mn) throws AnalyzerException {
        ensureAnalysisMaxStack(mn);
        while (true) {
            try {
                return new Analyzer<>(new SourceInterpreter()).analyze(owner, mn);
            } catch (AnalyzerException ex) {
                if (!raiseAnalysisMaxStackAfter(ex, mn)) throw ex;
            }
        }
    }

    private static void ensureAnalysisMaxStack(MethodNode mn) {
        if (mn.maxStack < SOURCE_ANALYSIS_MIN_MAX_STACK) {
            mn.maxStack = SOURCE_ANALYSIS_MIN_MAX_STACK;
        }
    }

    private static boolean raiseAnalysisMaxStackAfter(AnalyzerException ex, MethodNode mn) {
        String message = ex.getMessage();
        if (message == null || !message.contains("Insufficient maximum stack size")) return false;
        int current = Math.max(mn.maxStack, SOURCE_ANALYSIS_MIN_MAX_STACK);
        if (current >= SOURCE_ANALYSIS_MAX_MAX_STACK) return false;
        mn.maxStack = Math.min(SOURCE_ANALYSIS_MAX_MAX_STACK, Math.max(current + 1, current << 1));
        return true;
    }

    private static boolean isGetParameters(MethodInsnNode call) {
        return ("java/lang/reflect/Executable".equals(call.owner)
            || "java/lang/reflect/Method".equals(call.owner)
            || "java/lang/reflect/Constructor".equals(call.owner))
            && "getParameters".equals(call.name)
            && "()[Ljava/lang/reflect/Parameter;".equals(call.desc);
    }

    private static boolean isReflectionMethodLookup(MethodInsnNode call) {
        return "java/lang/Class".equals(call.owner)
            && ("getMethod".equals(call.name) || "getDeclaredMethod".equals(call.name))
            && "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;".equals(call.desc);
    }

    private static boolean isReflectionConstructorLookup(MethodInsnNode call) {
        return "java/lang/Class".equals(call.owner)
            && ("getConstructor".equals(call.name) || "getDeclaredConstructor".equals(call.name))
            && "([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;".equals(call.desc);
    }

    private static boolean returnsClassObject(MethodInsnNode call) {
        return "()Ljava/lang/Class;".equals(call.desc)
            || call.desc.endsWith(")Ljava/lang/Class;");
    }

    private static boolean isClassArraySourceBookkeeping(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        return opcode == Opcodes.AASTORE || opcode == Opcodes.ASTORE;
    }

    private static String normalizedClassName(PipelineContext pctx, String name) {
        if (name == null || name.isEmpty()) return null;
        String internal = name;
        if (internal.startsWith("[L") && internal.endsWith(";")) {
            internal = internal.substring(2, internal.length() - 1);
        }
        internal = internal.replace('.', '/');
        if (pctx == null || pctx.classMap().containsKey(internal)) {
            return internal;
        }
        return internal.indexOf('/') >= 0 ? internal : null;
    }

    private static Integer intConstant(AbstractInsnNode insn) {
        if (insn == null) return null;
        int opcode = insn.getOpcode();
        if (opcode == Opcodes.ICONST_M1) return -1;
        if (opcode >= Opcodes.ICONST_0 && opcode <= Opcodes.ICONST_5) return opcode - Opcodes.ICONST_0;
        if (opcode == Opcodes.BIPUSH || opcode == Opcodes.SIPUSH) return ((IntInsnNode) insn).operand;
        if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof Integer value) return value;
        return null;
    }

    private static Type classConstant(AbstractInsnNode insn) {
        if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof Type type) {
            return type;
        }
        if (!(insn instanceof FieldInsnNode field) ||
            field.getOpcode() != Opcodes.GETSTATIC ||
            !"TYPE".equals(field.name) ||
            !"Ljava/lang/Class;".equals(field.desc)) {
            return null;
        }
        return switch (field.owner) {
            case "java/lang/Boolean" -> Type.BOOLEAN_TYPE;
            case "java/lang/Character" -> Type.CHAR_TYPE;
            case "java/lang/Byte" -> Type.BYTE_TYPE;
            case "java/lang/Short" -> Type.SHORT_TYPE;
            case "java/lang/Integer" -> Type.INT_TYPE;
            case "java/lang/Float" -> Type.FLOAT_TYPE;
            case "java/lang/Long" -> Type.LONG_TYPE;
            case "java/lang/Double" -> Type.DOUBLE_TYPE;
            case "java/lang/Void" -> Type.VOID_TYPE;
            default -> null;
        };
    }

    private static int storeOpcodeForLoad(int loadOpcode) {
        return switch (loadOpcode) {
            case Opcodes.ILOAD -> Opcodes.ISTORE;
            case Opcodes.LLOAD -> Opcodes.LSTORE;
            case Opcodes.FLOAD -> Opcodes.FSTORE;
            case Opcodes.DLOAD -> Opcodes.DSTORE;
            case Opcodes.ALOAD -> Opcodes.ASTORE;
            default -> -1;
        };
    }

    private static boolean sameTypes(Type[] left, Type[] right) {
        if (left == null || right == null || left.length != right.length) return false;
        for (int i = 0; i < left.length; i++) {
            if (!left[i].equals(right[i])) return false;
        }
        return true;
    }

    private static String key(String owner, String name, String desc) {
        return owner + "." + name + desc;
    }

    private record ExecutableLookup(String owner, String name, Type[] parameterTypes) {
        @Override
        public boolean equals(Object other) {
            if (!(other instanceof ExecutableLookup lookup)) return false;
            return owner.equals(lookup.owner)
                && name.equals(lookup.name)
                && (parameterTypes == null
                    ? lookup.parameterTypes == null
                    : sameTypes(parameterTypes, lookup.parameterTypes));
        }

        @Override
        public int hashCode() {
            int result = owner.hashCode();
            result = 31 * result + name.hashCode();
            if (parameterTypes != null) {
                for (Type parameterType : parameterTypes) {
                    result = 31 * result + parameterType.hashCode();
                }
            }
            return result;
        }
    }
}

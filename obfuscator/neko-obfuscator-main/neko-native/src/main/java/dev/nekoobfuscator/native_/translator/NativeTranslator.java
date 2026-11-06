package dev.nekoobfuscator.native_.translator;

import dev.nekoobfuscator.core.ir.l1.L1Class;
import dev.nekoobfuscator.core.ir.l1.L1Method;
import dev.nekoobfuscator.core.ir.l3.CFunction;
import dev.nekoobfuscator.core.ir.l3.CStatement;
import dev.nekoobfuscator.core.ir.l3.CType;
import dev.nekoobfuscator.core.ir.l3.CVariable;
import dev.nekoobfuscator.native_.codegen.CCodeGenerator;
import dev.nekoobfuscator.native_.codegen.CCodeGenerator.GeneratedSourceSet;
import dev.nekoobfuscator.native_.codegen.CStringLiteral;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FrameNode;
import org.objectweb.asm.tree.IincInsnNode;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.MultiANewArrayInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class NativeTranslator {
    private static final String METHOD_HANDLE_DESC = "Ljava/lang/invoke/MethodHandle;";
    private static final String LAMBDA_FORM_HIDDEN_DESC = "Ljava/lang/invoke/LambdaForm$Hidden;";
    private static final String JDK_HIDDEN_DESC = "Ljdk/internal/vm/annotation/Hidden;";

    private final CCodeGenerator codeGenerator;
    private int concatLiteralIndex = 0;
    private int primitiveArrayLiteralIndex = 0;
    private int stringRecurrenceIndex = 0;
    private int doubleMacLoopIndex = 0;

    public NativeTranslator(String outputPrefix, boolean obfuscateJniSlotDispatch, boolean cacheJniIds, long masterSeed) {
        this.codeGenerator = new CCodeGenerator(masterSeed);
    }

    public TranslationResult translate(List<MethodSelection> selectedMethods) {
        Map<String, L1Class> ownersByName = new HashMap<>();
        for (MethodSelection selection : selectedMethods) {
            ownersByName.putIfAbsent(selection.owner().name(), selection.owner());
        }
        return translate(selectedMethods, ownersByName.values());
    }

    public TranslationResult translate(List<MethodSelection> selectedMethods, Iterable<L1Class> applicationClasses) {
        List<NativeMethodBinding> bindings = new ArrayList<>();
        Map<String, NativeMethodBinding> bindingMap = new HashMap<>();
        Map<String, L1Class> ownersByName = new HashMap<>();
        for (MethodSelection selection : selectedMethods) {
            ownersByName.putIfAbsent(selection.owner().name(), selection.owner());
        }
        Map<String, L1Class> applicationClassesByName = new HashMap<>();
        for (L1Class applicationClass : applicationClasses) {
            applicationClassesByName.putIfAbsent(applicationClass.name(), applicationClass);
        }
        for (int i = 0; i < selectedMethods.size(); i++) {
            MethodSelection selection = selectedMethods.get(i);
            String cFunctionName = "neko_native_entry_" + i;
            String rawFunctionName = "neko_native_impl_" + i;
            NativeMethodBinding binding = new NativeMethodBinding(
                selection.owner().name(),
                selection.method().name(),
                selection.method().descriptor(),
                cFunctionName,
                rawFunctionName,
                null,
                null,
                selection.method().isStatic(),
                isDirectCallSafe(selection.owner(), selection.method(), applicationClassesByName),
                false
            );
            bindings.add(binding);
            bindingMap.put(bindingKey(binding.ownerInternalName(), binding.methodName(), binding.descriptor()), binding);
        }

        OpcodeTranslator opcodeTranslator = new OpcodeTranslator(codeGenerator, bindingMap, new MethodHandleBridgeRegistry(ownersByName));
        boolean shadowStackRequired = selectedMethods.stream()
            .anyMatch(selection -> methodCallsThrowableGetStackTrace(selection.method().asmNode()));
        List<CFunction> functions = new ArrayList<>(selectedMethods.size());
        for (int i = 0; i < selectedMethods.size(); i++) {
            codeGenerator.registerBindingOwner(selectedMethods.get(i).owner().name());
            functions.add(translateMethod(selectedMethods.get(i), bindings.get(i), opcodeTranslator, shadowStackRequired));
        }

        List<NativeMethodBinding> finalBindings = new ArrayList<>(bindings.size());
        for (int i = 0; i < bindings.size(); i++) {
            NativeMethodBinding binding = bindings.get(i);
            finalBindings.add(new NativeMethodBinding(
                binding.ownerInternalName(),
                binding.methodName(),
                binding.descriptor(),
                binding.cFunctionName(),
                binding.rawFunctionName(),
                binding.helperMethodName(),
                binding.helperDescriptor(),
                binding.isStatic(),
                binding.directCallSafe(),
                isNoHandleDispatcherSafe(selectedMethods.get(i), functions.get(i))
            ));
        }

        codeGenerator.configureStringCacheCount(opcodeTranslator.stringCacheCount());

        GeneratedSourceSet sourceSet = codeGenerator.generateSourceSet(functions, finalBindings);
        String source = sourceSet.monolithicSource();
        String header = codeGenerator.generateHeader(finalBindings);
        return new TranslationResult(source, header, finalBindings.size(), finalBindings, sourceSet);
    }

    private CFunction translateMethod(MethodSelection selection, NativeMethodBinding binding, OpcodeTranslator opcodes, boolean shadowEnabled) {
        L1Method method = selection.method();
        MethodNode node = method.asmNode();
        Type returnType = Type.getReturnType(method.descriptor());
        CType cReturnType = mapType(returnType);

        List<CVariable> params = new ArrayList<>();
        params.add(new CVariable("thread", CType.JOBJECT, 0));
        params.add(new CVariable("env", CType.JOBJECT, 0));
        params.add(new CVariable("clazz", CType.JCLASS, 1));
        if (!method.isStatic()) {
            params.add(new CVariable("self", CType.JOBJECT, 2));
        }

        Type[] argTypes = Type.getArgumentTypes(method.descriptor());
        int paramIndex = method.isStatic() ? 2 : 3;
        int argsLocalsSize = method.isStatic() ? 0 : 1;
        for (int i = 0; i < argTypes.length; i++) {
            params.add(new CVariable("p" + i, mapType(argTypes[i]), paramIndex++));
            argsLocalsSize += argTypes[i].getSize();
        }

        CFunction fn = new CFunction(binding.rawFunctionName(), cReturnType, params);
        fn.setMaxStack(Math.max(method.maxStack(), 16));
        fn.setMaxLocals(Math.max(method.maxLocals(), argsLocalsSize));
        fn.setUsesMonitors(bytecodeUsesMonitors(node));

        Map<LabelNode, String> labelMap = buildLabelMap(node);
        Map<LabelNode, Integer> jumpTargetCounts = buildJumpTargetCounts(node);
        Map<AbstractInsnNode, Integer> pcMap = buildPcMap(node);
        Map<Integer, List<TryHandler>> activeHandlers = buildActiveHandlers(method, labelMap, pcMap);

        if (methodMayUseObjectLocalRoots(method, argTypes)) {
            int localRootCount = fn.maxLocals() + 8;
            fn.addStatement(new CStatement.RawC(
                "jobject __neko_local_roots[" + localRootCount + "]; neko_prepare_local_oop_roots(thread, __neko_local_roots, " + localRootCount + ");"
            ));
        }
        emitParamToLocals(fn, method, argTypes);
        opcodes.beginMethod(selection.owner().name(), selection.method().name(), selection.method().descriptor(), selection.method().isStatic(), shadowEnabled);
        int ownerKlassInsertIndex = fn.body().size();
        if (methodMayUseBoundStrings(node)) {
            fn.addStatement(new CStatement.RawC(codeGenerator.ownerStringBindCall(selection.owner().name())));
        }
        if (shadowEnabled) {
            fn.addStatement(new CStatement.RawC(
                "static const neko_shadow_frame_desc __neko_shadow_desc = { \""
                    + CStringLiteral.escape(selection.owner().name()) + "\", \""
                    + CStringLiteral.escape(selection.method().name()) + "\", \""
                    + CStringLiteral.escape(OpcodeTranslator.simpleSourceFileName(selection.owner().name()))
                    + "\" }; neko_shadow_push(&__neko_shadow_desc);"
            ));
        }
        /* Tail-call landing pad: tryTailRecursion rewrites self-recursion
         * into `goto __neko_tco_entry`. Emitted unconditionally so unrelated
         * label numbering (L0/L1/…) is unaffected. */
        fn.addStatement(new CStatement.Label("__neko_tco_entry"));

        /* --- exception-check coalescing state ---
         * HotSpot's interpreter polls _pending_exception only at safepoints
         * (back-edges, method exits, and try-region transitions), not after
         * every JNI call. We mirror that: instead of emitting a check after
         * every potentially-throwing op, defer it as `pendingHandlers` and
         * flush it at:
         *   - A control-flow boundary that needs accurate dispatch (jump,
         *     switch, return, athrow, label that's a branch target)
         *   - An instruction whose active handler set differs from the
         *     pending op's (we're crossing a try-region edge, so an exception
         *     thrown by the pending op must still be caught by the OLDER
         *     handlers, not the new ones)
         * If the method ends without flushing, the pending exception is
         * preserved naturally — the JVM observes _pending_exception when our
         * native function returns. */
        List<TryHandler> pendingHandlers = null;
        for (AbstractInsnNode insn = node.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof LabelNode labelNode) {
                if (pendingHandlers != null) {
                    fn.addStatement(new CStatement.RawC(renderExceptionDispatch(pendingHandlers, selection.owner().name())));
                    pendingHandlers = null;
                }
                fn.addStatement(new CStatement.Label(labelMap.get(labelNode)));
                continue;
            }
            if (insn instanceof LineNumberNode || insn instanceof FrameNode) {
                continue;
            }
            if (pendingHandlers != null && needsCheckBefore(insn, pendingHandlers, activeHandlers, pcMap)) {
                fn.addStatement(new CStatement.RawC(renderExceptionDispatch(pendingHandlers, selection.owner().name())));
                pendingHandlers = null;
            }
            StringConcatRecurrenceFusion stringRecurrence = tryStringConcatRecurrenceFusion(insn, labelMap, jumpTargetCounts, activeHandlers, pcMap);
            StringConcatPattern concatPattern = stringRecurrence == null ? renderedStringConcatPattern(insn, selection.owner().name()) : null;
            PrimitiveArrayLiteralPattern arrayLiteral = (stringRecurrence == null && concatPattern == null) ? renderedPrimitiveArrayLiteralPattern(insn) : null;
            PrimitiveIntTailCallFusion primitiveIntTailCall = (stringRecurrence == null && concatPattern == null && arrayLiteral == null)
                ? tryPrimitiveIntTailCallFusion(opcodes, insn, selection, argTypes, activeHandlers, pcMap)
                : null;
            PrimitiveIntReturnFusion primitiveIntReturn = (stringRecurrence == null && concatPattern == null && arrayLiteral == null && primitiveIntTailCall == null)
                ? tryPrimitiveIntReturnFusion(opcodes, insn, shadowEnabled)
                : null;
            StaticIntAddUpdateFusion staticIntAddUpdate = (stringRecurrence == null && concatPattern == null && arrayLiteral == null && primitiveIntTailCall == null && primitiveIntReturn == null)
                ? tryStaticIntAddUpdateFusion(opcodes, insn)
                : null;
            StaticDirectSingleIntInvokeFusion staticDirectSingleIntInvoke = (stringRecurrence == null && concatPattern == null && arrayLiteral == null && primitiveIntTailCall == null && primitiveIntReturn == null && staticIntAddUpdate == null)
                ? tryStaticDirectSingleIntInvokeFusion(opcodes, insn)
                : null;
            PrimitiveConstantLocalStoreFusion primitiveConstantLocalStore = (stringRecurrence == null && concatPattern == null && arrayLiteral == null && primitiveIntTailCall == null && primitiveIntReturn == null && staticIntAddUpdate == null && staticDirectSingleIntInvoke == null)
                ? tryPrimitiveConstantLocalStoreFusion(opcodes, insn)
                : null;
            PrimitiveFloatDoubleLocalAddUpdateFusion primitiveFloatDoubleLocalAddUpdate = (stringRecurrence == null && concatPattern == null && arrayLiteral == null && primitiveIntTailCall == null && primitiveIntReturn == null && staticIntAddUpdate == null && staticDirectSingleIntInvoke == null && primitiveConstantLocalStore == null)
                ? tryPrimitiveFloatDoubleLocalAddUpdateFusion(opcodes, insn)
                : null;
            CountedDoubleArrayMacLoopFusion countedDoubleArrayMacLoop = (stringRecurrence == null && concatPattern == null && arrayLiteral == null && primitiveIntTailCall == null && primitiveIntReturn == null && staticIntAddUpdate == null && staticDirectSingleIntInvoke == null && primitiveConstantLocalStore == null && primitiveFloatDoubleLocalAddUpdate == null)
                ? tryCountedDoubleArrayMacLoopFusion(opcodes, insn, labelMap, jumpTargetCounts, activeHandlers, pcMap)
                : null;
            PrimitiveCompareBranchFusion primitiveCompareBranch = (stringRecurrence == null && concatPattern == null && arrayLiteral == null && primitiveIntTailCall == null && primitiveIntReturn == null && staticIntAddUpdate == null && staticDirectSingleIntInvoke == null && primitiveConstantLocalStore == null && primitiveFloatDoubleLocalAddUpdate == null && countedDoubleArrayMacLoop == null)
                ? tryPrimitiveCompareBranchFusion(opcodes, insn, labelMap)
                : null;
            PrimitiveBranchFusion primitiveBranch = (stringRecurrence == null && concatPattern == null && arrayLiteral == null && primitiveIntTailCall == null && primitiveIntReturn == null && staticIntAddUpdate == null && staticDirectSingleIntInvoke == null && primitiveConstantLocalStore == null && primitiveFloatDoubleLocalAddUpdate == null && countedDoubleArrayMacLoop == null && primitiveCompareBranch == null)
                ? tryPrimitiveBranchFusion(opcodes, insn, labelMap)
                : null;
            OpcodeTranslator.FusedTranslation fused = (stringRecurrence == null && concatPattern == null && arrayLiteral == null && primitiveIntTailCall == null && primitiveIntReturn == null && staticIntAddUpdate == null && staticDirectSingleIntInvoke == null && primitiveConstantLocalStore == null && primitiveFloatDoubleLocalAddUpdate == null && countedDoubleArrayMacLoop == null && primitiveCompareBranch == null && primitiveBranch == null)
                ? tryFusedAALoad(opcodes, insn, activeHandlers, pcMap)
                : null;
            TailCallRewrite tail = (stringRecurrence == null && concatPattern == null && arrayLiteral == null && primitiveIntTailCall == null && primitiveIntReturn == null && staticIntAddUpdate == null && staticDirectSingleIntInvoke == null && primitiveConstantLocalStore == null && primitiveFloatDoubleLocalAddUpdate == null && countedDoubleArrayMacLoop == null && primitiveCompareBranch == null && primitiveBranch == null && fused == null)
                ? tryTailRecursion(insn, selection, argTypes, activeHandlers, pcMap)
                : null;
            if (insn instanceof JumpInsnNode jumpInsn) {
                fn.addStatement(opcodes.translateJump(jumpInsn, labelMap.get(jumpInsn.label)));
            } else if (insn instanceof TableSwitchInsnNode tableSwitchInsn) {
                fn.addStatement(new CStatement.RawC(renderTableSwitch(tableSwitchInsn, labelMap)));
            } else if (insn instanceof LookupSwitchInsnNode lookupSwitchInsn) {
                fn.addStatement(new CStatement.RawC(renderLookupSwitch(lookupSwitchInsn, labelMap)));
            } else if (stringRecurrence != null) {
                if (pendingHandlers != null) {
                    fn.addStatement(new CStatement.RawC(renderExceptionDispatch(pendingHandlers, selection.owner().name())));
                    pendingHandlers = null;
                }
                fn.addStatement(new CStatement.RawC(stringRecurrence.code));
                insn = stringRecurrence.lastInsn;
                continue;
            } else if (concatPattern != null) {
                fn.addStatement(new CStatement.RawC(concatPattern.code));
                insn = concatPattern.lastInsn;
            } else if (arrayLiteral != null) {
                fn.addStatement(new CStatement.RawC(arrayLiteral.code));
                pendingHandlers = activeHandlers.getOrDefault(pcMap.get(arrayLiteral.newArrayInsn), List.of());
                insn = arrayLiteral.lastInsn;
                continue;
            } else if (primitiveIntTailCall != null) {
                if (pendingHandlers != null) {
                    fn.addStatement(new CStatement.RawC(renderExceptionDispatch(pendingHandlers, selection.owner().name())));
                    pendingHandlers = null;
                }
                fn.addStatement(new CStatement.RawC(primitiveIntTailCall.code));
                insn = primitiveIntTailCall.lastInsn;
                continue;
            } else if (primitiveIntReturn != null) {
                if (pendingHandlers != null) {
                    fn.addStatement(new CStatement.RawC(renderExceptionDispatch(pendingHandlers, selection.owner().name())));
                    pendingHandlers = null;
                }
                fn.addStatement(new CStatement.RawC(primitiveIntReturn.code));
                insn = primitiveIntReturn.lastInsn;
            } else if (staticIntAddUpdate != null) {
                fn.addStatement(new CStatement.RawC(staticIntAddUpdate.code));
                insn = staticIntAddUpdate.lastInsn;
            } else if (staticDirectSingleIntInvoke != null) {
                fn.addStatement(new CStatement.RawC(staticDirectSingleIntInvoke.code));
                insn = staticDirectSingleIntInvoke.lastInsn;
            } else if (primitiveConstantLocalStore != null) {
                fn.addStatement(new CStatement.RawC(primitiveConstantLocalStore.code));
                insn = primitiveConstantLocalStore.lastInsn;
            } else if (primitiveFloatDoubleLocalAddUpdate != null) {
                fn.addStatement(new CStatement.RawC(primitiveFloatDoubleLocalAddUpdate.code));
                insn = primitiveFloatDoubleLocalAddUpdate.lastInsn;
            } else if (countedDoubleArrayMacLoop != null) {
                if (pendingHandlers != null) {
                    fn.addStatement(new CStatement.RawC(renderExceptionDispatch(pendingHandlers, selection.owner().name())));
                    pendingHandlers = null;
                }
                fn.addStatement(new CStatement.RawC(countedDoubleArrayMacLoop.code));
                insn = countedDoubleArrayMacLoop.lastInsn;
            } else if (primitiveCompareBranch != null) {
                if (pendingHandlers != null) {
                    fn.addStatement(new CStatement.RawC(renderExceptionDispatch(pendingHandlers, selection.owner().name())));
                    pendingHandlers = null;
                }
                fn.addStatement(new CStatement.RawC(primitiveCompareBranch.code));
                insn = primitiveCompareBranch.lastInsn;
            } else if (primitiveBranch != null) {
                if (pendingHandlers != null) {
                    fn.addStatement(new CStatement.RawC(renderExceptionDispatch(pendingHandlers, selection.owner().name())));
                    pendingHandlers = null;
                }
                fn.addStatement(new CStatement.RawC(primitiveBranch.code));
                insn = primitiveBranch.lastInsn;
            } else if (fused != null) {
                fn.addStatement(new CStatement.RawC(fused.code()));
                insn = fused.lastInsn();
            } else if (tail != null) {
                fn.addStatement(new CStatement.RawC(tail.code));
                pendingHandlers = null;
                continue;
            } else {
                for (CStatement statement : opcodes.translate(insn)) {
                    fn.addStatement(statement);
                }
            }

            AbstractInsnNode exceptionSource = concatPattern == null ? insn : concatPattern.exceptionInsn;
            if (isRealInsn(exceptionSource) && isPotentiallyExcepting(exceptionSource)) {
                List<TryHandler> handlers = activeHandlers.getOrDefault(pcMap.get(exceptionSource), List.of());
                pendingHandlers = handlers;
            }
        }
        if (opcodes.requiresLexicalCurrentOwnerClass()) {
            fn.body().add(ownerKlassInsertIndex, new CStatement.RawC(
                "void *__neko_current_owner_klass = neko_class_mirror_to_klass(clazz); "
                    + "if (__neko_current_owner_klass == NULL) { fprintf(stderr, \"[neko-bind] current translated owner Klass unavailable: "
                    + CStringLiteral.escape(selection.owner().name()) + "." + CStringLiteral.escape(selection.method().name()) + CStringLiteral.escape(selection.method().descriptor())
                    + "\\n\"); abort(); }"
            ));
        }
        if (pendingHandlers != null) {
            fn.addStatement(new CStatement.RawC(renderExceptionDispatch(pendingHandlers, selection.owner().name())));
        }

        if (referencesLabel(fn.body(), "__neko_exception_exit")) {
            fn.addStatement(new CStatement.Label("__neko_exception_exit"));
            emitDefaultReturn(fn, cReturnType, shadowEnabled);
        }
        return fn;
    }

    private static boolean methodCallsThrowableGetStackTrace(MethodNode method) {
        if (method == null || method.instructions == null) return false;
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof MethodInsnNode call
                && call.getOpcode() == Opcodes.INVOKEVIRTUAL
                && "java/lang/Throwable".equals(call.owner)
                && "getStackTrace".equals(call.name)
                && "()[Ljava/lang/StackTraceElement;".equals(call.desc)) {
                return true;
            }
        }
        return false;
    }

    private boolean referencesLabel(List<CStatement> statements, String label) {
        for (CStatement statement : statements) {
            if (statementReferencesLabel(statement, label)) {
                return true;
            }
        }
        return false;
    }

    private boolean statementReferencesLabel(CStatement statement, String label) {
        if (statement instanceof CStatement.Goto gotoStatement) {
            return label.equals(gotoStatement.label());
        }
        if (statement instanceof CStatement.CheckException check) {
            return label.equals(check.handlerLabel());
        }
        if (statement instanceof CStatement.SetJmp setJmp) {
            return label.equals(setJmp.handlerLabel());
        }
        if (statement instanceof CStatement.If ifStatement) {
            return referencesLabel(ifStatement.thenBlock(), label)
                || referencesLabel(ifStatement.elseBlock(), label);
        }
        if (statement instanceof CStatement.Switch switchStatement) {
            return referencesLabel(switchStatement.defaultCase(), label)
                || switchStatement.cases().values().stream().anyMatch(block -> referencesLabel(block, label));
        }
        if (statement instanceof CStatement.RawC raw) {
            return raw.code().contains(label);
        }
        return false;
    }

    private record PrimitiveIntTailCallFusion(String code, AbstractInsnNode lastInsn) {}

    private PrimitiveIntTailCallFusion tryPrimitiveIntTailCallFusion(
        OpcodeTranslator opcodes,
        AbstractInsnNode insn,
        MethodSelection selection,
        Type[] argTypes,
        Map<Integer, List<TryHandler>> activeHandlers,
        Map<AbstractInsnNode, Integer> pcMap
    ) {
        L1Method current = selection.method();
        if (!current.isStatic()) return null;
        if (argTypes.length != 1 || argTypes[0].getSort() != Type.INT) return null;

        String left = opcodes.intPushExpression(insn);
        if (left == null) return null;
        AbstractInsnNode rhsInsn = nextNonMetaSameBlock(insn);
        String right = opcodes.intPushExpression(rhsInsn);
        if (right == null) return null;
        AbstractInsnNode arithmeticInsn = nextNonMetaSameBlock(rhsInsn);
        if (!(arithmeticInsn instanceof InsnNode)) return null;
        String operator = switch (arithmeticInsn.getOpcode()) {
            case Opcodes.IADD -> "+";
            case Opcodes.ISUB -> "-";
            case Opcodes.IMUL -> "*";
            default -> null;
        };
        if (operator == null) return null;
        AbstractInsnNode callInsn = nextNonMetaSameBlock(arithmeticInsn);
        if (!(callInsn instanceof MethodInsnNode mi) || mi.getOpcode() != Opcodes.INVOKESTATIC) return null;
        if (!mi.owner.equals(selection.owner().name())
            || !mi.name.equals(current.name())
            || !mi.desc.equals(current.descriptor())) {
            return null;
        }
        Integer callPc = pcMap.get(callInsn);
        if (callPc == null || !activeHandlers.getOrDefault(callPc, List.of()).isEmpty()) return null;
        AbstractInsnNode returnInsn = nextRealInsn(callInsn);
        if (returnInsn == null || !isMatchingReturn(returnInsn.getOpcode(), Type.getReturnType(current.descriptor()))) return null;

        return new PrimitiveIntTailCallFusion(
            "{ /* tail-call int arithmetic → goto L0 */ locals[0].i = (jint)((" + left + ") " + operator + " (" + right + ")); sp = 0; goto __neko_tco_entry; }",
            callInsn
        );
    }

    private record PrimitiveIntReturnFusion(String code, AbstractInsnNode lastInsn) {}

    private PrimitiveIntReturnFusion tryPrimitiveIntReturnFusion(OpcodeTranslator opcodes, AbstractInsnNode insn, boolean shadowEnabled) {
        String left = opcodes.intPushExpression(insn);
        if (left == null) return null;
        AbstractInsnNode rhsInsn = nextNonMetaSameBlock(insn);
        String right = opcodes.intPushExpression(rhsInsn);
        if (right == null) return null;
        AbstractInsnNode arithmeticInsn = nextNonMetaSameBlock(rhsInsn);
        if (!(arithmeticInsn instanceof InsnNode)) return null;
        String operator = switch (arithmeticInsn.getOpcode()) {
            case Opcodes.IADD -> "+";
            case Opcodes.IMUL -> "*";
            default -> null;
        };
        if (operator == null) return null;
        AbstractInsnNode returnInsn = nextNonMetaSameBlock(arithmeticInsn);
        if (!(returnInsn instanceof InsnNode) || returnInsn.getOpcode() != Opcodes.IRETURN) return null;
        return new PrimitiveIntReturnFusion(
            "{ jint __ret = (jint)((" + left + ") " + operator + " (" + right + ")); "
                + (shadowEnabled ? "neko_shadow_pop(); " : "")
                + "return __ret; }",
            returnInsn
        );
    }

    private record StaticIntAddUpdateFusion(String code, AbstractInsnNode lastInsn) {}

    private StaticIntAddUpdateFusion tryStaticIntAddUpdateFusion(OpcodeTranslator opcodes, AbstractInsnNode insn) {
        if (!(insn instanceof FieldInsnNode get) || get.getOpcode() != Opcodes.GETSTATIC || !"I".equals(get.desc)) {
            return null;
        }
        AbstractInsnNode rhsInsn = nextNonMetaSameBlock(get);
        String rhsExpr = intConstantExpression(rhsInsn);
        if (rhsExpr == null) return null;
        AbstractInsnNode addInsn = nextNonMetaSameBlock(rhsInsn);
        if (!(addInsn instanceof InsnNode) || addInsn.getOpcode() != Opcodes.IADD) return null;
        AbstractInsnNode putInsn = nextNonMetaSameBlock(addInsn);
        if (!(putInsn instanceof FieldInsnNode put) || put.getOpcode() != Opcodes.PUTSTATIC) return null;
        if (!get.owner.equals(put.owner) || !get.name.equals(put.name) || !get.desc.equals(put.desc)) return null;
        return new StaticIntAddUpdateFusion(opcodes.translateStaticIntAddUpdate(get, rhsExpr), put);
    }

    private record StaticDirectSingleIntInvokeFusion(String code, AbstractInsnNode lastInsn) {}

    private StaticDirectSingleIntInvokeFusion tryStaticDirectSingleIntInvokeFusion(
        OpcodeTranslator opcodes,
        AbstractInsnNode insn
    ) {
        String argExpr = opcodes.intPushExpression(insn);
        if (argExpr == null) return null;
        AbstractInsnNode callInsn = nextNonMetaSameBlock(insn);
        if (!(callInsn instanceof MethodInsnNode mi) || mi.getOpcode() != Opcodes.INVOKESTATIC) return null;
        String code = opcodes.translateDirectStaticInvokeWithSingleIntArg(mi, argExpr);
        return code == null ? null : new StaticDirectSingleIntInvokeFusion(code, callInsn);
    }

    private record PrimitiveConstantLocalStoreFusion(String code, AbstractInsnNode lastInsn) {}

    private PrimitiveConstantLocalStoreFusion tryPrimitiveConstantLocalStoreFusion(
        OpcodeTranslator opcodes,
        AbstractInsnNode insn
    ) {
        AbstractInsnNode storeInsn = nextNonMetaSameBlock(insn);
        if (!(storeInsn instanceof VarInsnNode store)) return null;
        String field;
        String expr;
        switch (store.getOpcode()) {
            case Opcodes.ISTORE -> {
                field = "i";
                expr = intConstantExpression(insn);
            }
            case Opcodes.LSTORE -> {
                field = "j";
                expr = longConstantExpression(opcodes, insn);
            }
            case Opcodes.FSTORE -> {
                field = "f";
                expr = floatConstantExpression(opcodes, insn);
            }
            case Opcodes.DSTORE -> {
                field = "d";
                expr = doubleConstantExpression(opcodes, insn);
            }
            default -> {
                return null;
            }
        }
        if (expr == null) return null;
        return new PrimitiveConstantLocalStoreFusion(
            "{ locals[" + store.var + "]." + field + " = " + expr + "; }",
            storeInsn
        );
    }

    private record PrimitiveFloatDoubleLocalAddUpdateFusion(String code, AbstractInsnNode lastInsn) {}

    private PrimitiveFloatDoubleLocalAddUpdateFusion tryPrimitiveFloatDoubleLocalAddUpdateFusion(
        OpcodeTranslator opcodes,
        AbstractInsnNode insn
    ) {
        if (!(insn instanceof VarInsnNode load)) return null;
        int loadOpcode = load.getOpcode();
        if (loadOpcode != Opcodes.FLOAD && loadOpcode != Opcodes.DLOAD) return null;
        AbstractInsnNode rhsInsn = nextNonMetaSameBlock(load);
        String rhsExpr = loadOpcode == Opcodes.FLOAD
            ? floatConstantExpression(opcodes, rhsInsn)
            : doubleConstantExpression(opcodes, rhsInsn);
        if (rhsExpr == null) return null;
        AbstractInsnNode addInsn = nextNonMetaSameBlock(rhsInsn);
        int expectedAdd = loadOpcode == Opcodes.FLOAD ? Opcodes.FADD : Opcodes.DADD;
        if (!(addInsn instanceof InsnNode) || addInsn.getOpcode() != expectedAdd) return null;
        AbstractInsnNode storeInsn = nextNonMetaSameBlock(addInsn);
        int expectedStore = loadOpcode == Opcodes.FLOAD ? Opcodes.FSTORE : Opcodes.DSTORE;
        if (!(storeInsn instanceof VarInsnNode store) || store.getOpcode() != expectedStore || store.var != load.var) {
            return null;
        }
        String slot = loadOpcode == Opcodes.FLOAD ? "f" : "d";
        return new PrimitiveFloatDoubleLocalAddUpdateFusion(
            "{ locals[" + load.var + "]." + slot + " = locals[" + load.var + "]." + slot + " + " + rhsExpr + "; }",
            storeInsn
        );
    }

    private String floatConstantExpression(OpcodeTranslator opcodes, AbstractInsnNode insn) {
        if (insn == null) return null;
        int op = insn.getOpcode();
        if (op == Opcodes.FCONST_0 || op == Opcodes.FCONST_1 || op == Opcodes.FCONST_2) {
            return opcodes.floatPushExpression(insn);
        }
        if (op == Opcodes.LDC && ((LdcInsnNode) insn).cst instanceof Float) {
            return opcodes.floatPushExpression(insn);
        }
        return null;
    }

    private String doubleConstantExpression(OpcodeTranslator opcodes, AbstractInsnNode insn) {
        if (insn == null) return null;
        int op = insn.getOpcode();
        if (op == Opcodes.DCONST_0 || op == Opcodes.DCONST_1) {
            return opcodes.doublePushExpression(insn);
        }
        if (op == Opcodes.LDC && ((LdcInsnNode) insn).cst instanceof Double) {
            return opcodes.doublePushExpression(insn);
        }
        return null;
    }

    private String longConstantExpression(OpcodeTranslator opcodes, AbstractInsnNode insn) {
        if (insn == null) return null;
        int op = insn.getOpcode();
        if (op == Opcodes.LCONST_0 || op == Opcodes.LCONST_1) {
            return opcodes.longPushExpression(insn);
        }
        if (op == Opcodes.LDC && ((LdcInsnNode) insn).cst instanceof Long) {
            return opcodes.longPushExpression(insn);
        }
        return null;
    }

    private String intConstantExpression(AbstractInsnNode insn) {
        if (insn == null) return null;
        int op = insn.getOpcode();
        if (op == Opcodes.ICONST_M1) return "-1";
        if (op >= Opcodes.ICONST_0 && op <= Opcodes.ICONST_5) return String.valueOf(op - Opcodes.ICONST_0);
        if (op == Opcodes.BIPUSH || op == Opcodes.SIPUSH) return String.valueOf(((IntInsnNode) insn).operand);
        if (op == Opcodes.LDC && ((LdcInsnNode) insn).cst instanceof Integer i) return String.valueOf(i);
        return null;
    }

    private record CountedDoubleArrayMacLoopFusion(String code, AbstractInsnNode lastInsn) {}

    private record LoopDoubleArrayLoadExpr(String expr, AbstractInsnNode lastInsn) {}

    private CountedDoubleArrayMacLoopFusion tryCountedDoubleArrayMacLoopFusion(
        OpcodeTranslator opcodes,
        AbstractInsnNode start,
        Map<LabelNode, String> labelMap,
        Map<LabelNode, Integer> jumpTargetCounts,
        Map<Integer, List<TryHandler>> activeHandlers,
        Map<AbstractInsnNode, Integer> pcMap
    ) {
        if (!(start instanceof VarInsnNode indexLoad) || indexLoad.getOpcode() != Opcodes.ILOAD) {
            return null;
        }
        int indexLocal = indexLoad.var;
        LabelNode loopHeader = previousLabelBefore(start);
        if (loopHeader == null) {
            return null;
        }
        AbstractInsnNode boundInsn = nextNonMetaSameBlock(indexLoad);
        if (intPushUsesLocal(boundInsn, indexLocal)) {
            return null;
        }
        String boundExpr = opcodes.intPushExpression(boundInsn);
        if (boundExpr == null) {
            return null;
        }
        AbstractInsnNode branchInsn = nextNonMetaSameBlock(boundInsn);
        if (!(branchInsn instanceof JumpInsnNode exitBranch) || exitBranch.getOpcode() != Opcodes.IF_ICMPGE) {
            return null;
        }
        String exitLabel = labelMap.get(exitBranch.label);
        if (exitLabel == null) {
            return null;
        }
        AbstractInsnNode accLoadInsn = nextNonMetaSameBlock(branchInsn);
        if (!(accLoadInsn instanceof VarInsnNode accLoad) || accLoad.getOpcode() != Opcodes.DLOAD) {
            return null;
        }
        int accLocal = accLoad.var;
        String indexExpr = "__neko_mac_i_" + doubleMacLoopIndex;
        LoopDoubleArrayLoadExpr left = loopDoubleArrayLoadExpr(opcodes, nextNonMetaSameBlock(accLoadInsn), indexLocal, indexExpr);
        if (left == null) {
            return null;
        }
        LoopDoubleArrayLoadExpr right = loopDoubleArrayLoadExpr(opcodes, nextNonMetaSameBlock(left.lastInsn), indexLocal, indexExpr);
        if (right == null) {
            return null;
        }
        AbstractInsnNode multiply = nextNonMetaSameBlock(right.lastInsn);
        if (!(multiply instanceof InsnNode) || multiply.getOpcode() != Opcodes.DMUL) {
            return null;
        }
        AbstractInsnNode add = nextNonMetaSameBlock(multiply);
        if (!(add instanceof InsnNode) || add.getOpcode() != Opcodes.DADD) {
            return null;
        }
        AbstractInsnNode storeInsn = nextNonMetaSameBlock(add);
        if (!(storeInsn instanceof VarInsnNode accStore)
            || accStore.getOpcode() != Opcodes.DSTORE
            || accStore.var != accLocal) {
            return null;
        }
        AbstractInsnNode incrementInsn = nextNonMetaSameBlock(storeInsn);
        if (!(incrementInsn instanceof IincInsnNode increment)
            || increment.var != indexLocal
            || increment.incr != 1) {
            return null;
        }
        AbstractInsnNode backedgeInsn = nextNonMetaSameBlock(incrementInsn);
        if (!(backedgeInsn instanceof JumpInsnNode backedge)
            || backedge.getOpcode() != Opcodes.GOTO
            || backedge.label != loopHeader) {
            return null;
        }
        if (coveredRegionHasActiveHandlers(start, backedgeInsn, activeHandlers, pcMap)
            || coveredRegionHasBranchTarget(start, backedgeInsn, jumpTargetCounts)) {
            return null;
        }

        int loopId = doubleMacLoopIndex++;
        String iVar = "__neko_mac_i_" + loopId;
        String limitVar = "__neko_mac_limit_" + loopId;
        String leftVar = "__neko_mac_l_" + loopId;
        String rightVar = "__neko_mac_r_" + loopId;
        String reasonVar = "__neko_mac_reason_" + loopId;
        String code = "{ /* scalarized counted double[][] multiply-accumulate loop */ "
            + "jint " + iVar + " = locals[" + indexLocal + "].i; "
            + "jint " + limitVar + " = (jint)(" + boundExpr + "); "
            + "for (; " + iVar + " < " + limitVar + "; " + iVar + " = (jint)(" + iVar + " + 1)) { "
            + "int " + reasonVar + " = 0; "
            + "jdouble " + leftVar + " = " + left.expr + "; "
            + "if (" + reasonVar + " != NEKO_FAST_ARRAY_OK) { locals[" + indexLocal + "].i = " + iVar + "; "
            + "neko_raise_cached_fast_array_reason(thread, env, " + reasonVar + "); goto __neko_exception_exit; } "
            + reasonVar + " = 0; "
            + "jdouble " + rightVar + " = " + right.expr + "; "
            + "if (" + reasonVar + " != NEKO_FAST_ARRAY_OK) { locals[" + indexLocal + "].i = " + iVar + "; "
            + "neko_raise_cached_fast_array_reason(thread, env, " + reasonVar + "); goto __neko_exception_exit; } "
            + "locals[" + accLocal + "].d = locals[" + accLocal + "].d + (" + leftVar + " * " + rightVar + "); } "
            + "locals[" + indexLocal + "].i = " + iVar + "; goto " + exitLabel + "; }";
        return new CountedDoubleArrayMacLoopFusion(code, backedgeInsn);
    }

    private LoopDoubleArrayLoadExpr loopDoubleArrayLoadExpr(
        OpcodeTranslator opcodes,
        AbstractInsnNode start,
        int indexLocal,
        String indexExpr
    ) {
        if (!(start instanceof VarInsnNode outerVar) || outerVar.getOpcode() != Opcodes.ALOAD) {
            return null;
        }
        AbstractInsnNode idx1 = nextNonMetaSameBlock(start);
        String idx1Expr = loopIntPushExpression(opcodes, idx1, indexLocal, indexExpr);
        if (idx1Expr == null) {
            return null;
        }
        AbstractInsnNode aaload = nextNonMetaSameBlock(idx1);
        if (!(aaload instanceof InsnNode) || aaload.getOpcode() != Opcodes.AALOAD) {
            return null;
        }
        AbstractInsnNode idx2 = nextNonMetaSameBlock(aaload);
        String idx2Expr = loopIntPushExpression(opcodes, idx2, indexLocal, indexExpr);
        if (idx2Expr == null) {
            return null;
        }
        AbstractInsnNode daload = nextNonMetaSameBlock(idx2);
        if (!(daload instanceof InsnNode) || daload.getOpcode() != Opcodes.DALOAD) {
            return null;
        }
        String expr = "neko_fast_raw_aaload_daload((void*)(locals[" + outerVar.var + "].o), "
            + idx1Expr + ", " + idx2Expr + ", &__neko_mac_reason_" + doubleMacLoopIndex + ")";
        return new LoopDoubleArrayLoadExpr(expr, daload);
    }

    private String loopIntPushExpression(OpcodeTranslator opcodes, AbstractInsnNode insn, int indexLocal, String indexExpr) {
        if (insn instanceof VarInsnNode varInsn && varInsn.getOpcode() == Opcodes.ILOAD && varInsn.var == indexLocal) {
            return indexExpr;
        }
        return opcodes.intPushExpression(insn);
    }

    private boolean intPushUsesLocal(AbstractInsnNode insn, int local) {
        return insn instanceof VarInsnNode varInsn && varInsn.getOpcode() == Opcodes.ILOAD && varInsn.var == local;
    }

    private record PrimitiveCompareBranchFusion(String code, AbstractInsnNode lastInsn) {}

    private PrimitiveCompareBranchFusion tryPrimitiveCompareBranchFusion(
        OpcodeTranslator opcodes,
        AbstractInsnNode insn,
        Map<LabelNode, String> labelMap
    ) {
        AbstractInsnNode rhsInsn = nextNonMetaSameBlock(insn);
        AbstractInsnNode compareInsn = nextNonMetaSameBlock(rhsInsn);
        if (!(compareInsn instanceof InsnNode)) return null;
        int compareOpcode = compareInsn.getOpcode();
        String cType;
        String left;
        String right;
        String compareExpr;
        switch (compareOpcode) {
            case Opcodes.LCMP -> {
                cType = "jlong";
                left = opcodes.longPushExpression(insn);
                right = opcodes.longPushExpression(rhsInsn);
                compareExpr = "a > b ? 1 : (a < b ? -1 : 0)";
            }
            case Opcodes.FCMPL -> {
                cType = "jfloat";
                left = opcodes.floatPushExpression(insn);
                right = opcodes.floatPushExpression(rhsInsn);
                compareExpr = "a > b ? 1 : (a < b ? -1 : (a == b ? 0 : -1))";
            }
            case Opcodes.FCMPG -> {
                cType = "jfloat";
                left = opcodes.floatPushExpression(insn);
                right = opcodes.floatPushExpression(rhsInsn);
                compareExpr = "a > b ? 1 : (a < b ? -1 : (a == b ? 0 : 1))";
            }
            case Opcodes.DCMPL -> {
                cType = "jdouble";
                left = opcodes.doublePushExpression(insn);
                right = opcodes.doublePushExpression(rhsInsn);
                compareExpr = "a > b ? 1 : (a < b ? -1 : (a == b ? 0 : -1))";
            }
            case Opcodes.DCMPG -> {
                cType = "jdouble";
                left = opcodes.doublePushExpression(insn);
                right = opcodes.doublePushExpression(rhsInsn);
                compareExpr = "a > b ? 1 : (a < b ? -1 : (a == b ? 0 : 1))";
            }
            default -> {
                return null;
            }
        }
        if (left == null || right == null) return null;
        AbstractInsnNode branchInsn = nextNonMetaSameBlock(compareInsn);
        if (!(branchInsn instanceof JumpInsnNode jumpInsn)) return null;
        String condition = intZeroBranchCondition(jumpInsn.getOpcode(), "__cmp");
        if (condition == null) return null;
        return new PrimitiveCompareBranchFusion(
            "{ " + cType + " a = " + left + "; " + cType + " b = " + right
                + "; jint __cmp = " + compareExpr + "; if (" + condition + ") goto " + labelMap.get(jumpInsn.label) + "; }",
            jumpInsn
        );
    }

    private record PrimitiveBranchFusion(String code, AbstractInsnNode lastInsn) {}

    private PrimitiveBranchFusion tryPrimitiveBranchFusion(
        OpcodeTranslator opcodes,
        AbstractInsnNode insn,
        Map<LabelNode, String> labelMap
    ) {
        String left = opcodes.intPushExpression(insn);
        if (left == null) return null;
        AbstractInsnNode next = nextNonMetaSameBlock(insn);
        if (next instanceof JumpInsnNode jumpInsn) {
            String condition = intZeroBranchCondition(jumpInsn.getOpcode(), left);
            if (condition == null) return null;
            return new PrimitiveBranchFusion("if (" + condition + ") goto " + labelMap.get(jumpInsn.label) + ";", jumpInsn);
        }
        String right = opcodes.intPushExpression(next);
        if (right == null) return null;
        AbstractInsnNode branch = nextNonMetaSameBlock(next);
        if (!(branch instanceof JumpInsnNode jumpInsn)) return null;
        String condition = intCompareBranchCondition(jumpInsn.getOpcode(), left, right);
        if (condition == null) return null;
        return new PrimitiveBranchFusion("{ jint a = " + left + "; jint b = " + right + "; if (" + condition + ") goto " + labelMap.get(jumpInsn.label) + "; }", jumpInsn);
    }

    private AbstractInsnNode nextNonMetaSameBlock(AbstractInsnNode insn) {
        AbstractInsnNode next = insn == null ? null : insn.getNext();
        while (next instanceof LineNumberNode || next instanceof FrameNode) {
            next = next.getNext();
        }
        return next instanceof LabelNode ? null : next;
    }

    private String intZeroBranchCondition(int opcode, String expr) {
        return switch (opcode) {
            case Opcodes.IFEQ -> expr + " == 0";
            case Opcodes.IFNE -> expr + " != 0";
            case Opcodes.IFLT -> expr + " < 0";
            case Opcodes.IFGE -> expr + " >= 0";
            case Opcodes.IFGT -> expr + " > 0";
            case Opcodes.IFLE -> expr + " <= 0";
            default -> null;
        };
    }

    private String intCompareBranchCondition(int opcode, String left, String right) {
        return switch (opcode) {
            case Opcodes.IF_ICMPEQ -> "a == b";
            case Opcodes.IF_ICMPNE -> "a != b";
            case Opcodes.IF_ICMPLT -> "a < b";
            case Opcodes.IF_ICMPGE -> "a >= b";
            case Opcodes.IF_ICMPGT -> "a > b";
            case Opcodes.IF_ICMPLE -> "a <= b";
            default -> null;
        };
    }

    private Map<LabelNode, String> buildLabelMap(MethodNode node) {
        Map<LabelNode, String> labels = new LinkedHashMap<>();
        int counter = 0;
        for (AbstractInsnNode insn = node.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof LabelNode labelNode) {
                labels.put(labelNode, "L" + counter++);
            }
        }
        return labels;
    }

    private Map<LabelNode, Integer> buildJumpTargetCounts(MethodNode node) {
        Map<LabelNode, Integer> targets = new IdentityHashMap<>();
        for (AbstractInsnNode insn = node.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof JumpInsnNode jumpInsn) {
                incrementLabelCount(targets, jumpInsn.label);
            } else if (insn instanceof TableSwitchInsnNode tableSwitch) {
                incrementLabelCount(targets, tableSwitch.dflt);
                for (LabelNode label : tableSwitch.labels) {
                    incrementLabelCount(targets, label);
                }
            } else if (insn instanceof LookupSwitchInsnNode lookupSwitch) {
                incrementLabelCount(targets, lookupSwitch.dflt);
                for (LabelNode label : lookupSwitch.labels) {
                    incrementLabelCount(targets, label);
                }
            }
        }
        for (TryCatchBlockNode tcb : node.tryCatchBlocks) {
            incrementLabelCount(targets, tcb.handler);
        }
        return targets;
    }

    private void incrementLabelCount(Map<LabelNode, Integer> counts, LabelNode label) {
        counts.merge(label, 1, Integer::sum);
    }

    private Map<AbstractInsnNode, Integer> buildPcMap(MethodNode node) {
        Map<AbstractInsnNode, Integer> pcMap = new IdentityHashMap<>();
        int pc = 0;
        for (AbstractInsnNode insn = node.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (isRealInsn(insn)) {
                pcMap.put(insn, pc++);
            }
        }
        return pcMap;
    }

    private Map<Integer, List<TryHandler>> buildActiveHandlers(L1Method method, Map<LabelNode, String> labelMap, Map<AbstractInsnNode, Integer> pcMap) {
        Map<Integer, List<TryHandler>> active = new HashMap<>();
        for (TryCatchBlockNode tcb : method.tryCatchBlocks()) {
            int startPc = resolvePcAtOrAfter(tcb.start, pcMap);
            int endPc = resolvePcAtOrAfter(tcb.end, pcMap);
            if (startPc < 0 || endPc < 0 || startPc >= endPc) {
                continue;
            }
            TryHandler handler = new TryHandler(labelMap.get(tcb.handler), tcb.type);
            for (int pc = startPc; pc < endPc; pc++) {
                active.computeIfAbsent(pc, ignored -> new ArrayList<>()).add(handler);
            }
        }
        return active;
    }

    private int resolvePcAtOrAfter(AbstractInsnNode node, Map<AbstractInsnNode, Integer> pcMap) {
        for (AbstractInsnNode cur = node; cur != null; cur = cur.getNext()) {
            Integer pc = pcMap.get(cur);
            if (pc != null) {
                return pc;
            }
        }
        return -1;
    }

    private void emitParamToLocals(CFunction fn, L1Method method, Type[] argTypes) {
        int localIndex = 0;
        if (!method.isStatic()) {
            fn.addStatement(new CStatement.RawC("locals[0].o = neko_store_local_oop_ref(thread, &__neko_local_roots[0], self);"));
            localIndex = 1;
        }
        for (int i = 0; i < argTypes.length; i++) {
            if ("o".equals(slotField(argTypes[i]))) {
                fn.addStatement(new CStatement.RawC("locals[" + localIndex + "].o = neko_store_local_oop_ref(thread, &__neko_local_roots[" + localIndex + "], p" + i + ");"));
            } else {
                fn.addStatement(new CStatement.RawC("locals[" + localIndex + "]." + slotField(argTypes[i]) + " = p" + i + ";"));
            }
            localIndex += argTypes[i].getSize();
        }
    }

    private boolean methodMayUseObjectLocalRoots(L1Method method, Type[] argTypes) {
        if (!method.isStatic()) return true;
        for (Type argType : argTypes) {
            if (isReferenceType(argType)) return true;
        }
        return bytecodeStoresObjectLocal(method.asmNode());
    }

    private boolean bytecodeStoresObjectLocal(MethodNode node) {
        for (AbstractInsnNode insn = node.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof VarInsnNode varInsn && varInsn.getOpcode() == Opcodes.ASTORE) {
                return true;
            }
        }
        return false;
    }

    private boolean bytecodeUsesMonitors(MethodNode node) {
        for (AbstractInsnNode insn = node.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            int opcode = insn.getOpcode();
            if (opcode == Opcodes.MONITORENTER || opcode == Opcodes.MONITOREXIT) {
                return true;
            }
        }
        return false;
    }

    private boolean isNoHandleDispatcherSafe(MethodSelection selection, CFunction fn) {
        L1Method method = selection.method();
        if (!method.isStatic()) return false;
        if ((method.access() & Opcodes.ACC_SYNCHRONIZED) != 0) return false;
        if (!descriptorHasNoReferences(method.descriptor())) return false;
        if (!method.tryCatchBlocks().isEmpty()) return false;
        if (!bytecodeIsPrimitiveOnly(method.asmNode())) return false;
        return translatedBodyHasNoHandleExposure(fn);
    }

    private boolean methodMayUseBoundStrings(MethodNode node) {
        for (AbstractInsnNode insn = node.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof InvokeDynamicInsnNode) {
                return true;
            }
            if (insn instanceof LdcInsnNode ldc) {
                if (ldc.cst instanceof String || ldc.cst instanceof org.objectweb.asm.ConstantDynamic) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean descriptorHasNoReferences(String descriptor) {
        if (isReferenceType(Type.getReturnType(descriptor))) return false;
        for (Type arg : Type.getArgumentTypes(descriptor)) {
            if (isReferenceType(arg)) return false;
        }
        return true;
    }

    private boolean isReferenceType(Type type) {
        return type.getSort() == Type.OBJECT || type.getSort() == Type.ARRAY;
    }

    private boolean bytecodeIsPrimitiveOnly(MethodNode node) {
        for (AbstractInsnNode insn = node.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof LabelNode || insn instanceof LineNumberNode || insn instanceof FrameNode) {
                continue;
            }
            if (insn instanceof FieldInsnNode || insn instanceof MethodInsnNode || insn instanceof TypeInsnNode
                || insn instanceof MultiANewArrayInsnNode || insn instanceof InvokeDynamicInsnNode) {
                return false;
            }
            if (insn instanceof LdcInsnNode ldc) {
                Object cst = ldc.cst;
                if (!(cst instanceof Integer || cst instanceof Float || cst instanceof Long || cst instanceof Double)) {
                    return false;
                }
                continue;
            }
            if (insn instanceof VarInsnNode varInsn) {
                if (!isPrimitiveLocalOpcode(varInsn.getOpcode())) return false;
                continue;
            }
            if (insn instanceof IntInsnNode intInsn) {
                if (intInsn.getOpcode() != Opcodes.BIPUSH && intInsn.getOpcode() != Opcodes.SIPUSH) return false;
                continue;
            }
            if (insn instanceof JumpInsnNode jumpInsn) {
                if (!isPrimitiveJumpOpcode(jumpInsn.getOpcode())) return false;
                continue;
            }
            if (insn instanceof TableSwitchInsnNode || insn instanceof LookupSwitchInsnNode || insn instanceof IincInsnNode) {
                continue;
            }
            if (insn instanceof InsnNode insnNode) {
                if (!isPrimitiveInsnOpcode(insnNode.getOpcode())) return false;
                continue;
            }
            return false;
        }
        return true;
    }

    private boolean isPrimitiveLocalOpcode(int opcode) {
        return switch (opcode) {
            case Opcodes.ILOAD, Opcodes.LLOAD, Opcodes.FLOAD, Opcodes.DLOAD,
                 Opcodes.ISTORE, Opcodes.LSTORE, Opcodes.FSTORE, Opcodes.DSTORE -> true;
            default -> false;
        };
    }

    private boolean isPrimitiveJumpOpcode(int opcode) {
        return switch (opcode) {
            case Opcodes.IFEQ, Opcodes.IFNE, Opcodes.IFLT, Opcodes.IFGE, Opcodes.IFGT, Opcodes.IFLE,
                 Opcodes.IF_ICMPEQ, Opcodes.IF_ICMPNE, Opcodes.IF_ICMPLT, Opcodes.IF_ICMPGE,
                 Opcodes.IF_ICMPGT, Opcodes.IF_ICMPLE, Opcodes.GOTO -> true;
            default -> false;
        };
    }

    private boolean isPrimitiveInsnOpcode(int opcode) {
        return switch (opcode) {
            case Opcodes.NOP,
                 Opcodes.ICONST_M1, Opcodes.ICONST_0, Opcodes.ICONST_1, Opcodes.ICONST_2, Opcodes.ICONST_3,
                 Opcodes.ICONST_4, Opcodes.ICONST_5, Opcodes.LCONST_0, Opcodes.LCONST_1,
                 Opcodes.FCONST_0, Opcodes.FCONST_1, Opcodes.FCONST_2, Opcodes.DCONST_0, Opcodes.DCONST_1,
                 Opcodes.POP, Opcodes.POP2, Opcodes.DUP, Opcodes.DUP_X1, Opcodes.DUP_X2,
                 Opcodes.DUP2, Opcodes.DUP2_X1, Opcodes.DUP2_X2, Opcodes.SWAP,
                 Opcodes.IADD, Opcodes.LADD, Opcodes.FADD, Opcodes.DADD,
                 Opcodes.ISUB, Opcodes.LSUB, Opcodes.FSUB, Opcodes.DSUB,
                 Opcodes.IMUL, Opcodes.LMUL, Opcodes.FMUL, Opcodes.DMUL,
                 Opcodes.INEG, Opcodes.LNEG, Opcodes.FNEG, Opcodes.DNEG,
                 Opcodes.ISHL, Opcodes.LSHL, Opcodes.ISHR, Opcodes.LSHR, Opcodes.IUSHR, Opcodes.LUSHR,
                 Opcodes.IAND, Opcodes.LAND, Opcodes.IOR, Opcodes.LOR, Opcodes.IXOR, Opcodes.LXOR,
                 Opcodes.I2L, Opcodes.I2F, Opcodes.I2D, Opcodes.L2I, Opcodes.L2F, Opcodes.L2D,
                 Opcodes.F2I, Opcodes.F2L, Opcodes.F2D, Opcodes.D2I, Opcodes.D2L, Opcodes.D2F,
                 Opcodes.I2B, Opcodes.I2C, Opcodes.I2S,
                 Opcodes.LCMP, Opcodes.FCMPL, Opcodes.FCMPG, Opcodes.DCMPL, Opcodes.DCMPG,
                 Opcodes.IRETURN, Opcodes.LRETURN, Opcodes.FRETURN, Opcodes.DRETURN, Opcodes.RETURN -> true;
            default -> false;
        };
    }

    private boolean translatedBodyHasNoHandleExposure(CFunction fn) {
        for (CStatement statement : fn.body()) {
            if (statement instanceof CStatement.RawC raw && translatedStatementExposesHandle(raw.code())) {
                return false;
            }
        }
        return true;
    }

    private boolean translatedStatementExposesHandle(String code) {
        String[] denied = {
            "PUSH_O", "POP_O", ".o =", "jobject", "jarray", "jclass", "jthrowable",
            "neko_direct_oop_to_handle", "neko_handle_push", "neko_fast_aaload",
            "neko_fast_get_object", "neko_fast_set_object", "neko_fast_get_static_object",
            "neko_fast_set_static_object", "neko_fast_alloc", "neko_fast_new",
            "neko_multi_new_array", "neko_bound_string", "neko_bound_class",
            "neko_bound_method", "neko_bound_field", "neko_icache_dispatch",
            "neko_njx_", "neko_raise_implicit_exception", "neko_set_pending_exception",
            "neko_fast_monitor_", "MONITORENTER", "MONITOREXIT", "clazz", "self"
        };
        for (String needle : denied) {
            if (code.contains(needle)) return true;
        }
        return false;
    }

    private boolean isRealInsn(AbstractInsnNode insn) {
        return !(insn instanceof LabelNode) && !(insn instanceof LineNumberNode) && !(insn instanceof FrameNode);
    }

    private static final class MethodHandleBridgeRegistry implements OpcodeTranslator.MethodHandleBridgeFactory {
        private final Map<String, L1Class> ownersByName;
        private final Map<String, Integer> bridgeCounters = new HashMap<>();

        private MethodHandleBridgeRegistry(Map<String, L1Class> ownersByName) {
            this.ownersByName = ownersByName;
        }

        @Override
        public OpcodeTranslator.MethodHandleBridge ensureBridge(String ownerInternalName, String invokeDescriptor) {
            L1Class owner = ownersByName.get(ownerInternalName);
            if (owner == null) {
                return null;
            }

            Type[] invokeArgs = Type.getArgumentTypes(invokeDescriptor);
            Type[] bridgeArgs = new Type[invokeArgs.length + 1];
            bridgeArgs[0] = Type.getType(METHOD_HANDLE_DESC);
            System.arraycopy(invokeArgs, 0, bridgeArgs, 1, invokeArgs.length);

            Type returnType = Type.getReturnType(invokeDescriptor);
            String bridgeName = "neko$mh$" + bridgeCounters.merge(ownerInternalName, 1, Integer::sum);
            String bridgeDescriptor = Type.getMethodDescriptor(returnType, bridgeArgs);

            MethodNode bridge = new MethodNode(Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC, bridgeName, bridgeDescriptor, null, null);
            if (owner.version() >= 53) {
                addHiddenAnnotation(bridge, LAMBDA_FORM_HIDDEN_DESC);
                addHiddenAnnotation(bridge, JDK_HIDDEN_DESC);
            }

            int localIndex = 0;
            for (Type argumentType : bridgeArgs) {
                bridge.instructions.add(new VarInsnNode(argumentType.getOpcode(Opcodes.ILOAD), localIndex));
                localIndex += argumentType.getSize();
            }
            bridge.instructions.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/invoke/MethodHandle", "invokeExact", invokeDescriptor, false));
            bridge.instructions.add(new InsnNode(returnType.getOpcode(Opcodes.IRETURN)));
            bridge.maxStack = Math.max(localIndex, returnType.getSize());
            bridge.maxLocals = localIndex;

            owner.asmNode().methods.add(bridge);
            owner.methods().add(new L1Method(owner, bridge));
            owner.markDirty();
            return new OpcodeTranslator.MethodHandleBridge(ownerInternalName, bridgeName, bridgeDescriptor);
        }

        private void addHiddenAnnotation(MethodNode bridge, String descriptor) {
            if (bridge.visibleAnnotations == null) {
                bridge.visibleAnnotations = new ArrayList<>();
            }
            bridge.visibleAnnotations.add(new AnnotationNode(descriptor));
        }
    }

    /**
     * Decide whether the deferred exception check (for the most recent
     * potentially-throwing op, with its handler set) MUST be flushed before
     * the next instruction. Required when:
     *   - The next instruction's active handlers differ from the pending
     *     op's. (Crossing a try-region boundary; the pending op's exception
     *     must dispatch to its OWN handler set, not the new one.)
     *   - The next instruction is a branch / switch / return / athrow.
     *     Branches must observe the exception so dispatch is correct;
     *     returns are safe in principle (JVM sees pending exception on
     *     return) but skipping a check before athrow could mask the
     *     original exception with the new one.
     * Sequential straight-line instructions with the same handler set don't
     * trigger a flush — letting subsequent JNI calls become no-ops on
     * pending exception is harmless and the deferred check at the next
     * boundary catches it.
     */
    private boolean needsCheckBefore(
        AbstractInsnNode insn,
        List<TryHandler> pendingHandlers,
        Map<Integer, List<TryHandler>> activeHandlers,
        Map<AbstractInsnNode, Integer> pcMap
    ) {
        Integer pc = pcMap.get(insn);
        if (pc != null) {
            List<TryHandler> here = activeHandlers.getOrDefault(pc, List.of());
            if (!here.equals(pendingHandlers)) return true;
        }
        if (insn instanceof JumpInsnNode
            || insn instanceof TableSwitchInsnNode
            || insn instanceof LookupSwitchInsnNode) {
            return true;
        }
        int op = insn.getOpcode();
        return op == Opcodes.IRETURN
            || op == Opcodes.LRETURN
            || op == Opcodes.FRETURN
            || op == Opcodes.DRETURN
            || op == Opcodes.ARETURN
            || op == Opcodes.RETURN
            || op == Opcodes.ATHROW;
    }

    private record TailCallRewrite(String code, AbstractInsnNode lastInsn) {}

    /**
     * Tail-call elimination for self-recursion: when an INVOKESTATIC /
     * INVOKESPECIAL targets the current method and is in tail position
     * (immediately followed by a matching XRETURN, modulo labels/lines/frames),
     * rewrite the call into a `goto L0` that re-enters the method body with
     * the new argument values written into the local table.
     *
     * Mirrors what HotSpot's interpreter does for self-static recursion in
     * the rewriter — eliminates the JNI stack-frame and shadow-stack push for
     * every recursive level. Universal for any recursive Java method, not
     * just hand-picked ones.
     *
     * Skipped when an exception handler is active over the call site (the
     * handler must observe the call frame).
     */
    private TailCallRewrite tryTailRecursion(
        AbstractInsnNode insn,
        MethodSelection selection,
        Type[] argTypes,
        Map<Integer, List<TryHandler>> activeHandlers,
        Map<AbstractInsnNode, Integer> pcMap
    ) {
        if (!(insn instanceof MethodInsnNode mi)) return null;
        int opcode = mi.getOpcode();
        if (opcode != Opcodes.INVOKESTATIC && opcode != Opcodes.INVOKESPECIAL) return null;
        L1Method current = selection.method();
        if (!mi.owner.equals(selection.owner().name())
            || !mi.name.equals(current.name())
            || !mi.desc.equals(current.descriptor())) {
            return null;
        }
        boolean staticCall = (opcode == Opcodes.INVOKESTATIC);
        if (staticCall != current.isStatic()) return null;
        Integer callPc = pcMap.get(insn);
        if (callPc == null) return null;
        if (!activeHandlers.getOrDefault(callPc, List.of()).isEmpty()) return null;
        AbstractInsnNode next = nextRealInsn(insn);
        if (next == null) return null;
        Type returnType = Type.getReturnType(current.descriptor());
        if (!isMatchingReturn(next.getOpcode(), returnType)) return null;

        StringBuilder sb = new StringBuilder("{ /* tail-call → goto L0 */ ");
        for (int i = argTypes.length - 1; i >= 0; i--) {
            sb.append(jniTypeName(argTypes[i])).append(" __tco").append(i).append(" = ").append(popForType(argTypes[i])).append("; ");
        }
        if (!staticCall) {
            sb.append("jobject __tco_recv = POP_O(); ");
        }
        int localIndex = 0;
        if (!staticCall) {
            sb.append("locals[0].o = neko_store_local_oop_ref(thread, &__neko_local_roots[0], __tco_recv); ");
            localIndex = 1;
        }
        for (int i = 0; i < argTypes.length; i++) {
            if ("o".equals(slotField(argTypes[i]))) {
                sb.append("locals[").append(localIndex).append("].o = neko_store_local_oop_ref(thread, &__neko_local_roots[").append(localIndex).append("], __tco").append(i).append("); ");
            } else {
                sb.append("locals[").append(localIndex).append("].").append(slotField(argTypes[i])).append(" = __tco").append(i).append("; ");
            }
            localIndex += argTypes[i].getSize();
        }
        sb.append("sp = 0; goto __neko_tco_entry; }");
        return new TailCallRewrite(sb.toString(), next);
    }

    private boolean isMatchingReturn(int opcode, Type returnType) {
        return switch (returnType.getSort()) {
            case Type.VOID -> opcode == Opcodes.RETURN;
            case Type.LONG -> opcode == Opcodes.LRETURN;
            case Type.FLOAT -> opcode == Opcodes.FRETURN;
            case Type.DOUBLE -> opcode == Opcodes.DRETURN;
            case Type.OBJECT, Type.ARRAY -> opcode == Opcodes.ARETURN;
            default -> opcode == Opcodes.IRETURN;
        };
    }

    private String popForType(Type t) {
        return switch (t.getSort()) {
            case Type.LONG -> "POP_L()";
            case Type.FLOAT -> "POP_F()";
            case Type.DOUBLE -> "POP_D()";
            case Type.OBJECT, Type.ARRAY -> "POP_O()";
            default -> "POP_I()";
        };
    }

    private String jniTypeName(Type t) {
        return switch (t.getSort()) {
            case Type.BOOLEAN -> "jboolean";
            case Type.BYTE -> "jbyte";
            case Type.CHAR -> "jchar";
            case Type.SHORT -> "jshort";
            case Type.INT -> "jint";
            case Type.LONG -> "jlong";
            case Type.FLOAT -> "jfloat";
            case Type.DOUBLE -> "jdouble";
            case Type.OBJECT, Type.ARRAY -> "jobject";
            case Type.VOID -> "void";
            default -> "jint";
        };
    }

    private OpcodeTranslator.FusedTranslation tryFusedAALoad(
        OpcodeTranslator opcodes,
        AbstractInsnNode insn,
        Map<Integer, List<TryHandler>> activeHandlers,
        Map<AbstractInsnNode, Integer> pcMap
    ) {
        OpcodeTranslator.FusedTranslation candidate = opcodes.tryFuseLocalArrayLoad(insn);
        if (candidate == null) {
            if (insn.getOpcode() != Opcodes.AALOAD) return null;
            candidate = opcodes.tryFuseArrayLoad(insn);
        }
        if (candidate == null) return null;
        Integer aaloadPc = pcMap.get(candidate.firstThrowInsn());
        Integer lastPc = pcMap.get(candidate.lastInsn());
        if (aaloadPc == null || lastPc == null) return null;
        List<TryHandler> aaloadHandlers = activeHandlers.getOrDefault(aaloadPc, List.of());
        List<TryHandler> lastHandlers = activeHandlers.getOrDefault(lastPc, List.of());
        if (!aaloadHandlers.equals(lastHandlers)) return null;
        return candidate;
    }

    private record StringConcatRecurrenceFusion(String code, AbstractInsnNode lastInsn) {}

    private StringConcatRecurrenceFusion tryStringConcatRecurrenceFusion(
        AbstractInsnNode start,
        Map<LabelNode, String> labelMap,
        Map<LabelNode, Integer> jumpTargetCounts,
        Map<Integer, List<TryHandler>> activeHandlers,
        Map<AbstractInsnNode, Integer> pcMap
    ) {
        if (!(start instanceof VarInsnNode load) || load.getOpcode() != Opcodes.ALOAD) {
            return null;
        }
        int local = load.var;
        LabelNode loopLabel = previousLabelBefore(start);
        if (loopLabel == null) {
            return null;
        }
        AbstractInsnNode previousStore = previousRealInsn(start);
        if (!(previousStore instanceof VarInsnNode initialStore)
            || initialStore.getOpcode() != Opcodes.ASTORE
            || initialStore.var != local) {
            return null;
        }
        AbstractInsnNode initialValue = previousRealInsn(previousStore);
        if (!(initialValue instanceof LdcInsnNode initialLdc) || !(initialLdc.cst instanceof String initialString)) {
            return null;
        }

        AbstractInsnNode lengthCall = nextRealInsn(load);
        if (!isStringLengthCall(lengthCall)) {
            return null;
        }
        AbstractInsnNode limitInsn = nextRealInsn(lengthCall);
        Integer limit = intLiteral(limitInsn);
        if (limit == null) {
            return null;
        }
        AbstractInsnNode branchInsn = nextRealInsn(limitInsn);
        if (!(branchInsn instanceof JumpInsnNode exitBranch) || exitBranch.getOpcode() != Opcodes.IF_ICMPGE) {
            return null;
        }
        if (localEscapesAfterExit(exitBranch.label, local)) {
            return null;
        }

        AbstractInsnNode newBuilder = nextRealInsn(exitBranch);
        AbstractInsnNode dup = nextRealInsn(newBuilder);
        AbstractInsnNode init = nextRealInsn(dup);
        AbstractInsnNode first = nextRealInsn(init);
        AbstractInsnNode append1 = nextRealInsn(first);
        AbstractInsnNode second = nextRealInsn(append1);
        AbstractInsnNode append2 = nextRealInsn(second);
        AbstractInsnNode toString = nextRealInsn(append2);
        if (!(newBuilder instanceof TypeInsnNode newInsn)
            || newInsn.getOpcode() != Opcodes.NEW
            || !"java/lang/StringBuilder".equals(newInsn.desc)) {
            return null;
        }
        if (!(dup instanceof InsnNode dupInsn) || dupInsn.getOpcode() != Opcodes.DUP) {
            return null;
        }
        if (!(init instanceof MethodInsnNode initCall)
            || initCall.getOpcode() != Opcodes.INVOKESPECIAL
            || !"java/lang/StringBuilder".equals(initCall.owner)
            || !"<init>".equals(initCall.name)
            || !"()V".equals(initCall.desc)) {
            return null;
        }
        if (!(first instanceof VarInsnNode firstLoad) || firstLoad.getOpcode() != Opcodes.ALOAD || firstLoad.var != local) {
            return null;
        }
        if (!isStringBuilderAppendString(append1)) {
            return null;
        }
        if (!(second instanceof LdcInsnNode suffixLdc) || !(suffixLdc.cst instanceof String suffix) || suffix.isEmpty()) {
            return null;
        }
        if (!isStringBuilderAppendString(append2)) {
            return null;
        }
        if (!(toString instanceof MethodInsnNode toStringCall)
            || toStringCall.getOpcode() != Opcodes.INVOKEVIRTUAL
            || !"java/lang/StringBuilder".equals(toStringCall.owner)
            || !"toString".equals(toStringCall.name)
            || !"()Ljava/lang/String;".equals(toStringCall.desc)) {
            return null;
        }
        AbstractInsnNode storeInsn = nextNonMetaSameBlock(toString);
        if (!(storeInsn instanceof VarInsnNode store) || store.getOpcode() != Opcodes.ASTORE || store.var != local) {
            return null;
        }
        AbstractInsnNode backedgeInsn = nextRealInsn(storeInsn);
        if (!(backedgeInsn instanceof JumpInsnNode backedge)
            || backedge.getOpcode() != Opcodes.GOTO
            || backedge.label != loopLabel) {
            return null;
        }
        if (coveredRegionHasActiveHandlers(start, backedgeInsn, activeHandlers, pcMap)
            || coveredRegionHasBranchTarget(start, backedgeInsn, jumpTargetCounts)) {
            return null;
        }

        String exitLabel = labelMap.get(exitBranch.label);
        if (exitLabel == null) {
            return null;
        }
        int recurrence = stringRecurrenceIndex++;
        String code = "{ /* scalarized same-local StringBuilder concat recurrence */ "
            + "jlong __neko_scalar_concat_len_" + recurrence + " = " + initialString.length() + "LL; "
            + "jlong __neko_scalar_concat_limit_" + recurrence + " = " + limit + "LL; "
            + "jlong __neko_scalar_concat_step_" + recurrence + " = " + suffix.length() + "LL; "
            + "(void)__neko_scalar_concat_len_" + recurrence + "; "
            + "(void)__neko_scalar_concat_limit_" + recurrence + "; "
            + "(void)__neko_scalar_concat_step_" + recurrence + "; "
            + "goto " + exitLabel + "; }";
        return new StringConcatRecurrenceFusion(code, backedgeInsn);
    }

    private boolean isStringLengthCall(AbstractInsnNode insn) {
        return insn instanceof MethodInsnNode call
            && call.getOpcode() == Opcodes.INVOKEVIRTUAL
            && "java/lang/String".equals(call.owner)
            && "length".equals(call.name)
            && "()I".equals(call.desc);
    }

    private boolean isStringBuilderAppendString(AbstractInsnNode insn) {
        return insn instanceof MethodInsnNode call
            && call.getOpcode() == Opcodes.INVOKEVIRTUAL
            && "java/lang/StringBuilder".equals(call.owner)
            && "append".equals(call.name)
            && "(Ljava/lang/String;)Ljava/lang/StringBuilder;".equals(call.desc);
    }

    private boolean localEscapesAfterExit(LabelNode exitLabel, int local) {
        for (AbstractInsnNode cur = exitLabel.getNext(); cur != null; cur = cur.getNext()) {
            if (cur instanceof VarInsnNode varInsn && varInsn.getOpcode() == Opcodes.ALOAD && varInsn.var == local) {
                return true;
            }
        }
        return false;
    }

    private boolean coveredRegionHasActiveHandlers(
        AbstractInsnNode first,
        AbstractInsnNode last,
        Map<Integer, List<TryHandler>> activeHandlers,
        Map<AbstractInsnNode, Integer> pcMap
    ) {
        for (AbstractInsnNode cur = first; cur != null; cur = cur.getNext()) {
            if (isRealInsn(cur)) {
                Integer pc = pcMap.get(cur);
                if (pc == null || !activeHandlers.getOrDefault(pc, List.of()).isEmpty()) {
                    return true;
                }
            }
            if (cur == last) {
                return false;
            }
        }
        return true;
    }

    private boolean coveredRegionHasBranchTarget(
        AbstractInsnNode first,
        AbstractInsnNode last,
        Map<LabelNode, Integer> jumpTargetCounts
    ) {
        for (AbstractInsnNode cur = first; cur != null; cur = cur.getNext()) {
            if (cur instanceof LabelNode label && jumpTargetCounts.getOrDefault(label, 0) > 0) {
                return true;
            }
            if (cur == last) {
                return false;
            }
        }
        return true;
    }

    private LabelNode previousLabelBefore(AbstractInsnNode insn) {
        for (AbstractInsnNode cur = insn == null ? null : insn.getPrevious(); cur != null; cur = cur.getPrevious()) {
            if (cur instanceof LineNumberNode || cur instanceof FrameNode) {
                continue;
            }
            if (cur instanceof LabelNode label) {
                return label;
            }
            return null;
        }
        return null;
    }

    private AbstractInsnNode previousRealInsn(AbstractInsnNode insn) {
        for (AbstractInsnNode cur = insn == null ? null : insn.getPrevious(); cur != null; cur = cur.getPrevious()) {
            if (isRealInsn(cur)) {
                return cur;
            }
        }
        return null;
    }

    private StringConcatPattern renderedStringConcatPattern(AbstractInsnNode start, String currentOwnerInternalName) {
        if (!(start instanceof org.objectweb.asm.tree.TypeInsnNode newInsn)
            || start.getOpcode() != Opcodes.NEW
            || !"java/lang/StringBuilder".equals(newInsn.desc)) {
            return null;
        }
        AbstractInsnNode dup = nextRealInsn(start);
        AbstractInsnNode init = nextRealInsn(dup);
        AbstractInsnNode first = nextRealInsn(init);
        AbstractInsnNode append1 = nextRealInsn(first);
        AbstractInsnNode second = nextRealInsn(append1);
        AbstractInsnNode append2 = nextRealInsn(second);
        AbstractInsnNode toString = nextRealInsn(append2);
        if (!(dup instanceof InsnNode dupInsn) || dupInsn.getOpcode() != Opcodes.DUP) {
            return null;
        }
        if (!(init instanceof MethodInsnNode initCall)
            || initCall.getOpcode() != Opcodes.INVOKESPECIAL
            || !"java/lang/StringBuilder".equals(initCall.owner)
            || !"<init>".equals(initCall.name)
            || !"()V".equals(initCall.desc)) {
            return null;
        }
        if (!(append1 instanceof MethodInsnNode appendCall1)
            || appendCall1.getOpcode() != Opcodes.INVOKEVIRTUAL
            || !"java/lang/StringBuilder".equals(appendCall1.owner)
            || !"append".equals(appendCall1.name)
            || !"(Ljava/lang/String;)Ljava/lang/StringBuilder;".equals(appendCall1.desc)) {
            return null;
        }
        if (!(append2 instanceof MethodInsnNode appendCall2)
            || appendCall2.getOpcode() != Opcodes.INVOKEVIRTUAL
            || !"java/lang/StringBuilder".equals(appendCall2.owner)
            || !"append".equals(appendCall2.name)
            || !"(Ljava/lang/String;)Ljava/lang/StringBuilder;".equals(appendCall2.desc)) {
            return null;
        }
        if (!(toString instanceof MethodInsnNode toStringCall)
            || toStringCall.getOpcode() != Opcodes.INVOKEVIRTUAL
            || !"java/lang/StringBuilder".equals(toStringCall.owner)
            || !"toString".equals(toStringCall.name)
            || !"()Ljava/lang/String;".equals(toStringCall.desc)) {
            return null;
        }
        StringProducer firstProducer = stringProducer(first);
        if (firstProducer == null) {
            return null;
        }
        String code;
        AbstractInsnNode lastInsn = toString;
        VarInsnNode immediateStore = immediateAstoreAfter(toString);
        codeGenerator.registerOwnerFieldReference(currentOwnerInternalName, "java/lang/String", "value", "[B", false);
        codeGenerator.registerOwnerFieldReference(currentOwnerInternalName, "java/lang/String", "coder", "B", false);
        if (second instanceof LdcInsnNode ldcInsn && ldcInsn.cst instanceof String s) {
            StringProducer secondProducer = literalStringProducer(s);
            code = "{ " + firstProducer.prefix + secondProducer.prefix
                + "jstring __lhs = (jstring)(" + firstProducer.expr + "); "
                + "jstring __rhs = (jstring)(" + secondProducer.expr + "); "
                + "NEKO_HANDLE_AUDIT_HIT(g_neko_stringbuilder_concat_fast_total_count); "
                + "NEKO_HANDLE_AUDIT_HIT(g_neko_stringbuilder_concat_fast_literal_count); "
                + stringBuilderConcatResultConsumer("__lhs", "__rhs", immediateStore) + " }";
        } else {
            StringProducer secondProducer = stringProducer(second);
            if (secondProducer == null) {
                return null;
            }
            code = "{ " + firstProducer.prefix + secondProducer.prefix
                + "jstring __lhs = (jstring)(" + firstProducer.expr + "); "
                + "jstring __rhs = (jstring)(" + secondProducer.expr + "); "
                + "NEKO_HANDLE_AUDIT_HIT(g_neko_stringbuilder_concat_fast_total_count); "
                + "NEKO_HANDLE_AUDIT_HIT(g_neko_stringbuilder_concat_fast_dynamic_count); "
                + stringBuilderConcatResultConsumer("__lhs", "__rhs", immediateStore) + " }";
        }
        if (immediateStore != null) {
            lastInsn = immediateStore;
        }
        return new StringConcatPattern(code, lastInsn, toString);
    }

    private String stringBuilderConcatResultConsumer(String lhsExpr, String rhsExpr, VarInsnNode immediateStore) {
        String valueOffset = codeGenerator.fieldOffsetSlotName("java/lang/String", "value", "[B", false);
        String coderOffset = codeGenerator.fieldOffsetSlotName("java/lang/String", "coder", "B", false);
        if (immediateStore != null) {
            int local = immediateStore.var;
            return "jobject __fastConcat = neko_concat_append_inline_store_local(thread, env, &__neko_local_roots[" + local + "], "
                + lhsExpr + ", " + rhsExpr + ", " + valueOffset + ", " + coderOffset + "); "
                + "locals[" + local + "].o = __fastConcat;";
        }
        return "jobject __fastConcat = neko_concat_append_inline(thread, env, " + lhsExpr + ", " + rhsExpr + ", "
            + valueOffset + ", " + coderOffset + "); PUSH_O(__fastConcat);";
    }

    private VarInsnNode immediateAstoreAfter(AbstractInsnNode insn) {
        for (AbstractInsnNode cur = insn == null ? null : insn.getNext(); cur != null; cur = cur.getNext()) {
            if (cur instanceof LineNumberNode || cur instanceof FrameNode) {
                continue;
            }
            if (cur instanceof LabelNode) {
                return null;
            }
            return cur instanceof VarInsnNode varInsn && varInsn.getOpcode() == Opcodes.ASTORE ? varInsn : null;
        }
        return null;
    }

    private AbstractInsnNode nextRealInsn(AbstractInsnNode insn) {
        for (AbstractInsnNode cur = insn == null ? null : insn.getNext(); cur != null; cur = cur.getNext()) {
            if (isRealInsn(cur)) {
                return cur;
            }
        }
        return null;
    }

    private StringProducer stringProducer(AbstractInsnNode insn) {
        if (insn instanceof VarInsnNode varInsn && varInsn.getOpcode() == Opcodes.ALOAD) {
            return new StringProducer("", "locals[" + varInsn.var + "].o");
        }
        if (insn instanceof LdcInsnNode ldcInsn && ldcInsn.cst instanceof String s) {
            return literalStringProducer(s);
        }
        return null;
    }

    private StringProducer literalStringProducer(String value) {
        String literalVar = "__neko_concat_lit_" + concatLiteralIndex++;
        String prefix = "static jstring " + literalVar + " = NULL; "
            + "neko_bind_string_slot(thread, env, &" + literalVar + ", \"" + CStringLiteral.escape(value) + "\"); ";
        return new StringProducer(prefix, literalVar);
    }

    private PrimitiveArrayLiteralPattern renderedPrimitiveArrayLiteralPattern(AbstractInsnNode firstInsn) {
        Integer len = intLiteral(firstInsn);
        if (len == null || len < 4) {
            return null;
        }
        AbstractInsnNode newArrayInsn = nextLiteralPatternInsn(firstInsn);
        if (!(newArrayInsn instanceof IntInsnNode newArray) || newArray.getOpcode() != Opcodes.NEWARRAY) {
            return null;
        }
        PrimitiveArrayLiteralKind kind = PrimitiveArrayLiteralKind.forNewArrayOperand(newArray.operand);
        if (kind == null) {
            return null;
        }
        List<String> values = new ArrayList<>(len);
        AbstractInsnNode cur = nextLiteralPatternInsn(newArrayInsn);
        AbstractInsnNode lastStore = null;
        for (int expectedIndex = 0; expectedIndex < len; expectedIndex++) {
            if (cur == null || cur.getOpcode() != Opcodes.DUP) {
                return null;
            }
            AbstractInsnNode indexInsn = nextLiteralPatternInsn(cur);
            Integer index = intLiteral(indexInsn);
            if (index == null || index != expectedIndex) {
                return null;
            }
            AbstractInsnNode valueInsn = nextLiteralPatternInsn(indexInsn);
            String value = kind.literalValue(valueInsn);
            if (value == null) {
                return null;
            }
            AbstractInsnNode storeInsn = nextLiteralPatternInsn(valueInsn);
            if (storeInsn == null || storeInsn.getOpcode() != kind.storeOpcode) {
                return null;
            }
            values.add(value);
            lastStore = storeInsn;
            cur = nextLiteralPatternInsn(storeInsn);
        }
        if (lastStore == null) {
            return null;
        }
        String literalName = "__neko_primitive_array_literal_" + primitiveArrayLiteralIndex++;
        StringBuilder code = new StringBuilder();
        code.append("{ static const ").append(kind.cLiteralType).append(' ').append(literalName).append("[] = { ");
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) {
                code.append(", ");
            }
            code.append(values.get(i));
        }
        code.append(" }; ")
            .append(kind.cArrayType).append(" __a = (").append(kind.cArrayType).append(")neko_fast_new_primitive_array(thread, env, ")
            .append(len).append(", ").append(kind.kindConstant).append("); ")
            .append("char *__oop = (char*)neko_handle_oop((jobject)__a); ")
            .append("if (__oop == NULL || neko_const_prim_array_scale(").append(kind.kindConstant).append(") != (jint)sizeof(").append(kind.cElementType).append(") ")
            .append("|| *(jint*)(__oop + neko_const_array_length_offset()) != ").append(len).append(") { ")
            .append("fprintf(stderr, \"[neko-direct] primitive array literal init unavailable kind=%d len=%d arr=%p\\n\", ")
            .append(kind.kindConstant).append(", ").append(len).append(", (void*)__a); abort(); } ")
            .append("memcpy(__oop + neko_const_prim_array_base(").append(kind.kindConstant).append("), ").append(literalName).append(", sizeof(").append(literalName).append(")); ")
            .append("PUSH_O(__a); }");
        return new PrimitiveArrayLiteralPattern(code.toString(), newArrayInsn, lastStore);
    }

    private AbstractInsnNode nextLiteralPatternInsn(AbstractInsnNode insn) {
        AbstractInsnNode cur = insn == null ? null : insn.getNext();
        while (cur instanceof LineNumberNode || cur instanceof FrameNode) {
            cur = cur.getNext();
        }
        return cur;
    }

    private static Integer intLiteral(AbstractInsnNode insn) {
        if (insn == null) {
            return null;
        }
        int opcode = insn.getOpcode();
        if (opcode == Opcodes.ICONST_M1) return -1;
        if (opcode >= Opcodes.ICONST_0 && opcode <= Opcodes.ICONST_5) return opcode - Opcodes.ICONST_0;
        if (opcode == Opcodes.BIPUSH || opcode == Opcodes.SIPUSH) return ((IntInsnNode) insn).operand;
        if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof Integer value) return value;
        return null;
    }

    private static String doubleLiteral(AbstractInsnNode insn) {
        Double value = null;
        if (insn != null && insn.getOpcode() == Opcodes.DCONST_0) value = 0.0d;
        if (insn != null && insn.getOpcode() == Opcodes.DCONST_1) value = 1.0d;
        if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof Double ldcValue) value = ldcValue;
        if (value == null) {
            return null;
        }
        String hex = Long.toHexString(Double.doubleToRawLongBits(value));
        return "0x" + "0".repeat(16 - hex.length()) + hex + "ULL";
    }

    private record PrimitiveArrayLiteralPattern(String code, AbstractInsnNode newArrayInsn, AbstractInsnNode lastInsn) {}

    private enum PrimitiveArrayLiteralKind {
        INT(Opcodes.T_INT, Opcodes.IASTORE, "jint", "jint", "jintArray", "NEKO_PRIM_I") {
            @Override
            String literalValue(AbstractInsnNode insn) {
                Integer value = NativeTranslator.intLiteral(insn);
                return value == null ? null : value.toString();
            }
        },
        DOUBLE(Opcodes.T_DOUBLE, Opcodes.DASTORE, "uint64_t", "jdouble", "jdoubleArray", "NEKO_PRIM_D") {
            @Override
            String literalValue(AbstractInsnNode insn) {
                return NativeTranslator.doubleLiteral(insn);
            }
        };

        final int newArrayOperand;
        final int storeOpcode;
        final String cLiteralType;
        final String cElementType;
        final String cArrayType;
        final String kindConstant;

        PrimitiveArrayLiteralKind(int newArrayOperand, int storeOpcode, String cLiteralType, String cElementType, String cArrayType, String kindConstant) {
            this.newArrayOperand = newArrayOperand;
            this.storeOpcode = storeOpcode;
            this.cLiteralType = cLiteralType;
            this.cElementType = cElementType;
            this.cArrayType = cArrayType;
            this.kindConstant = kindConstant;
        }

        abstract String literalValue(AbstractInsnNode insn);

        static PrimitiveArrayLiteralKind forNewArrayOperand(int operand) {
            for (PrimitiveArrayLiteralKind kind : values()) {
                if (kind.newArrayOperand == operand) {
                    return kind;
                }
            }
            return null;
        }
    }

    private String renderTableSwitch(TableSwitchInsnNode insn, Map<LabelNode, String> labelMap) {
        StringBuilder sb = new StringBuilder();
        sb.append("{ jint __key = POP_I(); switch(__key) {");
        for (int i = 0; i < insn.labels.size(); i++) {
            sb.append(" case ").append(insn.min + i).append(": goto ").append(labelMap.get(insn.labels.get(i))).append(';');
        }
        sb.append(" default: goto ").append(labelMap.get(insn.dflt)).append("; } }");
        return sb.toString();
    }

    private String renderLookupSwitch(LookupSwitchInsnNode insn, Map<LabelNode, String> labelMap) {
        StringBuilder sb = new StringBuilder();
        sb.append("{ jint __key = POP_I(); switch(__key) {");
        for (int i = 0; i < insn.keys.size(); i++) {
            sb.append(" case ").append(insn.keys.get(i)).append(": goto ").append(labelMap.get(insn.labels.get(i))).append(';');
        }
        sb.append(" default: goto ").append(labelMap.get(insn.dflt)).append("; } }");
        return sb.toString();
    }

    private String renderExceptionDispatch(List<TryHandler> handlers, String bindingOwner) {
        StringBuilder sb = new StringBuilder();
        if (handlers.isEmpty()) {
            sb.append("if (neko_pending_exception_oop(thread) != NULL) { goto __neko_exception_exit; }");
            return sb.toString();
        }
        sb.append("{ jthrowable __exc = neko_take_pending_exception(thread); if (__exc != NULL) { ");
        boolean catchAllEmitted = false;
        for (TryHandler handler : handlers) {
            if (handler.exceptionType == null) {
                sb.append("sp = 0; PUSH_O(__exc); goto ").append(handler.handlerLabel).append("; ");
                catchAllEmitted = true;
                break;
            } else {
                sb.append("if (")
                    .append(cachedHandlerMatchExpression(bindingOwner, handler.exceptionType))
                    .append(") { sp = 0; PUSH_O(__exc); goto ").append(handler.handlerLabel).append("; } ");
            }
        }
        if (!catchAllEmitted) {
            sb.append("neko_set_pending_exception(thread, __exc); goto __neko_exception_exit; ");
        }
        sb.append("} }");
        return sb.toString();
    }

    private String cachedHandlerMatchExpression(String bindingOwner, String exceptionType) {
        String ref = codeGenerator.classDescriptorRefName(bindingOwner, exceptionType);
        return "neko_exception_handler_matches_ref(env, __exc, &" + ref + ")";
    }

    private boolean isPotentiallyExcepting(AbstractInsnNode insn) {
        int opcode = insn.getOpcode();
        if (insn instanceof org.objectweb.asm.tree.FieldInsnNode fi
            && (opcode == Opcodes.GETSTATIC || opcode == Opcodes.PUTSTATIC)
            && fi.desc.length() == 1
            && "ZBCSIJFD".indexOf(fi.desc.charAt(0)) >= 0) {
            return false;
        }
        return switch (opcode) {
            case Opcodes.NEW,
                 Opcodes.NEWARRAY,
                 Opcodes.ANEWARRAY,
                 Opcodes.MULTIANEWARRAY,
                 Opcodes.ATHROW,
                 Opcodes.CHECKCAST,
                 Opcodes.INVOKEVIRTUAL,
                 Opcodes.INVOKEINTERFACE,
                 Opcodes.INVOKESPECIAL,
                 Opcodes.INVOKESTATIC,
                 Opcodes.INVOKEDYNAMIC,
                 Opcodes.AASTORE,
                 Opcodes.ARRAYLENGTH,
                 Opcodes.GETFIELD,
                 Opcodes.PUTFIELD,
                 Opcodes.GETSTATIC,
                 Opcodes.PUTSTATIC,
                 Opcodes.IDIV,
                 Opcodes.IREM,
                 Opcodes.LDIV,
                 Opcodes.LREM,
                 Opcodes.MONITORENTER,
                 Opcodes.MONITOREXIT -> true;
            default -> false;
        };
    }

    private void emitDefaultReturn(CFunction function, CType returnType, boolean shadowEnabled) {
        if (shadowEnabled) {
            function.addStatement(new CStatement.RawC("neko_shadow_pop();"));
        }
        switch (returnType) {
            case VOID -> function.addStatement(new CStatement.ReturnVoid());
            case JLONG -> function.addStatement(new CStatement.RawC("return (jlong)0;"));
            case JFLOAT -> function.addStatement(new CStatement.RawC("return (jfloat)0;"));
            case JDOUBLE -> function.addStatement(new CStatement.RawC("return (jdouble)0;"));
            case JOBJECT, JCLASS, JSTRING, JARRAY -> function.addStatement(new CStatement.RawC("return NULL;"));
            default -> function.addStatement(new CStatement.RawC("return (" + returnType.jniName() + ")0;"));
        }
    }

    private CType mapType(Type type) {
        return switch (type.getSort()) {
            case Type.VOID -> CType.VOID;
            case Type.BOOLEAN -> CType.JBOOLEAN;
            case Type.CHAR -> CType.JCHAR;
            case Type.BYTE -> CType.JBYTE;
            case Type.SHORT -> CType.JSHORT;
            case Type.INT -> CType.JINT;
            case Type.FLOAT -> CType.JFLOAT;
            case Type.LONG -> CType.JLONG;
            case Type.DOUBLE -> CType.JDOUBLE;
            case Type.ARRAY -> CType.JARRAY;
            default -> CType.JOBJECT;
        };
    }

    private String slotField(Type type) {
        return switch (type.getSort()) {
            case Type.LONG -> "j";
            case Type.FLOAT -> "f";
            case Type.DOUBLE -> "d";
            case Type.ARRAY, Type.OBJECT -> "o";
            default -> "i";
        };
    }

    private String bindingKey(String owner, String name, String desc) {
        return owner + '#' + name + desc;
    }

    private boolean isDirectCallSafe(L1Class owner, L1Method method, Map<String, L1Class> applicationClassesByName) {
        if (method.isStatic()) {
            return true;
        }
        int access = method.access();
        if ((access & (Opcodes.ACC_FINAL | Opcodes.ACC_PRIVATE)) != 0
            || (owner.access() & Opcodes.ACC_FINAL) != 0) {
            return true;
        }
        if ((access & (Opcodes.ACC_PUBLIC | Opcodes.ACC_PROTECTED)) != 0) {
            return false;
        }
        for (L1Class candidate : applicationClassesByName.values()) {
            if (candidate.name().equals(owner.name())) {
                continue;
            }
            if (!isSubclassOf(candidate, owner.name(), applicationClassesByName)) {
                continue;
            }
            if (declaresVirtualOverride(candidate, method)) {
                return false;
            }
        }
        return true;
    }

    private boolean isSubclassOf(L1Class candidate, String ownerName, Map<String, L1Class> applicationClassesByName) {
        String cursor = candidate.asmNode().superName;
        while (cursor != null) {
            if (cursor.equals(ownerName)) {
                return true;
            }
            L1Class next = applicationClassesByName.get(cursor);
            if (next == null) {
                return false;
            }
            cursor = next.asmNode().superName;
        }
        return false;
    }

    private boolean declaresVirtualOverride(L1Class candidate, L1Method method) {
        for (L1Method candidateMethod : candidate.methods()) {
            if (!candidateMethod.name().equals(method.name()) || !candidateMethod.descriptor().equals(method.descriptor())) {
                continue;
            }
            int access = candidateMethod.access();
            if ((access & (Opcodes.ACC_STATIC | Opcodes.ACC_PRIVATE)) == 0) {
                return true;
            }
        }
        return false;
    }


    public record MethodSelection(L1Class owner, L1Method method) {}

    public record TranslationResult(
        String source,
        String header,
        int methodCount,
        List<NativeMethodBinding> bindings,
        GeneratedSourceSet sourceSet
    ) {
        public TranslationResult(
            String source,
            String header,
            int methodCount,
            List<NativeMethodBinding> bindings
        ) {
            this(source, header, methodCount, bindings, null);
        }
    }

    public record NativeMethodBinding(
        String ownerInternalName,
        String methodName,
        String descriptor,
        String cFunctionName,
        String rawFunctionName,
        String helperMethodName,
        String helperDescriptor,
        boolean isStatic,
        boolean directCallSafe,
        boolean noHandleDispatcherSafe
    ) {}

    private record TryHandler(String handlerLabel, String exceptionType) {}

    private record StringConcatPattern(String code, AbstractInsnNode lastInsn, AbstractInsnNode exceptionInsn) {}
    private record StringProducer(String prefix, String expr) {}
}

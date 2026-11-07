package dev.nekoobfuscator.transforms.jvm.renamer;

import dev.nekoobfuscator.api.transform.IRLevel;
import dev.nekoobfuscator.api.transform.TransformContext;
import dev.nekoobfuscator.api.transform.TransformPass;
import dev.nekoobfuscator.api.transform.TransformPhase;
import dev.nekoobfuscator.core.ir.l1.L1Class;
import dev.nekoobfuscator.core.ir.l1.L1Method;
import dev.nekoobfuscator.core.pipeline.PipelineContext;
import dev.nekoobfuscator.transforms.jvm.internal.JvmBridgeAbi;
import dev.nekoobfuscator.transforms.jvm.internal.JvmEnumAbi;
import dev.nekoobfuscator.transforms.jvm.internal.JvmRecordAbi;
import dev.nekoobfuscator.transforms.jvm.internal.JvmSerializationAbi;
import dev.nekoobfuscator.transforms.util.TransformGuards;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Type;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.commons.Remapper;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.AnalyzerException;
import org.objectweb.asm.tree.analysis.Frame;
import org.objectweb.asm.tree.analysis.SourceInterpreter;
import org.objectweb.asm.tree.analysis.SourceValue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.jar.Manifest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Deterministic ZKM-style application class/member renaming.
 */
public final class JvmRenamerPass implements TransformPass {
    public static final String ID = "renamer";
    private static final String PREPARED = "renamer.prepared";
    private static final String CLASS_MAP = "renamer.classMap";
    private static final String MEMBER_MAP = "renamer.memberMap";
    private static final String MAP_LINES = "renamer.mapLines";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String name() {
        return "JVM Renamer";
    }

    @Override
    public TransformPhase phase() {
        return TransformPhase.PRE_TRANSFORM;
    }

    @Override
    public IRLevel requiredLevel() {
        return IRLevel.L1;
    }

    @Override
    public void transformClass(TransformContext ctx) {
        if (!(ctx instanceof PipelineContext pctx)) return;
        if (Boolean.TRUE.equals(ctx.getPassData(PREPARED))) return;
        renameAll(pctx);
        ctx.putPassData(PREPARED, Boolean.TRUE);
    }

    @Override
    public void transformMethod(TransformContext ctx) {
    }

    @SuppressWarnings("unchecked")
    private static Map<String, String> classMap(TransformContext ctx) {
        Map<String, String> map = ctx.getPassData(CLASS_MAP);
        if (map == null) {
            map = new LinkedHashMap<>();
            ctx.putPassData(CLASS_MAP, map);
        }
        return map;
    }

    @SuppressWarnings("unchecked")
    private static Map<MemberKey, String> memberMap(TransformContext ctx) {
        Map<MemberKey, String> map = ctx.getPassData(MEMBER_MAP);
        if (map == null) {
            map = new LinkedHashMap<>();
            ctx.putPassData(MEMBER_MAP, map);
        }
        return map;
    }

    @SuppressWarnings("unchecked")
    private static List<String> mapLines(TransformContext ctx) {
        List<String> lines = ctx.getPassData(MAP_LINES);
        if (lines == null) {
            lines = new ArrayList<>();
            ctx.putPassData(MAP_LINES, lines);
        }
        return lines;
    }

    private void renameAll(PipelineContext pctx) {
        List<L1Class> remapClasses = pctx.classMap().values().stream()
            .filter(this::canRemapClassReferences)
            .sorted(Comparator.comparing(L1Class::name))
            .toList();
        List<L1Class> renameClasses = remapClasses;
        if (remapClasses.isEmpty() || renameClasses.isEmpty()) return;

        Map<String, String> classesByOldName = buildClassMap(pctx, renameClasses);
        verifyMainEntryClassesRenamed(pctx, remapClasses, classesByOldName);
        Map<MemberKey, String> membersByOldKey = booleanOption(pctx, "renameMembers", true)
            ? buildMemberMap(pctx, renameClasses)
            : Map.of();
        Map<String, Map<String, String>> methodNameMap = methodNameMap(membersByOldKey);
        Map<String, Map<String, String>> fieldNameMap = fieldNameMap(membersByOldKey);
        Map<MemberKey, Map<Integer, Set<String>>> proxyHandlerMethodOwners =
            dynamicProxyHandlerMethodOwners(pctx, remapClasses);

        Renamer remapper = new Renamer(pctx.classMap(), classesByOldName, membersByOldKey);
        var coverage = dev.nekoobfuscator.transforms.util.JvmObfuscationCoverage.get(pctx);
        Map<String, L1Class> remappedClassEntries = new LinkedHashMap<>();
        Map<L1Class, String> originalNames = new java.util.IdentityHashMap<>();
        for (L1Class clazz : remapClasses) {
            String originalName = clazz.name();
            originalNames.put(clazz, originalName);
            rewriteReflectiveStrings(
                clazz.asmNode(),
                classesByOldName,
                methodNameMap,
                fieldNameMap,
                proxyHandlerMethodOwners
            );
            rewriteHookTargetAnnotationStrings(
                clazz.asmNode(),
                remapper,
                classesByOldName,
                membersByOldKey
            );
            rewriteAnnotationEnumValueNames(clazz.asmNode(), membersByOldKey);
            ClassNode remapped = new ClassNode();
            clazz.asmNode().accept(new ClassRemapper(remapped, remapper));
            stripDebugMetadata(remapped);
            String remappedName = remapped.name;
            copyInto(clazz.asmNode(), remapped);
            clazz.markDirty();
            remappedClassEntries.put(remappedName, clazz);
            for (L1Method method : clazz.methods()) {
                if (method.hasCode()) {
                    coverage.full(ID, remappedName, method.name(), method.descriptor(), "renamed-symbols");
                }
            }
        }

        for (L1Class clazz : remapClasses) {
            String originalName = originalNames.get(clazz);
            if (originalName != null && !originalName.equals(clazz.name())) {
                pctx.classMap().remove(originalName);
            }
        }
        pctx.classMap().putAll(remappedClassEntries);
        classMap(pctx).putAll(classesByOldName);
        memberMap(pctx).putAll(membersByOldKey);
        rewriteManifestMainClass(pctx, classesByOldName);
        writeMapLines(pctx, classesByOldName, membersByOldKey);
    }

    private boolean canRemapClassReferences(L1Class clazz) {
        if (TransformGuards.isRuntimeClass(clazz)) return false;
        String name = clazz.name();
        return !"module-info".equals(name) &&
            !name.endsWith("/module-info");
    }

    private boolean canRenameClass(L1Class clazz) {
        return canRemapClassReferences(clazz);
    }

    private Map<String, String> buildClassMap(PipelineContext pctx, List<L1Class> classes) {
        String prefix = stringOption(pctx, "packagePrefix", "a/");
        String alphabet = stringOption(pctx, "classNameAlphabet", "abcdefghijklmnopqrstuvwxyz");
        int minimumLength = intOption(pctx, "classNameLength", 0);
        List<String> keepClassNames = stringListOption(pctx, "keepClassNames");
        Set<String> occupied = new HashSet<>(pctx.classMap().keySet());
        NameSource names = new NameSource(prefix, alphabet, minimumLength);
        Map<String, String> out = new LinkedHashMap<>();
        for (L1Class clazz : classes) {
            if (matchesAnyClassPattern(keepClassNames, clazz.name())) {
                out.put(clazz.name(), clazz.name());
                continue;
            }
            String newName;
            do {
                newName = names.nextInternalName();
            } while (occupied.contains(newName));
            out.put(clazz.name(), newName);
            occupied.add(newName);
        }
        return out;
    }

    private void verifyMainEntryClassesRenamed(
        PipelineContext pctx,
        List<L1Class> remapClasses,
        Map<String, String> classes
    ) {
        for (L1Class clazz : remapClasses) {
            if (!declaresMainEntry(clazz)) continue;
            String mapped = classes.get(clazz.name());
            if (mapped == null || mapped.equals(clazz.name())) {
                throw new IllegalStateException(
                    "Renamer must rename JVM main owner class: " + clazz.name()
                );
            }
        }
    }

    private boolean declaresMainEntry(L1Class clazz) {
        for (MethodNode method : clazz.asmNode().methods) {
            if ("main".equals(method.name)
                && "([Ljava/lang/String;)V".equals(method.desc)
                && (method.access & Opcodes.ACC_STATIC) != 0
                && (method.access & Opcodes.ACC_PUBLIC) != 0) {
                return true;
            }
        }
        return false;
    }

    private Map<MemberKey, String> buildMemberMap(PipelineContext pctx, List<L1Class> classes) {
        Map<MemberKey, String> out = new LinkedHashMap<>();
        Map<String, NameNode> methodNodes = new LinkedHashMap<>();
        DisjointSet<NameNode> methodGroups = new DisjointSet<>();

        for (L1Class clazz : classes) {
            for (MethodNode method : clazz.asmNode().methods) {
                if (!canRenameMethod(pctx, clazz, method)) continue;
                NameNode node = methodNode(methodNodes, clazz.name(), method.name);
                methodGroups.add(node);
            }
        }
        for (L1Class clazz : classes) {
            for (MethodNode method : clazz.asmNode().methods) {
                if (!canRenameMethod(pctx, clazz, method)) continue;
                NameNode current = methodNode(methodNodes, clazz.name(), method.name);
                unionAppAncestors(pctx, methodGroups, methodNodes, clazz, method);
                if (overridesExternalMethod(pctx, clazz, method, method.desc)) {
                    methodGroups.markFixed(current, method.name);
                }
            }
        }
        for (L1Class clazz : classes) {
            unionImplementedInterfaceMethods(pctx, methodGroups, methodNodes, clazz);
        }

        Map<NameNode, Set<String>> ownersByGroup = new LinkedHashMap<>();
        for (NameNode node : methodNodes.values()) {
            ownersByGroup.computeIfAbsent(methodGroups.find(node), ignored -> new LinkedHashSet<>()).add(node.owner());
        }
        Map<NameNode, String> methodGroupNames = assignGroupNames(ownersByGroup, methodGroups, pctx.classMap(), true);
        for (L1Class clazz : classes) {
            for (MethodNode method : clazz.asmNode().methods) {
                if (!canRenameMethod(pctx, clazz, method)) continue;
                NameNode node = methodGroups.find(methodNode(methodNodes, clazz.name(), method.name));
                String newName = methodGroupNames.get(node);
                if (newName != null && !newName.equals(method.name)) {
                    out.put(MemberKey.method(clazz.name(), method.name, method.desc), newName);
                }
            }
        }

        for (L1Class clazz : classes) {
            Set<String> occupied = new HashSet<>();
            for (FieldNode field : clazz.asmNode().fields) {
                if (!canRenameField(pctx, clazz, field)) {
                    occupied.add(field.name);
                }
            }
            NameSource fieldNames = new NameSource("");
            List<FieldNode> fields = new ArrayList<>(clazz.asmNode().fields);
            fields.sort(Comparator.comparing((FieldNode f) -> f.name).thenComparing(f -> f.desc));
            for (FieldNode field : fields) {
                if (!canRenameField(pctx, clazz, field)) continue;
                String newName;
                do {
                    newName = fieldNames.nextSimpleName();
                } while (!occupied.add(newName));
                if (!newName.equals(field.name)) {
                    out.put(MemberKey.field(clazz.name(), field.name, field.desc), newName);
                }
            }
        }
        return out;
    }

    private NameNode methodNode(Map<String, NameNode> nodes, String owner, String name) {
        return nodes.computeIfAbsent(owner + "." + name, ignored -> new NameNode(owner, name));
    }

    private void unionAppAncestors(
        PipelineContext pctx,
        DisjointSet<NameNode> groups,
        Map<String, NameNode> nodes,
        L1Class clazz,
        MethodNode method
    ) {
        NameNode current = methodNode(nodes, clazz.name(), method.name);
        L1Class superClass = pctx.classMap().get(clazz.superName());
        if (superClass != null && declaresMethod(superClass, method.name, method.desc)) {
            groups.union(current, methodNode(nodes, superClass.name(), method.name));
        }
        for (String ifaceName : clazz.interfaces()) {
            unionAppInterface(pctx, groups, nodes, current, ifaceName, method.name, method.desc);
        }
    }

    private void unionAppInterface(
        PipelineContext pctx,
        DisjointSet<NameNode> groups,
        Map<String, NameNode> nodes,
        NameNode current,
        String ifaceName,
        String name,
        String desc
    ) {
        L1Class iface = pctx.classMap().get(ifaceName);
        if (iface == null) return;
        if (declaresMethod(iface, name, desc)) {
            groups.union(current, methodNode(nodes, iface.name(), name));
        }
        for (String parent : iface.interfaces()) {
            unionAppInterface(pctx, groups, nodes, current, parent, name, desc);
        }
    }

    private void unionImplementedInterfaceMethods(
        PipelineContext pctx,
        DisjointSet<NameNode> groups,
        Map<String, NameNode> nodes,
        L1Class clazz
    ) {
        for (String ifaceName : clazz.interfaces()) {
            unionImplementedInterfaceMethods(pctx, groups, nodes, clazz, ifaceName);
        }
    }

    private void unionImplementedInterfaceMethods(
        PipelineContext pctx,
        DisjointSet<NameNode> groups,
        Map<String, NameNode> nodes,
        L1Class clazz,
        String ifaceName
    ) {
        L1Class iface = pctx.classMap().get(ifaceName);
        if (iface == null) return;
        for (MethodNode ifaceMethod : iface.asmNode().methods) {
            if (!canRenameMethod(pctx, iface, ifaceMethod)) continue;
            L1Class implementation = findImplementation(pctx, clazz, ifaceMethod.name, ifaceMethod.desc);
            if (implementation != null) {
                groups.union(
                    methodNode(nodes, implementation.name(), ifaceMethod.name),
                    methodNode(nodes, iface.name(), ifaceMethod.name)
                );
            }
        }
        for (String parent : iface.interfaces()) {
            unionImplementedInterfaceMethods(pctx, groups, nodes, clazz, parent);
        }
    }

    private L1Class findImplementation(PipelineContext pctx, L1Class clazz, String name, String desc) {
        for (L1Class current = clazz; current != null; current = pctx.classMap().get(current.superName())) {
            if (current.findMethod(name, desc) != null) return current;
        }
        return null;
    }

    private boolean declaresMethod(L1Class clazz, String name, String desc) {
        return clazz.findMethod(name, desc) != null;
    }

    private Map<NameNode, String> assignGroupNames(
        Map<NameNode, Set<String>> ownersByGroup,
        DisjointSet<NameNode> groups,
        Map<String, L1Class> classMap,
        boolean methods
    ) {
        Map<String, Set<String>> occupiedByOwner = new HashMap<>();
        for (Map.Entry<String, L1Class> entry : classMap.entrySet()) {
            Set<String> occupied = new HashSet<>();
            if (methods) {
                for (MethodNode method : entry.getValue().asmNode().methods) {
                    if ("<init>".equals(method.name) || "<clinit>".equals(method.name)) {
                        occupied.add(method.name);
                    }
                }
            }
            occupiedByOwner.put(entry.getKey(), occupied);
        }
        Map<NameNode, String> out = new LinkedHashMap<>();
        Map<String, String> preferredByOriginalName = new LinkedHashMap<>();
        NameSource names = new NameSource("");
        List<NameNode> roots = new ArrayList<>(ownersByGroup.keySet());
        roots.sort(Comparator.comparing(NameNode::owner).thenComparing(NameNode::name));
        for (NameNode root : roots) {
            String fixed = groups.fixedName(root);
            if (fixed != null) {
                out.put(root, fixed);
                markOccupied(occupiedByOwner, ownersByGroup.get(root), fixed);
                continue;
            }
            String candidate = preferredByOriginalName.get(root.name());
            if (candidate == null || isOccupied(occupiedByOwner, ownersByGroup.get(root), candidate)) {
                do {
                    candidate = names.nextSimpleName();
                } while (isOccupied(occupiedByOwner, ownersByGroup.get(root), candidate));
                preferredByOriginalName.putIfAbsent(root.name(), candidate);
            }
            out.put(root, candidate);
            markOccupied(occupiedByOwner, ownersByGroup.get(root), candidate);
        }
        return out;
    }

    private boolean isOccupied(Map<String, Set<String>> occupiedByOwner, Set<String> owners, String name) {
        for (String owner : owners) {
            Set<String> occupied = occupiedByOwner.get(owner);
            if (occupied != null && occupied.contains(name)) return true;
        }
        return false;
    }

    private void markOccupied(Map<String, Set<String>> occupiedByOwner, Set<String> owners, String name) {
        for (String owner : owners) {
            occupiedByOwner.computeIfAbsent(owner, ignored -> new HashSet<>()).add(name);
        }
    }

    private boolean canRenameMethod(PipelineContext pctx, L1Class clazz, MethodNode method) {
        if (booleanOption(pctx, "privateMembersOnly", false) && (method.access & Opcodes.ACC_PRIVATE) == 0) return false;
        if ("<init>".equals(method.name) || "<clinit>".equals(method.name)) return false;
        if (matchesAnyClassPattern(stringListOption(pctx, "keepMemberNamesInClasses"), clazz.name())) return false;
        if (matchesAnyMemberPattern(stringListOption(pctx, "keepMethodNames"), clazz.name(), method.name, method.desc)) return false;
        if ((method.access & Opcodes.ACC_NATIVE) != 0) return false;
        if (clazz.isAnnotation()) return false;
        if (JvmBridgeAbi.isBridgeFamilyMethod(pctx, clazz, method)) return false;
        if (JvmEnumAbi.isEnumValuesMethod(clazz, method) || JvmEnumAbi.isEnumValueOfMethod(clazz, method)) return false;
        if (JvmSerializationAbi.isSerializationMagicMethod(pctx, clazz, method)) return false;
        if ("main".equals(method.name)
            && "([Ljava/lang/String;)V".equals(method.desc)
            && (method.access & Opcodes.ACC_STATIC) != 0) {
            return false;
        }
        if (JvmRecordAbi.isRecordComponentAccessor(clazz, method)) return false;
        return !overridesExternalMethod(pctx, clazz, method, method.desc);
    }

    private boolean canRenameField(PipelineContext pctx, L1Class clazz, FieldNode field) {
        if (booleanOption(pctx, "privateMembersOnly", false) && (field.access & Opcodes.ACC_PRIVATE) == 0) return false;
        if (matchesAnyClassPattern(stringListOption(pctx, "keepMemberNamesInClasses"), clazz.name())) return false;
        if (JvmEnumAbi.isEnumConstantField(clazz, field)) return false;
        if (JvmRecordAbi.isRecordComponentField(clazz, field)) return false;
        if (JvmSerializationAbi.isSerializationAbiField(pctx, clazz, field)) return false;
        return true;
    }

    private boolean matchesAnyMemberPattern(List<String> patterns, String owner, String name, String desc) {
        String dottedOwner = owner.replace('/', '.');
        String shortKey = dottedOwner + "." + name;
        String fullKey = shortKey + desc;
        for (String pattern : patterns) {
            String dottedPattern = pattern.replace('/', '.');
            if (matchesGlob(dottedPattern, shortKey) || matchesGlob(dottedPattern, fullKey)) return true;
        }
        return false;
    }

    private boolean matchesGlob(String pattern, String value) {
        StringBuilder regex = new StringBuilder("^");
        for (int index = 0; index < pattern.length(); index++) {
            char current = pattern.charAt(index);
            if (current == '*') {
                if (index + 1 < pattern.length() && pattern.charAt(index + 1) == '*') {
                    regex.append(".*");
                    index++;
                } else {
                    regex.append(".*");
                }
            } else if (current == '?') {
                regex.append('.');
            } else {
                regex.append(Pattern.quote(String.valueOf(current)));
            }
        }
        regex.append('$');
        return Pattern.matches(regex.toString(), value);
    }

    private Map<String, Map<String, String>> methodNameMap(Map<MemberKey, String> members) {
        Map<String, Map<String, String>> out = new LinkedHashMap<>();
        for (Map.Entry<MemberKey, String> entry : members.entrySet()) {
            MemberKey key = entry.getKey();
            if (!key.method()) continue;
            out.computeIfAbsent(key.owner(), ignored -> new LinkedHashMap<>())
                .putIfAbsent(key.name(), entry.getValue());
        }
        return out;
    }

    private Map<String, Map<String, String>> fieldNameMap(Map<MemberKey, String> members) {
        Map<String, Map<String, String>> out = new LinkedHashMap<>();
        for (Map.Entry<MemberKey, String> entry : members.entrySet()) {
            MemberKey key = entry.getKey();
            if (key.method()) continue;
            out.computeIfAbsent(key.owner(), ignored -> new LinkedHashMap<>())
                .putIfAbsent(key.name(), entry.getValue());
        }
        return out;
    }

    private void rewriteReflectiveStrings(
        ClassNode node,
        Map<String, String> classes,
        Map<String, Map<String, String>> methodNames,
        Map<String, Map<String, String>> fieldNames,
        Map<MemberKey, Map<Integer, Set<String>>> proxyHandlerMethodOwners
    ) {
        Map<String, String> classStrings = new LinkedHashMap<>();
        for (Map.Entry<String, String> entry : classes.entrySet()) {
            classStrings.put(entry.getKey(), entry.getValue());
            classStrings.put(entry.getKey().replace('/', '.'), entry.getValue().replace('/', '.'));
            classStrings.put(entry.getKey() + ".class", entry.getValue() + ".class");
            classStrings.put("/" + entry.getKey() + ".class", "/" + entry.getValue() + ".class");
        }
        Map<String, String> simpleClassStrings = uniqueSimpleClassStrings(classes);
        List<Map.Entry<String, String>> packageStrings = packageMap(classes);
        Set<MemberKey> stackWalkerNamePredicates = stackWalkerNamePredicateMethods(node);
        for (MethodNode method : node.methods) {
            if (method.instructions == null) continue;
            Frame<SourceValue>[] frames = null;
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof String value) {
                    String mapped = classStrings.get(value);
                    if (mapped == null) mapped = remapResourcePath(value, packageStrings);
                    if (mapped != null) {
                        ldc.cst = mapped;
                    }
                }
                if (insn instanceof InvokeDynamicInsnNode indy) {
                    rewriteLambdaName(indy, methodNames);
                }
                if (!(insn instanceof MethodInsnNode call)) continue;
                if (isMethodReflectionLookup(call)) {
                    RewriteNameResult result = rewriteClassReflectionNameLiteral(method, frames, call, classes, methodNames);
                    if (result == RewriteNameResult.UNKNOWN) {
                        frames = analyzeSourceValuesQuietly(method);
                        result = rewriteClassReflectionNameLiteral(method, frames, call, classes, methodNames);
                    }
                    if (result == RewriteNameResult.UNKNOWN) {
                        rewritePreviousNameLiteral(call, methodNames);
                    }
                } else if (isMethodHandleMethodLookup(call)) {
                    RewriteNameResult result = rewriteMethodHandleNameLiteral(method, frames, call, classes, methodNames);
                    if (result == RewriteNameResult.UNKNOWN) {
                        frames = analyzeSourceValuesQuietly(method);
                        result = rewriteMethodHandleNameLiteral(method, frames, call, classes, methodNames);
                    }
                    if (result == RewriteNameResult.UNKNOWN) {
                        rewritePreviousMethodHandleNameLiteral(call, methodNames);
                    }
                } else if (isFieldReflectionLookup(call)) {
                    RewriteNameResult result = rewriteClassReflectionNameLiteral(method, frames, call, classes, fieldNames);
                    if (result == RewriteNameResult.UNKNOWN) {
                        frames = analyzeSourceValuesQuietly(method);
                        result = rewriteClassReflectionNameLiteral(method, frames, call, classes, fieldNames);
                    }
                    if (result == RewriteNameResult.UNKNOWN) {
                        rewritePreviousNameLiteral(call, fieldNames);
                    }
                } else if (isMethodHandleFieldLookup(call)) {
                    RewriteNameResult result = rewriteMethodHandleNameLiteral(method, frames, call, classes, fieldNames);
                    if (result == RewriteNameResult.UNKNOWN) {
                        frames = analyzeSourceValuesQuietly(method);
                        result = rewriteMethodHandleNameLiteral(method, frames, call, classes, fieldNames);
                    }
                    if (result == RewriteNameResult.UNKNOWN) {
                        rewritePreviousMethodHandleNameLiteral(call, fieldNames);
                    }
                }
                if (!simpleClassStrings.isEmpty()
                    && mayConsumeNameSensitiveString(call)) {
                    if (frames == null) {
                        frames = analyzeSourceValuesQuietly(method);
                    }
                    rewriteNameSensitiveSimpleClassNameLiterals(
                        node.name,
                        method,
                        frames,
                        call,
                        classes,
                        simpleClassStrings,
                        stackWalkerNamePredicates
                    );
                }
            }
            if (proxyHandlerMethodOwners.containsKey(MemberKey.method(node.name, method.name, method.desc))) {
                if (frames == null) {
                    frames = analyzeSourceValuesQuietly(method);
                }
                rewriteDynamicProxyMethodNameComparisons(
                    node.name,
                    method,
                    frames,
                    proxyHandlerMethodOwners,
                    methodNames
                );
            }
        }
    }

    private Map<String, String> uniqueSimpleClassStrings(Map<String, String> classes) {
        Map<String, String> out = new LinkedHashMap<>();
        Set<String> ambiguous = new LinkedHashSet<>();
        for (Map.Entry<String, String> entry : classes.entrySet()) {
            String oldSimple = classSimpleName(entry.getKey());
            String newSimple = classSimpleName(entry.getValue());
            if (oldSimple.isEmpty() || newSimple.isEmpty() || oldSimple.equals(newSimple)) continue;
            String previous = out.putIfAbsent(oldSimple, newSimple);
            if (previous != null && !previous.equals(newSimple)) {
                ambiguous.add(oldSimple);
            }
        }
        for (String value : ambiguous) {
            out.remove(value);
        }
        return out;
    }

    private String classSimpleName(String internalName) {
        if (internalName == null || internalName.isEmpty()) return "";
        int slash = internalName.lastIndexOf('/');
        String simple = slash < 0 ? internalName : internalName.substring(slash + 1);
        int dollar = simple.lastIndexOf('$');
        if (dollar >= 0) {
            simple = simple.substring(dollar + 1);
        }
        if (simple.isEmpty()) return "";
        boolean numeric = true;
        for (int i = 0; i < simple.length(); i++) {
            if (!Character.isDigit(simple.charAt(i))) {
                numeric = false;
                break;
            }
        }
        return numeric ? "" : simple;
    }

    private Set<MemberKey> stackWalkerNamePredicateMethods(ClassNode node) {
        Set<MemberKey> out = new LinkedHashSet<>();
        for (MethodNode method : node.methods) {
            if (method.instructions == null) continue;
            boolean stackFrameNamePipeline = false;
            List<Handle> applicationLambdas = new ArrayList<>();
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                if (insn instanceof MethodInsnNode call && isStackFrameClassNameCall(call)) {
                    stackFrameNamePipeline = true;
                }
                if (!(insn instanceof InvokeDynamicInsnNode indy)) continue;
                Handle handle = lambdaImplementationHandle(indy);
                if (handle == null) continue;
                if (isStackFrameClassNameHandle(handle)) {
                    stackFrameNamePipeline = true;
                } else if (node.name.equals(handle.getOwner())) {
                    applicationLambdas.add(handle);
                }
            }
            if (!stackFrameNamePipeline) continue;
            for (Handle handle : applicationLambdas) {
                out.add(MemberKey.method(handle.getOwner(), handle.getName(), handle.getDesc()));
            }
        }
        return out;
    }

    private boolean isStackFrameClassNameHandle(Handle handle) {
        return "java/lang/StackWalker$StackFrame".equals(handle.getOwner())
            && "getClassName".equals(handle.getName())
            && "()Ljava/lang/String;".equals(handle.getDesc());
    }

    private boolean mayConsumeNameSensitiveString(MethodInsnNode call) {
        if (isStringNameComparison(call)) return true;
        Type returnType = Type.getReturnType(call.desc);
        if (returnType.getSort() == Type.VOID || returnType.getSort() == Type.BOOLEAN) return true;
        for (Type arg : Type.getArgumentTypes(call.desc)) {
            if (arg.getSort() == Type.OBJECT
                && ("java/lang/String".equals(arg.getInternalName())
                    || "java/lang/Object".equals(arg.getInternalName()))) {
                return true;
            }
        }
        return false;
    }

    private void rewriteNameSensitiveSimpleClassNameLiterals(
        String owner,
        MethodNode method,
        Frame<SourceValue>[] frames,
        MethodInsnNode call,
        Map<String, String> classes,
        Map<String, String> simpleClassStrings,
        Set<MemberKey> stackWalkerNamePredicates
    ) {
        if (frames == null) return;
        int index = method.instructions.indexOf(call);
        if (index < 0 || index >= frames.length) return;
        Frame<SourceValue> frame = frames[index];
        if (frame == null) return;
        Type[] args = Type.getArgumentTypes(call.desc);
        boolean isStatic = call.getOpcode() == Opcodes.INVOKESTATIC;
        int receiverSlots = isStatic ? 0 : 1;
        if (frame.getStackSize() < args.length + receiverSlots) return;
        int base = frame.getStackSize() - args.length - receiverSlots;
        boolean stackWalkerPredicate = stackWalkerNamePredicates.contains(
            MemberKey.method(owner, method.name, method.desc)
        );

        if (isStringNameComparison(call) && frame.getStackSize() >= 2) {
            SourceValue receiver = frame.getStack(frame.getStackSize() - 2);
            SourceValue argument = frame.getStack(frame.getStackSize() - 1);
            rewriteSimpleClassNameLiteralAgainstNameSource(
                method,
                frames,
                receiver,
                argument,
                classes,
                simpleClassStrings,
                stackWalkerPredicate
            );
            rewriteSimpleClassNameLiteralAgainstNameSource(
                method,
                frames,
                argument,
                receiver,
                classes,
                simpleClassStrings,
                stackWalkerPredicate
            );
            return;
        }

        List<SourceValue> operands = new ArrayList<>(args.length + receiverSlots);
        if (!isStatic) {
            operands.add(frame.getStack(base));
        }
        for (int i = 0; i < args.length; i++) {
            operands.add(frame.getStack(base + receiverSlots + i));
        }
        boolean[] nameSensitive = new boolean[operands.size()];
        boolean anyNameSensitive = false;
        for (int i = 0; i < operands.size(); i++) {
            nameSensitive[i] = sourceNameSensitiveString(method, frames, operands.get(i), classes, 0);
            anyNameSensitive |= nameSensitive[i];
        }
        if (!anyNameSensitive) return;
        for (int i = receiverSlots; i < operands.size(); i++) {
            if (nameSensitive[i]) continue;
            rewriteSimpleClassNameLiteral(
                method,
                frames,
                operands.get(i),
                simpleClassStrings
            );
        }
    }

    private boolean rewriteSimpleClassNameLiteralAgainstNameSource(
        MethodNode method,
        Frame<SourceValue>[] frames,
        SourceValue literalValue,
        SourceValue nameValue,
        Map<String, String> classes,
        Map<String, String> simpleClassStrings,
        boolean stackWalkerPredicate
    ) {
        if (!stackWalkerPredicate
            && !sourceNameSensitiveString(method, frames, nameValue, classes, 0)) {
            return false;
        }
        return rewriteSimpleClassNameLiteral(method, frames, literalValue, simpleClassStrings);
    }

    private boolean rewriteSimpleClassNameLiteral(
        MethodNode method,
        Frame<SourceValue>[] frames,
        SourceValue literalValue,
        Map<String, String> simpleClassStrings
    ) {
        String oldName = sourceString(method, frames, literalValue, 0);
        if (oldName == null) return false;
        String mapped = simpleClassStrings.get(oldName);
        if (mapped == null || mapped.equals(oldName)) return false;
        LdcInsnNode literal = sourceStringLiteral(method, frames, literalValue, oldName, 0);
        if (literal == null) return false;
        literal.cst = mapped;
        return true;
    }

    private boolean sourceNameSensitiveString(
        MethodNode method,
        Frame<SourceValue>[] frames,
        SourceValue value,
        Map<String, String> classes,
        int depth
    ) {
        if (value == null || depth > 8) return false;
        for (AbstractInsnNode source : value.insns) {
            if (source instanceof MethodInsnNode call) {
                if (isRuntimeClassNameStringCall(call)) {
                    return true;
                }
                if (isClassValueGetCall(call)
                    && classValueGetApplicationClass(method, frames, call, classes)) {
                    return true;
                }
            } else if (source instanceof VarInsnNode var && var.getOpcode() == Opcodes.ALOAD) {
                if (sourceNameSensitiveString(method, frames, loadedLocalValue(method, frames, var), classes, depth + 1)) {
                    return true;
                }
            } else if (source instanceof VarInsnNode var && var.getOpcode() == Opcodes.ASTORE) {
                if (sourceNameSensitiveString(method, frames, storedValue(method, frames, var), classes, depth + 1)) {
                    return true;
                }
            } else if (source instanceof TypeInsnNode type && type.getOpcode() == Opcodes.CHECKCAST) {
                if (sourceNameSensitiveString(method, frames, castInputValue(method, frames, type), classes, depth + 1)) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean isStringNameComparison(MethodInsnNode call) {
        if (!"java/lang/String".equals(call.owner)) return false;
        return ("endsWith".equals(call.name)
                || "startsWith".equals(call.name)
                || "contains".equals(call.name))
            && "(Ljava/lang/String;)Z".equals(call.desc)
            || "equals".equals(call.name)
                && "(Ljava/lang/Object;)Z".equals(call.desc);
    }

    private boolean isRuntimeClassNameStringCall(MethodInsnNode call) {
        if ("java/lang/Class".equals(call.owner)) {
            return ("getName".equals(call.name)
                    || "getSimpleName".equals(call.name)
                    || "getCanonicalName".equals(call.name))
                && "()Ljava/lang/String;".equals(call.desc);
        }
        if ("java/lang/StackWalker$StackFrame".equals(call.owner)
            || "java/lang/StackTraceElement".equals(call.owner)) {
            return "getClassName".equals(call.name)
                && "()Ljava/lang/String;".equals(call.desc);
        }
        return "java/lang/StackWalker".equals(call.owner)
            && "walk".equals(call.name)
            && "(Ljava/util/function/Function;)Ljava/lang/Object;".equals(call.desc);
    }

    private boolean isStackFrameClassNameCall(MethodInsnNode call) {
        return "java/lang/StackWalker$StackFrame".equals(call.owner)
            && "getClassName".equals(call.name)
            && "()Ljava/lang/String;".equals(call.desc);
    }

    private boolean isClassValueGetCall(MethodInsnNode call) {
        return "java/lang/ClassValue".equals(call.owner)
            && "get".equals(call.name)
            && "(Ljava/lang/Class;)Ljava/lang/Object;".equals(call.desc);
    }

    private boolean classValueGetApplicationClass(
        MethodNode method,
        Frame<SourceValue>[] frames,
        MethodInsnNode call,
        Map<String, String> classes
    ) {
        int index = method.instructions.indexOf(call);
        if (index < 0 || index >= frames.length) return false;
        Frame<SourceValue> frame = frames[index];
        if (frame == null || frame.getStackSize() < 2) return false;
        String owner = sourceClassObjectOwner(method, frames, frame.getStack(frame.getStackSize() - 1), 0);
        return owner != null && classes.containsKey(owner);
    }

    private Map<MemberKey, Map<Integer, Set<String>>> dynamicProxyHandlerMethodOwners(
        PipelineContext pctx,
        List<L1Class> classes
    ) {
        Map<MemberKey, Map<Integer, Set<String>>> out = new LinkedHashMap<>();
        for (L1Class clazz : classes) {
            for (MethodNode method : clazz.asmNode().methods) {
                if (method.instructions == null) continue;
                Frame<SourceValue>[] frames = analyzeSourceValuesQuietly(method);
                if (frames == null) continue;
                for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
                    if (!(insn instanceof MethodInsnNode call) || !isProxyNewProxyInstance(call)) continue;
                    int index = method.instructions.indexOf(call);
                    if (index < 0 || index >= frames.length) continue;
                    Frame<SourceValue> frame = frames[index];
                    if (frame == null || frame.getStackSize() < 3) continue;
                    int base = frame.getStackSize() - 3;
                    Set<String> interfaces = sourceProxyInterfaceOwners(
                        pctx,
                        method,
                        frames,
                        frame.getStack(base + 1),
                        0
                    );
                    if (interfaces.isEmpty()) {
                        interfaces = nearbyProxyInterfaceOwners(pctx, method, call);
                    }
                    if (interfaces.isEmpty()) continue;
                    Handle implementation = sourceLambdaImplementationHandle(
                        method,
                        frames,
                        frame.getStack(base + 2),
                        0
                    );
                    if (implementation == null) {
                        implementation = nearbyInvocationHandlerLambdaImplementation(method, call);
                    }
                    if (implementation == null || implementation.getTag() != Opcodes.H_INVOKESTATIC) continue;
                    if (!pctx.classMap().containsKey(implementation.getOwner())) continue;
                    int methodLocal = reflectiveMethodArgumentLocal(implementation);
                    if (methodLocal < 0) continue;
                    out.computeIfAbsent(
                            MemberKey.method(
                                implementation.getOwner(),
                                implementation.getName(),
                                implementation.getDesc()
                            ),
                            ignored -> new LinkedHashMap<>()
                        )
                        .computeIfAbsent(methodLocal, ignored -> new LinkedHashSet<>())
                        .addAll(interfaces);
                }
            }
        }
        return out;
    }

    private boolean isProxyNewProxyInstance(MethodInsnNode call) {
        return call.getOpcode() == Opcodes.INVOKESTATIC
            && "java/lang/reflect/Proxy".equals(call.owner)
            && "newProxyInstance".equals(call.name)
            && "(Ljava/lang/ClassLoader;[Ljava/lang/Class;Ljava/lang/reflect/InvocationHandler;)Ljava/lang/Object;"
                .equals(call.desc);
    }

    private Set<String> sourceProxyInterfaceOwners(
        PipelineContext pctx,
        MethodNode method,
        Frame<SourceValue>[] frames,
        SourceValue value,
        int depth
    ) {
        if (value == null || depth > 8) return Set.of();
        Set<String> owners = new LinkedHashSet<>();
        for (AbstractInsnNode source : value.insns) {
            if (source instanceof VarInsnNode var && var.getOpcode() == Opcodes.ALOAD) {
                owners.addAll(sourceProxyInterfaceOwners(pctx, method, frames, loadedLocalValue(method, frames, var), depth + 1));
                continue;
            }
            if (source instanceof VarInsnNode var && var.getOpcode() == Opcodes.ASTORE) {
                owners.addAll(sourceProxyInterfaceOwners(pctx, method, frames, storedValue(method, frames, var), depth + 1));
                continue;
            }
            if (source instanceof TypeInsnNode type && type.getOpcode() == Opcodes.CHECKCAST) {
                owners.addAll(sourceProxyInterfaceOwners(pctx, method, frames, castInputValue(method, frames, type), depth + 1));
                continue;
            }
            if (source.getOpcode() == Opcodes.AASTORE) {
                int index = method.instructions.indexOf(source);
                if (index < 0 || index >= frames.length) continue;
                Frame<SourceValue> frame = frames[index];
                if (frame == null || frame.getStackSize() < 3) continue;
                String owner = sourceClassObjectOwner(method, frames, frame.getStack(frame.getStackSize() - 1), depth + 1);
                addProxyInterfaceOwner(pctx, owners, owner);
            }
        }
        return owners;
    }

    private Set<String> nearbyProxyInterfaceOwners(PipelineContext pctx, MethodNode method, MethodInsnNode call) {
        Set<String> owners = new LinkedHashSet<>();
        int scanned = 0;
        for (AbstractInsnNode scan = call.getPrevious(); scan != null && scanned++ < 64; scan = scan.getPrevious()) {
            if (scan instanceof LdcInsnNode ldc
                && ldc.cst instanceof Type type
                && type.getSort() == Type.OBJECT) {
                addProxyInterfaceOwner(pctx, owners, type.getInternalName());
            }
            if (scan instanceof MethodInsnNode previous
                && "java/lang/reflect/Proxy".equals(previous.owner)
                && "newProxyInstance".equals(previous.name)) {
                break;
            }
            if (method.instructions.indexOf(scan) == 0) break;
        }
        return owners;
    }

    private void addProxyInterfaceOwner(PipelineContext pctx, Set<String> owners, String owner) {
        if (owner == null) return;
        L1Class clazz = pctx.classMap().get(owner);
        if (clazz == null || !clazz.isInterface()) return;
        if (!owners.add(owner)) return;
        for (String parent : clazz.interfaces()) {
            addProxyInterfaceOwner(pctx, owners, parent);
        }
    }

    private Handle sourceLambdaImplementationHandle(
        MethodNode method,
        Frame<SourceValue>[] frames,
        SourceValue value,
        int depth
    ) {
        if (value == null || depth > 8) return null;
        Handle result = null;
        for (AbstractInsnNode source : value.insns) {
            Handle sourced = null;
            if (source instanceof InvokeDynamicInsnNode indy) {
                sourced = lambdaImplementationHandle(indy);
            } else if (source instanceof VarInsnNode var && var.getOpcode() == Opcodes.ALOAD) {
                sourced = sourceLambdaImplementationHandle(method, frames, loadedLocalValue(method, frames, var), depth + 1);
            } else if (source instanceof VarInsnNode var && var.getOpcode() == Opcodes.ASTORE) {
                sourced = sourceLambdaImplementationHandle(method, frames, storedValue(method, frames, var), depth + 1);
            } else if (source instanceof TypeInsnNode type && type.getOpcode() == Opcodes.CHECKCAST) {
                sourced = sourceLambdaImplementationHandle(method, frames, castInputValue(method, frames, type), depth + 1);
            }
            if (sourced == null) return null;
            if (result != null && !sameHandle(result, sourced)) return null;
            result = sourced;
        }
        return result;
    }

    private Handle nearbyInvocationHandlerLambdaImplementation(MethodNode method, MethodInsnNode call) {
        int scanned = 0;
        for (AbstractInsnNode scan = call.getPrevious(); scan != null && scanned++ < 32; scan = scan.getPrevious()) {
            if (scan instanceof InvokeDynamicInsnNode indy && isInvocationHandlerLambda(indy)) {
                return lambdaImplementationHandle(indy);
            }
            if (scan instanceof MethodInsnNode) break;
            if (method.instructions.indexOf(scan) == 0) break;
        }
        return null;
    }

    private boolean isInvocationHandlerLambda(InvokeDynamicInsnNode indy) {
        Handle handle = lambdaImplementationHandle(indy);
        if (handle == null) return false;
        Type returnType = Type.getReturnType(indy.desc);
        return returnType.getSort() == Type.OBJECT
            && "java/lang/reflect/InvocationHandler".equals(returnType.getInternalName());
    }

    private boolean sameHandle(Handle left, Handle right) {
        return left.getTag() == right.getTag()
            && left.isInterface() == right.isInterface()
            && left.getOwner().equals(right.getOwner())
            && left.getName().equals(right.getName())
            && left.getDesc().equals(right.getDesc());
    }

    private Handle lambdaImplementationHandle(InvokeDynamicInsnNode indy) {
        if (indy.bsm == null
            || !"java/lang/invoke/LambdaMetafactory".equals(indy.bsm.getOwner())
            || (!"metafactory".equals(indy.bsm.getName()) && !"altMetafactory".equals(indy.bsm.getName()))
            || indy.bsmArgs.length < 2
            || !(indy.bsmArgs[1] instanceof Handle handle)) {
            return null;
        }
        return handle;
    }

    private int reflectiveMethodArgumentLocal(Handle implementation) {
        Type[] args = Type.getArgumentTypes(implementation.getDesc());
        int local = 0;
        for (Type arg : args) {
            if (arg.getSort() == Type.OBJECT && "java/lang/reflect/Method".equals(arg.getInternalName())) {
                return local;
            }
            local += arg.getSize();
        }
        return -1;
    }

    private void rewriteDynamicProxyMethodNameComparisons(
        String owner,
        MethodNode method,
        Frame<SourceValue>[] frames,
        Map<MemberKey, Map<Integer, Set<String>>> proxyHandlerMethodOwners,
        Map<String, Map<String, String>> methodNames
    ) {
        if (frames == null) return;
        Map<Integer, Set<String>> ownersByLocal = proxyHandlerMethodOwners.get(
            MemberKey.method(owner, method.name, method.desc)
        );
        if (ownersByLocal == null || ownersByLocal.isEmpty()) return;
        for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (!(insn instanceof MethodInsnNode call) || !isStringEquals(call)) continue;
            int index = method.instructions.indexOf(call);
            if (index < 0 || index >= frames.length) continue;
            Frame<SourceValue> frame = frames[index];
            if (frame == null || frame.getStackSize() < 2) continue;
            SourceValue receiver = frame.getStack(frame.getStackSize() - 2);
            SourceValue argument = frame.getStack(frame.getStackSize() - 1);
            if (!rewriteDynamicProxyMethodNameComparison(method, frames, receiver, argument, ownersByLocal, methodNames)) {
                rewriteDynamicProxyMethodNameComparison(method, frames, argument, receiver, ownersByLocal, methodNames);
            }
        }
    }

    private boolean rewriteDynamicProxyMethodNameComparison(
        MethodNode method,
        Frame<SourceValue>[] frames,
        SourceValue literalValue,
        SourceValue methodNameValue,
        Map<Integer, Set<String>> ownersByLocal,
        Map<String, Map<String, String>> methodNames
    ) {
        String oldName = sourceString(method, frames, literalValue, 0);
        if (oldName == null) return false;
        Integer methodLocal = sourceMethodGetNameLocal(method, frames, methodNameValue, 0);
        if (methodLocal == null) return false;
        Set<String> owners = ownersByLocal.get(methodLocal);
        if (owners == null || owners.isEmpty()) return false;
        String mapped = uniqueProxyMethodName(owners, methodNames, oldName);
        if (mapped == null || mapped.equals(oldName)) return false;
        LdcInsnNode literal = sourceStringLiteral(method, frames, literalValue, oldName, 0);
        if (literal == null) return false;
        literal.cst = mapped;
        return true;
    }

    private boolean isStringEquals(MethodInsnNode call) {
        return "java/lang/String".equals(call.owner)
            && "equals".equals(call.name)
            && "(Ljava/lang/Object;)Z".equals(call.desc);
    }

    private Integer sourceMethodGetNameLocal(
        MethodNode method,
        Frame<SourceValue>[] frames,
        SourceValue value,
        int depth
    ) {
        if (value == null || depth > 8) return null;
        Integer result = null;
        for (AbstractInsnNode source : value.insns) {
            Integer sourced = null;
            if (source instanceof MethodInsnNode call && isReflectiveMethodGetName(call)) {
                int index = method.instructions.indexOf(call);
                if (index < 0 || index >= frames.length) return null;
                Frame<SourceValue> frame = frames[index];
                if (frame == null || frame.getStackSize() < 1) return null;
                sourced = sourceLoadLocal(method, frames, frame.getStack(frame.getStackSize() - 1), depth + 1);
            } else if (source instanceof VarInsnNode var && var.getOpcode() == Opcodes.ALOAD) {
                sourced = sourceMethodGetNameLocal(method, frames, loadedLocalValue(method, frames, var), depth + 1);
            } else if (source instanceof VarInsnNode var && var.getOpcode() == Opcodes.ASTORE) {
                sourced = sourceMethodGetNameLocal(method, frames, storedValue(method, frames, var), depth + 1);
            } else if (source instanceof TypeInsnNode type && type.getOpcode() == Opcodes.CHECKCAST) {
                sourced = sourceMethodGetNameLocal(method, frames, castInputValue(method, frames, type), depth + 1);
            }
            if (sourced == null) return null;
            if (result != null && !result.equals(sourced)) return null;
            result = sourced;
        }
        return result;
    }

    private boolean isReflectiveMethodGetName(MethodInsnNode call) {
        return "java/lang/reflect/Method".equals(call.owner)
            && "getName".equals(call.name)
            && "()Ljava/lang/String;".equals(call.desc);
    }

    private Integer sourceLoadLocal(MethodNode method, Frame<SourceValue>[] frames, SourceValue value, int depth) {
        if (value == null || depth > 8) return null;
        Integer result = null;
        for (AbstractInsnNode source : value.insns) {
            Integer sourced = null;
            if (source instanceof VarInsnNode var && var.getOpcode() == Opcodes.ALOAD) {
                sourced = var.var;
            } else if (source instanceof VarInsnNode var && var.getOpcode() == Opcodes.ASTORE) {
                sourced = sourceLoadLocal(method, frames, storedValue(method, frames, var), depth + 1);
            } else if (source instanceof TypeInsnNode type && type.getOpcode() == Opcodes.CHECKCAST) {
                sourced = sourceLoadLocal(method, frames, castInputValue(method, frames, type), depth + 1);
            }
            if (sourced == null) return null;
            if (result != null && !result.equals(sourced)) return null;
            result = sourced;
        }
        return result;
    }

    private String uniqueProxyMethodName(
        Set<String> owners,
        Map<String, Map<String, String>> methodNames,
        String oldName
    ) {
        String mapped = null;
        for (String owner : owners) {
            Map<String, String> ownerNames = methodNames.get(owner);
            if (ownerNames == null) continue;
            String candidate = ownerNames.get(oldName);
            if (candidate == null) continue;
            if (mapped != null && !mapped.equals(candidate)) return null;
            mapped = candidate;
        }
        return mapped;
    }

    private void rewriteLambdaName(
        InvokeDynamicInsnNode indy,
        Map<String, Map<String, String>> methodNames
    ) {
        if (indy.bsm == null
            || !"java/lang/invoke/LambdaMetafactory".equals(indy.bsm.getOwner())
            || (!"metafactory".equals(indy.bsm.getName()) && !"altMetafactory".equals(indy.bsm.getName()))) {
            return;
        }
        Type returnType = Type.getReturnType(indy.desc);
        if (returnType.getSort() != Type.OBJECT) return;
        Map<String, String> ownerNames = methodNames.get(returnType.getInternalName());
        if (ownerNames == null) return;
        String mapped = ownerNames.get(indy.name);
        if (mapped != null) {
            indy.name = mapped;
        }
    }

    private List<Map.Entry<String, String>> packageMap(Map<String, String> classes) {
        Map<String, String> packages = new LinkedHashMap<>();
        for (Map.Entry<String, String> entry : classes.entrySet()) {
            String oldPackage = packageName(entry.getKey());
            String newPackage = packageName(entry.getValue());
            if (!oldPackage.isEmpty() && !newPackage.isEmpty()) {
                packages.putIfAbsent(oldPackage, newPackage);
            }
        }
        List<Map.Entry<String, String>> out = new ArrayList<>(packages.entrySet());
        out.sort((left, right) -> Integer.compare(right.getKey().length(), left.getKey().length()));
        return out;
    }

    private String remapResourcePath(String value, List<Map.Entry<String, String>> packages) {
        for (Map.Entry<String, String> entry : packages) {
            String oldPackage = entry.getKey();
            String newPackage = entry.getValue();
            if (value.startsWith(oldPackage + "/")) {
                return newPackage + value.substring(oldPackage.length());
            }
            if (value.startsWith("/" + oldPackage + "/")) {
                return "/" + newPackage + value.substring(oldPackage.length() + 1);
            }
        }
        return null;
    }

    private String packageName(String internalName) {
        int slash = internalName.lastIndexOf('/');
        return slash < 0 ? "" : internalName.substring(0, slash);
    }

    private boolean isMethodReflectionLookup(MethodInsnNode call) {
        return "java/lang/Class".equals(call.owner)
            && ("getMethod".equals(call.name) || "getDeclaredMethod".equals(call.name))
            && "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;".equals(call.desc);
    }

    private boolean isFieldReflectionLookup(MethodInsnNode call) {
        return "java/lang/Class".equals(call.owner)
            && ("getField".equals(call.name) || "getDeclaredField".equals(call.name))
            && "(Ljava/lang/String;)Ljava/lang/reflect/Field;".equals(call.desc);
    }

    private boolean isMethodHandleMethodLookup(MethodInsnNode call) {
        return "java/lang/invoke/MethodHandles$Lookup".equals(call.owner)
            && ("findStatic".equals(call.name)
                || "findVirtual".equals(call.name)
                || "findSpecial".equals(call.name))
            && call.desc.startsWith("(Ljava/lang/Class;Ljava/lang/String;");
    }

    private boolean isMethodHandleFieldLookup(MethodInsnNode call) {
        return "java/lang/invoke/MethodHandles$Lookup".equals(call.owner)
            && ("findGetter".equals(call.name)
                || "findSetter".equals(call.name)
                || "findStaticGetter".equals(call.name)
                || "findStaticSetter".equals(call.name)
                || "findVarHandle".equals(call.name)
                || "findStaticVarHandle".equals(call.name))
            && call.desc.startsWith("(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/Class;)");
    }

    private RewriteNameResult rewriteClassReflectionNameLiteral(
        MethodNode method,
        Frame<SourceValue>[] frames,
        MethodInsnNode call,
        Map<String, String> classes,
        Map<String, Map<String, String>> namesByOwner
    ) {
        if (frames == null) return RewriteNameResult.UNKNOWN;
        int index = method.instructions.indexOf(call);
        if (index < 0 || index >= frames.length) return RewriteNameResult.UNKNOWN;
        Frame<SourceValue> frame = frames[index];
        Type[] args = Type.getArgumentTypes(call.desc);
        if (frame == null || frame.getStackSize() < args.length + 1) return RewriteNameResult.UNKNOWN;
        int receiverIndex = frame.getStackSize() - args.length - 1;
        String owner = sourceClassObjectOwner(method, frames, frame.getStack(receiverIndex), 0);
        SourceValue nameValue = frame.getStack(receiverIndex + 1);
        String oldName = sourceString(method, frames, nameValue, 0);
        if (owner == null || oldName == null) return RewriteNameResult.UNKNOWN;

        String originalOwner = originalOwnerName(owner, classes);
        if (originalOwner == null) {
            return RewriteNameResult.OWNER_KNOWN_UNCHANGED;
        }
        Map<String, String> ownerNames = namesByOwner.get(originalOwner);
        if (ownerNames == null) return RewriteNameResult.OWNER_KNOWN_UNCHANGED;
        String mapped = ownerNames.get(oldName);
        if (mapped == null || mapped.equals(oldName)) return RewriteNameResult.OWNER_KNOWN_UNCHANGED;
        LdcInsnNode literal = sourceStringLiteral(method, frames, nameValue, oldName, 0);
        if (literal == null) return RewriteNameResult.UNKNOWN;
        literal.cst = mapped;
        return RewriteNameResult.REWRITTEN;
    }

    private RewriteNameResult rewriteMethodHandleNameLiteral(
        MethodNode method,
        Frame<SourceValue>[] frames,
        MethodInsnNode call,
        Map<String, String> classes,
        Map<String, Map<String, String>> namesByOwner
    ) {
        if (frames == null) return RewriteNameResult.UNKNOWN;
        int index = method.instructions.indexOf(call);
        if (index < 0 || index >= frames.length) return RewriteNameResult.UNKNOWN;
        Frame<SourceValue> frame = frames[index];
        Type[] args = Type.getArgumentTypes(call.desc);
        if (frame == null || frame.getStackSize() < args.length + 1 || args.length < 2) {
            return RewriteNameResult.UNKNOWN;
        }
        int base = frame.getStackSize() - args.length;
        String owner = sourceClassObjectOwner(method, frames, frame.getStack(base), 0);
        SourceValue nameValue = frame.getStack(base + 1);
        String oldName = sourceString(method, frames, nameValue, 0);
        if (owner == null || oldName == null) return RewriteNameResult.UNKNOWN;

        String originalOwner = originalOwnerName(owner, classes);
        if (originalOwner == null) {
            return RewriteNameResult.OWNER_KNOWN_UNCHANGED;
        }
        Map<String, String> ownerNames = namesByOwner.get(originalOwner);
        if (ownerNames == null) return RewriteNameResult.OWNER_KNOWN_UNCHANGED;
        String mapped = ownerNames.get(oldName);
        if (mapped == null || mapped.equals(oldName)) return RewriteNameResult.OWNER_KNOWN_UNCHANGED;
        LdcInsnNode literal = sourceStringLiteral(method, frames, nameValue, oldName, 0);
        if (literal == null) return RewriteNameResult.UNKNOWN;
        literal.cst = mapped;
        return RewriteNameResult.REWRITTEN;
    }

    private String originalOwnerName(String owner, Map<String, String> classes) {
        if (classes.containsKey(owner)) return owner;
        for (Map.Entry<String, String> entry : classes.entrySet()) {
            if (entry.getValue().equals(owner)) return entry.getKey();
        }
        return null;
    }

    private void rewritePreviousNameLiteral(MethodInsnNode call, Map<String, Map<String, String>> namesByOwner) {
        LdcInsnNode nameInsn = null;
        String owner = null;
        for (AbstractInsnNode scan = call.getPrevious(); scan != null; scan = scan.getPrevious()) {
            if (scan instanceof MethodInsnNode) break;
            if (scan instanceof LdcInsnNode ldc) {
                if (nameInsn == null && ldc.cst instanceof String) {
                    nameInsn = ldc;
                    continue;
                }
                if (ldc.cst instanceof Type type && type.getSort() == Type.OBJECT) {
                    owner = type.getInternalName();
                    break;
                }
            }
        }
        if (nameInsn == null || !(nameInsn.cst instanceof String oldName)) return;
        String mapped = null;
        if (owner != null) {
            Map<String, String> ownerNames = namesByOwner.get(owner);
            if (ownerNames != null) mapped = ownerNames.get(oldName);
        }
        if (mapped == null) mapped = uniqueGlobalMemberName(namesByOwner, oldName);
        if (mapped != null) nameInsn.cst = mapped;
    }

    private String sourceClassObjectOwner(
        MethodNode mn,
        Frame<SourceValue>[] frames,
        SourceValue value,
        int depth
    ) {
        if (value == null || depth > 8) return null;
        String owner = null;
        for (AbstractInsnNode insn : value.insns) {
            String sourced = null;
            if (insn instanceof LdcInsnNode ldc
                && ldc.cst instanceof Type type
                && type.getSort() == Type.OBJECT) {
                sourced = type.getInternalName();
            } else if (insn instanceof MethodInsnNode call && isClassForName(call)) {
                sourced = sourceClassForNameOwner(mn, frames, call, depth + 1);
            } else if (insn instanceof VarInsnNode var && var.getOpcode() == Opcodes.ALOAD) {
                sourced = sourceClassObjectOwner(mn, frames, loadedLocalValue(mn, frames, var), depth + 1);
            } else if (insn instanceof VarInsnNode var && var.getOpcode() == Opcodes.ASTORE) {
                sourced = sourceClassObjectOwner(mn, frames, storedValue(mn, frames, var), depth + 1);
            } else if (insn instanceof TypeInsnNode type && type.getOpcode() == Opcodes.CHECKCAST) {
                sourced = sourceClassObjectOwner(mn, frames, castInputValue(mn, frames, type), depth + 1);
            }
            if (sourced == null) return null;
            if (owner != null && !owner.equals(sourced)) return null;
            owner = sourced;
        }
        return owner;
    }

    private boolean isClassForName(MethodInsnNode call) {
        return call.getOpcode() == Opcodes.INVOKESTATIC
            && "java/lang/Class".equals(call.owner)
            && "forName".equals(call.name)
            && ("(Ljava/lang/String;)Ljava/lang/Class;".equals(call.desc)
                || "(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;".equals(call.desc));
    }

    private String sourceClassForNameOwner(
        MethodNode mn,
        Frame<SourceValue>[] frames,
        MethodInsnNode call,
        int depth
    ) {
        int index = mn.instructions.indexOf(call);
        if (index < 0 || index >= frames.length) return null;
        Frame<SourceValue> frame = frames[index];
        if (frame == null) return null;
        Type[] args = Type.getArgumentTypes(call.desc);
        if (frame.getStackSize() < args.length) return null;
        String binaryName = sourceString(mn, frames, frame.getStack(frame.getStackSize() - args.length), depth);
        return binaryClassNameToInternal(binaryName);
    }

    private String binaryClassNameToInternal(String binaryName) {
        if (binaryName == null || binaryName.isEmpty() || binaryName.charAt(0) == '[') return null;
        return binaryName.replace('.', '/');
    }

    private String sourceString(MethodNode mn, Frame<SourceValue>[] frames, SourceValue value, int depth) {
        if (value == null || depth > 8) return null;
        String result = null;
        for (AbstractInsnNode insn : value.insns) {
            String sourced = null;
            if (insn instanceof LdcInsnNode ldc && ldc.cst instanceof String text) {
                sourced = text;
            } else if (insn instanceof VarInsnNode var && var.getOpcode() == Opcodes.ALOAD) {
                sourced = sourceString(mn, frames, loadedLocalValue(mn, frames, var), depth + 1);
            } else if (insn instanceof VarInsnNode var && var.getOpcode() == Opcodes.ASTORE) {
                sourced = sourceString(mn, frames, storedValue(mn, frames, var), depth + 1);
            } else if (insn instanceof TypeInsnNode type && type.getOpcode() == Opcodes.CHECKCAST) {
                sourced = sourceString(mn, frames, castInputValue(mn, frames, type), depth + 1);
            }
            if (sourced == null) return null;
            if (result != null && !result.equals(sourced)) return null;
            result = sourced;
        }
        return result;
    }

    private LdcInsnNode sourceStringLiteral(
        MethodNode mn,
        Frame<SourceValue>[] frames,
        SourceValue value,
        String expected,
        int depth
    ) {
        if (value == null || depth > 8) return null;
        LdcInsnNode result = null;
        for (AbstractInsnNode insn : value.insns) {
            LdcInsnNode sourced = null;
            if (insn instanceof LdcInsnNode ldc && Objects.equals(ldc.cst, expected)) {
                sourced = ldc;
            } else if (insn instanceof VarInsnNode var && var.getOpcode() == Opcodes.ALOAD) {
                sourced = sourceStringLiteral(mn, frames, loadedLocalValue(mn, frames, var), expected, depth + 1);
            } else if (insn instanceof VarInsnNode var && var.getOpcode() == Opcodes.ASTORE) {
                sourced = sourceStringLiteral(mn, frames, storedValue(mn, frames, var), expected, depth + 1);
            } else if (insn instanceof TypeInsnNode type && type.getOpcode() == Opcodes.CHECKCAST) {
                sourced = sourceStringLiteral(mn, frames, castInputValue(mn, frames, type), expected, depth + 1);
            }
            if (sourced == null) return null;
            if (result != null && result != sourced) return null;
            result = sourced;
        }
        return result;
    }

    private SourceValue loadedLocalValue(MethodNode mn, Frame<SourceValue>[] frames, VarInsnNode load) {
        int index = mn.instructions.indexOf(load);
        if (index < 0 || index >= frames.length) return null;
        Frame<SourceValue> frame = frames[index];
        if (frame == null || load.var >= frame.getLocals()) return null;
        return frame.getLocal(load.var);
    }

    private SourceValue storedValue(MethodNode mn, Frame<SourceValue>[] frames, VarInsnNode store) {
        int index = mn.instructions.indexOf(store);
        if (index < 0 || index >= frames.length) return null;
        Frame<SourceValue> frame = frames[index];
        if (frame == null || frame.getStackSize() < 1) return null;
        return frame.getStack(frame.getStackSize() - 1);
    }

    private SourceValue castInputValue(MethodNode mn, Frame<SourceValue>[] frames, TypeInsnNode cast) {
        int index = mn.instructions.indexOf(cast);
        if (index < 0 || index >= frames.length) return null;
        Frame<SourceValue> frame = frames[index];
        if (frame == null || frame.getStackSize() < 1) return null;
        return frame.getStack(frame.getStackSize() - 1);
    }

    private Frame<SourceValue>[] analyzeSourceValuesQuietly(MethodNode mn) {
        try {
            mn.maxStack = Math.max(mn.maxStack, 256);
            return new Analyzer<>(new SourceInterpreter()).analyze("java/lang/Object", mn);
        } catch (AnalyzerException | RuntimeException ignored) {
            return null;
        }
    }

    private void rewritePreviousMethodHandleNameLiteral(
        MethodInsnNode call,
        Map<String, Map<String, String>> namesByOwner
    ) {
        LdcInsnNode nameInsn = null;
        String owner = null;
        int scanned = 0;
        for (AbstractInsnNode scan = call.getPrevious(); scan != null && scanned++ < 48; scan = scan.getPrevious()) {
            if (!(scan instanceof LdcInsnNode ldc)) continue;
            if (nameInsn == null && ldc.cst instanceof String) {
                nameInsn = ldc;
                continue;
            }
            if (owner == null && ldc.cst instanceof Type type && type.getSort() == Type.OBJECT) {
                owner = type.getInternalName();
            }
            if (nameInsn != null && owner != null) break;
        }
        if (nameInsn == null || !(nameInsn.cst instanceof String oldName)) return;
        String mapped = null;
        if (owner != null) {
            Map<String, String> ownerNames = namesByOwner.get(owner);
            if (ownerNames != null) mapped = ownerNames.get(oldName);
        }
        if (mapped == null) mapped = uniqueGlobalMemberName(namesByOwner, oldName);
        if (mapped != null) nameInsn.cst = mapped;
    }

    private String uniqueGlobalMemberName(Map<String, Map<String, String>> namesByOwner, String oldName) {
        String mapped = null;
        for (Map<String, String> names : namesByOwner.values()) {
            String candidate = names.get(oldName);
            if (candidate == null) continue;
            if (mapped != null && !mapped.equals(candidate)) return null;
            mapped = candidate;
        }
        return mapped;
    }

    private enum RewriteNameResult {
        UNKNOWN,
        OWNER_KNOWN_UNCHANGED,
        REWRITTEN
    }

    private boolean overridesExternalMethod(PipelineContext pctx, L1Class clazz, MethodNode mn, String desc) {
        return overridesExternalIn(pctx, clazz.superName(), mn.name, desc)
            || overridesExternalInInterfaces(pctx, clazz.interfaces(), mn.name, desc);
    }

    private boolean overridesExternalIn(PipelineContext pctx, String owner, String name, String desc) {
        if (owner == null) return false;
        L1Class appClass = pctx.classMap().get(owner);
        if (appClass != null) {
            // A declaration in an application ancestor does not end the search:
            // it may itself override an external ABI method. Descendants must
            // retain that same name to preserve virtual dispatch.
            return overridesExternalIn(pctx, appClass.superName(), name, desc)
                || overridesExternalInInterfaces(pctx, appClass.interfaces(), name, desc);
        }
        return externalClassDeclares(pctx, owner, name, desc, new HashSet<>());
    }

    private boolean overridesExternalInInterfaces(PipelineContext pctx, List<String> interfaces, String name, String desc) {
        for (String iface : interfaces) {
            L1Class appInterface = pctx.classMap().get(iface);
            if (appInterface != null) {
                if (overridesExternalInInterfaces(pctx, appInterface.interfaces(), name, desc)) return true;
                continue;
            }
            if (externalClassDeclares(pctx, iface, name, desc, new HashSet<>())) return true;
        }
        return false;
    }

    private boolean externalClassDeclares(
        PipelineContext pctx,
        String owner,
        String name,
        String desc,
        Set<String> visited
    ) {
        if (owner == null || !visited.add(owner)) return false;
        var info = pctx.hierarchy().getInfo(owner);
        if (info != null) {
            if (info.methods().contains(name + desc)) return true;
            if (externalClassDeclares(pctx, info.superName(), name, desc, visited)) return true;
            for (String iface : info.interfaces()) {
                if (externalClassDeclares(pctx, iface, name, desc, visited)) return true;
            }
        }
        try {
            Class<?> type = Class.forName(owner.replace('/', '.'), false, JvmRenamerPass.class.getClassLoader());
            for (java.lang.reflect.Method method : type.getDeclaredMethods()) {
                if (method.getName().equals(name) && Type.getMethodDescriptor(method).equals(desc)) return true;
            }
            Class<?> parent = type.getSuperclass();
            if (parent != null && externalClassDeclares(
                pctx, parent.getName().replace('.', '/'), name, desc, visited
            )) return true;
            for (Class<?> iface : type.getInterfaces()) {
                if (externalClassDeclares(
                    pctx, iface.getName().replace('.', '/'), name, desc, visited
                )) return true;
            }
            return false;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private String classNameBeforeRename(L1Class clazz, Map<String, String> classMap) {
        for (Map.Entry<String, String> entry : classMap.entrySet()) {
            if (entry.getValue().equals(clazz.name())) return entry.getKey();
        }
        return clazz.name();
    }

    private String stringOption(PipelineContext pctx, String name, String defaultValue) {
        var transform = pctx.config().transforms().get(ID);
        if (transform == null) return defaultValue;
        Object value = transform.options().get(name);
        return value instanceof String text ? text : defaultValue;
    }

    private boolean booleanOption(PipelineContext pctx, String name, boolean defaultValue) {
        var transform = pctx.config().transforms().get(ID);
        if (transform == null) return defaultValue;
        Object value = transform.options().get(name);
        return value instanceof Boolean flag ? flag : defaultValue;
    }

    private int intOption(PipelineContext pctx, String name, int defaultValue) {
        var transform = pctx.config().transforms().get(ID);
        if (transform == null) return defaultValue;
        Object value = transform.options().get(name);
        return value instanceof Number number ? number.intValue() : defaultValue;
    }

    private List<String> stringListOption(PipelineContext pctx, String name) {
        var transform = pctx.config().transforms().get(ID);
        if (transform == null) return List.of();
        Object value = transform.options().get(name);
        if (!(value instanceof List<?> values)) return List.of();
        List<String> result = new ArrayList<>();
        for (Object item : values) {
            if (item instanceof String text && !text.isBlank()) {
                result.add(text);
            }
        }
        return List.copyOf(result);
    }

    private boolean matchesAnyClassPattern(List<String> patterns, String internalName) {
        String dottedName = internalName.replace('/', '.');
        for (String configuredPattern : patterns) {
            String dottedPattern = configuredPattern.replace('/', '.');
            StringBuilder regex = new StringBuilder("^");
            for (int index = 0; index < dottedPattern.length(); index++) {
                char current = dottedPattern.charAt(index);
                if (current == '*') {
                    if (index + 1 < dottedPattern.length() && dottedPattern.charAt(index + 1) == '*') {
                        regex.append(".*");
                        index++;
                    } else {
                        regex.append("[^.]*");
                    }
                } else if (current == '?') {
                    regex.append("[^.]");
                } else {
                    regex.append(Pattern.quote(String.valueOf(current)));
                }
            }
            regex.append('$');
            if (Pattern.matches(regex.toString(), dottedName)) return true;
        }
        return false;
    }

    private void rewriteManifestMainClass(PipelineContext pctx, Map<String, String> classes) {
        if (classes.isEmpty()) return;
        rewriteManifestMaps(pctx, classes);
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private void rewriteManifestMaps(Object holder, Map<String, String> classes) {
        Set<Object> seen = java.util.Collections.newSetFromMap(new java.util.IdentityHashMap<>());
        java.util.ArrayDeque<Object> work = new java.util.ArrayDeque<>();
        work.add(holder);
        int budget = 512;
        while (!work.isEmpty() && budget-- > 0) {
            Object value = work.removeFirst();
            if (value == null || !seen.add(value)) continue;
            if (value instanceof Manifest manifest) {
                rewriteManifestObject(manifest, classes);
                continue;
            }
            if (value instanceof Map map) {
                rewriteManifestMap(map, classes);
                work.addAll(map.values());
                continue;
            }
            if (value instanceof Iterable iterable) {
                for (Object element : iterable) {
                    if (element != null) work.add(element);
                }
                continue;
            }
            Class<?> type = value.getClass();
            if (type.isArray() && !type.getComponentType().isPrimitive()) {
                int length = java.lang.reflect.Array.getLength(value);
                for (int i = 0; i < length; i++) {
                    Object element = java.lang.reflect.Array.get(value, i);
                    if (element != null) work.add(element);
                }
                continue;
            }
            if (!isInspectableResourceHolder(type)) continue;
            rewriteManifestHolder(value, classes);
            for (Class<?> current = type; current != null; current = current.getSuperclass()) {
                for (Field field : current.getDeclaredFields()) {
                    if (!shouldTraverseManifestField(current, field)) continue;
                    try {
                        field.setAccessible(true);
                        Object nested = field.get(value);
                        if (nested != null) work.add(nested);
                    } catch (ReflectiveOperationException | RuntimeException ignored) {
                    }
                }
            }
            for (Method method : type.getMethods()) {
                if (method.getParameterCount() != 0) continue;
                Class<?> returnType = method.getReturnType();
                if (!Map.class.isAssignableFrom(returnType)
                    && !Iterable.class.isAssignableFrom(returnType)
                    && !Manifest.class.isAssignableFrom(returnType)
                    && !(returnType.isArray() && !returnType.getComponentType().isPrimitive())) {
                    continue;
                }
                try {
                    Object nested = method.invoke(value);
                    if (nested != null) work.add(nested);
                } catch (ReflectiveOperationException | RuntimeException ignored) {
                }
            }
        }
    }

    private boolean shouldTraverseManifestField(Class<?> ownerType, Field field) {
        if (java.lang.reflect.Modifier.isStatic(field.getModifiers())) return false;
        Class<?> fieldType = field.getType();
        if (fieldType.isPrimitive() || fieldType.isEnum()) return false;
        if (Map.class.isAssignableFrom(fieldType)
            || Iterable.class.isAssignableFrom(fieldType)
            || Manifest.class.isAssignableFrom(fieldType)
            || (fieldType.isArray() && !fieldType.getComponentType().isPrimitive())
            || isInspectableResourceHolder(fieldType)) {
            return true;
        }
        String ownerName = ownerType == null ? "" : ownerType.getName();
        String fieldName = fieldType.getName();
        return ownerName.startsWith("dev.nekoobfuscator.")
            && !fieldName.startsWith("java.lang.");
    }

    private boolean isInspectableResourceHolder(Class<?> type) {
        if (type == null || type.isPrimitive()) return false;
        String name = type.getName();
        return name.startsWith("dev.nekoobfuscator.")
            || name.startsWith("java.util.")
            || name.contains("Resource")
            || name.contains("Jar")
            || name.contains("Entry");
    }

    private void rewriteManifestHolder(Object holder, Map<String, String> classes) {
        String resourceName = resourceName(holder);
        if (!isManifestResourceName(resourceName)) return;
        for (Class<?> current = holder.getClass(); current != null; current = current.getSuperclass()) {
            for (Field field : current.getDeclaredFields()) {
                if (java.lang.reflect.Modifier.isStatic(field.getModifiers())) continue;
                if (!isManifestContentField(field) && field.getType() != Manifest.class) continue;
                try {
                    field.setAccessible(true);
                    Object value = field.get(holder);
                    Object rewritten = rewriteManifestValue(value, classes);
                    if (rewritten != value) field.set(holder, rewritten);
                } catch (ReflectiveOperationException | RuntimeException ignored) {
                }
            }
        }
    }

    private String resourceName(Object holder) {
        for (Class<?> current = holder.getClass(); current != null; current = current.getSuperclass()) {
            for (Field field : current.getDeclaredFields()) {
                if (java.lang.reflect.Modifier.isStatic(field.getModifiers()) || field.getType() != String.class) continue;
                String fieldName = field.getName().toLowerCase(java.util.Locale.ROOT);
                if (!(fieldName.contains("name") || fieldName.contains("path") || fieldName.contains("entry"))) continue;
                try {
                    field.setAccessible(true);
                    Object value = field.get(holder);
                    if (value instanceof String text && isManifestResourceName(text)) return text;
                } catch (ReflectiveOperationException | RuntimeException ignored) {
                }
            }
        }
        return null;
    }

    private boolean isManifestResourceName(String value) {
        return value != null && "META-INF/MANIFEST.MF".equalsIgnoreCase(value.replace('\\', '/'));
    }

    private boolean isManifestContentField(Field field) {
        Class<?> type = field.getType();
        if (type != byte[].class && type != String.class) return false;
        String name = field.getName().toLowerCase(java.util.Locale.ROOT);
        return name.contains("data")
            || name.contains("byte")
            || name.contains("content")
            || name.contains("body")
            || name.contains("text");
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private void rewriteManifestMap(Map map, Map<String, String> classes) {
        Object manifestKey = null;
        for (Object key : map.keySet()) {
            if (key instanceof String text && "META-INF/MANIFEST.MF".equalsIgnoreCase(text)) {
                manifestKey = key;
                break;
            }
        }
        if (manifestKey == null) return;
        Object value = map.get(manifestKey);
        Object rewritten = rewriteManifestValue(value, classes);
        if (rewritten != value) {
            map.put(manifestKey, rewritten);
        }
    }

    private Object rewriteManifestValue(Object value, Map<String, String> classes) {
        if (value instanceof Manifest manifest) {
            rewriteManifestObject(manifest, classes);
            return value;
        }
        if (value instanceof byte[] bytes) {
            byte[] rewritten = rewriteManifestBytes(bytes, classes);
            return rewritten == bytes ? value : rewritten;
        }
        if (value instanceof String text) {
            byte[] original = text.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            byte[] rewritten = rewriteManifestBytes(original, classes);
            return rewritten == original ? value : new String(rewritten, java.nio.charset.StandardCharsets.UTF_8);
        }
        if (value == null) return value;
        for (Class<?> current = value.getClass(); current != null; current = current.getSuperclass()) {
            for (Field field : current.getDeclaredFields()) {
                if (field.getType() != byte[].class) continue;
                String name = field.getName();
                if (!("data".equals(name) || "bytes".equals(name) || "content".equals(name))) continue;
                try {
                    field.setAccessible(true);
                    byte[] bytes = (byte[]) field.get(value);
                    byte[] rewritten = rewriteManifestBytes(bytes, classes);
                    if (rewritten != bytes) field.set(value, rewritten);
                } catch (ReflectiveOperationException | RuntimeException ignored) {
                }
            }
        }
        return value;
    }

    private boolean rewriteManifestObject(Manifest manifest, Map<String, String> classes) {
        if (manifest == null) return false;
        String mainClass = manifest.getMainAttributes().getValue("Main-Class");
        if (mainClass == null) return false;
        String mapped = classes.get(mainClass.replace('.', '/'));
        if (mapped == null || mapped.replace('/', '.').equals(mainClass)) return false;
        manifest.getMainAttributes().putValue("Main-Class", mapped.replace('/', '.'));
        return true;
    }

    private byte[] rewriteManifestBytes(byte[] bytes, Map<String, String> classes) {
        if (bytes == null || bytes.length == 0) return bytes;
        try {
            Manifest manifest = new Manifest(new ByteArrayInputStream(bytes));
            if (!rewriteManifestObject(manifest, classes)) return bytes;
            ByteArrayOutputStream out = new ByteArrayOutputStream(bytes.length + 32);
            manifest.write(out);
            return out.toByteArray();
        } catch (Exception ignored) {
            return bytes;
        }
    }

    private void rewriteAnnotationEnumValueNames(ClassNode node, Map<MemberKey, String> members) {
        rewriteAnnotationEnumValues(node.visibleAnnotations, members);
        rewriteAnnotationEnumValues(node.invisibleAnnotations, members);
        rewriteAnnotationEnumValues(node.visibleTypeAnnotations, members);
        rewriteAnnotationEnumValues(node.invisibleTypeAnnotations, members);
        for (FieldNode field : node.fields) {
            rewriteAnnotationEnumValues(field.visibleAnnotations, members);
            rewriteAnnotationEnumValues(field.invisibleAnnotations, members);
            rewriteAnnotationEnumValues(field.visibleTypeAnnotations, members);
            rewriteAnnotationEnumValues(field.invisibleTypeAnnotations, members);
        }
        for (MethodNode method : node.methods) {
            method.annotationDefault = rewriteAnnotationEnumValue(method.annotationDefault, members);
            rewriteAnnotationEnumValues(method.visibleAnnotations, members);
            rewriteAnnotationEnumValues(method.invisibleAnnotations, members);
            rewriteAnnotationEnumValues(method.visibleTypeAnnotations, members);
            rewriteAnnotationEnumValues(method.invisibleTypeAnnotations, members);
            rewriteAnnotationEnumValues(method.visibleParameterAnnotations, members);
            rewriteAnnotationEnumValues(method.invisibleParameterAnnotations, members);
            rewriteAnnotationEnumValues(method.visibleLocalVariableAnnotations, members);
            rewriteAnnotationEnumValues(method.invisibleLocalVariableAnnotations, members);
        }
        if (node.recordComponents != null) {
            for (var component : node.recordComponents) {
                rewriteAnnotationEnumValues(component.visibleAnnotations, members);
                rewriteAnnotationEnumValues(component.invisibleAnnotations, members);
                rewriteAnnotationEnumValues(component.visibleTypeAnnotations, members);
                rewriteAnnotationEnumValues(component.invisibleTypeAnnotations, members);
            }
        }
    }

    /**
     * Hook target names are ordinary annotation string values, so ASM's
     * ClassRemapper does not treat them as class/member references. Rewrite
     * application-owned targets explicitly while leaving Minecraft/Forge
     * target strings untouched.
     */
    private void rewriteHookTargetAnnotationStrings(
        ClassNode node,
        Renamer remapper,
        Map<String, String> classes,
        Map<MemberKey, String> members
    ) {
        rewriteHookAnnotations(node.visibleAnnotations, remapper, classes, members);
        rewriteHookAnnotations(node.invisibleAnnotations, remapper, classes, members);
        rewriteHookAnnotations(node.visibleTypeAnnotations, remapper, classes, members);
        rewriteHookAnnotations(node.invisibleTypeAnnotations, remapper, classes, members);
        for (FieldNode field : node.fields) {
            rewriteHookAnnotations(field.visibleAnnotations, remapper, classes, members);
            rewriteHookAnnotations(field.invisibleAnnotations, remapper, classes, members);
            rewriteHookAnnotations(field.visibleTypeAnnotations, remapper, classes, members);
            rewriteHookAnnotations(field.invisibleTypeAnnotations, remapper, classes, members);
        }
        for (MethodNode method : node.methods) {
            rewriteHookAnnotations(method.visibleAnnotations, remapper, classes, members);
            rewriteHookAnnotations(method.invisibleAnnotations, remapper, classes, members);
            rewriteHookAnnotations(method.visibleTypeAnnotations, remapper, classes, members);
            rewriteHookAnnotations(method.invisibleTypeAnnotations, remapper, classes, members);
            rewriteHookAnnotations(method.visibleParameterAnnotations, remapper, classes, members);
            rewriteHookAnnotations(method.invisibleParameterAnnotations, remapper, classes, members);
            rewriteHookAnnotations(method.visibleLocalVariableAnnotations, remapper, classes, members);
            rewriteHookAnnotations(method.invisibleLocalVariableAnnotations, remapper, classes, members);
        }
        if (node.recordComponents != null) {
            for (var component : node.recordComponents) {
                rewriteHookAnnotations(component.visibleAnnotations, remapper, classes, members);
                rewriteHookAnnotations(component.invisibleAnnotations, remapper, classes, members);
                rewriteHookAnnotations(component.visibleTypeAnnotations, remapper, classes, members);
                rewriteHookAnnotations(component.invisibleTypeAnnotations, remapper, classes, members);
            }
        }
    }

    private void rewriteHookAnnotations(
        List<? extends AnnotationNode> annotations,
        Renamer remapper,
        Map<String, String> classes,
        Map<MemberKey, String> members
    ) {
        if (annotations == null) return;
        for (AnnotationNode annotation : annotations) {
            rewriteHookAnnotation(annotation, remapper, classes, members);
        }
    }

    private void rewriteHookAnnotations(
        List<? extends AnnotationNode>[] annotations,
        Renamer remapper,
        Map<String, String> classes,
        Map<MemberKey, String> members
    ) {
        if (annotations == null) return;
        for (List<? extends AnnotationNode> annotationList : annotations) {
            rewriteHookAnnotations(annotationList, remapper, classes, members);
        }
    }

    private void rewriteHookAnnotation(
        AnnotationNode annotation,
        Renamer remapper,
        Map<String, String> classes,
        Map<MemberKey, String> members
    ) {
        if (annotation == null || annotation.values == null) return;
        if ("Lcom/himitsu/secret/hook/AsmHook;".equals(annotation.desc)) {
            rewriteSingleHookTarget(annotation, remapper, classes, members);
        }
        for (int i = 1; i < annotation.values.size(); i += 2) {
            Object value = annotation.values.get(i);
            if (value instanceof AnnotationNode nested) {
                rewriteHookAnnotation(nested, remapper, classes, members);
            } else if (value instanceof List<?> values) {
                for (Object element : values) {
                    if (element instanceof AnnotationNode nested) {
                        rewriteHookAnnotation(nested, remapper, classes, members);
                    }
                }
            }
        }
    }

    @SuppressWarnings("unchecked")
    private void rewriteSingleHookTarget(
        AnnotationNode annotation,
        Renamer remapper,
        Map<String, String> classes,
        Map<MemberKey, String> members
    ) {
        int classIndex = annotationValueIndex(annotation, "targetClass");
        int methodIndex = annotationValueIndex(annotation, "targetMethod");
        int aliasesIndex = annotationValueIndex(annotation, "targetAliases");
        int descriptorIndex = annotationValueIndex(annotation, "targetDescriptor");
        if (classIndex < 0 || methodIndex < 0 || descriptorIndex < 0) return;

        Object classValue = annotation.values.get(classIndex);
        Object methodValue = annotation.values.get(methodIndex);
        Object descriptorValue = annotation.values.get(descriptorIndex);
        if (!(classValue instanceof String targetClass)
            || !(methodValue instanceof String targetMethod)
            || !(descriptorValue instanceof String targetDescriptor)) return;

        String owner = targetClass.replace('.', '/');
        if (!classes.containsKey(owner)) return;
        String mappedOwner = classes.get(owner);
        String mappedMethod = members.get(MemberKey.method(owner, targetMethod, targetDescriptor));
        annotation.values.set(classIndex, mappedOwner);
        if (mappedMethod != null) annotation.values.set(methodIndex, mappedMethod);
        annotation.values.set(descriptorIndex, remapper.mapMethodDesc(targetDescriptor));

        if (aliasesIndex >= 0 && annotation.values.get(aliasesIndex) instanceof List<?> rawAliases) {
            List<Object> aliases = (List<Object>) rawAliases;
            for (int i = 0; i < aliases.size(); i++) {
                Object aliasValue = aliases.get(i);
                if (!(aliasValue instanceof String alias)) continue;
                String mappedAlias = members.get(MemberKey.method(owner, alias, targetDescriptor));
                if (mappedAlias != null) aliases.set(i, mappedAlias);
            }
        }
    }

    private int annotationValueIndex(AnnotationNode annotation, String name) {
        for (int i = 0; i + 1 < annotation.values.size(); i += 2) {
            if (name.equals(annotation.values.get(i))) return i + 1;
        }
        return -1;
    }

    private void rewriteAnnotationEnumValues(List<? extends AnnotationNode> annotations, Map<MemberKey, String> members) {
        if (annotations == null) return;
        for (AnnotationNode annotation : annotations) {
            rewriteAnnotationEnumValue(annotation, members);
        }
    }

    private void rewriteAnnotationEnumValues(
        List<? extends AnnotationNode>[] annotations,
        Map<MemberKey, String> members
    ) {
        if (annotations == null) return;
        for (List<? extends AnnotationNode> annotationList : annotations) {
            rewriteAnnotationEnumValues(annotationList, members);
        }
    }

    @SuppressWarnings("unchecked")
    private Object rewriteAnnotationEnumValue(Object value, Map<MemberKey, String> members) {
        if (value instanceof AnnotationNode annotation) {
            if (annotation.values != null) {
                for (int i = 1; i < annotation.values.size(); i += 2) {
                    annotation.values.set(i, rewriteAnnotationEnumValue(annotation.values.get(i), members));
                }
            }
            return value;
        }
        if (value instanceof List<?> list) {
            List<Object> values = (List<Object>) list;
            for (int i = 0; i < values.size(); i++) {
                values.set(i, rewriteAnnotationEnumValue(values.get(i), members));
            }
            return value;
        }
        if (value instanceof String[] enumValue && enumValue.length == 2) {
            String descriptor = enumValue[0];
            String constantName = enumValue[1];
            Type type = Type.getType(descriptor);
            if (type.getSort() == Type.OBJECT) {
                String mapped = members.get(MemberKey.field(type.getInternalName(), constantName, descriptor));
                if (mapped != null) {
                    enumValue[1] = mapped;
                }
            }
        }
        return value;
    }

    private void writeMapLines(
        PipelineContext pctx,
        Map<String, String> classes,
        Map<MemberKey, String> members
    ) {
        List<String> lines = mapLines(pctx);
        for (Map.Entry<String, String> entry : classes.entrySet()) {
            lines.add("CLASS " + entry.getKey() + " -> " + entry.getValue());
        }
        for (Map.Entry<MemberKey, String> entry : members.entrySet()) {
            MemberKey key = entry.getKey();
            lines.add((key.method() ? "METHOD " : "FIELD ") +
                key.owner() + "." + key.name() + key.desc() + " -> " + entry.getValue());
        }
    }

    private void stripDebugMetadata(ClassNode node) {
        node.sourceFile = null;
        node.sourceDebug = null;
        for (MethodNode method : node.methods) {
            method.localVariables = null;
            method.visibleLocalVariableAnnotations = null;
            method.invisibleLocalVariableAnnotations = null;
            if (method.instructions == null) continue;
            for (AbstractInsnNode insn = method.instructions.getFirst(); insn != null; ) {
                AbstractInsnNode next = insn.getNext();
                if (insn instanceof LineNumberNode) {
                    method.instructions.remove(insn);
                }
                insn = next;
            }
        }
    }

    private void copyInto(ClassNode target, ClassNode source) {
        target.version = source.version;
        target.access = source.access;
        target.name = source.name;
        target.signature = source.signature;
        target.superName = source.superName;
        target.interfaces = source.interfaces;
        target.sourceFile = source.sourceFile;
        target.sourceDebug = source.sourceDebug;
        target.module = source.module;
        target.outerClass = source.outerClass;
        target.outerMethod = source.outerMethod;
        target.outerMethodDesc = source.outerMethodDesc;
        target.visibleAnnotations = source.visibleAnnotations;
        target.invisibleAnnotations = source.invisibleAnnotations;
        target.visibleTypeAnnotations = source.visibleTypeAnnotations;
        target.invisibleTypeAnnotations = source.invisibleTypeAnnotations;
        target.attrs = source.attrs;
        target.innerClasses = source.innerClasses;
        target.nestHostClass = source.nestHostClass;
        target.nestMembers = source.nestMembers;
        target.permittedSubclasses = source.permittedSubclasses;
        target.recordComponents = source.recordComponents;
        target.fields = source.fields;
        target.methods = source.methods;
    }

    private static final class Renamer extends Remapper {
        private final Map<String, L1Class> classes;
        private final Map<String, String> classMap;
        private final Map<MemberKey, String> memberMap;

        private Renamer(
            Map<String, L1Class> classes,
            Map<String, String> classMap,
            Map<MemberKey, String> memberMap
        ) {
            this.classes = classes;
            this.classMap = classMap;
            this.memberMap = memberMap;
        }

        @Override
        public String map(String internalName) {
            return classMap.getOrDefault(internalName, internalName);
        }

        @Override
        public String mapMethodName(String owner, String name, String descriptor) {
            String direct = memberMap.get(MemberKey.method(owner, name, descriptor));
            if (direct != null) return direct;
            String inherited = resolveMethod(owner, name, descriptor, new HashSet<>());
            return inherited == null ? name : inherited;
        }

        @Override
        public String mapFieldName(String owner, String name, String descriptor) {
            String direct = memberMap.get(MemberKey.field(owner, name, descriptor));
            if (direct != null) return direct;
            String inherited = resolveField(owner, name, descriptor, new HashSet<>());
            return inherited == null ? name : inherited;
        }

        @Override
        public String mapAnnotationAttributeName(String descriptor, String name) {
            Type type = Type.getType(descriptor);
            if (type.getSort() != Type.OBJECT) return name;
            String mapped = uniqueMethodName(type.getInternalName(), name);
            return mapped == null ? name : mapped;
        }

        @Override
        public String mapRecordComponentName(String owner, String name, String descriptor) {
            L1Class clazz = classes.get(owner);
            if (JvmRecordAbi.isRecordComponent(clazz, name, descriptor)) return name;
            String mapped = memberMap.get(MemberKey.field(owner, name, descriptor));
            return mapped == null ? name : mapped;
        }

        private String resolveMethod(String owner, String name, String desc, Set<String> seen) {
            if (owner == null || !seen.add(owner)) return null;
            L1Class clazz = classes.get(owner);
            if (clazz == null) return null;
            L1Method method = clazz.findMethod(name, desc);
            if (method != null) {
                return memberMap.get(MemberKey.method(owner, name, desc));
            }
            String fromSuper = resolveMethod(clazz.superName(), name, desc, seen);
            if (fromSuper != null) return fromSuper;
            for (String iface : clazz.interfaces()) {
                String fromIface = resolveMethod(iface, name, desc, seen);
                if (fromIface != null) return fromIface;
            }
            return null;
        }

        private String resolveField(String owner, String name, String desc, Set<String> seen) {
            if (owner == null || !seen.add(owner)) return null;
            L1Class clazz = classes.get(owner);
            if (clazz == null) return null;
            if (clazz.findField(name, desc) != null) {
                return memberMap.get(MemberKey.field(owner, name, desc));
            }
            String fromSuper = resolveField(clazz.superName(), name, desc, seen);
            if (fromSuper != null) return fromSuper;
            for (String iface : clazz.interfaces()) {
                String fromIface = resolveField(iface, name, desc, seen);
                if (fromIface != null) return fromIface;
            }
            return null;
        }

        private String uniqueMethodName(String owner, String name) {
            String mapped = null;
            for (Map.Entry<MemberKey, String> entry : memberMap.entrySet()) {
                MemberKey key = entry.getKey();
                if (!key.method() || !key.owner().equals(owner) || !key.name().equals(name)) continue;
                if (mapped != null && !mapped.equals(entry.getValue())) return null;
                mapped = entry.getValue();
            }
            return mapped;
        }
    }

    private static final class DisjointSet<T> {
        private final Map<T, T> parent = new LinkedHashMap<>();
        private final Map<T, String> fixed = new LinkedHashMap<>();

        void add(T value) {
            parent.putIfAbsent(value, value);
        }

        T find(T value) {
            add(value);
            T p = parent.get(value);
            if (Objects.equals(p, value)) return value;
            T root = find(p);
            parent.put(value, root);
            return root;
        }

        void union(T a, T b) {
            T ra = find(a);
            T rb = find(b);
            if (Objects.equals(ra, rb)) return;
            parent.put(rb, ra);
            String fixedA = fixed.get(ra);
            String fixedB = fixed.remove(rb);
            if (fixedA == null && fixedB != null) {
                fixed.put(ra, fixedB);
            }
        }

        void markFixed(T value, String name) {
            fixed.putIfAbsent(find(value), name);
        }

        String fixedName(T value) {
            return fixed.get(find(value));
        }
    }

    private static final class NameSource {
        private final String prefix;
        private final String alphabet;
        private final int minimumLength;
        private int index;

        private NameSource(String prefix) {
            this(prefix, "abcdefghijklmnopqrstuvwxyz", 0);
        }

        private NameSource(String prefix, String alphabet, int minimumLength) {
            this.prefix = prefix == null ? "" : prefix;
            String requestedAlphabet = alphabet == null ? "" : alphabet;
            this.alphabet = requestedAlphabet.chars().distinct().count() >= 2
                ? requestedAlphabet
                : "abcdefghijklmnopqrstuvwxyz";
            this.minimumLength = Math.max(0, Math.min(62, minimumLength));
        }

        String nextInternalName() {
            return prefix + nextSimpleName();
        }

        String nextSimpleName() {
            int value = index++;
            if (minimumLength > 0 && alphabet.length() == 2) {
                long alternatingMask = 0x5555555555555555L;
                long encoded = Integer.toUnsignedLong(value) ^ alternatingMask;
                StringBuilder fixed = new StringBuilder(minimumLength);
                for (int bit = minimumLength - 1; bit >= 0; bit--) {
                    fixed.append(alphabet.charAt((int) ((encoded >>> bit) & 1L)));
                }
                return fixed.toString();
            }
            StringBuilder name = new StringBuilder();
            do {
                name.append(alphabet.charAt(Math.floorMod(value, alphabet.length())));
                value = value / alphabet.length() - 1;
            } while (value >= 0);
            while (name.length() < minimumLength) {
                name.append(alphabet.charAt(0));
            }
            return name.toString();
        }
    }

    private record NameNode(String owner, String name) {}

    private record MemberKey(String owner, String name, String desc, boolean method) {
        static MemberKey method(String owner, String name, String desc) {
            return new MemberKey(owner, name, desc, true);
        }

        static MemberKey field(String owner, String name, String desc) {
            return new MemberKey(owner, name, desc, false);
        }
    }
}

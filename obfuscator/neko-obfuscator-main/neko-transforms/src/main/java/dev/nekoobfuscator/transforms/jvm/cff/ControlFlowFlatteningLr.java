package dev.nekoobfuscator.transforms.jvm.cff;
import dev.nekoobfuscator.transforms.jvm.internal.JvmPassBytecode;

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.LabelNode;

/**
 * Lightweight CFF planning representation and relation math.
 *
 * <p>The pass owns bytecode rewriting. This helper owns the block, edge and
 * dispatcher relation data that must stay easy to audit independently.</p>
 */
final class ControlFlowFlatteningLr {
    private ControlFlowFlatteningLr() {}

    static long domainSeed(IslandGroup group) {
        return group.salt() ^ 0x444F4D41494E4B31L;
    }

    static long transitionKeySeed(
        long edgeSeed,
        int state,
        DispatchTarget target,
        EdgeRole role
    ) {
        long seed = JvmPassBytecode.mix(
            edgeSeed ^ target.selectorSeed(),
            state
        );
        seed = JvmPassBytecode.mix(
            seed ^ target.domainSeed(),
            target.island() ^ role.ordinal()
        );
        return seed == 0L ? edgeSeed ^ 0x4346465354455031L : seed;
    }

    static EdgeKind chooseEdgeKind(
        long seed,
        EdgeRole role,
        DispatchTarget target
    ) {
        if (target.islandLabels().length == 1) {
            return EdgeKind.DIRECT_ISLAND;
        }
        if (role == EdgeRole.HANDLER) {
            return hasAliasHub(target) && ((seed >>> 9) & 1L) == 0L
                ? EdgeKind.ALIAS_HUB
                : EdgeKind.HUB;
        }
        int choice = (int) ((seed >>> 56) & 7L);
        return switch (choice) {
            case 0, 1, 5 -> EdgeKind.DIRECT_ISLAND;
            case 2, 7 -> hasAliasHub(target)
                ? EdgeKind.ALIAS_HUB
                : EdgeKind.HUB;
            default -> EdgeKind.HUB;
        };
    }

    static boolean hasAliasHub(DispatchTarget target) {
        return target.aliasHubs().length > 0;
    }

    static LabelNode selectAliasHub(DispatchTarget target, long seed) {
        LabelNode[] aliases = target.aliasHubs();
        if (aliases.length == 0) return target.hub();
        return aliases[(int) Long.remainderUnsigned(seed, aliases.length)];
    }

    static int islandCount(int nonHandlerCount) {
        if (nonHandlerCount <= 1) return 1;
        return Math.min(16, Math.max(2, (nonHandlerCount + 3) / 4));
    }

    static int islandFor(
        int nonHandlerIndex,
        int nonHandlerCount,
        int islandCount
    ) {
        return (nonHandlerIndex * islandCount) / Math.max(1, nonHandlerCount);
    }

    static int aliasHubCount(int nonHandlerCount) {
        if (nonHandlerCount <= 2) return 1;
        return Math.min(3, 1 + nonHandlerCount / 6);
    }

    static int aliasHubCount(int nonHandlerCount, SyntheticNoiseBudget budget) {
        int normal = aliasHubCount(nonHandlerCount);
        return switch (budget) {
            case NORMAL -> normal;
            case PRESSURE -> Math.min(1, normal);
            case CRITICAL -> 0;
        };
    }

    static int fakeCaseCount(long seed) {
        return 1 + (int) Long.remainderUnsigned(seed >>> 29, 3L);
    }

    static int fakeCaseCount(long seed, SyntheticNoiseBudget budget) {
        return switch (budget) {
            case NORMAL -> fakeCaseCount(seed);
            case PRESSURE -> (int) ((seed >>> 61) & 1L);
            case CRITICAL -> 0;
        };
    }

    static long edgeSeed(
        long salt,
        LabelNode from,
        LabelNode to,
        long discriminator
    ) {
        long seed = JvmPassBytecode.mix(
            salt ^ discriminator,
            System.identityHashCode(from)
        );
        seed = JvmPassBytecode.mix(seed, System.identityHashCode(to));
        return seed == 0L ? discriminator ^ 0x5DEECE66DL : seed;
    }

    static int fakeState(long salt, int state) {
        int fake = (int) JvmPassBytecode.mix(salt ^ 0x46414B4543415345L, state);
        return fake == state ? fake ^ 0x13579BDF : fake;
    }

    static int[] uniqueStates(int seed, int count) {
        int[] states = new int[count];
        Set<Integer> used = new HashSet<>();
        long state = seed;
        for (int i = 0; i < count; i++) {
            int candidate;
            do {
                state = JvmPassBytecode.mix(state, i + 0x51ED2705L);
                candidate = (int) state;
            } while (!used.add(candidate));
            states[i] = candidate;
        }
        return states;
    }

    record Block(
        LabelNode label,
        AbstractInsnNode endExclusive,
        boolean handler
    ) {}

    record BlockPlan(
        List<Block> blocks,
        Map<LabelNode, LabelNode> aliases
    ) {}

    enum EdgeKind {
        HUB,
        DIRECT_ISLAND,
        ALIAS_HUB,
    }

    enum EdgeRole {
        FALLTHROUGH,
        GOTO,
        CONDITIONAL_TRUE,
        CONDITIONAL_FALSE,
        SWITCH_CASE,
        SWITCH_DEFAULT,
        HANDLER,
        FAKE,
        POISON,
    }

    enum SyntheticNoiseBudget {
        NORMAL,
        PRESSURE,
        CRITICAL,
    }

    record DispatchTarget(
        LabelNode hub,
        LabelNode[] islandLabels,
        LabelNode[] aliasHubs,
        int island,
        long selectorSeed,
        long domainSeed,
        int domainToken
    ) {}

    record IslandGroup(
        LabelNode hub,
        LabelNode[] islandLabels,
        LabelNode[] aliasHubs,
        List<Block> blocks,
        Map<LabelNode, Integer> islands,
        long salt
    ) {}

    record DispatchPlan(
        List<IslandGroup> groups,
        Map<LabelNode, DispatchTarget> targets
    ) {}
}

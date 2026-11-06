package dev.nekoobfuscator.native_.codegen.emit;

/**
 * Emits the runtime VMStructs walk that discovers Method* field offsets
 * across HotSpot versions, plus the {@code neko_patch_method_entry} routine
 * that swaps {@code _i2i_entry}, {@code _from_interpreted_entry}, and
 * {@code _from_compiled_entry} to per-signature trampolines. It also ORs
 * no-compile flags so the JIT can't recompile around the patch.
 *
 * Discovery is fully native: dlsym + {@code /proc/self/maps} fallback for
 * libjvm, then VMStructs / VMTypes / VMIntConstants / VMLongConstants walks.
 * No JVM helper methods are used.
 */
public final class MethodPatcherEmitter {

    public String render() {
        return MethodPatcherLayoutEmitter.render()
            + MethodPatcherVmStructEmitter.render()
            + MethodPatcherThunkEmitter.render()
            + MethodPatcherBootstrapEmitter.render();
    }

}

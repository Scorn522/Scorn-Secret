package dev.nekoobfuscator.native_.codegen.emit;

/**
 * Naked-function trampolines for x86_64 Windows.
 *
 * Windows x64 calling convention:
 *   GP args:  rcx, rdx, r8, r9 (then stack)
 *   FP args:  xmm0..3 (then stack); each FP arg also reserves the
 *             corresponding GP register slot
 *   Caller reserves a 32-byte "shadow space" on the stack
 *   Callee-saved adds: rbx, rbp, rdi, rsi, r12-r15
 *   Stack-spilled args start at [rbp + 16 + i*8] where i is the
 *   zero-based slot index *across* both GP and FP shadow registers.
 *
 * HotSpot's interpreter calling convention is platform-independent above
 * the C-ABI boundary: rbx=Method*, r13=sender_sp, r15=JavaThread*.
 *
 * These stubs are entered from Java ABI entry points patched into Method.
 * JavaThread therefore stays in _thread_in_java across the dispatcher call;
 * the trampoline only builds the dispatcher arguments and returns through
 * the normal Java caller path.
 */
public final class X86_64WindowsTrampoline {

    public String render(int sigId, SignaturePlan.Shape shape) {
        StringBuilder sb = new StringBuilder();
        sb.append(renderI2i(sigId, shape, false));
        if (shape.extraspaceWords() > 0) {
            sb.append(renderI2i(sigId, shape, true));
        }
        sb.append(renderC2i(sigId, shape));
        return sb.toString();
    }

    private String renderI2i(int sigId, SignaturePlan.Shape shape, boolean compiledCallerMode) {
        StringBuilder sb = new StringBuilder();
        char ret = shape.returnKind();
        char[] args = shape.argKinds();
        int receiverSlot = shape.isStatic() ? 0 : 1;
        int totalSlots = receiverSlot;
        for (char a : args) totalSlots += (a == 'J' || a == 'D') ? 2 : 1;

        int[] argSlotIndex = new int[args.length];
        int receiverIndex = -1;
        {
            int remaining = totalSlots;
            if (!shape.isStatic()) {
                receiverIndex = remaining - 1;
                remaining -= 1;
            }
            for (int i = 0; i < args.length; i++) {
                int slots = (args[i] == 'J' || args[i] == 'D') ? 2 : 1;
                argSlotIndex[i] = remaining - slots;
                remaining -= slots;
            }
        }

        String fnName = compiledCallerMode
            ? ("neko_sig_" + sigId + "_i2i_path2")
            : ("neko_sig_" + sigId + "_i2i");

        sb.append("/* sig ").append(sigId).append(compiledCallerMode ? " i2i_path2" : " i2i").append(" (Win x64, ")
          .append(shape.isStatic() ? "static" : "instance")
          .append(", args=\"");
        for (char a : args) sb.append(a);
        sb.append("\", ret=").append(ret);
        if (compiledCallerMode) {
            sb.append(", extraspace_bytes=").append(shape.extraspaceWords() * 8);
        }
        sb.append(") */\n");
        sb.append("__attribute__((naked, used, visibility(\"hidden\")))\n");
        sb.append("void ").append(fnName).append("(void) {\n");
        sb.append("    __asm__ volatile (\n");
        sb.append("        \"pushq %%rbp\\n\"\n");
        sb.append("        \"movq  %%rsp, %%rbp\\n\"\n");
        // 32-byte shadow + alignment + spill scratch (mirror SysV: 256 bytes).
        sb.append("        \"subq  $256, %%rsp\\n\"\n");
        sb.append("        \"andq  $-16, %%rsp\\n\"\n");
        // scan primary and alias Method* tables for matching rbx
        sb.append("        \"leaq  g_neko_manifest_method_stars(%%rip), %%r10\\n\"\n");
        sb.append("        \"movl  g_neko_manifest_method_count(%%rip), %%r11d\\n\"\n");
        sb.append("        \"xorl  %%eax, %%eax\\n\"\n");
        sb.append("        \"1:\\n\"\n");
        sb.append("        \"cmpl  %%r11d, %%eax\\n\"\n");
        sb.append("        \"jge   3f\\n\"\n");
        sb.append("        \"cmpq  %%rbx, (%%r10, %%rax, 8)\\n\"\n");
        sb.append("        \"je    2f\\n\"\n");
        sb.append("        \"incl  %%eax\\n\"\n");
        sb.append("        \"jmp   1b\\n\"\n");
        sb.append("        \"3:\\n\"\n");
        sb.append("        \"leaq  g_neko_manifest_alias_method_stars(%%rip), %%r10\\n\"\n");
        sb.append("        \"movl  g_neko_manifest_alias_count(%%rip), %%r11d\\n\"\n");
        sb.append("        \"xorl  %%eax, %%eax\\n\"\n");
        sb.append("        \".Lneko_w_i2i_alias_loop_%=:\\n\"\n");
        sb.append("        \"cmpl  %%r11d, %%eax\\n\"\n");
        sb.append("        \"jge   .Lneko_w_i2i_miss_%=\\n\"\n");
        sb.append("        \"cmpq  %%rbx, (%%r10, %%rax, 8)\\n\"\n");
        sb.append("        \"je    .Lneko_w_i2i_alias_hit_%=\\n\"\n");
        sb.append("        \"incl  %%eax\\n\"\n");
        sb.append("        \"jmp   .Lneko_w_i2i_alias_loop_%=\\n\"\n");
        sb.append("        \".Lneko_w_i2i_alias_hit_%=:\\n\"\n");
        sb.append("        \"leaq  g_neko_manifest_alias_indices(%%rip), %%r10\\n\"\n");
        sb.append("        \"movl  (%%r10, %%rax, 4), %%eax\\n\"\n");
        sb.append("        \"jmp   2f\\n\"\n");
        sb.append("        \".Lneko_w_i2i_miss_%=:\\n\"\n");
        sb.append("        \"xorl  %%eax, %%eax\\n\"\n");
        sb.append("        \"pxor  %%xmm0, %%xmm0\\n\"\n");
        sb.append("        \"jmp   9f\\n\"\n");
        sb.append("        \"2:\\n\"\n");
        // entry = &g_neko_manifest_methods[idx]; first arg in rcx
        sb.append("        \"leaq  g_neko_manifest_methods(%%rip), %%rcx\\n\"\n");
        sb.append("        \"imulq $").append(PatcherLayoutConstants.MANIFEST_METHOD_SIZE)
          .append(", %%rax, %%r11\\n\"\n");
        sb.append("        \"addq  %%r11, %%rcx\\n\"\n");

        // Args layout to dispatcher (Windows ABI):
        //   rcx=entry, rdx=thread (=r15), r8=receiver_slot_addr (if instance), r9=arg0, then stack
        // Each FP arg consumes both an xmm slot AND its GP shadow position.
        sb.append("        \"movq  %%r15, %%rdx\\n\"\n");
        int gpUsed = 2; // rcx, rdx taken
        int xmmUsed = 0;
        int extraStackSlot = 0;
        int spillBase = -32;
        int spillIndex = 0;
        if (!shape.isStatic()) {
            int slotOffset = receiverIndex * 8;
            if (compiledCallerMode) {
                int spillOff = spillBase - spillIndex * 8;
                sb.append("        \"movq  ").append(slotOffset + 32).append("(%%rbp), %%rax\\n\"\n");
                sb.append("        \"movq  %%rax, ").append(spillOff).append("(%%rbp)\\n\"\n");
                sb.append("        \"leaq  ").append(spillOff).append("(%%rbp), %").append(gpReg(gpUsed)).append("\\n\"\n");
                spillIndex++;
            } else {
                sb.append("        \"leaq  ").append(slotOffset + 32).append("(%%rbp), %").append(gpReg(gpUsed)).append("\\n\"\n");
            }
            gpUsed++;
        }
        for (int i = 0; i < args.length; i++) {
            char a = args[i];
            int slotOffset = argSlotIndex[i] * 8;
            if (a == 'F' || a == 'D') {
                if (gpUsed < 4 && xmmUsed < 4) {
                    if (a == 'F') sb.append("        \"movss ");
                    else sb.append("        \"movsd ");
                    sb.append(slotOffset + 32).append("(%%rbp), %%xmm").append(xmmUsed).append("\\n\"\n");
                    xmmUsed++;
                    gpUsed++; // shadow GP slot also consumed
                } else {
                    sb.append("        \"movq  ").append(slotOffset + 32).append("(%%rbp), %%rax\\n\"\n");
                    sb.append("        \"movq  %%rax, ").append(32 + extraStackSlot * 8).append("(%%rsp)\\n\"\n");
                    extraStackSlot++;
                }
            } else if (a == 'L') {
                int handleAddrOffset;
                if (compiledCallerMode) {
                    int spillOff = spillBase - spillIndex * 8;
                    sb.append("        \"movq  ").append(slotOffset + 32).append("(%%rbp), %%rax\\n\"\n");
                    sb.append("        \"movq  %%rax, ").append(spillOff).append("(%%rbp)\\n\"\n");
                    handleAddrOffset = spillOff;
                    spillIndex++;
                } else {
                    handleAddrOffset = slotOffset + 32;
                }
                if (gpUsed < 4) {
                    sb.append("        \"leaq  ").append(handleAddrOffset).append("(%%rbp), %").append(gpReg(gpUsed)).append("\\n\"\n");
                    gpUsed++;
                } else {
                    sb.append("        \"leaq  ").append(handleAddrOffset).append("(%%rbp), %%rax\\n\"\n");
                    sb.append("        \"movq  %%rax, ").append(32 + extraStackSlot * 8).append("(%%rsp)\\n\"\n");
                    extraStackSlot++;
                }
            } else {
                if (gpUsed < 4) {
                    sb.append("        \"movq  ").append(slotOffset + 32).append("(%%rbp), %").append(gpReg(gpUsed)).append("\\n\"\n");
                    gpUsed++;
                } else {
                    sb.append("        \"movq  ").append(slotOffset + 32).append("(%%rbp), %%rax\\n\"\n");
                    sb.append("        \"movq  %%rax, ").append(32 + extraStackSlot * 8).append("(%%rsp)\\n\"\n");
                    extraStackSlot++;
                }
            }
        }
        if (compiledCallerMode) {
            int extraspaceBytes = shape.extraspaceWords() * 8;
            sb.append("        \"movq 16(%%rbp), %%r11\\n\"\n");
            sb.append("        \"movq %%r11, ").append(16 + extraspaceBytes).append("(%%rbp)\\n\"\n");
        }
        sb.append("        \"call  neko_sig_").append(sigId).append("_dispatch\\n\"\n");
        sb.append("        \"9:\\n\"\n");
        // Return to interpreter caller via r13 sender_sp tail-jump (mirror SysV).
        if (compiledCallerMode) {
            int extraspaceBytes = shape.extraspaceWords() * 8;
            sb.append("        \"movq  ").append(16 + extraspaceBytes).append("(%%rbp), %%r11\\n\"\n");
            sb.append("        \"movq  %%rbp, %%rsp\\n\"\n");
            sb.append("        \"popq  %%rbp\\n\"\n");
            sb.append("        \"movq  16(%%rsp), %%r10\\n\"\n");
            sb.append("        \"movq  %%r11, %%rbp\\n\"\n");
            sb.append("        \"movq  %%r13, %%rsp\\n\"\n");
            sb.append("        \"jmp   *%%r10\\n\"\n");
        } else {
            sb.append("        \"movq  %%rbp, %%rsp\\n\"\n");
            sb.append("        \"popq  %%rbp\\n\"\n");
            sb.append("        \"movq  16(%%rsp), %%r10\\n\"\n");
            sb.append("        \"movq  (%%rbp), %%rbp\\n\"\n");
            sb.append("        \"movq  %%r13, %%rsp\\n\"\n");
            sb.append("        \"jmp   *%%r10\\n\"\n");
        }
        sb.append("        :\n        :\n        : \"memory\"\n");
        sb.append("    );\n}\n\n");
        return sb.toString();
    }

    /**
     * c2i adapter for Windows x64. Compiled callers deliver:
     *   rbx = Method*
     *   rcx/rdx/r8/r9 = JIT GP args (rcx = receiver for instance, else rcx = first)
     *   xmm0..xmm3 = JIT FP args
     *   [rbp + 16 + i*8] = stack-spilled args (each FP arg also reserves a GP shadow slot)
     *   (rsp) = JIT return PC
     *
     * Same shape as SysV c2i: spill ref args (and receiver) to stable stack slots
     * and pass slot addresses to the dispatcher while JavaThread remains in Java.
     */
    private String renderC2i(int sigId, SignaturePlan.Shape shape) {
        StringBuilder sb = new StringBuilder();
        char ret = shape.returnKind();
        char[] args = shape.argKinds();
        boolean isStatic = shape.isStatic();

        int dispatcherGpUsed = 2 + (isStatic ? 0 : 1); // entry, thread, receiver
        int dispatcherXmmUsed = 0;
        int dispatcherStackSlots = 0;
        for (char a : args) {
            if (a == 'F' || a == 'D') {
                if (dispatcherGpUsed < 4 && dispatcherXmmUsed < 4) {
                    dispatcherGpUsed++;
                    dispatcherXmmUsed++;
                } else {
                    dispatcherStackSlots++;
                }
            } else if (dispatcherGpUsed < 4) {
                dispatcherGpUsed++;
            } else {
                dispatcherStackSlots++;
            }
        }

        int refCount = isStatic ? 0 : 1;
        for (char a : args) if (a == 'L') refCount++;
        // Windows ABI: caller reserves 32-byte shadow space for callee.
        int outgoingStackBytes = Math.max(32, 32 + dispatcherStackSlots * 8);
        int localBase = outgoingStackBytes;
        int refBase = localBase;
        int entryOffset = refBase + refCount * 8;
        int gpSaveBase = entryOffset + 8;
        int localBytes = gpSaveBase + 32; // 4 GP regs only on Win
        int frameBytes = ((localBytes + 32 + 15) & ~15);

        sb.append("/* sig ").append(sigId).append(" c2i (Win x64, ").append(isStatic ? "static" : "instance")
          .append(", args=\"");
        for (char a : args) sb.append(a);
        sb.append("\", ret=").append(ret).append(", refCount=").append(refCount).append(") */\n");
        sb.append("__attribute__((naked, used, visibility(\"hidden\")))\n");
        sb.append("void neko_sig_").append(sigId).append("_c2i(void) {\n");
        sb.append("    __asm__ volatile (\n");
        sb.append("        \"pushq %%rbp\\n\"\n");
        sb.append("        \"movq  %%rsp, %%rbp\\n\"\n");
        sb.append("        \"pushq %%rbx\\n\"\n");
        // Save rsi, rdi too — they're callee-saved on Windows (unlike SysV).
        sb.append("        \"pushq %%rsi\\n\"\n");
        sb.append("        \"pushq %%rdi\\n\"\n");
        sb.append("        \"subq  $").append(frameBytes).append(", %%rsp\\n\"\n");
        sb.append("        \"andq  $-16, %%rsp\\n\"\n");

        // Save all 4 compiled-call GP arg regs to stable slots.
        for (int i = 0; i < 4; i++) {
            sb.append("        \"movq  %").append(winGpReg(i)).append(", ")
                .append(gpSaveBase + i * 8).append("(%%rsp)\\n\"\n");
        }

        int spillIndex = 0;
        if (!isStatic) {
            sb.append("        \"movq  ").append(gpSaveBase).append("(%%rsp), %%rax\\n\"\n");
            sb.append("        \"movq  %%rax, ").append(refBase + spillIndex * 8).append("(%%rsp)\\n\"\n");
            spillIndex++;
        }
        int gpSrc = isStatic ? 0 : 1;
        int xmmSrc = 0;
        int stackSrc = 0;
        int[] jitGpReg = new int[args.length];
        int[] jitXmmReg = new int[args.length];
        int[] jitStackOff = new int[args.length];
        java.util.Arrays.fill(jitGpReg, -1);
        java.util.Arrays.fill(jitXmmReg, -1);
        java.util.Arrays.fill(jitStackOff, -1);
        for (int i = 0; i < args.length; i++) {
            char a = args[i];
            if (a == 'F' || a == 'D') {
                if (gpSrc < 4 && xmmSrc < 4) {
                    jitXmmReg[i] = xmmSrc++;
                    gpSrc++; // shadow GP slot also consumed
                } else {
                    jitStackOff[i] = 16 + stackSrc * 8;
                    stackSrc++;
                }
            } else {
                if (gpSrc < 4) {
                    jitGpReg[i] = gpSrc++;
                } else {
                    jitStackOff[i] = 16 + stackSrc * 8;
                    stackSrc++;
                }
            }
        }
        int[] argSpillSlot = new int[args.length];
        java.util.Arrays.fill(argSpillSlot, -1);
        for (int i = 0; i < args.length; i++) {
            if (args[i] != 'L') continue;
            argSpillSlot[i] = spillIndex;
            int dst = refBase + spillIndex * 8;
            if (jitGpReg[i] >= 0) {
                sb.append("        \"movq  ").append(gpSaveBase + jitGpReg[i] * 8)
                    .append("(%%rsp), %%rax\\n\"\n");
                sb.append("        \"movq  %%rax, ").append(dst).append("(%%rsp)\\n\"\n");
            } else {
                sb.append("        \"movq  ").append(jitStackOff[i]).append("(%%rbp), %%rax\\n\"\n");
                sb.append("        \"movq  %%rax, ").append(dst).append("(%%rsp)\\n\"\n");
            }
            spillIndex++;
        }

        // Manifest scan
        sb.append("        \"leaq  g_neko_manifest_method_stars(%%rip), %%r10\\n\"\n");
        sb.append("        \"movl  g_neko_manifest_method_count(%%rip), %%r11d\\n\"\n");
        sb.append("        \"xorl  %%eax, %%eax\\n\"\n");
        sb.append("        \"1:\\n\"\n");
        sb.append("        \"cmpl  %%r11d, %%eax\\n\"\n");
        sb.append("        \"jge   3f\\n\"\n");
        sb.append("        \"cmpq  %%rbx, (%%r10, %%rax, 8)\\n\"\n");
        sb.append("        \"je    2f\\n\"\n");
        sb.append("        \"incl  %%eax\\n\"\n");
        sb.append("        \"jmp   1b\\n\"\n");
        sb.append("        \"3:\\n\"\n");
        sb.append("        \"leaq  g_neko_manifest_alias_method_stars(%%rip), %%r10\\n\"\n");
        sb.append("        \"movl  g_neko_manifest_alias_count(%%rip), %%r11d\\n\"\n");
        sb.append("        \"xorl  %%eax, %%eax\\n\"\n");
        sb.append("        \".Lneko_w_c2i_alias_loop_%=:\\n\"\n");
        sb.append("        \"cmpl  %%r11d, %%eax\\n\"\n");
        sb.append("        \"jge   .Lneko_w_c2i_miss_%=\\n\"\n");
        sb.append("        \"cmpq  %%rbx, (%%r10, %%rax, 8)\\n\"\n");
        sb.append("        \"je    .Lneko_w_c2i_alias_hit_%=\\n\"\n");
        sb.append("        \"incl  %%eax\\n\"\n");
        sb.append("        \"jmp   .Lneko_w_c2i_alias_loop_%=\\n\"\n");
        sb.append("        \".Lneko_w_c2i_alias_hit_%=:\\n\"\n");
        sb.append("        \"leaq  g_neko_manifest_alias_indices(%%rip), %%r10\\n\"\n");
        sb.append("        \"movl  (%%r10, %%rax, 4), %%eax\\n\"\n");
        sb.append("        \"jmp   2f\\n\"\n");
        sb.append("        \".Lneko_w_c2i_miss_%=:\\n\"\n");
        sb.append("        \"xorl  %%eax, %%eax\\n\"\n");
        sb.append("        \"pxor  %%xmm0, %%xmm0\\n\"\n");
        sb.append("        \"jmp   9f\\n\"\n");
        sb.append("        \"2:\\n\"\n");
        sb.append("        \"leaq  g_neko_manifest_methods(%%rip), %%r10\\n\"\n");
        sb.append("        \"imulq $").append(PatcherLayoutConstants.MANIFEST_METHOD_SIZE)
          .append(", %%rax, %%r11\\n\"\n");
        sb.append("        \"addq  %%r11, %%r10\\n\"\n");
        sb.append("        \"movq  %%r10, ").append(entryOffset).append("(%%rsp)\\n\"\n");

        // Build dispatcher arg list (Windows ABI: rcx, rdx, r8, r9, then stack starting at [rsp+32]).
        sb.append("        \"movq  %%r15, %%rdx\\n\"\n");
        int dispGpUsed = 2; // rcx, rdx taken
        int dispXmmUsed = 0;
        int dispStackSlots = 0;
        if (!isStatic) {
            sb.append("        \"leaq  ").append(refBase).append("(%%rsp), %%r8\\n\"\n");
            dispGpUsed++;
        }
        for (int i = 0; i < args.length; i++) {
            char a = args[i];
            if (a == 'L') {
                int srcOff = refBase + argSpillSlot[i] * 8;
                if (dispGpUsed < 4) {
                    sb.append("        \"leaq  ").append(srcOff).append("(%%rsp), %").append(winGpReg(dispGpUsed)).append("\\n\"\n");
                    dispGpUsed++;
                } else {
                    sb.append("        \"leaq  ").append(srcOff).append("(%%rsp), %%rax\\n\"\n");
                    sb.append("        \"movq  %%rax, ").append(32 + dispStackSlots * 8).append("(%%rsp)\\n\"\n");
                    dispStackSlots++;
                }
            } else if (a == 'F' || a == 'D') {
                if (dispGpUsed < 4 && dispXmmUsed < 4) {
                    if (jitXmmReg[i] >= 0 && jitXmmReg[i] != dispXmmUsed) {
                        if (a == 'F') sb.append("        \"movss %%xmm").append(jitXmmReg[i]).append(", %%xmm").append(dispXmmUsed).append("\\n\"\n");
                        else sb.append("        \"movsd %%xmm").append(jitXmmReg[i]).append(", %%xmm").append(dispXmmUsed).append("\\n\"\n");
                    } else if (jitXmmReg[i] < 0) {
                        if (a == 'F') sb.append("        \"movss ").append(jitStackOff[i]).append("(%%rbp), %%xmm").append(dispXmmUsed).append("\\n\"\n");
                        else sb.append("        \"movsd ").append(jitStackOff[i]).append("(%%rbp), %%xmm").append(dispXmmUsed).append("\\n\"\n");
                    }
                    dispXmmUsed++;
                    dispGpUsed++;
                } else {
                    if (jitXmmReg[i] >= 0) {
                        sb.append("        \"movq  %%xmm").append(jitXmmReg[i]).append(", ").append(32 + dispStackSlots * 8).append("(%%rsp)\\n\"\n");
                    } else {
                        sb.append("        \"movq  ").append(jitStackOff[i]).append("(%%rbp), %%rax\\n\"\n");
                        sb.append("        \"movq  %%rax, ").append(32 + dispStackSlots * 8).append("(%%rsp)\\n\"\n");
                    }
                    dispStackSlots++;
                }
            } else {
                if (dispGpUsed < 4) {
                    if (jitGpReg[i] >= 0) {
                        sb.append("        \"movq  ").append(gpSaveBase + jitGpReg[i] * 8)
                            .append("(%%rsp), %").append(winGpReg(dispGpUsed)).append("\\n\"\n");
                    } else {
                        sb.append("        \"movq  ").append(jitStackOff[i]).append("(%%rbp), %").append(winGpReg(dispGpUsed)).append("\\n\"\n");
                    }
                    dispGpUsed++;
                } else {
                    if (jitGpReg[i] >= 0) {
                        sb.append("        \"movq  ").append(gpSaveBase + jitGpReg[i] * 8)
                            .append("(%%rsp), %%rax\\n\"\n");
                        sb.append("        \"movq  %%rax, ").append(32 + dispStackSlots * 8).append("(%%rsp)\\n\"\n");
                    } else {
                        sb.append("        \"movq  ").append(jitStackOff[i]).append("(%%rbp), %%rax\\n\"\n");
                        sb.append("        \"movq  %%rax, ").append(32 + dispStackSlots * 8).append("(%%rsp)\\n\"\n");
                    }
                    dispStackSlots++;
                }
            }
        }
        // Finally load rcx = entry.
        sb.append("        \"movq  ").append(entryOffset).append("(%%rsp), %%rcx\\n\"\n");

        sb.append("        \"call  neko_sig_").append(sigId).append("_dispatch\\n\"\n");
        sb.append("        \"9:\\n\"\n");
        // Restore stack and ret. Pop callee-saved regs we pushed.
        sb.append("        \"movq  %%rbp, %%rsp\\n\"\n");
        sb.append("        \"subq  $24, %%rsp\\n\"\n");
        sb.append("        \"popq  %%rdi\\n\"\n");
        sb.append("        \"popq  %%rsi\\n\"\n");
        sb.append("        \"popq  %%rbx\\n\"\n");
        sb.append("        \"popq  %%rbp\\n\"\n");
        sb.append("        \"ret\\n\"\n");
        sb.append("        :\n        :\n        : \"memory\"\n");
        sb.append("    );\n}\n\n");
        return sb.toString();
    }

    private String gpReg(int idx) {
        return switch (idx) {
            case 0 -> "%rcx";
            case 1 -> "%rdx";
            case 2 -> "%r8";
            case 3 -> "%r9";
            default -> throw new IllegalStateException("Win x64 GP regs exhausted: " + idx);
        };
    }

    private String winGpReg(int idx) {
        return gpReg(idx);
    }
}

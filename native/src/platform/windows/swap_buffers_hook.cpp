#include "himitsu/platform/windows/swap_buffers_hook.hpp"

#include "himitsu/core/native_log.hpp"
#include "himitsu/jvm/class_control.hpp"
#include "himitsu/platform/windows/directx_overlay_assets.hpp"
#include "himitsu/platform/windows/module_guard.hpp"
#include "himitsu/platform/windows/thread_guard.hpp"
#include "himitsu/core/runtime_state.hpp"

#include <windows.h>
#include <tlhelp32.h>
#include <GL/gl.h>
#include <d3d9.h>
#include <d3d11.h>
#include <d3d11_1.h>
#include <dxgi.h>
#include <MinHook.h>

#include <atomic>
#include <algorithm>
#include <array>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

namespace {
constexpr jint stage_gdi_swap = 1;
constexpr jint stage_glfw_swap = 2;
constexpr jint stage_wgl_layer_swap = 3;
constexpr jint stage_framebuffer_bind = 4;
constexpr jint stage_framebuffer_blit = 5;
constexpr jint stage_ntgdi_swap = 6;
constexpr jint stage_front_overlay = 7;
constexpr jint stage_d3d9_present = 8;
constexpr jint stage_dxgi_present = 9;

constexpr GLenum gl_framebuffer = 0x8D40;
constexpr GLenum gl_draw_framebuffer = 0x8CA9;
constexpr GLenum gl_draw_framebuffer_binding = 0x8CA6;

using SwapBuffersFunction = BOOL(WINAPI*)(HDC);
using GlfwSwapBuffersFunction = void(__cdecl*)(void*);
using WglSwapLayerBuffersFunction = BOOL(WINAPI*)(HDC, UINT);
using NtGdiSwapBuffersFunction = BOOL(WINAPI*)(HDC);
using WglGetProcAddressFunction = PROC(WINAPI*)(LPCSTR);
using D3D9PresentFunction = HRESULT(WINAPI*)(
    IDirect3DDevice9*, const RECT*, const RECT*, HWND, const RGNDATA*
);
using DxgiPresentFunction = HRESULT(WINAPI*)(IDXGISwapChain*, UINT, UINT);
using GlBindFramebufferFunction = void(APIENTRY*)(GLenum, GLuint);
using GlBlitFramebufferFunction = void(APIENTRY*)(
    GLint, GLint, GLint, GLint, GLint, GLint, GLint, GLint, GLbitfield, GLenum
);

struct ImportPatch {
    void** slot;
    void* original;
    void* replacement;
    std::uint64_t guard_token = 0;
    void* allocation = nullptr;
};

struct InlineHook {
    const char* name = nullptr;
    void* target = nullptr;
    void* trampoline = nullptr;
    bool active = false;
    std::uint64_t target_guard = 0;
};

SRWLOCK hook_lock = SRWLOCK_INIT;
std::vector<ImportPatch> import_patches;
InlineHook gdi_inline{"gdi32!SwapBuffers"};
InlineHook glfw_inline{"GLFW!glfwSwapBuffers"};
InlineHook wgl_layer_inline{"opengl32!wglSwapLayerBuffers"};
InlineHook ntgdi_inline{"win32u!NtGdiSwapBuffers"};
InlineHook wgl_get_proc_inline{"opengl32!wglGetProcAddress"};
InlineHook bind_framebuffer_inline{"OpenGL!glBindFramebuffer"};
InlineHook blit_framebuffer_inline{"OpenGL!glBlitFramebuffer"};
InlineHook bind_framebuffer_ext_inline{"OpenGL!glBindFramebufferEXT"};
InlineHook blit_framebuffer_ext_inline{"OpenGL!glBlitFramebufferEXT"};
InlineHook d3d9_present_inline{"Direct3D9!Present"};
InlineHook dxgi_present_inline{"DXGI!Present"};

SwapBuffersFunction original_swap_buffers = nullptr;
GlfwSwapBuffersFunction original_glfw_swap_buffers = nullptr;
WglSwapLayerBuffersFunction original_wgl_swap_layer_buffers = nullptr;
NtGdiSwapBuffersFunction original_ntgdi_swap_buffers = nullptr;
WglGetProcAddressFunction original_wgl_get_proc_address = nullptr;
GlBindFramebufferFunction original_gl_bind_framebuffer = nullptr;
GlBlitFramebufferFunction original_gl_blit_framebuffer = nullptr;
GlBindFramebufferFunction original_gl_bind_framebuffer_ext = nullptr;
GlBlitFramebufferFunction original_gl_blit_framebuffer_ext = nullptr;
D3D9PresentFunction original_d3d9_present = nullptr;
DxgiPresentFunction original_dxgi_present = nullptr;

HMODULE self_module = nullptr;
std::atomic<bool> context_hooks_ready{false};
std::atomic_flag context_installing = ATOMIC_FLAG_INIT;
thread_local unsigned int swap_depth = 0;
thread_local bool inside_gl_callback = false;
thread_local GLuint draw_framebuffer = 0;
bool minhook_initialized = false;
std::atomic<bool> hook_maintenance_enabled{false};
std::atomic<ULONGLONG> last_hook_maintenance{0};
std::atomic<ULONGLONG> last_directx_probe{0};

struct EntityRectangle {
    LONG left;
    LONG top;
    LONG right;
    LONG bottom;
    D3DCOLOR color;
};

SRWLOCK directx_overlay_lifecycle_lock = SRWLOCK_INIT;
std::atomic<HWND> directx_target_window{nullptr};
std::atomic<bool> directx_overlay_stop{false};
std::atomic<HANDLE> directx_overlay_thread{nullptr};
std::atomic<HWND> directx_overlay_window{nullptr};
std::atomic<IDirect3DDevice9*> directx_overlay_device{nullptr};

class HookLock {
public:
    HookLock() { AcquireSRWLockExclusive(&hook_lock); }
    ~HookLock() { ReleaseSRWLockExclusive(&hook_lock); }
    HookLock(const HookLock&) = delete;
    HookLock& operator=(const HookLock&) = delete;
};

void observe_directx_target(HDC device_context);
void observe_directx_process_target();
void ensure_directx_overlay();
bool stop_directx_overlay(std::uint64_t deadline);

bool install_inline_hook(InlineHook& hook, void* target, void* replacement, void** original) {
    if (hook.active) {
        if (original != nullptr) *original = hook.trampoline;
        return true;
    }
    if (target == nullptr || replacement == nullptr || target == replacement) return false;

    if (!minhook_initialized) return false;
    void* trampoline=hook.trampoline;
    if(trampoline && hook.target!=target) return false;
    if(!trampoline) {
        if(MH_CreateHook(target,replacement,&trampoline)!=MH_OK) return false;
        hook.target=target;hook.trampoline=trampoline;
    }
    if(original) *original=trampoline;
    if(!himitsu::platform::windows::guarded_hook_intact(target))return false;
    MH_STATUS enable_status;
    { himitsu::platform::windows::ThreadHookMaintenance scope; enable_status=MH_EnableHook(target); }
    if(enable_status!=MH_OK && enable_status!=MH_ERROR_ENABLED) return false;
    hook.active = true;
    const std::string base_name = hook.name == nullptr ? "原生渲染入口" : hook.name;
    hook.target_guard = himitsu::platform::windows::register_guarded_hook(base_name.c_str(),target);
    if(!hook.target_guard)return false;
    if (original != nullptr) *original = trampoline;
    return true;
}

bool uninstall_inline_hook(InlineHook& hook,std::uint64_t deadline) {
    if(!hook.active || !hook.target) return true;
    if(!himitsu::platform::windows::guarded_hook_intact(hook.target)
        || !himitsu::platform::windows::unregister_guarded_region(hook.target_guard,deadline))return false;
    MH_STATUS status;
    { himitsu::platform::windows::ThreadHookMaintenance scope;status=MH_DisableHook(hook.target); }
    if(status!=MH_OK && status!=MH_ERROR_DISABLED) return false;
    hook.active=false; // Retain the trampoline and original function for in-flight detours.
    return true;
}
struct NativeDraw {
    bool entered=himitsu::core::RuntimeState::instance().enter_call();
    ~NativeDraw() {if(entered) himitsu::core::RuntimeState::instance().leave_call();}
};

bool valid_gl_address(PROC address) {
    const auto value = reinterpret_cast<std::uintptr_t>(address);
    return address != nullptr && value > 4 && value != static_cast<std::uintptr_t>(-1);
}

class RenderCallbackScope {
public:
    RenderCallbackScope() : entered_(!inside_gl_callback) {
        if (entered_) inside_gl_callback = true;
    }
    ~RenderCallbackScope() {
        if (entered_) inside_gl_callback = false;
    }
    explicit operator bool() const { return entered_; }

private:
    bool entered_;
};

bool invoke_layer(bool before, jint stage, jlong context) {
    const RenderCallbackScope scope;
    if (!scope) return true;
    return himitsu::jvm::invoke_render_callback(before, stage, context);
}

void dispatch_layer(jint stage, jlong context) {
    invoke_layer(true, stage, context);
}

void after_bind_framebuffer(GLenum target, GLuint framebuffer) {
    if (target == gl_framebuffer || target == gl_draw_framebuffer) {
        draw_framebuffer = framebuffer;
        if (framebuffer == 0) dispatch_layer(stage_framebuffer_bind, static_cast<jlong>(framebuffer));
    }
}

void APIENTRY hooked_gl_bind_framebuffer(GLenum target, GLuint framebuffer) {
    if (original_gl_bind_framebuffer == nullptr) return;
    original_gl_bind_framebuffer(target, framebuffer);
    after_bind_framebuffer(target, framebuffer);
}

void APIENTRY hooked_gl_bind_framebuffer_ext(GLenum target, GLuint framebuffer) {
    if (original_gl_bind_framebuffer_ext == nullptr) return;
    original_gl_bind_framebuffer_ext(target, framebuffer);
    after_bind_framebuffer(target, framebuffer);
}

void after_blit_framebuffer(GLbitfield mask) {
    if ((mask & GL_COLOR_BUFFER_BIT) != 0 && draw_framebuffer == 0) {
        dispatch_layer(stage_framebuffer_blit, static_cast<jlong>(draw_framebuffer));
    }
}

void call_blit_framebuffer(
    GlBlitFramebufferFunction function,
    GLint source_x0,
    GLint source_y0,
    GLint source_x1,
    GLint source_y1,
    GLint target_x0,
    GLint target_y0,
    GLint target_x1,
    GLint target_y1,
    GLbitfield mask,
    GLenum filter
) {
    if (function == nullptr) return;
    function(
        source_x0, source_y0, source_x1, source_y1,
        target_x0, target_y0, target_x1, target_y1,
        mask, filter
    );
    after_blit_framebuffer(mask);
}

void APIENTRY hooked_gl_blit_framebuffer(
    GLint source_x0, GLint source_y0, GLint source_x1, GLint source_y1,
    GLint target_x0, GLint target_y0, GLint target_x1, GLint target_y1,
    GLbitfield mask, GLenum filter
) {
    call_blit_framebuffer(
        original_gl_blit_framebuffer,
        source_x0, source_y0, source_x1, source_y1,
        target_x0, target_y0, target_x1, target_y1, mask, filter
    );
}

void APIENTRY hooked_gl_blit_framebuffer_ext(
    GLint source_x0, GLint source_y0, GLint source_x1, GLint source_y1,
    GLint target_x0, GLint target_y0, GLint target_x1, GLint target_y1,
    GLbitfield mask, GLenum filter
) {
    call_blit_framebuffer(
        original_gl_blit_framebuffer_ext,
        source_x0, source_y0, source_x1, source_y1,
        target_x0, target_y0, target_x1, target_y1, mask, filter
    );
}

PROC WINAPI hooked_wgl_get_proc_address(LPCSTR name) {
    NativeDraw call; if(!call.entered) {return original_wgl_get_proc_address?original_wgl_get_proc_address(name):nullptr;}
    if (original_wgl_get_proc_address == nullptr) return nullptr;
    PROC result = original_wgl_get_proc_address(name);
    if (name == nullptr || !valid_gl_address(result)) return result;
    if (std::strcmp(name, "glBindFramebuffer") == 0) {
        if (original_gl_bind_framebuffer == nullptr) {
            original_gl_bind_framebuffer = reinterpret_cast<GlBindFramebufferFunction>(result);
        }
        return reinterpret_cast<PROC>(&hooked_gl_bind_framebuffer);
    }
    if (std::strcmp(name, "glBindFramebufferEXT") == 0) {
        if (bind_framebuffer_inline.active
            && reinterpret_cast<void*>(result) == bind_framebuffer_inline.target) {
            return reinterpret_cast<PROC>(&hooked_gl_bind_framebuffer);
        }
        if (original_gl_bind_framebuffer_ext == nullptr) {
            original_gl_bind_framebuffer_ext = reinterpret_cast<GlBindFramebufferFunction>(result);
        }
        return reinterpret_cast<PROC>(&hooked_gl_bind_framebuffer_ext);
    }
    if (std::strcmp(name, "glBlitFramebuffer") == 0) {
        if (original_gl_blit_framebuffer == nullptr) {
            original_gl_blit_framebuffer = reinterpret_cast<GlBlitFramebufferFunction>(result);
        }
        return reinterpret_cast<PROC>(&hooked_gl_blit_framebuffer);
    }
    if (std::strcmp(name, "glBlitFramebufferEXT") == 0) {
        if (blit_framebuffer_inline.active
            && reinterpret_cast<void*>(result) == blit_framebuffer_inline.target) {
            return reinterpret_cast<PROC>(&hooked_gl_blit_framebuffer);
        }
        if (original_gl_blit_framebuffer_ext == nullptr) {
            original_gl_blit_framebuffer_ext = reinterpret_cast<GlBlitFramebufferFunction>(result);
        }
        return reinterpret_cast<PROC>(&hooked_gl_blit_framebuffer_ext);
    }
    return result;
}

PROC resolve_gl_proc_address(LPCSTR name) {
    if (original_wgl_get_proc_address != nullptr) {
        return original_wgl_get_proc_address(name);
    }
    return wglGetProcAddress(name);
}

void ensure_context_hooks() {
    if (context_hooks_ready.load(std::memory_order_acquire) || wglGetCurrentContext() == nullptr) return;
    if (context_installing.test_and_set(std::memory_order_acquire)) return;

    PROC bind_address = resolve_gl_proc_address("glBindFramebuffer");
    PROC blit_address = resolve_gl_proc_address("glBlitFramebuffer");
    PROC bind_ext_address = resolve_gl_proc_address("glBindFramebufferEXT");
    PROC blit_ext_address = resolve_gl_proc_address("glBlitFramebufferEXT");
    bool bind_installed = false;
    bool blit_installed = false;
    bool bind_ext_installed = false;
    bool blit_ext_installed = false;
    {
        HookLock lock;
        if (valid_gl_address(bind_address)) {
            bind_installed = install_inline_hook(
                bind_framebuffer_inline,
                reinterpret_cast<void*>(bind_address),
                reinterpret_cast<void*>(&hooked_gl_bind_framebuffer),
                reinterpret_cast<void**>(&original_gl_bind_framebuffer)
            );
        }
        if (valid_gl_address(blit_address)) {
            blit_installed = install_inline_hook(
                blit_framebuffer_inline,
                reinterpret_cast<void*>(blit_address),
                reinterpret_cast<void*>(&hooked_gl_blit_framebuffer),
                reinterpret_cast<void**>(&original_gl_blit_framebuffer)
            );
        }
        if (valid_gl_address(bind_ext_address) && bind_ext_address != bind_address) {
            bind_ext_installed = install_inline_hook(
                bind_framebuffer_ext_inline,
                reinterpret_cast<void*>(bind_ext_address),
                reinterpret_cast<void*>(&hooked_gl_bind_framebuffer_ext),
                reinterpret_cast<void**>(&original_gl_bind_framebuffer_ext)
            );
        }
        if (valid_gl_address(blit_ext_address) && blit_ext_address != blit_address) {
            blit_ext_installed = install_inline_hook(
                blit_framebuffer_ext_inline,
                reinterpret_cast<void*>(blit_ext_address),
                reinterpret_cast<void*>(&hooked_gl_blit_framebuffer_ext),
                reinterpret_cast<void**>(&original_gl_blit_framebuffer_ext)
            );
        }
    }
    context_hooks_ready.store(true, std::memory_order_release);
    context_installing.clear(std::memory_order_release);
    if (bind_installed || blit_installed || bind_ext_installed || blit_ext_installed) {
        HIMITSU_LOG_INFO(
            "Render",
            "OpenGL 帧缓冲渲染层安装完成（Bind=%s，Blit=%s，BindEXT=%s，BlitEXT=%s）",
            bind_installed ? "是" : "否",
            blit_installed ? "是" : "否",
            bind_ext_installed ? "是" : "否",
            blit_ext_installed ? "是" : "否"
        );
    } else {
        HIMITSU_LOG_WARNING("Render", "OpenGL 帧缓冲渲染层未找到可用入口，交换缓冲层继续工作");
    }
}

void render_front_overlay(jlong context) {
    if (!invoke_layer(false, stage_front_overlay, context)) return;
    if (wglGetCurrentContext() == nullptr) return;
    GLint framebuffer = 0;
    glGetIntegerv(gl_draw_framebuffer_binding, &framebuffer);
    if (framebuffer != 0) return;
    GLint previous = GL_BACK;
    glGetIntegerv(GL_DRAW_BUFFER, &previous);
    glDrawBuffer(GL_FRONT);
    dispatch_layer(stage_front_overlay, context);
    glFlush();
    glDrawBuffer(static_cast<GLenum>(previous));
}

BOOL WINAPI hooked_swap_buffers(HDC device_context) {
    NativeDraw call; if(!call.entered) {return original_swap_buffers?original_swap_buffers(device_context):FALSE;}
    observe_directx_target(device_context);
    const bool outermost = swap_depth++ == 0;
    if (outermost) {
        ensure_context_hooks();
    }
    const bool allow_swap = !outermost || invoke_layer(
        true, stage_gdi_swap, reinterpret_cast<jlong>(device_context)
    );
    const BOOL result = allow_swap && original_swap_buffers != nullptr
        ? original_swap_buffers(device_context)
        : TRUE;
    if (outermost && result != FALSE) {
        render_front_overlay(reinterpret_cast<jlong>(device_context));
    }
    if (outermost) {
        invoke_layer(
            false, stage_gdi_swap, reinterpret_cast<jlong>(device_context)
        );
    }
    --swap_depth;
    return result;
}

void __cdecl hooked_glfw_swap_buffers(void* window) {
    NativeDraw call; if(!call.entered) {if(original_glfw_swap_buffers) original_glfw_swap_buffers(window);return;}
    observe_directx_process_target();
    const bool outermost = swap_depth++ == 0;
    if (outermost) {
        ensure_context_hooks();
    }
    const bool allow_swap = !outermost || invoke_layer(
        true, stage_glfw_swap, reinterpret_cast<jlong>(window)
    );
    if (allow_swap && original_glfw_swap_buffers != nullptr) original_glfw_swap_buffers(window);
    if (outermost) {
        render_front_overlay(reinterpret_cast<jlong>(window));
        invoke_layer(
            false, stage_glfw_swap, reinterpret_cast<jlong>(window)
        );
    }
    --swap_depth;
}

BOOL WINAPI hooked_wgl_swap_layer_buffers(HDC device_context, UINT planes) {
    NativeDraw call; if(!call.entered) {return original_wgl_swap_layer_buffers?original_wgl_swap_layer_buffers(device_context,planes):FALSE;}
    observe_directx_target(device_context);
    const bool outermost = swap_depth++ == 0;
    if (outermost) {
        ensure_context_hooks();
    }
    const bool allow_swap = !outermost || invoke_layer(
        true, stage_wgl_layer_swap, reinterpret_cast<jlong>(device_context)
    );
    const BOOL result = allow_swap && original_wgl_swap_layer_buffers != nullptr
        ? original_wgl_swap_layer_buffers(device_context, planes)
        : TRUE;
    if (outermost && result != FALSE) {
        render_front_overlay(reinterpret_cast<jlong>(device_context));
    }
    if (outermost) {
        invoke_layer(
            false, stage_wgl_layer_swap, reinterpret_cast<jlong>(device_context)
        );
    }
    --swap_depth;
    return result;
}

BOOL WINAPI hooked_ntgdi_swap_buffers(HDC device_context) {
    NativeDraw call; if(!call.entered) {return original_ntgdi_swap_buffers?original_ntgdi_swap_buffers(device_context):FALSE;}
    observe_directx_target(device_context);
    const bool outermost = swap_depth++ == 0;
    if (outermost) {
        ensure_context_hooks();
    }
    const bool allow_swap = !outermost || invoke_layer(
        true, stage_ntgdi_swap, reinterpret_cast<jlong>(device_context)
    );
    const BOOL result = allow_swap && original_ntgdi_swap_buffers != nullptr
        ? original_ntgdi_swap_buffers(device_context)
        : TRUE;
    if (outermost && result != FALSE) {
        render_front_overlay(reinterpret_cast<jlong>(device_context));
    }
    if (outermost) {
        invoke_layer(
            false, stage_ntgdi_swap, reinterpret_cast<jlong>(device_context)
        );
    }
    --swap_depth;
    return result;
}

void render_d3d9_death_layer(IDirect3DDevice9* device) {
    if (device == nullptr) return;
    D3DVIEWPORT9 viewport{};
    if (FAILED(device->GetViewport(&viewport)) || viewport.Width == 0 || viewport.Height == 0) return;
    const DWORD pulse = static_cast<DWORD>((GetTickCount64() / 70ULL) & 0x1FU);
    device->Clear(
        0,
        nullptr,
        D3DCLEAR_TARGET,
        D3DCOLOR_ARGB(255, 3 + pulse / 10, 1, 8 + pulse / 2),
        1.0F,
        0
    );
    const LONG width = static_cast<LONG>(viewport.Width);
    const LONG height = static_cast<LONG>(viewport.Height);
    const LONG center = height / 2;
    const std::array<EntityRectangle, 3> bands{{
        {0, center - 44, width, center + 44, D3DCOLOR_ARGB(255, 8, 1, 13)},
        {0, center - 46, width, center - 42, D3DCOLOR_ARGB(255, 91, 22, 125)},
        {0, center + 42, width, center + 46, D3DCOLOR_ARGB(255, 36, 0, 51)}
    }};
    for (const EntityRectangle& rectangle : bands) {
        D3DRECT area{rectangle.left, rectangle.top, rectangle.right, rectangle.bottom};
        device->Clear(1, &area, D3DCLEAR_TARGET, rectangle.color, 1.0F, 0);
    }
    std::uint64_t noise = (GetTickCount64() / 70ULL) * 0x9E3779B97F4A7C15ULL;
    for (int index = 0; index < 20; ++index) {
        noise ^= noise << 13U;
        noise ^= noise >> 7U;
        noise ^= noise << 17U;
        const LONG x = static_cast<LONG>(noise % static_cast<std::uint64_t>(std::max(1L, width)));
        const LONG y = static_cast<LONG>((noise >> 24U) % static_cast<std::uint64_t>(std::max(1L, height)));
        const LONG strip_width = 8 + static_cast<LONG>((noise >> 40U) % static_cast<std::uint64_t>(std::max(9L, width / 4)));
        const LONG strip_height = 1 + static_cast<LONG>((noise >> 57U) & 3ULL);
        D3DRECT strip{x, y, std::min(width, x + strip_width), std::min(height, y + strip_height)};
        const D3DCOLOR color = (index & 1) == 0
            ? D3DCOLOR_ARGB(255, 91, 22, 125)
            : D3DCOLOR_ARGB(255, 32, 0, 44);
        device->Clear(1, &strip, D3DCLEAR_TARGET, color, 1.0F, 0);
    }
    himitsu::platform::windows::directx_assets::draw_death_title(device, width, height);
}

void render_d3d9_death_overlay_layer(IDirect3DDevice9* device) {
    if (device == nullptr) return;
    D3DVIEWPORT9 viewport{};
    if (FAILED(device->GetViewport(&viewport)) || viewport.Width == 0 || viewport.Height == 0) return;
    const LONG width = static_cast<LONG>(viewport.Width);
    const LONG height = static_cast<LONG>(viewport.Height);
    const LONG center = height / 2;
    std::uint64_t noise = (GetTickCount64() / 70ULL) * 0x9E3779B97F4A7C15ULL;
    for (int index = 0; index < 16; ++index) {
        noise ^= noise << 13U;
        noise ^= noise >> 7U;
        noise ^= noise << 17U;
        const LONG x = static_cast<LONG>(noise % static_cast<std::uint64_t>(std::max(1L, width)));
        const LONG y = static_cast<LONG>((noise >> 24U) % static_cast<std::uint64_t>(std::max(1L, height)));
        if (std::abs(y - center) < 62) continue;
        const LONG strip_width = 8 + static_cast<LONG>((noise >> 40U) % static_cast<std::uint64_t>(std::max(9L, width / 4)));
        const LONG strip_height = 1 + static_cast<LONG>((noise >> 57U) & 3ULL);
        D3DRECT strip{x, y, std::min(width, x + strip_width), std::min(height, y + strip_height)};
        const D3DCOLOR color = (index & 1) == 0
            ? D3DCOLOR_ARGB(255, 91, 22, 125)
            : D3DCOLOR_ARGB(255, 32, 0, 44);
        device->Clear(1, &strip, D3DCLEAR_TARGET, color, 1.0F, 0);
    }
    himitsu::platform::windows::directx_assets::draw_death_title(device, width, height);
}

void draw_dxgi_image_runs(
    ID3D11DeviceContext1*, ID3D11RenderTargetView*,
    const himitsu::platform::windows::directx_assets::BgraImage&,
    unsigned int, unsigned int, unsigned int, unsigned int,
    float, float, float, float, LONG, LONG
);

void render_dxgi_death_layer(IDXGISwapChain* swap_chain) {
    if (swap_chain == nullptr) return;
    ID3D11Device* device = nullptr;
    if (FAILED(swap_chain->GetDevice(__uuidof(ID3D11Device), reinterpret_cast<void**>(&device)))
        || device == nullptr) return;
    ID3D11Texture2D* back_buffer = nullptr;
    ID3D11RenderTargetView* target = nullptr;
    ID3D11DeviceContext* context = nullptr;
    if (SUCCEEDED(swap_chain->GetBuffer(
            0,
            __uuidof(ID3D11Texture2D),
            reinterpret_cast<void**>(&back_buffer)
        )) && back_buffer != nullptr
        && SUCCEEDED(device->CreateRenderTargetView(back_buffer, nullptr, &target))
        && target != nullptr) {
        device->GetImmediateContext(&context);
        if (context != nullptr) {
            const float pulse = static_cast<float>((GetTickCount64() / 70ULL) & 0x1FU) / 255.0F;
            const float background[4]{0.012F + pulse * 0.08F, 0.004F, 0.03F + pulse, 1.0F};
            context->ClearRenderTargetView(target, background);
            ID3D11DeviceContext1* context1 = nullptr;
            if (SUCCEEDED(context->QueryInterface(
                    __uuidof(ID3D11DeviceContext1),
                    reinterpret_cast<void**>(&context1)
                )) && context1 != nullptr) {
                D3D11_TEXTURE2D_DESC description{};
                back_buffer->GetDesc(&description);
                const LONG width = static_cast<LONG>(description.Width);
                const LONG height = static_cast<LONG>(description.Height);
                const LONG center = height / 2;
                const std::array<D3D11_RECT, 3> bands{{
                    {0, center - 44, width, center + 44},
                    {0, center - 46, width, center - 42},
                    {0, center + 42, width, center + 46}
                }};
                const float colors[3][4]{
                    {0.03F, 0.004F, 0.05F, 1.0F},
                    {0.357F, 0.086F, 0.49F, 1.0F},
                    {0.141F, 0.0F, 0.20F, 1.0F}
                };
                for (std::size_t index = 0; index < bands.size(); ++index) {
                    context1->ClearView(target, colors[index], &bands[index], 1);
                }
                std::uint64_t noise = (GetTickCount64() / 70ULL) * 0x9E3779B97F4A7C15ULL;
                for (int index = 0; index < 20; ++index) {
                    noise ^= noise << 13U;
                    noise ^= noise >> 7U;
                    noise ^= noise << 17U;
                    const LONG x = static_cast<LONG>(noise % static_cast<std::uint64_t>(std::max(1L, width)));
                    const LONG y = static_cast<LONG>((noise >> 24U) % static_cast<std::uint64_t>(std::max(1L, height)));
                    const LONG strip_width = 8 + static_cast<LONG>((noise >> 40U) % static_cast<std::uint64_t>(std::max(9L, width / 4)));
                    const LONG strip_height = 1 + static_cast<LONG>((noise >> 57U) & 3ULL);
                    const D3D11_RECT strip{
                        x, y, std::min(width, x + strip_width), std::min(height, y + strip_height)
                    };
                    const float purple[4]{
                        (index & 1) == 0 ? 0.357F : 0.125F,
                        (index & 1) == 0 ? 0.086F : 0.0F,
                        (index & 1) == 0 ? 0.49F : 0.173F,
                        1.0F
                    };
                    context1->ClearView(target, purple, &strip, 1);
                }
                const auto title_image = himitsu::platform::windows::directx_assets::death_title_image();
                const float title_width = std::min(static_cast<float>(width) * 0.33F, 430.0F);
                const float title_height = title_width * static_cast<float>(title_image.height)
                    / static_cast<float>(title_image.width);
                draw_dxgi_image_runs(
                    context1,
                    target,
                    title_image,
                    0,
                    0,
                    title_image.width,
                    title_image.height,
                    (static_cast<float>(width) - title_width) * 0.5F,
                    static_cast<float>(height) * 0.5F - title_height * 0.5F - 18.0F,
                    title_width,
                    title_height,
                    width,
                    height
                );
                context1->Release();
            }
        }
    }
    if (context != nullptr) context->Release();
    if (target != nullptr) target->Release();
    if (back_buffer != nullptr) back_buffer->Release();
    device->Release();
}

void draw_dxgi_image_runs(
    ID3D11DeviceContext1* context,
    ID3D11RenderTargetView* target,
    const himitsu::platform::windows::directx_assets::BgraImage& image,
    unsigned int source_x,
    unsigned int source_y,
    unsigned int source_width,
    unsigned int source_height,
    float destination_x,
    float destination_y,
    float destination_width,
    float destination_height,
    LONG target_width,
    LONG target_height
) {
    if (context == nullptr || target == nullptr || image.pixels == nullptr
        || source_x + source_width > image.width || source_y + source_height > image.height) return;
    const float pixel_width = destination_width / static_cast<float>(source_width);
    const float pixel_height = destination_height / static_cast<float>(source_height);
    for (unsigned int row = 0; row < source_height; ++row) {
        int run_start = -1;
        std::uint32_t run_color = 0;
        for (unsigned int column = 0; column <= source_width; ++column) {
            std::uint32_t color = 0;
            if (column < source_width) {
                const std::size_t index = (
                    static_cast<std::size_t>(source_y + row) * image.width + source_x + column
                ) * 4U;
                const auto* pixel = image.pixels + index;
                if (pixel[3] > 8) {
                    color = 0xFF000000U
                        | (static_cast<std::uint32_t>(pixel[2]) << 16U)
                        | (static_cast<std::uint32_t>(pixel[1]) << 8U)
                        | pixel[0];
                }
            }
            if (color != 0 && run_start < 0) {
                run_start = static_cast<int>(column);
                run_color = color;
            }
            if ((color != run_color || color == 0) && run_start >= 0) {
                const LONG left = static_cast<LONG>(std::lround(destination_x + run_start * pixel_width));
                const LONG right = static_cast<LONG>(std::lround(destination_x + column * pixel_width));
                const LONG top = static_cast<LONG>(std::lround(destination_y + row * pixel_height));
                const LONG bottom = static_cast<LONG>(std::lround(destination_y + (row + 1U) * pixel_height));
                if (right > left && bottom > top) {
                    const D3D11_RECT area{
                        std::max(0L, left), std::max(0L, top),
                        std::min(target_width, right), std::min(target_height, bottom)
                    };
                    if (area.right > area.left && area.bottom > area.top) {
                        const float rgba[4]{
                            static_cast<float>((run_color >> 16U) & 0xFFU) / 255.0F,
                            static_cast<float>((run_color >> 8U) & 0xFFU) / 255.0F,
                            static_cast<float>(run_color & 0xFFU) / 255.0F,
                            1.0F
                        };
                        context->ClearView(target, rgba, &area, 1);
                    }
                }
                if (color != 0) {
                    run_start = static_cast<int>(column);
                    run_color = color;
                } else {
                    run_start = -1;
                    run_color = 0;
                }
            }
        }
    }
}

LRESULT CALLBACK directx_overlay_window_proc(HWND window, UINT message, WPARAM wide, LPARAM value) {
    if (message == WM_NCHITTEST) return HTTRANSPARENT;
    if (message == WM_ERASEBKGND) return TRUE;
    if (message == WM_CLOSE) {
        DestroyWindow(window);
        return 0;
    }
    if (message == WM_DESTROY) {
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(window, message, wide, value);
}

bool current_process_window(HWND window) {
    if (window == nullptr || !IsWindow(window)) return false;
    DWORD process = 0;
    GetWindowThreadProcessId(window, &process);
    return process == GetCurrentProcessId();
}

BOOL CALLBACK enumerate_directx_target(HWND window, LPARAM parameter) {
    if (!current_process_window(window)
        || !IsWindowVisible(window)
        || GetWindow(window, GW_OWNER) != nullptr
        || (GetWindowLongPtrW(window, GWL_EXSTYLE) & WS_EX_TOOLWINDOW) != 0) {
        return TRUE;
    }
    RECT client{};
    if (!GetClientRect(window, &client)) return TRUE;
    const long long area = static_cast<long long>(client.right - client.left)
        * static_cast<long long>(client.bottom - client.top);
    auto* result = reinterpret_cast<std::pair<HWND, long long>*>(parameter);
    if (result != nullptr && area > result->second) *result = {window, area};
    return TRUE;
}

HWND find_directx_target_window() {
    HWND foreground = GetForegroundWindow();
    if (current_process_window(foreground)) return foreground;
    std::pair<HWND, long long> result{nullptr, 0};
    EnumWindows(enumerate_directx_target, reinterpret_cast<LPARAM>(&result));
    return result.first;
}

DWORD WINAPI directx_overlay_worker(void*) {
    const HINSTANCE instance = GetModuleHandleW(nullptr);
    WNDCLASSEXW descriptor{};
    descriptor.cbSize = sizeof(descriptor);
    descriptor.lpfnWndProc = directx_overlay_window_proc;
    descriptor.hInstance = instance;
    descriptor.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512));
    descriptor.lpszClassName = L"SecretDirectXDeathOverlay";
    RegisterClassExW(&descriptor);

    HWND target = directx_target_window.load(std::memory_order_acquire);
    HWND window = CreateWindowExW(
        WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
        descriptor.lpszClassName,
        L"",
        WS_POPUP,
        0,
        0,
        16,
        16,
        target,
        nullptr,
        instance,
        nullptr
    );
    if (window == nullptr) return 1;
    directx_overlay_window.store(window, std::memory_order_release);
    SetLayeredWindowAttributes(window, RGB(0, 0, 0), 0, LWA_COLORKEY);

    IDirect3D9* direct3d = Direct3DCreate9(D3D_SDK_VERSION);
    if (direct3d == nullptr) {
        DestroyWindow(window);
        directx_overlay_window.store(nullptr, std::memory_order_release);
        return 1;
    }
    D3DPRESENT_PARAMETERS parameters{};
    parameters.Windowed = TRUE;
    parameters.SwapEffect = D3DSWAPEFFECT_DISCARD;
    parameters.hDeviceWindow = window;
    parameters.BackBufferFormat = D3DFMT_UNKNOWN;
    parameters.BackBufferWidth = 16;
    parameters.BackBufferHeight = 16;
    parameters.PresentationInterval = D3DPRESENT_INTERVAL_IMMEDIATE;
    IDirect3DDevice9* device = nullptr;
    HRESULT status = direct3d->CreateDevice(
        D3DADAPTER_DEFAULT,
        D3DDEVTYPE_HAL,
        window,
        D3DCREATE_SOFTWARE_VERTEXPROCESSING | D3DCREATE_MULTITHREADED,
        &parameters,
        &device
    );
    if (FAILED(status)) {
        status = direct3d->CreateDevice(
            D3DADAPTER_DEFAULT,
            D3DDEVTYPE_REF,
            window,
            D3DCREATE_SOFTWARE_VERTEXPROCESSING | D3DCREATE_MULTITHREADED,
            &parameters,
            &device
        );
    }
    if (FAILED(status) || device == nullptr) {
        direct3d->Release();
        DestroyWindow(window);
        directx_overlay_window.store(nullptr, std::memory_order_release);
        return 1;
    }
    directx_overlay_device.store(device, std::memory_order_release);

    LONG device_width = 16;
    LONG device_height = 16;
    MSG message{};
    while (!directx_overlay_stop.load(std::memory_order_acquire)) {
        while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE)) {
            if (message.message == WM_QUIT) {
                directx_overlay_stop.store(true, std::memory_order_release);
                break;
            }
            TranslateMessage(&message);
            DispatchMessageW(&message);
        }
        target = directx_target_window.load(std::memory_order_acquire);
        RECT client{};
        POINT origin{};
        const bool drawable = current_process_window(target)
            && IsWindowVisible(target)
            && !IsIconic(target)
            && GetClientRect(target, &client)
            && ClientToScreen(target, &origin);
        const LONG width = client.right - client.left;
        const LONG height = client.bottom - client.top;
        if (!drawable || width <= 1 || height <= 1) {
            ShowWindow(window, SW_HIDE);
            Sleep(32);
            continue;
        }
        const bool foreground = GetForegroundWindow() == target;
        const UINT position_flags = SWP_NOACTIVATE | SWP_SHOWWINDOW
            | (foreground ? 0U : SWP_NOZORDER);
        SetWindowPos(
            window,
            foreground ? HWND_TOP : nullptr,
            origin.x,
            origin.y,
            width,
            height,
            position_flags
        );
        if (width != device_width || height != device_height) {
            directx_overlay_device.store(nullptr, std::memory_order_release);
            parameters.BackBufferWidth = static_cast<UINT>(width);
            parameters.BackBufferHeight = static_cast<UINT>(height);
            status = device->Reset(&parameters);
            directx_overlay_device.store(device, std::memory_order_release);
            if (FAILED(status)) {
                Sleep(50);
                continue;
            }
            device_width = width;
            device_height = height;
        }
        device->Clear(0, nullptr, D3DCLEAR_TARGET, D3DCOLOR_ARGB(0, 0, 0, 0), 1.0F, 0);
        device->Present(nullptr, nullptr, window, nullptr);
        Sleep(16);
    }

    directx_overlay_device.store(nullptr, std::memory_order_release);
    himitsu::platform::windows::directx_assets::release_device(device);
    device->Release();
    direct3d->Release();
    if (IsWindow(window)) DestroyWindow(window);
    directx_overlay_window.store(nullptr, std::memory_order_release);
    return 0;
}

void ensure_directx_overlay() {
    AcquireSRWLockExclusive(&directx_overlay_lifecycle_lock);
    if(himitsu::core::RuntimeState::instance().shutting_down()) {ReleaseSRWLockExclusive(&directx_overlay_lifecycle_lock);return;}
    HANDLE existing = directx_overlay_thread.load(std::memory_order_relaxed);
    if (existing != nullptr && WaitForSingleObject(existing, 0) == WAIT_OBJECT_0) {
        CloseHandle(existing);
        directx_overlay_thread.store(nullptr, std::memory_order_relaxed);
        existing = nullptr;
    }
    if (existing == nullptr) {
        directx_overlay_stop.store(false, std::memory_order_release);
        HANDLE thread = CreateThread(nullptr, 0, directx_overlay_worker, nullptr, 0, nullptr);
        directx_overlay_thread.store(thread, std::memory_order_release);
    }
    ReleaseSRWLockExclusive(&directx_overlay_lifecycle_lock);
}

bool stop_directx_overlay(std::uint64_t deadline) {
    AcquireSRWLockExclusive(&directx_overlay_lifecycle_lock);
    HANDLE thread=directx_overlay_thread.load(std::memory_order_acquire);
    directx_overlay_stop.store(true,std::memory_order_release);
    HWND window=directx_overlay_window.load(std::memory_order_acquire);
    ReleaseSRWLockExclusive(&directx_overlay_lifecycle_lock);
    if(window) PostMessageW(window,WM_CLOSE,0,0);
    if(thread) {
        auto now=GetTickCount64();
        if(WaitForSingleObject(thread,static_cast<DWORD>(now<deadline?deadline-now:0))!=WAIT_OBJECT_0) return false;
        AcquireSRWLockExclusive(&directx_overlay_lifecycle_lock);
        directx_overlay_thread.store(nullptr,std::memory_order_release);
        ReleaseSRWLockExclusive(&directx_overlay_lifecycle_lock);
        CloseHandle(thread);
    }
    return true;
}

void observe_directx_target(HDC device_context) {
    HWND window = device_context == nullptr ? nullptr : WindowFromDC(device_context);
    if (!current_process_window(window)) return;
    directx_target_window.store(window, std::memory_order_release);
    ensure_directx_overlay();
}

void observe_directx_process_target() {
    HWND window = find_directx_target_window();
    if (window == nullptr) return;
    directx_target_window.store(window, std::memory_order_release);
    ensure_directx_overlay();
}

HRESULT WINAPI hooked_d3d9_present(
    IDirect3DDevice9* device,
    const RECT* source,
    const RECT* destination,
    HWND override_window,
    const RGNDATA* dirty_region
) {
    NativeDraw call; if(!call.entered) return original_d3d9_present?original_d3d9_present(device,source,destination,override_window,dirty_region):D3D_OK;
    if (device == directx_overlay_device.load(std::memory_order_acquire)) {
        const bool death_active = !invoke_layer(
            true,
            stage_d3d9_present,
            reinterpret_cast<jlong>(device)
        );

        if (death_active) render_d3d9_death_overlay_layer(device);
        const HRESULT result = original_d3d9_present == nullptr
            ? D3D_OK
            : original_d3d9_present(device, source, destination, override_window, dirty_region);
        invoke_layer(false, stage_d3d9_present, reinterpret_cast<jlong>(device));
        return result;
    }
    const bool death_active = !invoke_layer(
        true,
        stage_d3d9_present,
        reinterpret_cast<jlong>(device)
    );
    if (death_active) render_d3d9_death_layer(device);
    const HRESULT result = original_d3d9_present == nullptr
        ? D3D_OK
        : original_d3d9_present(device, source, destination, override_window, dirty_region);
    invoke_layer(false, stage_d3d9_present, reinterpret_cast<jlong>(device));
    return result;
}

HRESULT WINAPI hooked_dxgi_present(IDXGISwapChain* swap_chain, UINT sync_interval, UINT flags) {
    NativeDraw call; if(!call.entered) {return original_dxgi_present?original_dxgi_present(swap_chain,sync_interval,flags):S_OK;}
    const bool death_active = !invoke_layer(
        true,
        stage_dxgi_present,
        reinterpret_cast<jlong>(swap_chain)
    );
    if (death_active) render_dxgi_death_layer(swap_chain);
    const HRESULT result = original_dxgi_present == nullptr
        ? S_OK
        : original_dxgi_present(swap_chain, sync_interval, flags);
    invoke_layer(false, stage_dxgi_present, reinterpret_cast<jlong>(swap_chain));
    return result;
}

LRESULT CALLBACK directx_probe_window_proc(HWND window, UINT message, WPARAM wide, LPARAM value) {
    return DefWindowProcW(window, message, wide, value);
}

HWND create_directx_probe_window() {
    static ATOM window_class = 0;
    if (window_class == 0) {
        WNDCLASSEXW descriptor{};
        descriptor.cbSize = sizeof(descriptor);
        descriptor.lpfnWndProc = directx_probe_window_proc;
        descriptor.hInstance = GetModuleHandleW(nullptr);
        descriptor.lpszClassName = L"SecretDirectXRenderProbe";
        window_class = RegisterClassExW(&descriptor);
        if (window_class == 0 && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) return nullptr;
    }
    return CreateWindowExW(
        WS_EX_TOOLWINDOW,
        L"SecretDirectXRenderProbe",
        L"",
        WS_POPUP,
        0,
        0,
        8,
        8,
        nullptr,
        nullptr,
        GetModuleHandleW(nullptr),
        nullptr
    );
}

bool install_d3d9_present_hook(HWND window) {
    IDirect3D9* direct3d = Direct3DCreate9(D3D_SDK_VERSION);
    if (direct3d == nullptr) return false;
    D3DPRESENT_PARAMETERS parameters{};
    parameters.Windowed = TRUE;
    parameters.SwapEffect = D3DSWAPEFFECT_DISCARD;
    parameters.hDeviceWindow = window;
    parameters.BackBufferFormat = D3DFMT_UNKNOWN;
    parameters.BackBufferWidth = 8;
    parameters.BackBufferHeight = 8;
    IDirect3DDevice9* device = nullptr;
    HRESULT status = direct3d->CreateDevice(
        D3DADAPTER_DEFAULT,
        D3DDEVTYPE_HAL,
        window,
        D3DCREATE_SOFTWARE_VERTEXPROCESSING | D3DCREATE_MULTITHREADED,
        &parameters,
        &device
    );
    if (FAILED(status)) {
        status = direct3d->CreateDevice(
            D3DADAPTER_DEFAULT,
            D3DDEVTYPE_REF,
            window,
            D3DCREATE_SOFTWARE_VERTEXPROCESSING | D3DCREATE_MULTITHREADED,
            &parameters,
            &device
        );
    }
    bool installed = false;
    if (SUCCEEDED(status) && device != nullptr) {
        void** table = *reinterpret_cast<void***>(device);
        installed = install_inline_hook(
            d3d9_present_inline,
            table[17],
            reinterpret_cast<void*>(&hooked_d3d9_present),
            reinterpret_cast<void**>(&original_d3d9_present)
        );
        device->Release();
    }
    direct3d->Release();
    return installed;
}

bool install_dxgi_present_hook(HWND window) {
    DXGI_SWAP_CHAIN_DESC description{};
    description.BufferDesc.Width = 8;
    description.BufferDesc.Height = 8;
    description.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    description.SampleDesc.Count = 1;
    description.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    description.BufferCount = 2;
    description.OutputWindow = window;
    description.Windowed = TRUE;
    description.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
    IDXGISwapChain* swap_chain = nullptr;
    ID3D11Device* device = nullptr;
    ID3D11DeviceContext* context = nullptr;
    D3D_FEATURE_LEVEL feature_level{};
    HRESULT status = D3D11CreateDeviceAndSwapChain(
        nullptr,
        D3D_DRIVER_TYPE_HARDWARE,
        nullptr,
        0,
        nullptr,
        0,
        D3D11_SDK_VERSION,
        &description,
        &swap_chain,
        &device,
        &feature_level,
        &context
    );
    if (FAILED(status)) {
        status = D3D11CreateDeviceAndSwapChain(
            nullptr,
            D3D_DRIVER_TYPE_WARP,
            nullptr,
            0,
            nullptr,
            0,
            D3D11_SDK_VERSION,
            &description,
            &swap_chain,
            &device,
            &feature_level,
            &context
        );
    }
    bool installed = false;
    if (SUCCEEDED(status) && swap_chain != nullptr) {
        void** table = *reinterpret_cast<void***>(swap_chain);
        installed = install_inline_hook(
            dxgi_present_inline,
            table[8],
            reinterpret_cast<void*>(&hooked_dxgi_present),
            reinterpret_cast<void**>(&original_dxgi_present)
        );
    }
    if (context != nullptr) context->Release();
    if (device != nullptr) device->Release();
    if (swap_chain != nullptr) swap_chain->Release();
    return installed;
}

bool install_directx_hooks() {
    if (d3d9_present_inline.active && dxgi_present_inline.active) return true;
    const ULONGLONG now = GetTickCount64();
    const ULONGLONG previous = last_directx_probe.load(std::memory_order_relaxed);
    if (previous != 0 && now - previous < 10000ULL) {
        return d3d9_present_inline.active || dxgi_present_inline.active;
    }
    last_directx_probe.store(now, std::memory_order_relaxed);
    HWND window = create_directx_probe_window();
    if (window == nullptr) return false;
    const bool d3d9 = d3d9_present_inline.active || install_d3d9_present_hook(window);
    const bool dxgi = dxgi_present_inline.active || install_dxgi_present_hook(window);
    DestroyWindow(window);
    HIMITSU_LOG_INFO(
        "Render",
        "DirectX render layer installation completed (D3D9=%s, DXGI=%s)",
        d3d9 ? "yes" : "no",
        dxgi ? "yes" : "no"
    );
    return d3d9 || dxgi;
}

bool patch_slot(void** slot, void* replacement, void** first_original) {
    if (slot == nullptr || replacement == nullptr || *slot == replacement) return false;
    void* original = *slot;
    if (first_original != nullptr && *first_original == nullptr) *first_original = original;
    MEMORY_BASIC_INFORMATION page{};
    if(VirtualQuery(slot,&page,sizeof(page))!=sizeof(page)
        || !himitsu::jvm::native_pointer_exchange(slot,original,replacement,page.AllocationBase))return false;
    const auto guard_token=himitsu::platform::windows::register_guarded_pointer("Render IAT slot",slot,replacement);
    if(!guard_token){himitsu::jvm::native_pointer_exchange(slot,replacement,original,page.AllocationBase);return false;}
    import_patches.push_back({slot,original,replacement,guard_token,page.AllocationBase});
    return true;
}

bool is_live_slot(void** slot) {
    MEMORY_BASIC_INFORMATION information{};
    return slot != nullptr
        && VirtualQuery(slot, &information, sizeof(information)) == sizeof(information)
        && information.State == MEM_COMMIT
        && (information.Protect & (PAGE_NOACCESS | PAGE_GUARD)) == 0;
}

bool patch_module(HMODULE module) {
    if (module == nullptr || module == self_module) return false;
    auto* base = reinterpret_cast<unsigned char*>(module);
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    const IMAGE_DATA_DIRECTORY& directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (directory.VirtualAddress == 0) return false;
    bool patched = false;
    auto* descriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + directory.VirtualAddress);
    for (; descriptor->Name != 0; ++descriptor) {
        if (descriptor->OriginalFirstThunk == 0) continue;
        auto* names = reinterpret_cast<IMAGE_THUNK_DATA*>(base + descriptor->OriginalFirstThunk);
        auto* addresses = reinterpret_cast<IMAGE_THUNK_DATA*>(base + descriptor->FirstThunk);
        for (; names->u1.AddressOfData != 0; ++names, ++addresses) {
            if (IMAGE_SNAP_BY_ORDINAL(names->u1.Ordinal)) continue;
            auto* import = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + names->u1.AddressOfData);
            const char* name = reinterpret_cast<const char*>(import->Name);
            void** slot = reinterpret_cast<void**>(&addresses->u1.Function);
            if (std::strcmp(name, "SwapBuffers") == 0) {
                patched |= patch_slot(
                    slot,
                    reinterpret_cast<void*>(&hooked_swap_buffers),
                    reinterpret_cast<void**>(&original_swap_buffers)
                );
            } else if (std::strcmp(name, "glfwSwapBuffers") == 0) {
                patched |= patch_slot(
                    slot,
                    reinterpret_cast<void*>(&hooked_glfw_swap_buffers),
                    reinterpret_cast<void**>(&original_glfw_swap_buffers)
                );
            } else if (std::strcmp(name, "wglSwapLayerBuffers") == 0) {
                patched |= patch_slot(
                    slot,
                    reinterpret_cast<void*>(&hooked_wgl_swap_layer_buffers),
                    reinterpret_cast<void**>(&original_wgl_swap_layer_buffers)
                );
            } else if (std::strcmp(name, "wglGetProcAddress") == 0) {
                patched |= patch_slot(
                    slot,
                    reinterpret_cast<void*>(&hooked_wgl_get_proc_address),
                    reinterpret_cast<void**>(&original_wgl_get_proc_address)
                );
            }
        }
    }
    return patched;
}

bool install_export_hooks(const std::vector<HMODULE>& modules) {
    bool installed = false;
    for (HMODULE module : modules) {
        FARPROC glfw = GetProcAddress(module, "glfwSwapBuffers");
        if (glfw != nullptr && module != self_module) {
            himitsu::platform::windows::observe_guarded_module(module);
            installed |= install_inline_hook(
                glfw_inline,
                reinterpret_cast<void*>(glfw),
                reinterpret_cast<void*>(&hooked_glfw_swap_buffers),
                reinterpret_cast<void**>(&original_glfw_swap_buffers)
            );
            if (glfw_inline.active) break;
        }
    }

    HMODULE opengl = GetModuleHandleW(L"opengl32.dll");
    if (opengl != nullptr) {
        FARPROC get_proc_address = GetProcAddress(opengl, "wglGetProcAddress");
        installed |= install_inline_hook(
            wgl_get_proc_inline,
            reinterpret_cast<void*>(get_proc_address),
            reinterpret_cast<void*>(&hooked_wgl_get_proc_address),
            reinterpret_cast<void**>(&original_wgl_get_proc_address)
        );
        FARPROC layer_swap = GetProcAddress(opengl, "wglSwapLayerBuffers");
        installed |= install_inline_hook(
            wgl_layer_inline,
            reinterpret_cast<void*>(layer_swap),
            reinterpret_cast<void*>(&hooked_wgl_swap_layer_buffers),
            reinterpret_cast<void**>(&original_wgl_swap_layer_buffers)
        );
    }

    HMODULE gdi = GetModuleHandleW(L"gdi32.dll");
    if (gdi != nullptr) {
        FARPROC swap = GetProcAddress(gdi, "SwapBuffers");
        installed |= install_inline_hook(
            gdi_inline,
            reinterpret_cast<void*>(swap),
            reinterpret_cast<void*>(&hooked_swap_buffers),
            reinterpret_cast<void**>(&original_swap_buffers)
        );
    }

    HMODULE win32u = GetModuleHandleW(L"win32u.dll");
    if (win32u == nullptr) win32u = LoadLibraryW(L"win32u.dll");
    if (win32u != nullptr) {
        FARPROC nt_swap = GetProcAddress(win32u, "NtGdiSwapBuffers");
        installed |= install_inline_hook(
            ntgdi_inline,
            reinterpret_cast<void*>(nt_swap),
            reinterpret_cast<void*>(&hooked_ntgdi_swap_buffers),
            reinterpret_cast<void**>(&original_ntgdi_swap_buffers)
        );
    }
    installed |= install_directx_hooks();
    return installed;
}
}

namespace himitsu::platform::windows {
bool install_swap_buffers_hook() {
    HookLock lock;
    if (self_module == nullptr) {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(&install_swap_buffers_hook),
            &self_module
        );
    }

    if (!minhook_initialized) {
        const MH_STATUS status = MH_Initialize();
        minhook_initialized = status == MH_OK || status == MH_ERROR_ALREADY_INITIALIZED;
        if (!minhook_initialized) {
            HIMITSU_LOG_WARNING("Render", "原生内联钩子初始化失败（状态=%d），继续使用 IAT 渲染层", status);
        }
    }

    HANDLE snapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
        GetCurrentProcessId()
    );
    if (snapshot == INVALID_HANDLE_VALUE) return false;

    std::vector<HMODULE> modules;
    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Module32FirstW(snapshot, &entry)) {
        do {
            modules.push_back(entry.hModule);
            patch_module(entry.hModule);
        } while (Module32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);

    const bool exports = install_export_hooks(modules);
    const bool installed = !import_patches.empty() || exports;
    hook_maintenance_enabled.store(installed, std::memory_order_release);
    HIMITSU_LOG_INFO(
        "Render",
        "多层原生渲染入口安装完成（IAT=%zu，GDI=%s，GLFW=%s，WGL层交换=%s，WGL动态入口=%s，NtGdi=%s）",
        import_patches.size(),
        gdi_inline.active ? "是" : "否",
        glfw_inline.active ? "是" : "否",
        wgl_layer_inline.active ? "是" : "否",
        wgl_get_proc_inline.active ? "是" : "否",
        ntgdi_inline.active ? "是" : "否"
    );
    return installed;
}

void maintain_swap_buffers_hook() {
    if (!hook_maintenance_enabled.load(std::memory_order_acquire)) return;
    const ULONGLONG now = GetTickCount64();
    ULONGLONG previous = last_hook_maintenance.load(std::memory_order_relaxed);
    if (now - previous < 500ULL
        || !last_hook_maintenance.compare_exchange_strong(
            previous,
            now,
            std::memory_order_acq_rel,
            std::memory_order_relaxed
        )) {
        return;
    }

    HookLock lock;
    if (!minhook_initialized) return;
    InlineHook* hooks[] = {
        &gdi_inline,
        &glfw_inline,
        &wgl_layer_inline,
        &ntgdi_inline,
        &wgl_get_proc_inline,
        &bind_framebuffer_inline,
        &blit_framebuffer_inline,
        &bind_framebuffer_ext_inline,
        &blit_framebuffer_ext_inline,
        &d3d9_present_inline,
        &dxgi_present_inline
    };
    for (InlineHook* hook : hooks) {
        if (hook == nullptr || !hook->active || hook->target == nullptr) continue;
        if(!himitsu::platform::windows::guarded_hook_intact(hook->target))continue;
        MH_HOOK_SNAPSHOT metadata{};
        if(MH_GetHookSnapshot(hook->target,&metadata)==MH_OK && !metadata.enabled) {
            ThreadHookMaintenance scope;
            auto status=MH_EnableHook(hook->target);
            if(status!=MH_OK)HIMITSU_LOG_WARNING("Render","Owned hook enable failed: %s",hook->name);
        }
    }

    HANDLE snapshot = CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
        GetCurrentProcessId()
    );
    if (snapshot == INVALID_HANDLE_VALUE) return;
    std::vector<HMODULE> modules;
    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Module32FirstW(snapshot, &entry)) {
        do {
            modules.push_back(entry.hModule);
            patch_module(entry.hModule);
        } while (Module32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    install_export_hooks(modules);
}

bool uninstall_swap_buffers_hook(std::uint64_t deadline) {
    hook_maintenance_enabled.store(false,std::memory_order_release);
    if(!stop_directx_overlay(deadline) || GetTickCount64()>deadline) return false;
    himitsu::platform::windows::directx_assets::release_all();
    HookLock lock;
    bool complete=true;
    complete=uninstall_inline_hook(dxgi_present_inline,deadline) && complete;
    complete=uninstall_inline_hook(d3d9_present_inline,deadline) && complete;
    complete=uninstall_inline_hook(blit_framebuffer_ext_inline,deadline) && complete;
    complete=uninstall_inline_hook(bind_framebuffer_ext_inline,deadline) && complete;
    complete=uninstall_inline_hook(blit_framebuffer_inline,deadline) && complete;
    complete=uninstall_inline_hook(bind_framebuffer_inline,deadline) && complete;
    complete=uninstall_inline_hook(ntgdi_inline,deadline) && complete;
    complete=uninstall_inline_hook(wgl_layer_inline,deadline) && complete;
    complete=uninstall_inline_hook(wgl_get_proc_inline,deadline) && complete;
    complete=uninstall_inline_hook(glfw_inline,deadline) && complete;
    complete=uninstall_inline_hook(gdi_inline,deadline) && complete;

    for (auto iterator = import_patches.rbegin(); iterator != import_patches.rend(); ++iterator) {
        if(!himitsu::platform::windows::unregister_guarded_region(iterator->guard_token,deadline)){complete=false;continue;}
        if(!is_live_slot(iterator->slot))continue;
        void* current=nullptr;
        if(!himitsu::jvm::native_memory_read(iterator->slot,&current,sizeof(current))){complete=false;continue;}
        if(current==iterator->original)continue;
        if(current!=iterator->replacement || !himitsu::jvm::native_pointer_exchange(iterator->slot,current,iterator->original,iterator->allocation))complete=false;
    }
    if(!complete) return false;
    import_patches.clear();
    // Late detours must still be able to call their original functions.
    context_hooks_ready.store(false, std::memory_order_release);
    last_hook_maintenance.store(0, std::memory_order_release);
    last_directx_probe.store(0, std::memory_order_release);
    directx_target_window.store(nullptr, std::memory_order_release);
    // All successfully enabled trampolines remain allocated until process exit.
    minhook_initialized = false;
    HIMITSU_LOG_INFO("Render", "Native render entries disabled; trampolines retained");
    return true;
}
}

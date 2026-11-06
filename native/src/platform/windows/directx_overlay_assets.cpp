#include "himitsu/platform/windows/directx_overlay_assets.hpp"

#include <windows.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <vector>

namespace {
constexpr UINT title_width = 512;
constexpr UINT title_height = 128;
constexpr DWORD sprite_fvf = D3DFVF_XYZRHW | D3DFVF_DIFFUSE | D3DFVF_TEX1;

struct SpriteVertex {
    float x;
    float y;
    float z;
    float rhw;
    D3DCOLOR color;
    float u;
    float v;
};

std::mutex assets_lock;
IDirect3DDevice9* asset_device = nullptr;
IDirect3DTexture9* title = nullptr;
std::once_flag title_create_once;
std::vector<std::uint8_t> title_bgra;

void release_assets_unlocked() {
    if (title != nullptr) {
        title->Release();
        title = nullptr;
    }
    if (asset_device != nullptr) {
        asset_device->Release();
        asset_device = nullptr;
    }
}

bool select_device_unlocked(IDirect3DDevice9* device) {
    if (device == nullptr) return false;
    if (asset_device == device) return true;
    release_assets_unlocked();
    asset_device = device;
    asset_device->AddRef();
    return true;
}

bool upload_texture(
    IDirect3DDevice9* device,
    UINT width,
    UINT height,
    const std::uint8_t* pixels,
    IDirect3DTexture9** output
) {
    if (device == nullptr || pixels == nullptr || output == nullptr) return false;
    IDirect3DTexture9* texture = nullptr;
    if (FAILED(device->CreateTexture(
            width,
            height,
            1,
            0,
            D3DFMT_A8R8G8B8,
            D3DPOOL_MANAGED,
            &texture,
            nullptr
        )) || texture == nullptr) return false;
    D3DLOCKED_RECT locked{};
    if (FAILED(texture->LockRect(0, &locked, nullptr, 0))) {
        texture->Release();
        return false;
    }
    const std::size_t source_pitch = static_cast<std::size_t>(width) * 4U;
    for (UINT y = 0; y < height; ++y) {
        std::memcpy(
            static_cast<std::uint8_t*>(locked.pBits) + static_cast<std::size_t>(locked.Pitch) * y,
            pixels + source_pitch * y,
            source_pitch
        );
    }
    texture->UnlockRect(0);
    *output = texture;
    return true;
}

std::vector<std::uint8_t> create_title_pixels() {
    BITMAPINFO information{};
    information.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    information.bmiHeader.biWidth = static_cast<LONG>(title_width);
    information.bmiHeader.biHeight = -static_cast<LONG>(title_height);
    information.bmiHeader.biPlanes = 1;
    information.bmiHeader.biBitCount = 32;
    information.bmiHeader.biCompression = BI_RGB;
    void* dib_pixels = nullptr;
    HDC device_context = CreateCompatibleDC(nullptr);
    HBITMAP bitmap = CreateDIBSection(
        device_context,
        &information,
        DIB_RGB_COLORS,
        &dib_pixels,
        nullptr,
        0
    );
    std::vector<std::uint8_t> result(
        static_cast<std::size_t>(title_width) * title_height * 4U,
        0
    );
    if (device_context == nullptr || bitmap == nullptr || dib_pixels == nullptr) {
        if (bitmap != nullptr) DeleteObject(bitmap);
        if (device_context != nullptr) DeleteDC(device_context);
        return result;
    }
    HGDIOBJ old_bitmap = SelectObject(device_context, bitmap);
    HBRUSH background = CreateSolidBrush(RGB(0, 0, 0));
    RECT canvas{0, 0, static_cast<LONG>(title_width), static_cast<LONG>(title_height)};
    FillRect(device_context, &canvas, background);
    DeleteObject(background);
    HFONT font = CreateFontW(
        -88,
        0,
        0,
        0,
        FW_BOLD,
        FALSE,
        FALSE,
        FALSE,
        GB2312_CHARSET,
        OUT_TT_PRECIS,
        CLIP_DEFAULT_PRECIS,
        NONANTIALIASED_QUALITY,
        FIXED_PITCH | FF_DONTCARE,
        L"Microsoft YaHei UI"
    );
    HGDIOBJ old_font = SelectObject(device_context, font);
    SetBkMode(device_context, TRANSPARENT);
    SetTextColor(device_context, RGB(255, 255, 255));
    RECT text_area{0, 8, static_cast<LONG>(title_width), static_cast<LONG>(title_height)};
    DrawTextW(
        device_context,
        L"你死了",
        -1,
        &text_area,
        DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX
    );
    GdiFlush();

    const auto* source = static_cast<const std::uint8_t*>(dib_pixels);
    for (std::size_t index = 0; index < result.size(); index += 4U) {
        const std::uint8_t coverage = std::max({source[index], source[index + 1], source[index + 2]});
        if (coverage == 0) continue;
        result[index] = 194;
        result[index + 1] = 79;
        result[index + 2] = 154;
        result[index + 3] = coverage;
    }
    SelectObject(device_context, old_font);
    SelectObject(device_context, old_bitmap);
    DeleteObject(font);
    DeleteObject(bitmap);
    DeleteDC(device_context);
    return result;
}

IDirect3DTexture9* title_texture_unlocked(IDirect3DDevice9* device) {
    if (!select_device_unlocked(device)) return nullptr;
    if (title == nullptr) {
        std::call_once(title_create_once, [] { title_bgra = create_title_pixels(); });
        upload_texture(device, title_width, title_height, title_bgra.data(), &title);
    }
    return title;
}
}

namespace himitsu::platform::windows::directx_assets {
BgraImage death_title_image() {
    std::call_once(title_create_once, [] { title_bgra = create_title_pixels(); });
    return {title_bgra.data(), title_width, title_height};
}

void draw_death_title(IDirect3DDevice9* device, long width, long height) {
    if (device == nullptr || width <= 0 || height <= 0) return;
    std::lock_guard guard(assets_lock);
    IDirect3DTexture9* texture = title_texture_unlocked(device);
    if (texture == nullptr) return;
    const float draw_width = std::min(static_cast<float>(width) * 0.33F, 430.0F);
    const float draw_height = draw_width * static_cast<float>(title_height) / title_width;
    const float left = (static_cast<float>(width) - draw_width) * 0.5F - 0.5F;
    const float top = static_cast<float>(height) * 0.5F - draw_height * 0.5F - 18.0F;
    const std::array<SpriteVertex, 4> vertices{{
        {left, top, 0.0F, 1.0F, 0xFFFFFFFFU, 0.0F, 0.0F},
        {left + draw_width, top, 0.0F, 1.0F, 0xFFFFFFFFU, 1.0F, 0.0F},
        {left, top + draw_height, 0.0F, 1.0F, 0xFFFFFFFFU, 0.0F, 1.0F},
        {left + draw_width, top + draw_height, 0.0F, 1.0F, 0xFFFFFFFFU, 1.0F, 1.0F}
    }};
    IDirect3DStateBlock9* state_block = nullptr;
    if (SUCCEEDED(device->CreateStateBlock(D3DSBT_ALL, &state_block)) && state_block != nullptr) {
        state_block->Capture();
    }
    if (SUCCEEDED(device->BeginScene())) {
        device->SetTexture(0, texture);
        device->SetFVF(sprite_fvf);
        device->SetRenderState(D3DRS_ZENABLE, FALSE);
        device->SetRenderState(D3DRS_CULLMODE, D3DCULL_NONE);
        device->SetRenderState(D3DRS_FILLMODE, D3DFILL_SOLID);
        device->SetRenderState(D3DRS_LIGHTING, FALSE);
        device->SetRenderState(D3DRS_ALPHABLENDENABLE, TRUE);
        device->SetRenderState(D3DRS_SRCBLEND, D3DBLEND_SRCALPHA);
        device->SetRenderState(D3DRS_DESTBLEND, D3DBLEND_INVSRCALPHA);
        device->SetTextureStageState(0, D3DTSS_COLOROP, D3DTOP_MODULATE);
        device->SetTextureStageState(0, D3DTSS_COLORARG1, D3DTA_TEXTURE);
        device->SetTextureStageState(0, D3DTSS_COLORARG2, D3DTA_DIFFUSE);
        device->SetTextureStageState(0, D3DTSS_ALPHAOP, D3DTOP_MODULATE);
        device->SetTextureStageState(0, D3DTSS_ALPHAARG1, D3DTA_TEXTURE);
        device->SetTextureStageState(0, D3DTSS_ALPHAARG2, D3DTA_DIFFUSE);
        device->SetSamplerState(0, D3DSAMP_MINFILTER, D3DTEXF_POINT);
        device->SetSamplerState(0, D3DSAMP_MAGFILTER, D3DTEXF_POINT);
        device->DrawPrimitiveUP(D3DPT_TRIANGLESTRIP, 2, vertices.data(), sizeof(SpriteVertex));
        device->EndScene();
    }
    if (state_block != nullptr) {
        state_block->Apply();
        state_block->Release();
    }
}

void release_device(IDirect3DDevice9* device) {
    std::lock_guard guard(assets_lock);
    if (asset_device == device) release_assets_unlocked();
}

void release_all() {
    std::lock_guard guard(assets_lock);
    release_assets_unlocked();
}
}

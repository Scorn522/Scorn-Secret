#include "himitsu/validation/validation_ui.hpp"

#include "himitsu/build_info.hpp"
#include "himitsu/embedded/login_pig_sprite.hpp"

#include "himitsu/validation/validation_backend.hpp"
#include "himitsu/validation/capability_registry.hpp"
#include "himitsu/validation/game_pause.hpp"
#include "himitsu/validation/integrity_check.hpp"
#include "himitsu/validation/runtime_lease.hpp"
#include "himitsu/validation/validation_gate.hpp"
#include "himitsu/validation/zhu_animation.hpp"

#include "imgui.h"
#include "imgui_impl_dx9.h"
#include "imgui_impl_win32.h"

#include <d3d9.h>
#include <wincodec.h>
#include <windowsx.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cmath>
#include <cstdio>
#include <ctime>
#include <cstring>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <vector>

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(
    HWND window,
    UINT message,
    WPARAM wide_parameter,
    LPARAM long_parameter
);

namespace {
constexpr int window_width = 750;
constexpr int window_height = 450;
constexpr wchar_t window_class_name[] = L"HimitsuNativeValidationWindow";

struct UiState {
    HMODULE module = nullptr;
    HWND window = nullptr;
    WNDCLASSEXW window_class{};
    IDirect3D9* d3d = nullptr;
    IDirect3DDevice9* device = nullptr;
    IDirect3DTexture9* login_pig_texture = nullptr;
    D3DPRESENT_PARAMETERS presentation{};
    std::size_t login_pig_frame = 0;
    ULONGLONG login_pig_next_frame = 0;
    bool com_initialized = false;
    bool running = true;
    bool accepted = false;
    bool imgui_ready = false;
    std::atomic<bool> authenticating{false};
    std::atomic<bool> authentication_finished{false};
    std::atomic<float> authentication_progress{0.0F};
    std::mutex authentication_mutex;
    std::thread authentication_thread;
    himitsu::validation::backend::Result authentication_result;
    std::string authentication_step;
    float displayed_progress = 0.0F;
    bool approval_pending = false;
    std::array<char, 160> username{};
    std::array<char, 160> password{};
    bool remember_me = false;
};

UiState* active_ui = nullptr;

template<typename Interface>
void release_com(Interface*& value) {
    if (value != nullptr) {
        value->Release();
        value = nullptr;
    }
}

bool create_login_pig_texture(UiState& state) {
    if (state.device == nullptr) return false;
    const HRESULT com_result = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (SUCCEEDED(com_result)) {
        state.com_initialized = true;
    } else if (com_result != RPC_E_CHANGED_MODE) {
        return false;
    }

    IWICImagingFactory* factory = nullptr;
    IWICStream* stream = nullptr;
    IWICBitmapDecoder* decoder = nullptr;
    IWICBitmapFrameDecode* frame = nullptr;
    IWICFormatConverter* converter = nullptr;
    auto release_wic = [&] {
        release_com(converter);
        release_com(frame);
        release_com(decoder);
        release_com(stream);
        release_com(factory);
    };

    HRESULT result = CoCreateInstance(
        CLSID_WICImagingFactory,
        nullptr,
        CLSCTX_INPROC_SERVER,
        IID_PPV_ARGS(&factory)
    );
    if (SUCCEEDED(result)) result = factory->CreateStream(&stream);
    if (SUCCEEDED(result)) {
        result = stream->InitializeFromMemory(
            const_cast<BYTE*>(himitsu::embedded::login_pig_sprite_png),
            static_cast<DWORD>(himitsu::embedded::login_pig_sprite_png_size)
        );
    }
    if (SUCCEEDED(result)) {
        result = factory->CreateDecoderFromStream(
            stream,
            nullptr,
            WICDecodeMetadataCacheOnLoad,
            &decoder
        );
    }
    if (SUCCEEDED(result)) result = decoder->GetFrame(0, &frame);
    if (SUCCEEDED(result)) result = factory->CreateFormatConverter(&converter);
    if (SUCCEEDED(result)) {
        result = converter->Initialize(
            frame,
            GUID_WICPixelFormat32bppBGRA,
            WICBitmapDitherTypeNone,
            nullptr,
            0.0,
            WICBitmapPaletteTypeCustom
        );
    }

    UINT width = 0;
    UINT height = 0;
    if (SUCCEEDED(result)) result = converter->GetSize(&width, &height);
    const UINT expected_height = himitsu::validation::zhu_animation::frame_height
        * himitsu::validation::zhu_animation::frame_count;
    if (FAILED(result)
        || width != himitsu::validation::zhu_animation::frame_width
        || height != expected_height) {
        release_wic();
        return false;
    }

    const UINT pitch = width * 4U;
    std::vector<BYTE> pixels(static_cast<std::size_t>(pitch) * height);
    result = converter->CopyPixels(
        nullptr,
        pitch,
        static_cast<UINT>(pixels.size()),
        pixels.data()
    );
    IDirect3DTexture9* texture = nullptr;
    if (SUCCEEDED(result)) {
        result = state.device->CreateTexture(
            width,
            height,
            1,
            0,
            D3DFMT_A8R8G8B8,
            D3DPOOL_MANAGED,
            &texture,
            nullptr
        );
    }
    D3DLOCKED_RECT locked{};
    if (SUCCEEDED(result)) result = texture->LockRect(0, &locked, nullptr, 0);
    if (SUCCEEDED(result)) {
        for (UINT row = 0; row < height; ++row) {
            std::memcpy(
                static_cast<BYTE*>(locked.pBits) + static_cast<std::size_t>(locked.Pitch) * row,
                pixels.data() + static_cast<std::size_t>(pitch) * row,
                pitch
            );
        }
        texture->UnlockRect(0);
        state.login_pig_texture = texture;
        state.login_pig_frame = 0;
        state.login_pig_next_frame = 0;
    } else if (texture != nullptr) {
        texture->Release();
    }
    release_wic();
    return SUCCEEDED(result);
}

std::string trim(std::string value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

std::wstring credentials_path() {
    std::array<wchar_t, 32768> profile{};
    const DWORD length = GetEnvironmentVariableW(
        L"USERPROFILE",
        profile.data(),
        static_cast<DWORD>(profile.size())
    );
    if (length == 0 || length >= profile.size()) {
        return L"Secret.ini";
    }
    std::wstring path(profile.data(), length);
    if (!path.empty() && path.back() != L'\\' && path.back() != L'/') {
        path.push_back(L'\\');
    }
    path.append(L"Secret.ini");
    return path;
}

void load_credentials(UiState& state) {
    const std::wstring path = credentials_path();
    HANDLE file = CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        nullptr
    );
    if (file == INVALID_HANDLE_VALUE) return;

    LARGE_INTEGER file_size{};
    if (!GetFileSizeEx(file, &file_size)
        || file_size.QuadPart <= 0
        || file_size.QuadPart > 64 * 1024) {
        CloseHandle(file);
        return;
    }

    std::string contents(static_cast<std::size_t>(file_size.QuadPart), '\0');
    DWORD bytes_read = 0;
    const BOOL read_ok = ReadFile(
        file,
        contents.data(),
        static_cast<DWORD>(contents.size()),
        &bytes_read,
        nullptr
    );
    CloseHandle(file);
    if (!read_ok || bytes_read == 0) return;
    contents.resize(bytes_read);

    bool in_info = false;
    bool remember = false;
    std::string username;
    std::string password;
    std::size_t cursor = 0;
    while (cursor < contents.size()) {
        const std::size_t newline = contents.find('\n', cursor);
        const std::size_t end = newline == std::string::npos ? contents.size() : newline;
        std::string line = contents.substr(cursor, end - cursor);
        cursor = newline == std::string::npos ? contents.size() : newline + 1;
        line = trim(line);
        if (line.empty() || line[0] == ';' || line[0] == '#') continue;
        if (line.front() == '[' && line.back() == ']') {
            in_info = trim(line.substr(1, line.size() - 2)) == "info";
            continue;
        }
        if (!in_info) continue;
        const auto separator = line.find('=');
        if (separator == std::string::npos) continue;
        const std::string key = trim(line.substr(0, separator));
        const std::string value = trim(line.substr(separator + 1));
        if (key == "Remember") {
            remember = value == "true" || value == "TRUE" || value == "1";
        } else if (key == "username") {
            username = value;
        } else if (key == "password") {
            password = value;
        }
    }

    state.remember_me = remember;
    if (remember) {
        strncpy_s(state.username.data(), state.username.size(), username.c_str(), _TRUNCATE);
        if (password.rfind("dpapi:", 0) != 0) {
            strncpy_s(state.password.data(), state.password.size(), password.c_str(), _TRUNCATE);
        }
    }
    if (!password.empty()) SecureZeroMemory(password.data(), password.size());
    if (!contents.empty()) SecureZeroMemory(contents.data(), contents.size());
}

void save_credentials(const UiState& state) {
    std::string contents;
    contents.reserve(384);
    contents.append("[info]\r\nRemember = ");
    contents.append(state.remember_me ? "true" : "false");
    contents.append("\r\nusername = ");
    if (state.remember_me) contents.append(state.username.data());
    contents.append("\r\npassword = ");
    if (state.remember_me) contents.append(state.password.data());
    contents.append("\r\n");

    const std::wstring path = credentials_path();
    HANDLE file = CreateFileW(
        path.c_str(),
        GENERIC_WRITE,
        FILE_SHARE_READ,
        nullptr,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr
    );
    if (file != INVALID_HANDLE_VALUE) {
        DWORD bytes_written = 0;
        WriteFile(
            file,
            contents.data(),
            static_cast<DWORD>(contents.size()),
            &bytes_written,
            nullptr
        );
        FlushFileBuffers(file);
        CloseHandle(file);
    }
    if (!contents.empty()) SecureZeroMemory(contents.data(), contents.size());
}

std::wstring utf8_to_wide(const std::string& value) {
    if (value.empty()) return {};
    const int size = MultiByteToWideChar(
        CP_UTF8,
        MB_ERR_INVALID_CHARS,
        value.data(),
        static_cast<int>(value.size()),
        nullptr,
        0
    );
    if (size <= 0) return std::wstring(value.begin(), value.end());
    std::wstring output(size, L'\0');
    MultiByteToWideChar(
        CP_UTF8,
        MB_ERR_INVALID_CHARS,
        value.data(),
        static_cast<int>(value.size()),
        output.data(),
        size
    );
    return output;
}

[[noreturn]] void show_login_error(UiState& state, const std::string& reason) {
    himitsu::validation::latch_rejection();
    std::wstring message;
    if (reason == "Invalid username or password") {
        message = L"用户名或密码不正确！\nIncorrect Password or Username!";
    } else if (reason == "This account is bound to another device") {
        message = L"账号已绑定到其他设备！\nThis account is bound to another device!";
    } else if (reason == "Too many attempts; retry later") {
        message = L"登录尝试过多，请稍后重试！\nToo many attempts; retry later!";
    } else {
        message = utf8_to_wide(reason.empty() ? "Login verification failed" : reason);
    }
    MessageBoxW(
        state.window,
        message.c_str(),
        L"Server Error",
        MB_OK | MB_ICONERROR | MB_TOPMOST | MB_SETFOREGROUND
    );
    state.accepted = false;
    state.running = false;
    himitsu::validation::terminate_rejected(0x48560004UL);
}

void start_authentication(UiState& state) {
    if (state.authenticating.load(std::memory_order_acquire)) return;
    const std::string username = trim(state.username.data());
    if (username.empty()) {
        show_login_error(state, "Please enter the username");
        return;
    }
    if (state.password[0] == '\0') {
        show_login_error(state, "Please enter the password");
        return;
    }

    if (state.authentication_thread.joinable()) state.authentication_thread.join();
    std::string password = state.password.data();
    state.displayed_progress = 0.0F;
    state.approval_pending = false;
    state.authentication_progress.store(0.02F, std::memory_order_release);
    {
        std::lock_guard lock(state.authentication_mutex);
        state.authentication_step = "准备开始验证";
    }
    state.authentication_finished.store(false, std::memory_order_release);
    state.authenticating.store(true, std::memory_order_release);
    state.authentication_thread = std::thread([&state, username, password]() mutable {

        himitsu::validation::backend::Request request{
            username,
            password,
            true,
            {},
            [&state](float progress, const std::string& step) {
                state.authentication_progress.store(
                    std::clamp(progress, 0.0F, 1.0F),
                    std::memory_order_release
                );
                std::lock_guard lock(state.authentication_mutex);
                state.authentication_step = step;
            }
        };
        auto result = himitsu::validation::backend::verify(request);
        if (!request.password.empty()) {
            SecureZeroMemory(request.password.data(), request.password.size());
        }
        if (!password.empty()) SecureZeroMemory(password.data(), password.size());
        {
            std::lock_guard lock(state.authentication_mutex);
            state.authentication_result = std::move(result);
        }
        state.authentication_finished.store(true, std::memory_order_release);
    });
}

void poll_authentication(UiState& state) {
    if (state.approval_pending) {
        if (state.displayed_progress < 0.995F) return;
        state.approval_pending = false;
        state.authenticating.store(false, std::memory_order_release);
        save_credentials(state);
        SecureZeroMemory(state.password.data(), state.password.size());
        state.accepted = true;
        state.running = false;
        return;
    }
    if (!state.authentication_finished.load(std::memory_order_acquire)) return;
    if (state.authentication_thread.joinable()) state.authentication_thread.join();

    himitsu::validation::backend::Result result;
    {
        std::lock_guard lock(state.authentication_mutex);
        result = std::move(state.authentication_result);
    }
    state.authentication_finished.store(false, std::memory_order_release);

    if (result.decision == himitsu::validation::backend::Decision::approved) {

        if (!himitsu::validation::integrity::verify_self(
                state.module,
                himitsu::validation::capability::dll_sha256())) {
            himitsu::validation::lease::stop();
            show_login_error(
                state,
                "Client integrity verification failed. "
                "DLL has been modified or does not match this release."
            );
        }
        state.authentication_progress.store(1.0F, std::memory_order_release);
        {
            std::lock_guard lock(state.authentication_mutex);
            state.authentication_step = "验证完成";
        }
        state.approval_pending = true;
        return;
    }

    state.authenticating.store(false, std::memory_order_release);
    SecureZeroMemory(state.password.data(), state.password.size());
    show_login_error(state, result.message);
}

std::string dll_build_time() {
    return std::string(himitsu::build_info::local_timestamp)
        + " (Local) / "
        + himitsu::build_info::utc_timestamp;
}

bool reset_device(UiState& state) {
    if (state.device == nullptr || !state.imgui_ready) {
        return false;
    }
    ImGui_ImplDX9_InvalidateDeviceObjects();
    const HRESULT result = state.device->Reset(&state.presentation);
    if (FAILED(result)) {
        return false;
    }
    ImGui_ImplDX9_CreateDeviceObjects();
    return true;
}

LRESULT CALLBACK window_process(
    HWND window,
    UINT message,
    WPARAM wide_parameter,
    LPARAM long_parameter
) {
    if (ImGui::GetCurrentContext() != nullptr
        && ImGui_ImplWin32_WndProcHandler(window, message, wide_parameter, long_parameter)) {
        return TRUE;
    }

    switch (message) {
        case WM_NCHITTEST: {
            POINT point{GET_X_LPARAM(long_parameter), GET_Y_LPARAM(long_parameter)};
            ScreenToClient(window, &point);
            const bool over_controls = point.x >= 170 && point.x <= 575
                && point.y >= 78 && point.y <= 360;
            return over_controls ? HTCLIENT : HTCAPTION;
        }
        case WM_SIZE:
            if (active_ui != nullptr
                && active_ui->device != nullptr
                && wide_parameter != SIZE_MINIMIZED) {
                active_ui->presentation.BackBufferWidth = LOWORD(long_parameter);
                active_ui->presentation.BackBufferHeight = HIWORD(long_parameter);
                reset_device(*active_ui);
            }
            return 0;
        case WM_SYSCOMMAND:
            if ((wide_parameter & 0xFFF0U) == SC_KEYMENU) {
                return 0;
            }
            break;
        case WM_CLOSE:
            if (active_ui != nullptr) {
                active_ui->accepted = false;
                active_ui->running = false;
            }
            return 0;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
        default:
            break;
    }
    return DefWindowProcW(window, message, wide_parameter, long_parameter);
}

bool create_window(UiState& state) {
    state.window_class.cbSize = sizeof(state.window_class);
    state.window_class.style = CS_CLASSDC;
    state.window_class.lpfnWndProc = window_process;
    state.window_class.hInstance = state.module;
    state.window_class.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512));
    state.window_class.lpszClassName = window_class_name;
    if (RegisterClassExW(&state.window_class) == 0) {
        return false;
    }

    const int screen_width = GetSystemMetrics(SM_CXSCREEN);
    const int screen_height = GetSystemMetrics(SM_CYSCREEN);
    const int left = std::max(0, (screen_width - window_width) / 2);
    const int top = std::max(0, (screen_height - window_height) / 2);
    state.window = CreateWindowExW(
        WS_EX_APPWINDOW | WS_EX_TOPMOST,
        window_class_name,
        L"Secret Verification",
        WS_POPUP,
        left,
        top,
        window_width,
        window_height,
        nullptr,
        nullptr,
        state.module,
        nullptr
    );
    if (state.window == nullptr) {
        UnregisterClassW(window_class_name, state.module);
        return false;
    }
    HRGN rounded_region = CreateRoundRectRgn(
        0,
        0,
        window_width + 1,
        window_height + 1,
        24,
        24
    );
    if (rounded_region != nullptr) {
        SetWindowRgn(state.window, rounded_region, FALSE);
    }
    ShowWindow(state.window, SW_SHOW);
    UpdateWindow(state.window);
    SetForegroundWindow(state.window);
    return true;
}

bool create_device(UiState& state) {
    state.d3d = Direct3DCreate9(D3D_SDK_VERSION);
    if (state.d3d == nullptr) {
        return false;
    }

    state.presentation = {};
    state.presentation.Windowed = TRUE;
    state.presentation.SwapEffect = D3DSWAPEFFECT_DISCARD;
    state.presentation.BackBufferFormat = D3DFMT_UNKNOWN;
    state.presentation.EnableAutoDepthStencil = TRUE;
    state.presentation.AutoDepthStencilFormat = D3DFMT_D16;
    state.presentation.PresentationInterval = D3DPRESENT_INTERVAL_ONE;
    state.presentation.hDeviceWindow = state.window;

    HRESULT result = state.d3d->CreateDevice(
        D3DADAPTER_DEFAULT,
        D3DDEVTYPE_HAL,
        state.window,
        D3DCREATE_HARDWARE_VERTEXPROCESSING,
        &state.presentation,
        &state.device
    );
    if (FAILED(result)) {
        result = state.d3d->CreateDevice(
            D3DADAPTER_DEFAULT,
            D3DDEVTYPE_HAL,
            state.window,
            D3DCREATE_SOFTWARE_VERTEXPROCESSING,
            &state.presentation,
            &state.device
        );
    }
    if (SUCCEEDED(result) && state.device != nullptr) {
        create_login_pig_texture(state);
        return true;
    }
    return false;
}

bool create_imgui(UiState& state) {
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr;
    io.LogFilename = nullptr;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    if (GetFileAttributesW(L"C:\\Windows\\Fonts\\msyh.ttc") != INVALID_FILE_ATTRIBUTES) {
        io.Fonts->AddFontFromFileTTF(
            "C:\\Windows\\Fonts\\msyh.ttc",
            22.0F,
            nullptr,
            io.Fonts->GetGlyphRangesChineseFull()
        );
    } else if (GetFileAttributesW(L"C:\\Windows\\Fonts\\segoeui.ttf") != INVALID_FILE_ATTRIBUTES) {
        io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\segoeui.ttf", 22.0F);
    }

    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding = 12.0F;
    style.FrameRounding = 2.0F;
    style.ChildRounding = 0.0F;
    style.PopupRounding = 2.0F;
    style.GrabRounding = 1.0F;
    style.WindowBorderSize = 0.0F;
    style.FrameBorderSize = 0.0F;
    style.WindowPadding = ImVec2(0.0F, 0.0F);
    style.FramePadding = ImVec2(8.0F, 6.0F);
    style.ItemSpacing = ImVec2(10.0F, 8.0F);
    style.Colors[ImGuiCol_Text] = ImVec4(0.97F, 0.97F, 0.99F, 1.00F);
    style.Colors[ImGuiCol_TextDisabled] = ImVec4(0.82F, 0.84F, 0.88F, 0.95F);
    style.Colors[ImGuiCol_WindowBg] = ImVec4(0.70F, 0.70F, 0.70F, 1.00F);
    style.Colors[ImGuiCol_FrameBg] = ImVec4(0.28F, 0.28F, 0.29F, 0.82F);
    style.Colors[ImGuiCol_FrameBgHovered] = ImVec4(0.34F, 0.34F, 0.36F, 0.90F);
    style.Colors[ImGuiCol_FrameBgActive] = ImVec4(0.38F, 0.38F, 0.40F, 0.96F);
    style.Colors[ImGuiCol_CheckMark] = ImVec4(1.00F, 1.00F, 1.00F, 1.00F);
    style.Colors[ImGuiCol_Button] = ImVec4(0.12F, 0.43F, 0.96F, 1.00F);
    style.Colors[ImGuiCol_ButtonHovered] = ImVec4(0.19F, 0.50F, 1.00F, 1.00F);
    style.Colors[ImGuiCol_ButtonActive] = ImVec4(0.08F, 0.35F, 0.84F, 1.00F);

    if (!ImGui_ImplWin32_Init(state.window)) {
        ImGui::DestroyContext();
        return false;
    }
    if (!ImGui_ImplDX9_Init(state.device)) {
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext();
        return false;
    }
    state.imgui_ready = true;
    return true;
}

struct Bubble {
    ImVec2 position;
    float radius;
    float speed;
    int alpha;
};

void reset_bubble(Bubble& bubble, std::mt19937& generator, bool initial) {
    std::uniform_real_distribution<float> radius(4.0F, 28.0F);
    std::uniform_real_distribution<float> speed(16.0F, 44.0F);
    std::uniform_real_distribution<float> x(0.0F, static_cast<float>(window_width));
    std::uniform_real_distribution<float> y(0.0F, static_cast<float>(window_height));
    std::uniform_int_distribution<int> alpha(55, 145);
    bubble.radius = radius(generator);
    bubble.speed = speed(generator);
    bubble.alpha = alpha(generator);
    if (initial) {
        bubble.position = ImVec2(x(generator), y(generator));
    } else {
        std::uniform_real_distribution<float> extra_x(0.0F, 180.0F);
        std::uniform_real_distribution<float> entry_y(-140.0F, 120.0F);
        bubble.position = ImVec2(
            window_width + bubble.radius + extra_x(generator),
            entry_y(generator)
        );
    }
}

void draw_background(ImDrawList* draw_list, const ImVec2& origin) {
    draw_list->AddRectFilled(
        origin,
        ImVec2(origin.x + window_width, origin.y + window_height),
        IM_COL32(176, 180, 187, 255),
        12.0F
    );
    draw_list->AddRectFilled(
        origin,
        ImVec2(origin.x + window_width, origin.y + 5.0F),
        IM_COL32(31, 117, 250, 255)
    );

    constexpr std::size_t bubble_count = 28;
    static std::array<Bubble, bubble_count> bubbles{};
    static std::mt19937 generator(GetTickCount());
    static bool initialized = false;
    if (!initialized) {
        for (Bubble& bubble : bubbles) reset_bubble(bubble, generator, true);
        initialized = true;
    }

    const float delta = std::min(ImGui::GetIO().DeltaTime, 0.05F);
    for (Bubble& bubble : bubbles) {
        bubble.position.x -= bubble.speed * delta;
        bubble.position.y += bubble.speed * 0.68F * delta;
        if (bubble.position.x < -bubble.radius
            || bubble.position.y > window_height + bubble.radius) {
            reset_bubble(bubble, generator, false);
        }
        draw_list->AddCircleFilled(
            ImVec2(origin.x + bubble.position.x, origin.y + bubble.position.y),
            bubble.radius,
            IM_COL32(255, 255, 255, bubble.alpha),
            40
        );
    }
}

void render_window(UiState& state) {
    constexpr float form_left = 175.0F;
    constexpr float form_width = 400.0F;
    constexpr float button_gap = 14.0F;
    constexpr float button_width = (form_width - button_gap) * 0.5F;
    const bool authenticating = state.authenticating.load(std::memory_order_acquire);
    ImGui::SetNextWindowPos(ImVec2(0.0F, 0.0F));
    ImGui::SetNextWindowSize(ImVec2(window_width, window_height));
    ImGui::Begin(
        "##himitsu-validation",
        nullptr,
        ImGuiWindowFlags_NoDecoration
            | ImGuiWindowFlags_NoMove
            | ImGuiWindowFlags_NoResize
            | ImGuiWindowFlags_NoScrollbar
            | ImGuiWindowFlags_NoSavedSettings
    );

    ImDrawList* draw_list = ImGui::GetWindowDrawList();
    const ImVec2 origin = ImGui::GetWindowPos();
    draw_background(draw_list, origin);

    ImGui::SetWindowFontScale(1.45F);
    const char* title = "Secret Login";
    const float title_width = ImGui::CalcTextSize(title).x;
    ImGui::SetCursorPos(ImVec2((window_width - title_width) * 0.5F, 27.0F));
    ImGui::TextColored(ImVec4(0.08F, 0.43F, 1.00F, 1.00F), "%s", title);
    ImGui::SetWindowFontScale(1.0F);

    ImGui::SetCursorPos(ImVec2(form_left, 88.0F));
    ImGui::TextUnformatted("用户名");
    ImGui::SetCursorPos(ImVec2(form_left, 119.0F));
    ImGui::SetNextItemWidth(form_width);
    ImGui::BeginDisabled(authenticating);
    ImGui::InputTextWithHint(
        "##username",
        "请输入用户名",
        state.username.data(),
        state.username.size()
    );
    ImGui::EndDisabled();

    ImGui::SetCursorPos(ImVec2(form_left, 177.0F));
    ImGui::TextUnformatted("密码");
    ImGui::SetCursorPos(ImVec2(form_left, 207.0F));
    ImGui::SetNextItemWidth(form_width);
    ImGui::BeginDisabled(authenticating);
    ImGui::InputTextWithHint(
        "##password",
        "请输入密码",
        state.password.data(),
        state.password.size(),
        ImGuiInputTextFlags_Password
    );
    ImGui::EndDisabled();

    ImGui::SetCursorPos(ImVec2(form_left, 258.0F));
    ImGui::BeginDisabled(authenticating);
    ImGui::Checkbox("Remember Me", &state.remember_me);
    ImGui::EndDisabled();
    const float build_code_width = ImGui::CalcTextSize("[Build Code]").x;
    ImGui::SetCursorPos(ImVec2(form_left + form_width - build_code_width, 260.0F));
    ImGui::TextColored(ImVec4(0.08F, 0.43F, 1.00F, 1.00F), "[Build Code]");
    if (ImGui::IsItemHovered()) {
        const std::string built_at = dll_build_time();
        ImGui::SetTooltip("DLL Build: %s", built_at.c_str());
    }

    ImGui::SetCursorPos(ImVec2(form_left, 309.0F));
    ImGui::BeginDisabled(authenticating);
    if (ImGui::Button("Sign In", ImVec2(button_width, 42.0F))) {
        start_authentication(state);
    }
    ImGui::EndDisabled();
    ImGui::SetCursorPos(ImVec2(form_left + button_width + button_gap, 309.0F));
    if (ImGui::Button("Exit", ImVec2(button_width, 42.0F))) {
        state.accepted = false;
        state.running = false;
    }

    if (authenticating) {
        const float target_progress = state.authentication_progress.load(std::memory_order_acquire);
        const float smoothing = 1.0F - std::exp(-7.5F * ImGui::GetIO().DeltaTime);
        state.displayed_progress += (target_progress - state.displayed_progress) * smoothing;
        if (target_progress - state.displayed_progress < 0.002F) {
            state.displayed_progress = target_progress;
        }
        std::string step;
        {
            std::lock_guard lock(state.authentication_mutex);
            step = state.authentication_step;
        }
        ImGui::SetCursorPos(ImVec2(form_left, 368.0F));
        ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.19F, 0.20F, 0.22F, 1.00F));
        ImGui::PushStyleColor(ImGuiCol_PlotHistogram, ImVec4(0.08F, 0.43F, 1.00F, 1.00F));
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 3.0F);
        ImGui::ProgressBar(state.displayed_progress, ImVec2(form_width, 10.0F), "");
        ImGui::PopStyleVar();
        ImGui::PopStyleColor(2);

        ImGui::SetWindowFontScale(1.08F);
        ImGui::SetCursorPos(ImVec2(15.0F, 408.0F));
        ImGui::TextColored(ImVec4(0.92F, 0.94F, 1.00F, 1.00F), "%s", step.c_str());
        ImGui::SetWindowFontScale(1.0F);
    }

    if (state.login_pig_texture != nullptr) {
        const ULONGLONG tick = GetTickCount64();
        if (state.login_pig_next_frame == 0) {
            state.login_pig_next_frame = tick
                + himitsu::validation::zhu_animation::frame_delays_ms[0];
        }
        unsigned int advances = 0;
        while (tick >= state.login_pig_next_frame
            && advances < himitsu::validation::zhu_animation::frame_count) {
            state.login_pig_frame = (state.login_pig_frame + 1)
                % himitsu::validation::zhu_animation::frame_count;
            state.login_pig_next_frame +=
                himitsu::validation::zhu_animation::frame_delays_ms[state.login_pig_frame];
            ++advances;
        }
        if (advances == himitsu::validation::zhu_animation::frame_count
            && tick >= state.login_pig_next_frame) {
            state.login_pig_next_frame = tick
                + himitsu::validation::zhu_animation::frame_delays_ms[state.login_pig_frame];
        }
        const float frame_count = static_cast<float>(
            himitsu::validation::zhu_animation::frame_count
        );
        const float uv_top = static_cast<float>(state.login_pig_frame) / frame_count;
        const float uv_bottom = static_cast<float>(state.login_pig_frame + 1) / frame_count;
        ImGui::SetCursorPos(ImVec2(593.0F, 312.0F));
        ImGui::Image(
            reinterpret_cast<ImTextureID>(state.login_pig_texture),
            ImVec2(
                static_cast<float>(himitsu::validation::zhu_animation::frame_width),
                static_cast<float>(himitsu::validation::zhu_animation::frame_height)
            ),
            ImVec2(0.0F, uv_top),
            ImVec2(1.0F, uv_bottom)
        );
    }

    std::time_t now = std::time(nullptr);
    std::tm local{};
    localtime_s(&local, &now);
    char time_text[32]{};
    std::strftime(time_text, sizeof(time_text), "%Y-%m-%d %H:%M:%S", &local);
    ImGui::SetWindowFontScale(1.20F);
    const float time_width = ImGui::CalcTextSize(time_text).x;
    ImGui::SetCursorPos(ImVec2(window_width - time_width - 22.0F, 404.0F));
    ImGui::TextColored(ImVec4(0.08F, 0.43F, 1.00F, 1.00F), "%s", time_text);
    ImGui::SetWindowFontScale(1.0F);
    ImGui::End();
}

void destroy(UiState& state) {
    if (state.imgui_ready) {
        ImGui_ImplDX9_Shutdown();
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext();
        state.imgui_ready = false;
    }
    if (state.login_pig_texture != nullptr) {
        state.login_pig_texture->Release();
        state.login_pig_texture = nullptr;
    }
    if (state.device != nullptr) {
        state.device->Release();
        state.device = nullptr;
    }
    if (state.d3d != nullptr) {
        state.d3d->Release();
        state.d3d = nullptr;
    }
    if (state.window != nullptr) {
        DestroyWindow(state.window);
        state.window = nullptr;
    }
    if (state.window_class.lpszClassName != nullptr) {
        UnregisterClassW(state.window_class.lpszClassName, state.window_class.hInstance);
    }
    if (state.com_initialized) {
        CoUninitialize();
        state.com_initialized = false;
    }
}
}

namespace himitsu::validation::ui {
Result run(HMODULE module) {
    UiState state{};
    state.module = module;
    load_credentials(state);
    active_ui = &state;

    himitsu::validation::game_pause::prepare();

    if (!create_window(state) || !create_device(state) || !create_imgui(state)) {
        destroy(state);
        active_ui = nullptr;
        return Result::initialization_failed;
    }

    bool pause_engaged = false;
    while (state.running) {
        if (pause_engaged) {
            himitsu::validation::game_pause::enforce();
        }
        MSG message{};
        while (PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE)) {
            TranslateMessage(&message);
            DispatchMessageW(&message);
            if (message.message == WM_QUIT) {
                state.running = false;
                state.accepted = false;
            }
        }
        if (!state.running) {
            break;
        }
        if ((GetAsyncKeyState(VK_ESCAPE) & 1) != 0) {
            state.accepted = false;
            state.running = false;
            break;
        }

        poll_authentication(state);
        if (!state.running) break;

        ImGui_ImplDX9_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();
        render_window(state);
        ImGui::EndFrame();

        state.device->SetRenderState(D3DRS_ZENABLE, FALSE);
        state.device->SetRenderState(D3DRS_ALPHABLENDENABLE, FALSE);
        state.device->SetRenderState(D3DRS_SCISSORTESTENABLE, FALSE);
        state.device->Clear(
            0,
            nullptr,
            D3DCLEAR_TARGET | D3DCLEAR_ZBUFFER,
            D3DCOLOR_RGBA(6, 8, 20, 255),
            1.0F,
            0
        );
        if (SUCCEEDED(state.device->BeginScene())) {
            ImGui::Render();
            ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
            state.device->EndScene();
        }

        const HRESULT present = state.device->Present(nullptr, nullptr, nullptr, nullptr);
        if (present == D3DERR_DEVICELOST
            && state.device->TestCooperativeLevel() == D3DERR_DEVICENOTRESET) {
            reset_device(state);
        }
        if (!pause_engaged && SUCCEEDED(present)) {

            himitsu::validation::game_pause::engage(state.window);
            pause_engaged = true;
        }
        Sleep(5);
    }

    if (state.authentication_thread.joinable()) {
        state.authentication_thread.join();
    }
    const bool accepted = state.accepted;
    destroy(state);
    active_ui = nullptr;
    return accepted ? Result::approved : Result::rejected;
}
}

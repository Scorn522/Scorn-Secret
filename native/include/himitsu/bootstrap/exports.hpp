#pragma once

#include <windows.h>

extern "C" __declspec(dllexport) int __cdecl HimitsuBootstrap(
    const wchar_t* game_directory,
    const wchar_t* mod_path
);

extern "C" __declspec(dllexport) int __cdecl HimitsuEarlyGuard(int disable_jvmti);

extern "C" __declspec(dllexport) int __cdecl HimitsuLoadSources(const wchar_t* archive, void* reserved);

#include <windows.h>

#include "himitsu/bootstrap/runtime_bootstrap.hpp"
#include "himitsu/validation/validation_gate.hpp"

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
        himitsu::bootstrap::set_module(module);

        himitsu::validation::begin(module);
    }
    return TRUE;
}

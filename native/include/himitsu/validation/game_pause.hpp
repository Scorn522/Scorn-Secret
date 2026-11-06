#pragma once

#include <windows.h>

namespace himitsu::validation::game_pause {

void prepare();

void engage(HWND validation_window);

void enforce();

void release();

}

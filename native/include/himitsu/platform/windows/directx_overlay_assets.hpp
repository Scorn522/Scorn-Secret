#pragma once

#include <d3d9.h>

namespace himitsu::platform::windows::directx_assets {
struct BgraImage {
    const unsigned char* pixels;
    unsigned int width;
    unsigned int height;
};

BgraImage death_title_image();
void draw_death_title(IDirect3DDevice9* device, long width, long height);
void release_device(IDirect3DDevice9* device);
void release_all();
}

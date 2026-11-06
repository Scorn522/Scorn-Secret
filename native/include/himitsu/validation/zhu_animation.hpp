#pragma once

#include <array>

namespace himitsu::validation::zhu_animation {
inline constexpr unsigned int frame_width = 135;
inline constexpr unsigned int frame_height = 88;
inline constexpr unsigned int frame_count = 30;
inline constexpr std::array<unsigned int, frame_count> frame_delays_ms = {20,20,20,20,20,20,20,20,20,20,20,20,20,20,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30};
}

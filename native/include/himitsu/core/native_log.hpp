#pragma once

#include <windows.h>

namespace himitsu::core::log {
enum class Level {
    debug,
    info,
    warning,
    error
};

void initialize(HMODULE module);
void shutdown();
void write(Level level, const char* component, const char* format, ...);
}

#define HIMITSU_LOG_DEBUG(component, ...) \
    ::himitsu::core::log::write(::himitsu::core::log::Level::debug, component, __VA_ARGS__)
#define HIMITSU_LOG_INFO(component, ...) \
    ::himitsu::core::log::write(::himitsu::core::log::Level::info, component, __VA_ARGS__)
#define HIMITSU_LOG_WARNING(component, ...) \
    ::himitsu::core::log::write(::himitsu::core::log::Level::warning, component, __VA_ARGS__)
#define HIMITSU_LOG_ERROR(component, ...) \
    ::himitsu::core::log::write(::himitsu::core::log::Level::error, component, __VA_ARGS__)

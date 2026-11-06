if(NOT DEFINED OUTPUT OR OUTPUT STREQUAL "")
    message(FATAL_ERROR "OUTPUT is required")
endif()

string(TIMESTAMP HIMITSU_BUILD_LOCAL "%Y-%m-%d %H:%M:%S")
string(TIMESTAMP HIMITSU_BUILD_UTC "%Y-%m-%d %H:%M:%S UTC" UTC)

get_filename_component(OUTPUT_DIRECTORY "${OUTPUT}" DIRECTORY)
file(MAKE_DIRECTORY "${OUTPUT_DIRECTORY}")
file(WRITE "${OUTPUT}"
"#pragma once\n\n"
"namespace himitsu::build_info {\n"
"inline constexpr char local_timestamp[] = \"${HIMITSU_BUILD_LOCAL}\";\n"
"inline constexpr char utc_timestamp[] = \"${HIMITSU_BUILD_UTC}\";\n"
"}\n"
)

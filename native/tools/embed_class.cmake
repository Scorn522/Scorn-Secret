if(NOT DEFINED INPUT OR NOT DEFINED OUTPUT)
    message(FATAL_ERROR "INPUT and OUTPUT are required")
endif()

if(NOT DEFINED SYMBOL)
    set(SYMBOL "native_bridge_class")
endif()

file(READ "${INPUT}" CLASS_HEX HEX)
string(LENGTH "${CLASS_HEX}" HEX_LENGTH)
math(EXPR BYTE_COUNT "${HEX_LENGTH} / 2")

string(REGEX REPLACE "([0-9A-Fa-f][0-9A-Fa-f])" "0x\\1," BODY "${CLASS_HEX}")

file(WRITE "${OUTPUT}"
"#pragma once\n\n#include <cstddef>\n\nnamespace himitsu::embedded {\ninline constexpr unsigned char ${SYMBOL}[] = {${BODY}};\ninline constexpr std::size_t ${SYMBOL}_size = ${BYTE_COUNT};\n}\n")

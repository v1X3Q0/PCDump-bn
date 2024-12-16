cmake_dummy = """
cmake_minimum_required(VERSION 3.13 FATAL_ERROR)
project({})

set(SOURCE_LIST
    {}
)

add_library(${{PROJECT_NAME}} SHARED ${{SOURCE_LIST}})
"""

types_macroprefix="""
#ifndef BN_TYPE_PARSER
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>
#include <wchar.h>

#define __packed
#define __noreturn
#define __convention(name)
#define __syscall(number)
#define __offset(...)
#define __padding
#define __named(name)
#define __inherited
#define __base(name, offset)
#define __ptr_offset(offset)
#define __data_var_refs
#define __vtable
#define __pure
#define __ptr_width(width)
#define __ptr8
#define __ptr16
// __ptr32 and __ptr64 are real keywords on MSVC
// #define __ptr32
// #define __ptr64
#define __based(...)
typedef uint16_t wchar16;
typedef uint32_t wchar32;
#endif

"""
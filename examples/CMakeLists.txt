# examples/CMakeLists.txt - IDASQL Example Programs
#
cmake_minimum_required(VERSION 3.20)

# Build from repository root:
#   cmake -S . -B build
#   cmake --build build --config Release --target example_basic
#
# Run:
#   Windows: set PATH=%IDASDK%\src\bin;%PATH%
#            build\Release\example_basic.exe database.i64
#   Linux:   LD_LIBRARY_PATH=$IDASDK/src/bin ./build/example_basic database.i64

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    project(idasql_examples LANGUAGES NONE)
    message(FATAL_ERROR
        "idasql examples are built from the repository root.\n"
        "Use:\n"
        "  cmake -S . -B build\n"
        "  cmake --build build --config Release --target example_basic"
    )
endif()

if(NOT TARGET idasql)
    message(FATAL_ERROR "idasql_examples requires parent target 'idasql'.")
endif()

if(NOT TARGET xsql::xsql)
    message(FATAL_ERROR "idasql_examples requires parent target 'xsql::xsql'.")
endif()

set(IDASQL_EXAMPLE_LIB idasql)

# Helper function to create examples
function(add_idasql_example name)
    ida_add_idalib(${name}
        TYPE EXECUTABLE
        SOURCES ${name}.cpp
    )
    target_link_libraries(${name} PRIVATE ${IDASQL_EXAMPLE_LIB} xsql::xsql)
    target_compile_definitions(${name} PRIVATE USE_IDA_SDK USE_HEXRAYS)
    if(MSVC)
        target_compile_options(${name} PRIVATE /bigobj)
    endif()

    # Platform-specific settings
    if(MSVC)
        file(TO_NATIVE_PATH "${IDABIN}" IDABIN_NATIVE)
        set_target_properties(${name} PROPERTIES
            VS_DEBUGGER_ENVIRONMENT "PATH=${IDABIN_NATIVE};%PATH%"
        )
    elseif(APPLE)
        get_filename_component(IDASQL_IDA_RUNTIME_DIR "${IDA_LIB_PATH}" DIRECTORY)
        set(IDASQL_MACOS_APP_RUNTIME_DIR "" CACHE PATH
            "Path to an installed IDA app Contents/MacOS directory for runtime dylibs")
        set(IDASQL_MACOS_RPATHS "@executable_path")
        set(_idasql_macos_runtime_dir "${IDASQL_MACOS_APP_RUNTIME_DIR}")
        if(NOT _idasql_macos_runtime_dir)
            file(GLOB _idasql_macos_runtime_candidates "/Applications/IDA Professional*.app/Contents/MacOS")
            foreach(_candidate IN LISTS _idasql_macos_runtime_candidates)
                if(EXISTS "${_candidate}/libida.dylib" AND EXISTS "${_candidate}/libidalib.dylib")
                    set(_idasql_macos_runtime_dir "${_candidate}")
                    break()
                endif()
            endforeach()
        endif()
        if(_idasql_macos_runtime_dir)
            list(APPEND IDASQL_MACOS_RPATHS "${_idasql_macos_runtime_dir}")
        endif()
        list(APPEND IDASQL_MACOS_RPATHS "${IDASQL_IDA_RUNTIME_DIR}")
        list(JOIN IDASQL_MACOS_RPATHS ";" IDASQL_MACOS_INSTALL_RPATH)
        set_target_properties(${name} PROPERTIES
            BUILD_WITH_INSTALL_RPATH TRUE
            INSTALL_RPATH "${IDASQL_MACOS_INSTALL_RPATH}"
        )
    elseif(UNIX)
        get_filename_component(IDASQL_IDA_RUNTIME_DIR "${IDA_LIB_PATH}" DIRECTORY)
        set_target_properties(${name} PROPERTIES
            BUILD_WITH_INSTALL_RPATH TRUE
            INSTALL_RPATH "$ORIGIN;${IDASQL_IDA_RUNTIME_DIR}"
        )
    endif()
endfunction()

# Example executables
add_idasql_example(example_basic)
add_idasql_example(example_functions)
add_idasql_example(example_strings)
add_idasql_example(example_instructions)
add_idasql_example(example_decompiler)
add_idasql_example(example_custom_vtable)
add_idasql_example(example_plugin_style)
add_idasql_example(example_grep_search)
add_idasql_example(example_grep_entities)
add_idasql_example(example_breakpoints)

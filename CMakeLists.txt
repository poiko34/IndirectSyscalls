cmake_minimum_required(VERSION 3.15)

project(IndirectSyscalls CXX ASM)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(POLICY CMP0091)
    cmake_policy(SET CMP0091 NEW)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

if(MSVC)
    set(ASM_SOURCE "src/syscall.asm")
elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    set(ASM_SOURCE "src/syscall.s")
endif()

add_executable(IndirectSyscalls
    src/main.cpp
    src/IndirectSyscalls.cpp
    ${ASM_SOURCE}
)

target_compile_options(IndirectSyscalls PRIVATE
    $<$<AND:$<CXX_COMPILER_ID:MSVC>,$<COMPILE_LANGUAGE:CXX>>:/Os /Zi>
    $<$<AND:$<CXX_COMPILER_ID:Clang>,$<COMPILE_LANGUAGE:CXX>>:-Oz -gcodeview>
)

target_link_options(IndirectSyscalls PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/DEBUG /OPT:REF /OPT:ICF>
    
    $<$<CXX_COMPILER_ID:Clang>:-Wl,-pdb=IndirectSyscalls.pdb -static>
)
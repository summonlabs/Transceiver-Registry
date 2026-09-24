# Copyright 2026 Summon Software Labs
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#     http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.24)
project(TransceiverRegistry VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(TRXREG_BUILD_TESTS "Build the Transceiver Registry test suite" ON)
option(TRXREG_BUILD_TOOLS "Build the CLI, server, and benchmark utilities" ON)
option(TRXREG_BUILD_EXAMPLES "Build the Transceiver Registry examples" ON)
option(TRXREG_INSTALL "Generate install rules and the CMake package" ON)
option(TRXREG_ENABLE_ASAN "Build with AddressSanitizer/UBSan where supported" OFF)
option(TRXREG_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" ON)

include(CTest)
include(GNUInstallDirs)
find_package(Threads REQUIRED)

if(MSVC)
  add_definitions(-D_CRT_SECURE_NO_WARNINGS -DNOMINMAX -DWIN32_LEAN_AND_MEAN)
endif()

# Strict warnings for every first-party target.
function(trxreg_strict_warnings target)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /permissive- /Zc:__cplusplus /EHsc /utf-8)
    if(TRXREG_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE /WX)
    endif()
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion)
    if(TRXREG_WARNINGS_AS_ERRORS)
      target_compile_options(${target} PRIVATE -Werror)
    endif()
  endif()
endfunction()

function(trxreg_sanitizers target)
  if(TRXREG_ENABLE_ASAN)
    if(MSVC)
      target_compile_options(${target} PRIVATE /fsanitize=address)
      target_link_options(${target} PRIVATE /INCREMENTAL:NO)
    else()
      target_compile_options(${target} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
      target_link_options(${target} PRIVATE -fsanitize=address,undefined)
    endif()
  endif()
endfunction()

add_subdirectory(src)
if(TRXREG_BUILD_TOOLS)
  add_subdirectory(tools)
endif()
if(TRXREG_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()
if(TRXREG_BUILD_TESTS)
  add_subdirectory(tests)
endif()

if(TRXREG_INSTALL)
  # The library is always installed; the tools are installed when they are built.
  set(TRXREG_INSTALL_TARGETS trxreg)
  foreach(tool_target IN ITEMS trxreg_server trxreg_cli trxreg_bench)
    if(TARGET ${tool_target})
      list(APPEND TRXREG_INSTALL_TARGETS ${tool_target})
    endif()
  endforeach()
  install(TARGETS ${TRXREG_INSTALL_TARGETS}
          EXPORT TransceiverRegistryTargets
          RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
          ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
          LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
  install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/trxreg
          DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
          FILES_MATCHING PATTERN "*.hpp")
  install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE ${CMAKE_CURRENT_SOURCE_DIR}/NOTICE
          DESTINATION ${CMAKE_INSTALL_DATADIR}/trxreg)
  install(EXPORT TransceiverRegistryTargets
          FILE TransceiverRegistryTargets.cmake
          NAMESPACE TransceiverRegistry::
          DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/TransceiverRegistry)
  include(CMakePackageConfigHelpers)
  write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/TransceiverRegistryConfigVersion.cmake
    VERSION ${PROJECT_VERSION} COMPATIBILITY SameMajorVersion)
  configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/TransceiverRegistryConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/TransceiverRegistryConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/TransceiverRegistry)
  install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/TransceiverRegistryConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/TransceiverRegistryConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/TransceiverRegistry)
endif()

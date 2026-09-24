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

# Standalone downstream consumer of the installed Transceiver Registry package.
#
# This project is deliberately NOT part of the Transceiver Registry build: no
# CMakeLists.txt in the repository adds it with add_subdirectory(), and it never
# reads the repository's build tree. It resolves the library exclusively through
# find_package(TransceiverRegistry), so it links whatever an installed package
# exports - the same way an unrelated product would.

cmake_minimum_required(VERSION 3.24)
project(TransceiverRegistryDownstream LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# The only dependency: the installed package, found through CMAKE_PREFIX_PATH.
find_package(TransceiverRegistry REQUIRED)

add_executable(trxreg_downstream main.cpp)
target_link_libraries(trxreg_downstream PRIVATE TransceiverRegistry::trxreg)

if(MSVC)
  target_compile_options(trxreg_downstream PRIVATE /W4 /permissive- /Zc:__cplusplus /EHsc /utf-8 /WX)
else()
  target_compile_options(trxreg_downstream PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

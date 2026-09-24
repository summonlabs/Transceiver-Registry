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

add_library(trxreg
  canonical.cpp
  capability.cpp
  clock.cpp
  codec.cpp
  compatibility.cpp
  digest.cpp
  health.cpp
  identity.cpp
  lifecycle.cpp
  net.cpp
  registry.cpp
  snapshot.cpp
  taxonomy.cpp
  wire.cpp
)

target_include_directories(trxreg
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

target_link_libraries(trxreg PUBLIC Threads::Threads)
if(WIN32)
  target_link_libraries(trxreg PUBLIC ws2_32)
endif()

set_target_properties(trxreg PROPERTIES
  VERSION ${PROJECT_VERSION}
  SOVERSION ${PROJECT_VERSION_MAJOR}
  POSITION_INDEPENDENT_CODE ON)

trxreg_strict_warnings(trxreg)
trxreg_sanitizers(trxreg)

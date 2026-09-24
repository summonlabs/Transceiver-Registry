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

add_executable(trxreg_tests
  test_main.cpp
  test_canonical.cpp
  test_identity.cpp
  test_lifecycle.cpp
  test_health.cpp
  test_compatibility.cpp
  test_persistence.cpp
  test_concurrency.cpp
  test_wire.cpp
  test_property.cpp
  test_multiprocess.cpp
)

target_link_libraries(trxreg_tests PRIVATE trxreg)
target_include_directories(trxreg_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
# The multi-process suite launches the real server and CLI binaries. When the
# tools are not part of the build, those tests report that they cannot run
# instead of silently passing.
if(TARGET trxreg_server)
  target_compile_definitions(trxreg_tests PRIVATE TRXREG_SERVER_EXECUTABLE="$<TARGET_FILE:trxreg_server>")
  add_dependencies(trxreg_tests trxreg_server)
endif()
if(TARGET trxreg_cli)
  target_compile_definitions(trxreg_tests PRIVATE TRXREG_CLI_EXECUTABLE="$<TARGET_FILE:trxreg_cli>")
  add_dependencies(trxreg_tests trxreg_cli)
endif()
trxreg_strict_warnings(trxreg_tests)
trxreg_sanitizers(trxreg_tests)

# One CTest entry per suite. No TIMEOUT property is set anywhere: a test that
# cannot finish is a defect to diagnose, never something to be timed out and
# reported as passing.
set(TRXREG_TEST_SUITES
  canonical
  identity
  lifecycle
  health
  compatibility
  persistence
  concurrency
  wire
  property
  multiprocess)

foreach(suite IN LISTS TRXREG_TEST_SUITES)
  if(suite STREQUAL "multiprocess" AND NOT TARGET trxreg_server)
    # The multi-process proof needs the server binary; without it the suite
    # reports the missing prerequisite instead of being registered as passing.
    continue()
  endif()
  add_test(NAME ${suite} COMMAND trxreg_tests --filter=${suite})
endforeach()

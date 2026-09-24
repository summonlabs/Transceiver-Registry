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

# The server is a separate OS process on purpose: the multi-process proof in the
# test suite spawns it and kills it at real lifecycle boundaries.
add_executable(trxreg_server server_main.cpp)
target_link_libraries(trxreg_server PRIVATE trxreg)
trxreg_strict_warnings(trxreg_server)
trxreg_sanitizers(trxreg_server)

add_executable(trxreg_cli cli_main.cpp)
target_link_libraries(trxreg_cli PRIVATE trxreg)
trxreg_strict_warnings(trxreg_cli)
trxreg_sanitizers(trxreg_cli)

add_executable(trxreg_bench bench_main.cpp)
target_link_libraries(trxreg_bench PRIVATE trxreg)
trxreg_strict_warnings(trxreg_bench)
trxreg_sanitizers(trxreg_bench)

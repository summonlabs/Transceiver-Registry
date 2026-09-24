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

add_executable(trxreg_example_lifecycle lifecycle_example.cpp)
target_link_libraries(trxreg_example_lifecycle PRIVATE trxreg)
trxreg_strict_warnings(trxreg_example_lifecycle)
trxreg_sanitizers(trxreg_example_lifecycle)

add_executable(trxreg_example_compatibility compatibility_example.cpp)
target_link_libraries(trxreg_example_compatibility PRIVATE trxreg)
trxreg_strict_warnings(trxreg_example_compatibility)
trxreg_sanitizers(trxreg_example_compatibility)

add_executable(trxreg_example_transport transport_example.cpp)
target_link_libraries(trxreg_example_transport PRIVATE trxreg)
trxreg_strict_warnings(trxreg_example_transport)
trxreg_sanitizers(trxreg_example_transport)

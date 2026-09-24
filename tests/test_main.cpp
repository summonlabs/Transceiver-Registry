// Copyright 2026 Summon Software Labs
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "test_support.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace trxreg::test {
namespace {

std::vector<std::string>* g_failures = nullptr;
int g_checks = 0;
const char* g_current_test = "";

}  // namespace

void register_test(const char* name, void (*function)()) { all_tests().push_back(new TestCase{name, function}); }

std::vector<const TestCase*>& all_tests() {
  static std::vector<const TestCase*> tests;
  return tests;
}

void report_failure(const char* file, int line, const std::string& message) {
  if (g_failures == nullptr) {
    static std::vector<std::string> fallback;
    g_failures = &fallback;
  }
  std::string rendered = std::string(g_current_test) + " " + file + ":" + std::to_string(line) + ": " + message;
  g_failures->push_back(rendered);
  std::fprintf(stderr, "FAIL %s\n", rendered.c_str());
}

void note(const std::string& message) { std::fprintf(stdout, "note: %s\n", message.c_str()); }

int run_all(int argc, char** argv) {
  std::vector<std::string> filters;
  for (int i = 1; i < argc; ++i) {
    const std::string argument = argv[i];
    if (argument == "--filter" && i + 1 < argc) {
      filters.emplace_back(argv[++i]);
      continue;
    }
    if (argument.rfind("--filter=", 0) == 0) {
      filters.push_back(argument.substr(std::strlen("--filter=")));
      continue;
    }
    std::fprintf(stderr, "unknown argument: %s\n", argument.c_str());
    return 2;
  }

  std::vector<std::string> failures;
  g_failures = &failures;
  int executed = 0;
  for (const TestCase* test : all_tests()) {
    if (!filters.empty()) {
      bool matches = false;
      for (const std::string& filter : filters) {
        if (test->name.find(filter) != std::string::npos) {
          matches = true;
          break;
        }
      }
      if (!matches) {
        continue;
      }
    }
    ++executed;
    g_current_test = test->name.c_str();
    std::fprintf(stdout, "== %s\n", test->name.c_str());
    std::fflush(stdout);
    test->function();
  }

  std::fprintf(stdout, "\n%d test(s) executed, %d failure(s)\n", executed, static_cast<int>(failures.size()));
  if (executed == 0) {
    std::fprintf(stderr, "no test matched the requested filter\n");
    return 2;
  }
  return failures.empty() ? 0 : 1;
}

}  // namespace trxreg::test

int main(int argc, char** argv) { return trxreg::test::run_all(argc, argv); }

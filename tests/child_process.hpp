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

#pragma once

// Minimal independent-process helper for the multi-process suite.
//
// The child runs as a real OS process with its own address space and its own
// registry: nothing here is a thread pretending to be a process. The test reads
// the child's readiness line with a blocking pipe read - there is no polling
// loop, no sleep, and no timeout: if the child dies, the pipe reaches end of
// file and the test fails with that observation.

#include <string>
#include <vector>

#if defined(_WIN32)
#if !defined(NOMINMAX)
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
extern char** environ;
#endif

namespace trxreg::test {

class ChildProcess {
 public:
  ChildProcess() = default;
  ~ChildProcess() { static_cast<void>(kill()); }

  ChildProcess(const ChildProcess&) = delete;
  ChildProcess& operator=(const ChildProcess&) = delete;

  /// Start a child with its standard output captured. Returns false with a
  /// diagnostic when the process could not be created.
  bool start(const std::string& executable, const std::vector<std::string>& arguments, std::string& error) {
    if (running_) {
      error = "a child process is already running";
      return false;
    }
#if defined(_WIN32)
    SECURITY_ATTRIBUTES attributes{};
    attributes.nLength = sizeof(attributes);
    attributes.bInheritHandle = TRUE;
    HANDLE read_end = nullptr;
    HANDLE write_end = nullptr;
    if (::CreatePipe(&read_end, &write_end, &attributes, 0) == 0) {
      error = "CreatePipe failed";
      return false;
    }
    if (::SetHandleInformation(read_end, HANDLE_FLAG_INHERIT, 0) == 0) {
      ::CloseHandle(read_end);
      ::CloseHandle(write_end);
      error = "SetHandleInformation failed";
      return false;
    }
    STARTUPINFOA startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdOutput = write_end;
    startup.hStdError = write_end;
    startup.hStdInput = nullptr;

    std::string command_line = quote(executable);
    for (const std::string& argument : arguments) {
      command_line += " ";
      command_line += quote(argument);
    }
    std::vector<char> mutable_command(command_line.begin(), command_line.end());
    mutable_command.push_back('\0');

    PROCESS_INFORMATION information{};
    const BOOL created = ::CreateProcessA(nullptr, mutable_command.data(), nullptr, nullptr, TRUE,
                                          CREATE_NO_WINDOW, nullptr, nullptr, &startup, &information);
    ::CloseHandle(write_end);
    if (created == 0) {
      ::CloseHandle(read_end);
      error = "CreateProcess failed";
      return false;
    }
    ::CloseHandle(information.hThread);
    read_end_ = read_end;
    process_ = information.hProcess;
    running_ = true;
    return true;
#else
    int pipe_fds[2] = {-1, -1};
    if (::pipe(pipe_fds) != 0) {
      error = "pipe failed";
      return false;
    }
    std::vector<std::string> storage;
    storage.push_back(executable);
    storage.insert(storage.end(), arguments.begin(), arguments.end());
    std::vector<char*> argv;
    argv.reserve(storage.size() + 1);
    for (std::string& entry : storage) {
      argv.push_back(entry.data());
    }
    argv.push_back(nullptr);

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, pipe_fds[1], STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&actions, pipe_fds[1], STDERR_FILENO);
    posix_spawn_file_actions_addclose(&actions, pipe_fds[0]);
    pid_t child = 0;
    const int spawned = ::posix_spawnp(&child, executable.c_str(), &actions, nullptr, argv.data(), environ);
    posix_spawn_file_actions_destroy(&actions);
    ::close(pipe_fds[1]);
    if (spawned != 0) {
      ::close(pipe_fds[0]);
      error = "posix_spawn failed";
      return false;
    }
    read_end_ = pipe_fds[0];
    process_ = child;
    running_ = true;
    return true;
#endif
  }

  /// Block until a line arrives on the child's standard output. Returns an
  /// empty string when the child closed its output (end of file) or failed.
  std::string read_line(std::string& error) {
    std::string line;
    while (true) {
      char byte = '\0';
#if defined(_WIN32)
      DWORD read = 0;
      if (::ReadFile(read_end_, &byte, 1, &read, nullptr) == 0 || read == 0) {
        error = "the child closed its output before reporting readiness";
        return {};
      }
#else
      const ssize_t read = ::read(read_end_, &byte, 1);
      if (read <= 0) {
        error = "the child closed its output before reporting readiness";
        return {};
      }
#endif
      if (byte == '\n') {
        return line;
      }
      line.push_back(byte);
      if (line.size() > 4096) {
        error = "the child produced an implausibly long line";
        return {};
      }
    }
  }

  /// Terminate the child immediately (a crash, not a graceful shutdown).
  bool kill() {
    if (!running_) {
      return true;
    }
#if defined(_WIN32)
    const BOOL killed = ::TerminateProcess(process_, 1);
    ::WaitForSingleObject(process_, INFINITE);
    ::CloseHandle(process_);
    process_ = nullptr;
    if (read_end_ != nullptr) {
      ::CloseHandle(read_end_);
      read_end_ = nullptr;
    }
    running_ = false;
    return killed != 0;
#else
    static_cast<void>(::kill(process_, SIGKILL));
    int status = 0;
    static_cast<void>(::waitpid(process_, &status, 0));
    if (read_end_ >= 0) {
      ::close(read_end_);
      read_end_ = -1;
    }
    running_ = false;
    return true;
#endif
  }

  [[nodiscard]] bool running() const noexcept { return running_; }

 private:
  static std::string quote(const std::string& value) {
    std::string out = "\"";
    for (const char character : value) {
      if (character == '"') {
        out += "\\\"";
      } else {
        out.push_back(character);
      }
    }
    out.push_back('"');
    return out;
  }

#if defined(_WIN32)
  HANDLE process_{nullptr};
  HANDLE read_end_{nullptr};
#else
  long process_{-1};
  int read_end_{-1};
#endif
  bool running_{false};
};

}  // namespace trxreg::test

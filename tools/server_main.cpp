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

// trxreg_server: the long-lived Transceiver Registry daemon.
//
// One process, one registry, one loopback listener. The Server owns every
// worker thread; this file owns no thread of its own and never touches the
// socket layer directly. A snapshot given with --snapshot is loaded before the
// listener is bound, autosaved after every committed mutation, and written once
// more on an orderly shutdown so that a hard kill still leaves a recoverable
// file behind.

#include <csignal>
#include <cstdio>
#include <cstdint>
#include <exception>
#include <memory>
#include <string>
#include <string_view>

#include "trxreg/canonical.hpp"
#include "trxreg/clock.hpp"
#include "trxreg/ids.hpp"
#include "trxreg/registry.hpp"
#include "trxreg/result.hpp"
#include "trxreg/snapshot.hpp"
#include "trxreg/version.hpp"
#include "trxreg/wire.hpp"

#ifdef _WIN32
#include <process.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

namespace {

constexpr int kExitOk = 0;
constexpr int kExitFailure = 1;
constexpr int kExitUsage = 2;

struct Options {
  std::uint16_t port{0};
  std::uint32_t max_connections{16};
  std::string bind_address{"127.0.0.1"};
  std::string ready_file;
  std::string snapshot;
};

void print_usage(std::FILE* out) {
  std::fprintf(out,
               "usage: trxreg_server [--port N] [--bind ADDR] [--ready-file PATH] [--snapshot PATH]\n"
               "                     [--max-connections N]\n"
               "  --port N             listen port, 0 selects an ephemeral port (default 0)\n"
               "  --bind ADDR          loopback bind address (default 127.0.0.1)\n"
               "  --ready-file PATH    write the bound port to PATH once listening\n"
               "  --snapshot PATH      load PATH when it exists, then autosave to it\n"
               "  --max-connections N  concurrent connection budget (default 16)\n");
}

void print_error(const trxreg::Error& error) {
  std::fprintf(stderr, "error: %s: %s\n", std::string(trxreg::to_string(error.code)).c_str(), error.message.c_str());
}

/// Parse an unsigned decimal value without allocating and without a locale.
bool parse_unsigned(std::string_view text, std::uint64_t& out) {
  if (text.empty()) {
    return false;
  }
  std::uint64_t value = 0;
  for (const char raw : text) {
    if (raw < '0' || raw > '9') {
      return false;
    }
    const std::uint64_t digit = static_cast<std::uint64_t>(raw - '0');
    if (value > (UINT64_MAX - digit) / 10u) {
      return false;
    }
    value = value * 10u + digit;
  }
  out = value;
  return true;
}

/// Consume "--flag value"; returns false when the flag is absent, and sets
/// `error` when the value is missing or unusable.
bool take_option(int argc, char** argv, int& index, std::string_view flag, std::string& out, std::string& error) {
  if (std::string_view(argv[index]) != flag) {
    return false;
  }
  if (index + 1 >= argc) {
    error = std::string(flag) + " requires a value";
    return true;
  }
  out = argv[index + 1];
  ++index;
  return true;
}

std::uint64_t file_size(const std::string& path) {
  std::FILE* file = std::fopen(path.c_str(), "rb");
  if (file == nullptr) {
    return 0;
  }
  std::uint64_t size = 0;
  if (std::fseek(file, 0, SEEK_END) == 0) {
    const long end = std::ftell(file);
    if (end > 0) {
      size = static_cast<std::uint64_t>(end);
    }
  }
  std::fclose(file);
  return size;
}

bool file_exists(const std::string& path) {
  std::FILE* file = std::fopen(path.c_str(), "rb");
  if (file == nullptr) {
    return false;
  }
  std::fclose(file);
  return true;
}

/// One-line JSON summary of what a load actually applied. The canonical
/// document is rendered by Value::to_json, so the line is valid JSON and every
/// counter names the same quantity as the LoadReport field.
trxreg::Value load_report_document(const trxreg::LoadReport& report, const std::string& path, std::uint64_t bytes) {
  using trxreg::Value;
  return Value::object({
      {"bytes", Value::integer(static_cast<std::int64_t>(bytes))},
      {"claims", Value::integer(static_cast<std::int64_t>(report.claims))},
      {"content_digest", Value::text(report.content_digest.to_hex())},
      {"declarations", Value::integer(static_cast<std::int64_t>(report.declarations))},
      {"dropped_tail_bytes", Value::integer(static_cast<std::int64_t>(report.dropped_tail_bytes))},
      {"evidence_invalidated_on_load", Value::integer(static_cast<std::int64_t>(report.evidence_invalidated_on_load))},
      {"fenced_incarnations", Value::integer(static_cast<std::int64_t>(report.fenced_incarnations))},
      {"format_version", Value::integer(static_cast<std::int64_t>(report.format_version))},
      {"generation", Value::integer(static_cast<std::int64_t>(report.generation.value()))},
      {"incarnations", Value::integer(static_cast<std::int64_t>(report.incarnations))},
      {"loaded_at_wall_ns", Value::integer(report.loaded_at_wall_ns)},
      {"modules", Value::integer(static_cast<std::int64_t>(report.modules))},
      {"path", Value::text(path)},
      {"ports", Value::integer(static_cast<std::int64_t>(report.ports))},
      {"recovery_note", Value::text(report.recovery_note)},
      {"registry_incarnation", Value::integer(static_cast<std::int64_t>(report.registry_incarnation))},
      {"rules", Value::integer(static_cast<std::int64_t>(report.rules))},
      {"samples", Value::integer(static_cast<std::int64_t>(report.samples))},
      {"sources", Value::integer(static_cast<std::int64_t>(report.sources))},
      {"tail_recovered", Value::boolean(report.tail_recovered)},
      {"thresholds", Value::integer(static_cast<std::int64_t>(report.thresholds))},
  });
}

// The signal handler is the only asynchronous control path: it flips a flag and
// asks the server to stop, which closes the listener and unblocks accept().
volatile std::sig_atomic_t g_stop_requested = 0;
volatile std::sig_atomic_t g_finished = 0;
trxreg::wire::Server* volatile g_server = nullptr;

void request_stop() {
  g_stop_requested = 1;
  trxreg::wire::Server* server = g_server;
  if (server != nullptr) {
    static_cast<void>(server->stop());
  }
}

extern "C" void handle_signal(int signal_number) {
  static_cast<void>(signal_number);
  request_stop();
}

#ifdef _WIN32
BOOL WINAPI handle_console_event(DWORD type) {
  switch (type) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
      request_stop();
      break;
    default:
      return FALSE;
  }
  // A console close or a session end kills the process once every handler has
  // returned, so wait briefly for the main thread to finish its final save.
  if (type == CTRL_CLOSE_EVENT || type == CTRL_LOGOFF_EVENT || type == CTRL_SHUTDOWN_EVENT) {
    for (int attempt = 0; attempt < 300 && g_finished == 0; ++attempt) {
      ::Sleep(10);
    }
  }
  return TRUE;
}
#endif

std::int64_t current_pid() {
#ifdef _WIN32
  return static_cast<std::int64_t>(::_getpid());
#else
  return static_cast<std::int64_t>(::getpid());
#endif
}


int run(int argc, char** argv) {
  Options options;
  std::string error;
  for (int index = 1; index < argc; ++index) {
    const std::string_view argument(argv[index]);
    if (argument == "--help" || argument == "-h") {
      print_usage(stdout);
      return kExitOk;
    }
    std::string value;
    if (take_option(argc, argv, index, "--port", value, error)) {
      std::uint64_t parsed = 0;
      if (!error.empty() || !parse_unsigned(value, parsed) || parsed > 65535) {
        std::fprintf(stderr, "trxreg_server: --port needs a value in [0, 65535]\n");
        print_usage(stderr);
        return kExitUsage;
      }
      options.port = static_cast<std::uint16_t>(parsed);
      continue;
    }
    if (take_option(argc, argv, index, "--max-connections", value, error)) {
      std::uint64_t parsed = 0;
      if (!error.empty() || !parse_unsigned(value, parsed) || parsed == 0 || parsed > 65535) {
        std::fprintf(stderr, "trxreg_server: --max-connections needs a value in [1, 65535]\n");
        print_usage(stderr);
        return kExitUsage;
      }
      options.max_connections = static_cast<std::uint32_t>(parsed);
      continue;
    }
    if (take_option(argc, argv, index, "--bind", value, error)) {
      if (!error.empty() || value.empty()) {
        std::fprintf(stderr, "trxreg_server: --bind needs a loopback address\n");
        print_usage(stderr);
        return kExitUsage;
      }
      options.bind_address = value;
      continue;
    }
    if (take_option(argc, argv, index, "--ready-file", value, error)) {
      if (!error.empty() || value.empty()) {
        std::fprintf(stderr, "trxreg_server: --ready-file needs a path\n");
        print_usage(stderr);
        return kExitUsage;
      }
      options.ready_file = value;
      continue;
    }
    if (take_option(argc, argv, index, "--snapshot", value, error)) {
      if (!error.empty() || value.empty()) {
        std::fprintf(stderr, "trxreg_server: --snapshot needs a path\n");
        print_usage(stderr);
        return kExitUsage;
      }
      options.snapshot = value;
      continue;
    }
    std::fprintf(stderr, "trxreg_server: unknown argument '%s'\n", std::string(argument).c_str());
    print_usage(stderr);
    return kExitUsage;
  }
  if (!error.empty()) {
    std::fprintf(stderr, "trxreg_server: %s\n", error.c_str());
    print_usage(stderr);
    return kExitUsage;
  }

  trxreg::Registry registry{trxreg::RegistryConfig{}, trxreg::make_system_clock()};

  if (!options.snapshot.empty() && file_exists(options.snapshot)) {
    const trxreg::Result<trxreg::LoadReport> report = registry.load(options.snapshot);
    if (!report.ok()) {
      std::fprintf(stderr, "trxreg_server: cannot load snapshot '%s'\n", options.snapshot.c_str());
      print_error(report.error());
      return kExitFailure;
    }
    const std::string summary =
        load_report_document(report.value(), options.snapshot, file_size(options.snapshot)).to_json();
    std::printf("%s\n", summary.c_str());
    std::fflush(stdout);
  }
  if (!options.snapshot.empty()) {
    const trxreg::Status autosave = registry.enable_autosave(options.snapshot);
    if (!autosave.ok()) {
      print_error(autosave.error());
      return kExitFailure;
    }
  }

  trxreg::wire::ServerOptions server_options;
  server_options.port = options.port;
  server_options.bind_address = options.bind_address;
  server_options.max_connections = options.max_connections;
  server_options.ready_file = options.ready_file;
  trxreg::wire::Server server(registry, std::move(server_options));

  g_server = &server;
  std::signal(SIGINT, handle_signal);
  std::signal(SIGTERM, handle_signal);
#ifdef SIGBREAK
  std::signal(SIGBREAK, handle_signal);
#endif
#ifdef _WIN32
  if (::SetConsoleCtrlHandler(handle_console_event, TRUE) == 0) {
    std::fprintf(stderr, "warning: the console control handler was not installed\n");
  }
#endif

  const trxreg::Status started = server.start();
  if (!started.ok()) {
    std::fprintf(stderr, "trxreg_server: cannot start the listener on %s:%u\n", options.bind_address.c_str(),
                 static_cast<unsigned>(options.port));
    print_error(started.error());
    g_server = nullptr;
    return kExitFailure;
  }

  std::printf("READY port=%u pid=%lld\n", static_cast<unsigned>(server.port()),
              static_cast<long long>(current_pid()));
  std::fflush(stdout);

  const trxreg::Status served = server.run();
  static_cast<void>(server.stop());
  g_server = nullptr;

  int exit_code = kExitOk;
  if (!options.snapshot.empty()) {
    const trxreg::Status saved = registry.save(options.snapshot);
    if (!saved.ok()) {
      std::fprintf(stderr, "trxreg_server: cannot save snapshot '%s'\n", options.snapshot.c_str());
      print_error(saved.error());
      exit_code = kExitFailure;
    }
  }
  g_finished = 1;
  if (!served.ok() && exit_code == kExitOk) {
    print_error(served.error());
    exit_code = kExitFailure;
  }
  return exit_code;
}

}  // namespace

int main(int argc, char** argv) {
  try {
    return run(argc, argv);
  } catch (const std::exception& error) {
    std::fprintf(stderr, "error: internal: %s\n", error.what());
    return kExitFailure;
  } catch (...) {
    std::fprintf(stderr, "error: internal: an unknown exception escaped the server\n");
    return kExitFailure;
  }
}



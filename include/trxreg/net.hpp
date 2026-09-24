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

#include <cstdint>
#include <span>
#include <string>

#include "trxreg/result.hpp"

// Minimal loopback socket layer. The runtime uses real OS sockets for its
// multi-process proof; there is no in-process simulation of the transport.

namespace trxreg::net {

/// Idempotent platform initialization (Winsock on Windows).
Status initialize();

/// A connected stream socket. Move-only RAII handle.
class Socket {
 public:
  Socket() noexcept = default;
  ~Socket();
  Socket(const Socket&) = delete;
  Socket& operator=(const Socket&) = delete;
  Socket(Socket&& other) noexcept;
  Socket& operator=(Socket&& other) noexcept;

  [[nodiscard]] bool valid() const noexcept;

  /// Connect to a listener. Only loopback literals are accepted (127.0.0.0/8 or
  /// ::1); host names are never resolved, so the transport cannot reach off-host
  /// endpoints by accident.
  static Result<Socket> connect_loopback(const std::string& address, std::uint16_t port);

  /// Send the whole buffer, retrying partial writes. Returns the byte count.
  Result<std::uint64_t> send_all(std::span<const std::byte> data);
  /// Receive at least one byte; returns 0 on orderly shutdown.
  Result<std::uint64_t> recv_some(std::span<std::byte> buffer);
  /// Close the socket. Idempotent and safe to call concurrently with a reader.
  Status close();
  /// Unblock a blocked reader without releasing the handle.
  void shutdown_both() noexcept;

  [[nodiscard]] std::intptr_t native_handle() const noexcept { return handle_; }

 private:
  explicit Socket(std::intptr_t handle) noexcept : handle_(handle) {}
  friend class Listener;
  std::intptr_t handle_{-1};
};

/// A listening socket bound to the loopback interface.
class Listener {
 public:
  Listener() noexcept = default;
  ~Listener();
  Listener(const Listener&) = delete;
  Listener& operator=(const Listener&) = delete;
  Listener(Listener&& other) noexcept;
  Listener& operator=(Listener&& other) noexcept;

  /// Bind to 127.0.0.1. Port 0 selects an ephemeral port; the chosen port is
  /// reported by `port()`.
  static Result<Listener> bind_loopback(std::uint16_t port, std::uint32_t backlog = 16);
  /// Bind to an explicit loopback address string (IPv4) for tests that need a
  /// non-default address; refuses anything that is not a loopback literal.
  static Result<Listener> bind_loopback_address(const std::string& address, std::uint16_t port,
                                               std::uint32_t backlog = 16);

  Result<Socket> accept();
  [[nodiscard]] std::uint16_t port() const noexcept { return port_; }
  [[nodiscard]] bool valid() const noexcept;
  Status close();

 private:
  std::intptr_t handle_{-1};
  std::uint16_t port_{0};
};

}  // namespace trxreg::net

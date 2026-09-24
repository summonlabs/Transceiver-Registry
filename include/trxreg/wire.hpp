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

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <thread>
#include <vector>

#include "trxreg/canonical.hpp"
#include "trxreg/net.hpp"
#include "trxreg/registry.hpp"
#include "trxreg/result.hpp"
#include "trxreg/version.hpp"

// Framed loopback transport.
//
// Frame layout (all integers little-endian):
//   magic 'TRXF' (4) | version (2) | type (2) | flags (2) | reserved (2)
//   | body length (4) | body (N) | CRC-32C of the preceding bytes (4)
//
// The body is a canonical document. Every field is validated before it is
// used, the frame length is bounded before allocation, and a frame that fails
// its CRC is rejected without being parsed.

namespace trxreg::wire {

enum class MessageType : std::uint16_t {
  Hello = 1,
  HelloAck = 2,
  Request = 3,
  Response = 4,
  Failure = 5,
  Ping = 6,
  Pong = 7,
  Shutdown = 8,
};

std::string_view to_string(MessageType type) noexcept;
bool message_type_from_string(std::string_view text, MessageType& out) noexcept;

inline constexpr std::size_t kFrameHeaderBytes = 16;
inline constexpr std::size_t kFrameTrailerBytes = 4;

struct FrameLimits {
  /// Largest accepted frame body. Frames larger than this are refused before
  /// any buffer is allocated for them.
  std::uint32_t max_body_bytes{1u << 20};
};

struct FrameHeader {
  std::uint16_t version{kWireProtocolVersion};
  MessageType type{MessageType::Request};
  std::uint16_t flags{0};
  std::uint32_t body_length{0};
};

struct Frame {
  MessageType type{MessageType::Request};
  std::uint16_t flags{0};
  Value body{};
};

Result<FrameHeader> parse_frame_header(std::span<const std::byte, kFrameHeaderBytes> header, const FrameLimits& limits);

/// Encode a complete frame (header + body + CRC).
std::vector<std::byte> encode_frame(MessageType type, std::uint16_t flags, std::span<const std::byte> body);

/// Validate a complete frame and decode its body.
Result<Frame> decode_frame(std::span<const std::byte> frame_bytes, const FrameLimits& limits,
                           CanonicalLimits document_limits);

/// Read exactly one frame from a socket, honoring the limits.
Result<Frame> read_frame(net::Socket& socket, const FrameLimits& limits, CanonicalLimits document_limits);

/// Write one frame to a socket.
Status write_frame(net::Socket& socket, MessageType type, std::uint16_t flags, const Value& body,
                   const FrameLimits& limits);

/// A client connection to a registry server.
class Client {
 public:
  Client() = default;
  ~Client() = default;
  Client(const Client&) = delete;
  Client& operator=(const Client&) = delete;
  Client(Client&&) noexcept = default;
  Client& operator=(Client&&) noexcept = default;

  static Result<Client> connect(const std::string& host, std::uint16_t port, FrameLimits limits = {});

  /// Send one request document and read the matching response.
  Result<Value> exchange(const Value& request);

  /// Build and send a request for `op` with the given parameters, returning the
  /// `result` member of the response, or a classified error.
  Result<Value> call(std::string_view op, Value parameters);

  Result<Value> hello(std::uint32_t client_incarnation);

  Status close();

 private:
  net::Socket socket_{};
  FrameLimits limits_{};
  std::uint64_t next_request_id_{1};
};

/// Request handling shared by the server and by in-process tests.
struct RequestOutcome {
  MessageType type{MessageType::Response};
  Value body{};
};

/// Handle one request document against a registry.
RequestOutcome dispatch(Registry& registry, const Value& request, CanonicalLimits document_limits);

struct ServerOptions {
  std::uint16_t port{0};
  std::string bind_address{"127.0.0.1"};
  std::uint32_t max_connections{16};
  std::uint32_t max_requests_per_connection{100000};
  FrameLimits frame_limits{};
  CanonicalLimits document_limits{CanonicalLimits::request()};
  /// When set, the resolved `port=<n>` line is written here once the listener
  /// is bound, so a parent process can discover an ephemeral port.
  std::string ready_file;
};

/// Multi-connection registry server. Threads are bounded by max_connections and
/// shutdown never joins a worker while holding a lock a worker needs.
class Server {
 public:
  Server(Registry& registry, ServerOptions options);
  ~Server();
  Server(const Server&) = delete;
  Server& operator=(const Server&) = delete;

  /// Bind and start serving. Returns after the listener is bound, so the caller
  /// can report readiness without racing the accept loop.
  Status start();
  /// Accept loop; returns when stop() is called or the listener fails.
  Status run();
  /// Stop accepting, unblock and join every worker, and close the listener.
  Status stop();
  [[nodiscard]] std::uint16_t port() const noexcept { return port_; }
  [[nodiscard]] bool running() const noexcept { return running_.load(); }

 private:
  struct Connection;
  void serve_connection(std::shared_ptr<Connection> connection);

  Registry& registry_;
  ServerOptions options_;
  net::Listener listener_{};
  std::uint16_t port_{0};
  std::atomic<bool> stopping_{false};
  std::atomic<bool> running_{false};
  mutable std::mutex connections_mutex_;
  std::vector<std::shared_ptr<Connection>> connections_;
  std::vector<std::thread> workers_;
  std::mutex worker_mutex_;
};

}  // namespace trxreg::wire

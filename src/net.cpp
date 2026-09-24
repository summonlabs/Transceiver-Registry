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

#include "trxreg/net.hpp"

#if defined(_WIN32)
// The socket layer is only usable with ws2_32 linked; the pragma keeps this
// translation unit (and standalone scratch tests of it) linkable on its own.
#if defined(_MSC_VER)
#pragma comment(lib, "ws2_32.lib")
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>

namespace trxreg::net {
namespace {

#if defined(_WIN32)
using native_socket = SOCKET;
using socket_length = int;
#else
using native_socket = int;
using socket_length = socklen_t;
#endif

/// The header fixes the invalid-handle sentinel at -1. On Windows SOCKET is an
/// unsigned pointer-sized integer whose INVALID_SOCKET is exactly that bit
/// pattern, so one sentinel serves both platforms.
constexpr std::intptr_t kInvalidHandle = -1;

#if defined(_WIN32)
static_assert(static_cast<std::intptr_t>(static_cast<std::uintptr_t>(INVALID_SOCKET)) == kInvalidHandle,
              "trxreg::net assumes INVALID_SOCKET is the -1 sentinel");
#endif

/// Bounded retry budget for transient (EINTR / EAGAIN style) socket failures.
constexpr std::uint32_t kTransientRetries = 1000;
/// accept() waits at most this long inside select() before it re-checks whether
/// the listener was closed by another thread.
constexpr std::int64_t kAcceptPollMicros = 50 * 1000;
#if defined(_WIN32)
/// send()/recv() take an int length on Windows, so a larger span is chunked. The
/// bound is spelled out because <limits> and windows.h disagree about the max
/// macro unless the consumer defines NOMINMAX.
constexpr std::size_t kIoChunkLimit = 0x7fffffffu;
#endif

native_socket to_native(std::intptr_t handle) noexcept {
#if defined(_WIN32)
  return static_cast<native_socket>(static_cast<std::uintptr_t>(handle));
#else
  return static_cast<native_socket>(handle);
#endif
}

std::intptr_t from_native(native_socket handle) noexcept {
#if defined(_WIN32)
  return static_cast<std::intptr_t>(static_cast<std::uintptr_t>(handle));
#else
  return static_cast<std::intptr_t>(handle);
#endif
}

bool handle_valid(std::intptr_t handle) noexcept { return handle != kInvalidHandle; }

/// handle_ is a plain std::intptr_t in the header, so the atomic exchange that
/// makes close() safe against a concurrent reader comes from std::atomic_ref:
/// the C++20 equivalent of the atomic member the header cannot declare.
std::intptr_t load_handle(std::intptr_t& handle) noexcept {
  return std::atomic_ref<std::intptr_t>(handle).load(std::memory_order_acquire);
}

std::intptr_t take_handle(std::intptr_t& handle) noexcept {
  return std::atomic_ref<std::intptr_t>(handle).exchange(kInvalidHandle, std::memory_order_acq_rel);
}

int last_socket_error() noexcept {
#if defined(_WIN32)
  return ::WSAGetLastError();
#else
  return errno;
#endif
}

/// Interrupted calls (EINTR) are always retried.
bool is_interrupted_error(int code) noexcept {
#if defined(_WIN32)
  return code == WSAEINTR;
#else
  return code == EINTR;
#endif
}

/// Retryable "try again" conditions. Blocking sockets rarely produce these, but
/// a signal or a momentarily full buffer must not be reported as a hard failure.
bool is_transient_error(int code) noexcept {
#if defined(_WIN32)
  return code == WSAEWOULDBLOCK || code == WSAENOBUFS;
#else
  return code == EAGAIN || code == EWOULDBLOCK || code == ENOBUFS;
#endif
}

/// A peer that reset or fully closed the connection.
bool is_peer_closed_error(int code) noexcept {
#if defined(_WIN32)
  return code == WSAECONNRESET || code == WSAECONNABORTED || code == WSAESHUTDOWN || code == WSAENOTCONN ||
         code == WSAEDISCON;
#else
  return code == ECONNRESET || code == ECONNABORTED || code == EPIPE || code == ENOTCONN || code == ESHUTDOWN;
#endif
}

/// A queued connection died before accept() picked it up; retry the accept.
bool is_connection_aborted_error(int code) noexcept {
#if defined(_WIN32)
  return code == WSAECONNABORTED;
#else
  return code == ECONNABORTED;
#endif
}

std::string io_message(std::string_view operation, int code) {
  std::string message(operation);
  message += " failed with socket error ";
  message += std::to_string(code);
  return message;
}

Error io_error(std::string message) { return Error{StatusCode::IoError, std::move(message)}; }

Status io_status(std::string message) { return Status(StatusCode::IoError, std::move(message)); }

/// Close without reporting: used by destructors and move assignment, which must
/// not allocate. The value was already claimed with take_handle().
void close_native(std::intptr_t handle) noexcept {
#if defined(_WIN32)
  (void)::closesocket(to_native(handle));
#else
  (void)::close(to_native(handle));
#endif
}

/// Close and report. The handle has already been claimed, so a failure here is
/// the operating system failure, never a double close.
Status close_handle(std::intptr_t handle) noexcept {
#if defined(_WIN32)
  if (::closesocket(to_native(handle)) == SOCKET_ERROR) {
    return io_status(io_message("closesocket()", last_socket_error()));
  }
  return Status::success();
#else
  // Retrying close() after EINTR is unsafe: the descriptor may already have been
  // released and reused, so EINTR is treated as success.
  if (::close(to_native(handle)) != 0 && errno != EINTR) {
    return io_status(io_message("close()", errno));
  }
  return Status::success();
#endif
}

/// One send() call. Returns the byte count, or -1 when the call failed.
std::ptrdiff_t send_once(std::intptr_t handle, const std::byte* data, std::size_t size) noexcept {
#if defined(_WIN32)
  const int chunk = static_cast<int>(size < kIoChunkLimit ? size : kIoChunkLimit);
  const int sent = ::send(to_native(handle), reinterpret_cast<const char*>(data), chunk, 0);
  return sent == SOCKET_ERROR ? std::ptrdiff_t{-1} : static_cast<std::ptrdiff_t>(sent);
#else
  int flags = 0;
#if defined(MSG_NOSIGNAL)
  flags |= MSG_NOSIGNAL;  // A reset peer must fail the call, not kill the process.
#endif
  const ssize_t sent = ::send(to_native(handle), data, size, flags);
  return sent < 0 ? std::ptrdiff_t{-1} : static_cast<std::ptrdiff_t>(sent);
#endif
}

/// One recv() call. Returns the byte count, or -1 when the call failed.
std::ptrdiff_t recv_once(std::intptr_t handle, std::byte* data, std::size_t size) noexcept {
#if defined(_WIN32)
  const int chunk = static_cast<int>(size < kIoChunkLimit ? size : kIoChunkLimit);
  const int received = ::recv(to_native(handle), reinterpret_cast<char*>(data), chunk, 0);
  return received == SOCKET_ERROR ? std::ptrdiff_t{-1} : static_cast<std::ptrdiff_t>(received);
#else
  const ssize_t received = ::recv(to_native(handle), data, size, 0);
  return received < 0 ? std::ptrdiff_t{-1} : static_cast<std::ptrdiff_t>(received);
#endif
}

/// listen() takes an int; clamp so that no caller can overflow the conversion.
int clamp_backlog(std::uint32_t backlog) noexcept {
  constexpr std::uint32_t kMaxBacklog = 0x7fffffffu;
  if (backlog == 0u) {
    return 1;
  }
  return static_cast<int>(backlog > kMaxBacklog ? kMaxBacklog : backlog);
}

std::uint16_t normalize_family(int family) noexcept { return static_cast<std::uint16_t>(family); }

// ---------------------------------------------------------------------------
// Process-lifetime platform initialization.
// ---------------------------------------------------------------------------

struct InitState {
  StatusCode code{StatusCode::Ok};
  std::string message;
};

std::once_flag& init_once() noexcept {
  static std::once_flag flag;
  return flag;
}

/// The only mutable global state in this translation unit, besides the once_flag.
InitState& init_state() noexcept {
  static InitState state;
  return state;
}

void run_initialize() {
#if defined(_WIN32)
  WSADATA data{};
  const int rc = ::WSAStartup(MAKEWORD(2, 2), &data);
  if (rc != 0) {
    init_state().code = StatusCode::IoError;
    init_state().message = "WSAStartup(2.2) failed with error " + std::to_string(rc);
    return;
  }
  const int major = static_cast<int>(LOBYTE(data.wVersion));
  const int minor = static_cast<int>(HIBYTE(data.wVersion));
  if (major != 2 || minor != 2) {
    // Deliberately no WSACleanup(): initialization lives for the whole process.
    init_state().code = StatusCode::IoError;
    init_state().message = "Winsock 2.2 is unavailable; the platform reported version " + std::to_string(major) +
                           "." + std::to_string(minor);
    return;
  }
#endif
  init_state().code = StatusCode::Ok;
  init_state().message.clear();
}

}  // namespace

Status initialize() {
  std::call_once(init_once(), run_initialize);
  const InitState& state = init_state();
  if (state.code == StatusCode::Ok) {
    return Status::success();
  }
  return Status(state.code, state.message);
}

// ---------------------------------------------------------------------------
// Socket
// ---------------------------------------------------------------------------

Socket::~Socket() {
  const std::intptr_t handle = take_handle(handle_);
  if (handle_valid(handle)) {
    close_native(handle);
  }
}

Socket::Socket(Socket&& other) noexcept : handle_(take_handle(other.handle_)) {}

Socket& Socket::operator=(Socket&& other) noexcept {
  if (this != &other) {
    const std::intptr_t previous = take_handle(handle_);
    if (handle_valid(previous)) {
      close_native(previous);
    }
    handle_ = take_handle(other.handle_);
  }
  return *this;
}

bool Socket::valid() const noexcept { return handle_ != kInvalidHandle; }

Result<std::uint64_t> Socket::send_all(std::span<const std::byte> data) {
  const Status init = initialize();
  if (!init.ok()) {
    return init.error();
  }

  const std::intptr_t handle = load_handle(handle_);
  if (!handle_valid(handle)) {
    return io_error("send_all() failed: the socket is closed");
  }

  std::size_t offset = 0;
  std::uint32_t transient = 0;
  while (offset < data.size()) {
    const std::ptrdiff_t sent = send_once(handle, data.data() + offset, data.size() - offset);
    if (sent == 0) {
      return io_error("send_all() failed: the peer closed the connection");
    }
    if (sent > 0) {
      offset += static_cast<std::size_t>(sent);
      continue;
    }
    const int code = last_socket_error();
    if (is_interrupted_error(code) || is_transient_error(code)) {
      if (transient >= kTransientRetries) {
        return io_error(io_message("send_all()", code) + " (transient retries exhausted)");
      }
      ++transient;
      continue;
    }
    std::string message = io_message("send_all()", code);
    if (is_peer_closed_error(code)) {
      message += " (the peer reset or closed the connection)";
    }
    return io_error(std::move(message));
  }
  return static_cast<std::uint64_t>(offset);
}

Result<std::uint64_t> Socket::recv_some(std::span<std::byte> buffer) {
  const Status init = initialize();
  if (!init.ok()) {
    return init.error();
  }

  const std::intptr_t handle = load_handle(handle_);
  if (!handle_valid(handle)) {
    return io_error("recv_some() failed: the socket is closed");
  }
  if (buffer.empty()) {
    return Result<std::uint64_t>(StatusCode::InvalidArgument, "recv_some() failed: the receive buffer is empty");
  }

  for (std::uint32_t attempt = 0;; ++attempt) {
    const std::ptrdiff_t received = recv_once(handle, buffer.data(), buffer.size());
    if (received >= 0) {
      return static_cast<std::uint64_t>(received);  // 0 is an orderly peer shutdown.
    }
    const int code = last_socket_error();
    if (is_interrupted_error(code) && attempt < kTransientRetries) {
      continue;
    }
    std::string message = io_message("recv_some()", code);
    if (is_peer_closed_error(code)) {
      message += " (the peer reset or closed the connection)";
    }
    return io_error(std::move(message));
  }
}

Status Socket::close() {
  const std::intptr_t handle = take_handle(handle_);
  if (!handle_valid(handle)) {
    return Status::success();  // Idempotent: nothing left to close.
  }
  return close_handle(handle);
}

void Socket::shutdown_both() noexcept {
  const std::intptr_t handle = load_handle(handle_);
  if (!handle_valid(handle)) {
    return;
  }
#if defined(_WIN32)
  (void)::shutdown(to_native(handle), SD_BOTH);
#else
  (void)::shutdown(to_native(handle), SHUT_RDWR);
#endif
}

// ---------------------------------------------------------------------------
// Listener
// ---------------------------------------------------------------------------

Listener::~Listener() {
  const std::intptr_t handle = take_handle(handle_);
  if (handle_valid(handle)) {
    close_native(handle);
  }
}

Listener::Listener(Listener&& other) noexcept : handle_(take_handle(other.handle_)), port_(other.port_) {
  other.port_ = 0;
}

Listener& Listener::operator=(Listener&& other) noexcept {
  if (this != &other) {
    const std::intptr_t previous = take_handle(handle_);
    if (handle_valid(previous)) {
      close_native(previous);
    }
    handle_ = take_handle(other.handle_);
    port_ = other.port_;
    other.port_ = 0;
  }
  return *this;
}

bool Listener::valid() const noexcept { return handle_ != kInvalidHandle; }

Result<Listener> Listener::bind_loopback(std::uint16_t port, std::uint32_t backlog) {
  return bind_loopback_address("127.0.0.1", port, backlog);
}

Result<Listener> Listener::bind_loopback_address(const std::string& address, std::uint16_t port,
                                                 std::uint32_t backlog) {
  const Status init = initialize();
  if (!init.ok()) {
    return init.error();
  }

  const std::string refused = "bind_loopback_address() refused '" + address +
                              "': only loopback literals (127.0.0.0/8 or ::1) may be bound";

  sockaddr_storage storage{};
  socket_length storage_length = 0;
  int family = AF_UNSPEC;

  // inet_pton only: this layer never consults the resolver, so a host name can
  // never widen the bind beyond the loopback interface.
  in_addr address_v4{};
  if (::inet_pton(AF_INET, address.c_str(), &address_v4) == 1) {
    if ((address_v4.s_addr & ::htonl(0xff000000u)) != ::htonl(0x7f000000u)) {
      return Result<Listener>(StatusCode::Refused, refused);
    }
    sockaddr_in local{};
    local.sin_family = normalize_family(AF_INET);
    local.sin_port = ::htons(port);
    local.sin_addr = address_v4;
    std::memcpy(&storage, &local, sizeof(local));
    storage_length = static_cast<socket_length>(sizeof(local));
    family = AF_INET;
  } else {
    in6_addr address_v6{};
    if (::inet_pton(AF_INET6, address.c_str(), &address_v6) != 1 || !IN6_IS_ADDR_LOOPBACK(&address_v6)) {
      return Result<Listener>(StatusCode::Refused, refused);
    }
    sockaddr_in6 local{};
    local.sin6_family = normalize_family(AF_INET6);
    local.sin6_port = ::htons(port);
    local.sin6_addr = address_v6;
    std::memcpy(&storage, &local, sizeof(local));
    storage_length = static_cast<socket_length>(sizeof(local));
    family = AF_INET6;
  }

  const native_socket handle = ::socket(family, SOCK_STREAM, IPPROTO_TCP);
  if (handle == INVALID_SOCKET) {
    return io_error(io_message("socket()", last_socket_error()));
  }
  const std::intptr_t raw = from_native(handle);

#if defined(_WIN32)
  // Windows SO_REUSEADDR would let a second process steal the port. The
  // exclusive option is the correct guard there: a second bind fails instead.
  const int exclusive = 1;
  if (::setsockopt(handle, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, reinterpret_cast<const char*>(&exclusive),
                   static_cast<socket_length>(sizeof(exclusive))) == SOCKET_ERROR) {
    const int code = last_socket_error();
    close_native(raw);
    return io_error(io_message("setsockopt(SO_EXCLUSIVEADDRUSE)", code));
  }
#else
  // On POSIX SO_REUSEADDR only skips TIME_WAIT; it does not permit port theft.
  const int reuse = 1;
  if (::setsockopt(handle, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse),
                   static_cast<socket_length>(sizeof(reuse))) == SOCKET_ERROR) {
    const int code = last_socket_error();
    close_native(raw);
    return io_error(io_message("setsockopt(SO_REUSEADDR)", code));
  }
#endif

  if (::bind(handle, reinterpret_cast<const sockaddr*>(&storage), storage_length) == SOCKET_ERROR) {
    const int code = last_socket_error();
    close_native(raw);
    return io_error(io_message("bind() to " + address + ":" + std::to_string(port), code));
  }

  const int effective_backlog = clamp_backlog(backlog);
  if (::listen(handle, effective_backlog) == SOCKET_ERROR) {
    const int code = last_socket_error();
    close_native(raw);
    return io_error(io_message("listen()", code));
  }

  // Port 0 asks the platform for an ephemeral port; report the chosen one.
  sockaddr_storage bound{};
  socket_length bound_length = static_cast<socket_length>(sizeof(bound));
  if (::getsockname(handle, reinterpret_cast<sockaddr*>(&bound), &bound_length) == SOCKET_ERROR) {
    const int code = last_socket_error();
    close_native(raw);
    return io_error(io_message("getsockname()", code));
  }

  std::uint16_t actual_port = 0;
  if (bound.ss_family == normalize_family(AF_INET)) {
    sockaddr_in local{};
    std::memcpy(&local, &bound, sizeof(local));
    actual_port = ::ntohs(local.sin_port);
  } else if (bound.ss_family == normalize_family(AF_INET6)) {
    sockaddr_in6 local{};
    std::memcpy(&local, &bound, sizeof(local));
    actual_port = ::ntohs(local.sin6_port);
  } else {
    close_native(raw);
    return io_error("getsockname() reported an unexpected address family");
  }

  Listener listener;
  listener.handle_ = raw;
  listener.port_ = actual_port;
  return Result<Listener>(std::move(listener));
}

Result<Socket> Listener::accept() {
  const Status init = initialize();
  if (!init.ok()) {
    return init.error();
  }

  std::uint32_t transient = 0;
  for (;;) {
    const std::intptr_t handle = load_handle(handle_);
    if (!handle_valid(handle)) {
      return io_error("accept() failed: the listener was closed");
    }
    const native_socket native = to_native(handle);

#if !defined(_WIN32)
    // select() cannot represent a descriptor at or above FD_SETSIZE; refusing it
    // is better than overflowing the fd_set.
    if (native >= FD_SETSIZE) {
      return io_error("accept() failed: the listener descriptor is at or above FD_SETSIZE");
    }
#endif

    // Wait for a pending connection with a bounded timeout rather than blocking
    // inside accept() itself. Closing a listening socket does not reliably wake
    // a blocked accept() on every platform, so the loop re-reads the handle and
    // reports the closure as an error instead of hanging forever.
    fd_set readable;
    FD_ZERO(&readable);
    FD_SET(native, &readable);
    timeval timeout{};
    timeout.tv_sec = 0;
    timeout.tv_usec = static_cast<decltype(timeout.tv_usec)>(kAcceptPollMicros);

    const int ready = ::select(static_cast<int>(native) + 1, &readable, nullptr, nullptr, &timeout);
    if (ready == SOCKET_ERROR) {
      const int code = last_socket_error();
      if (!handle_valid(load_handle(handle_))) {
        return io_error("accept() failed: the listener was closed");
      }
      if ((is_interrupted_error(code) || is_transient_error(code)) && transient < kTransientRetries) {
        ++transient;
        continue;
      }
      return io_error(io_message("select() on the listener", code));
    }
    if (ready == 0) {
      continue;  // Timeout: re-check whether another thread closed the listener.
    }
    if (!handle_valid(load_handle(handle_))) {
      return io_error("accept() failed: the listener was closed");
    }

    const native_socket connection = ::accept(native, nullptr, nullptr);
    if (connection == INVALID_SOCKET) {
      const int code = last_socket_error();
      if (!handle_valid(load_handle(handle_))) {
        return io_error("accept() failed: the listener was closed");
      }
      if ((is_interrupted_error(code) || is_transient_error(code) || is_connection_aborted_error(code)) &&
          transient < kTransientRetries) {
        ++transient;
        continue;
      }
      return io_error(io_message("accept()", code));
    }
    return Result<Socket>(Socket(from_native(connection)));
  }
}

Status Listener::close() {
  const std::intptr_t handle = take_handle(handle_);
  if (!handle_valid(handle)) {
    return Status::success();  // Idempotent: nothing left to close.
  }
  return close_handle(handle);
}

Result<Socket> Socket::connect_loopback(const std::string& address, std::uint16_t port) {
  const Status init = initialize();
  if (!init.ok()) {
    return init.error();
  }
  if (port == 0) {
    return Result<Socket>(StatusCode::InvalidArgument, "connect_loopback() requires a non-zero port");
  }

  const std::string refused = "connect_loopback() refused '" + address +
                              "': only loopback literals (127.0.0.0/8 or ::1) may be connected";

  sockaddr_storage storage{};
  socket_length storage_length = 0;
  int family = AF_UNSPEC;

  in_addr address_v4{};
  if (::inet_pton(AF_INET, address.c_str(), &address_v4) == 1) {
    if ((address_v4.s_addr & ::htonl(0xff000000u)) != ::htonl(0x7f000000u)) {
      return Result<Socket>(StatusCode::Refused, refused);
    }
    sockaddr_in remote{};
    remote.sin_family = normalize_family(AF_INET);
    remote.sin_port = ::htons(port);
    remote.sin_addr = address_v4;
    std::memcpy(&storage, &remote, sizeof(remote));
    storage_length = static_cast<socket_length>(sizeof(remote));
    family = AF_INET;
  } else {
    in6_addr address_v6{};
    if (::inet_pton(AF_INET6, address.c_str(), &address_v6) != 1 || !IN6_IS_ADDR_LOOPBACK(&address_v6)) {
      return Result<Socket>(StatusCode::Refused, refused);
    }
    sockaddr_in6 remote{};
    remote.sin6_family = normalize_family(AF_INET6);
    remote.sin6_port = ::htons(port);
    remote.sin6_addr = address_v6;
    std::memcpy(&storage, &remote, sizeof(remote));
    storage_length = static_cast<socket_length>(sizeof(remote));
    family = AF_INET6;
  }

  const native_socket handle = ::socket(family, SOCK_STREAM, IPPROTO_TCP);
  if (handle == INVALID_SOCKET) {
    return io_error(io_message("socket()", last_socket_error()));
  }
  Socket socket(from_native(handle));

  std::uint32_t transient = 0;
  while (true) {
    if (::connect(handle, reinterpret_cast<const sockaddr*>(&storage), storage_length) == 0) {
      return Result<Socket>(std::move(socket));
    }
    const int code = last_socket_error();
    if (is_interrupted_error(code) && transient < kTransientRetries) {
      ++transient;
      continue;
    }
    static_cast<void>(socket.close());
    return io_error(io_message("connect() to " + address + ":" + std::to_string(port), code));
  }
}

}  // namespace trxreg::net

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

// Tests for the framed loopback transport: the frame codec and its rejection
// paths, real loopback sockets, the request dispatcher, a client/server pair,
// and the server's containment of hostile or over-budget input.
//
// Every socket in this file is a real OS socket on the loopback interface and
// every assertion describes an exchange this test actually performed. No test
// uses a timeout or a watchdog: a server that refuses a frame is expected to
// close the connection, and that closure is observed as the end of the stream
// on the peer socket (an orderly FIN or a reset), never as a sleep.

#include "test_support.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "trxreg/canonical.hpp"
#include "trxreg/net.hpp"
#include "trxreg/provenance.hpp"
#include "trxreg/registry.hpp"
#include "trxreg/result.hpp"
#include "trxreg/version.hpp"
#include "trxreg/wire.hpp"

namespace {

using trxreg::CanonicalLimits;
using trxreg::CanonicalWriter;
using trxreg::Result;
using trxreg::Status;
using trxreg::StatusCode;
using trxreg::Value;
using trxreg::wire::Frame;
using trxreg::wire::FrameLimits;
using trxreg::wire::MessageType;
using trxreg::wire::RequestOutcome;

constexpr std::size_t kHeaderBytes = trxreg::wire::kFrameHeaderBytes;
constexpr std::size_t kTrailerBytes = trxreg::wire::kFrameTrailerBytes;

constexpr MessageType kEveryMessageType[] = {
    MessageType::Hello,   MessageType::HelloAck, MessageType::Request, MessageType::Response,
    MessageType::Failure, MessageType::Ping,     MessageType::Pong,    MessageType::Shutdown,
};

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

std::vector<std::byte> canonical_bytes(const Value& value) {
  CanonicalWriter writer;
  writer.write_value(value);
  return std::move(writer).take();
}

Value sample_document(std::int64_t id) {
  return Value::object({
      {"id", Value::integer(id)},
      {"name", Value::text("wire document")},
      {"values", Value::array({Value::null(), Value::boolean(true), Value::integer(-17), Value::real(2.5)})},
  });
}

void append_u16(std::vector<std::byte>& out, std::uint16_t value) {
  out.push_back(static_cast<std::byte>(value & 0xffu));
  out.push_back(static_cast<std::byte>((value >> 8u) & 0xffu));
}

void append_u32(std::vector<std::byte>& out, std::uint32_t value) {
  for (std::size_t i = 0; i < 4; ++i) {
    out.push_back(static_cast<std::byte>((value >> (8u * i)) & 0xffu));
  }
}

std::uint32_t read_u32_le(std::span<const std::byte> bytes, std::size_t offset) {
  std::uint32_t value = 0;
  for (std::size_t i = 0; i < 4; ++i) {
    value |= static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(bytes[offset + i])) << (8u * i);
  }
  return value;
}

/// Hand-built header bytes, so a test can express fields the encoder never
/// produces: foreign magic, a wrong version, an unknown type, a non-zero
/// reserved field, and a body length far above any limit.
std::vector<std::byte> header_bytes(std::uint16_t version, std::uint16_t type, std::uint16_t flags,
                                    std::uint16_t reserved, std::uint32_t body_length) {
  std::vector<std::byte> out;
  out.reserve(kHeaderBytes);
  for (const char magic : trxreg::kFrameMagic) {
    out.push_back(static_cast<std::byte>(static_cast<unsigned char>(magic)));
  }
  append_u16(out, version);
  append_u16(out, type);
  append_u16(out, flags);
  append_u16(out, reserved);
  append_u32(out, body_length);
  return out;
}

std::span<const std::byte, trxreg::wire::kFrameHeaderBytes> as_header(const std::vector<std::byte>& bytes) {
  return std::span<const std::byte, trxreg::wire::kFrameHeaderBytes>(bytes.data(), kHeaderBytes);
}

template <class T>
StatusCode failure_code(const Result<T>& result) {
  return result.ok() ? StatusCode::Ok : result.error().code;
}

std::string failure_code_text(const Value& body) {
  const Value* error = body.find("error");
  if (error == nullptr) {
    return {};
  }
  const Value* code = error->find("code");
  if (code == nullptr || !code->is_text()) {
    return {};
  }
  return code->as_text();
}

Value provenance_document() {
  trxreg::Provenance provenance;
  provenance.kind = trxreg::EvidenceKind::Synthetic;
  provenance.origin = "wire-test";
  provenance.method = "generated";
  return Value::object({
      {"capture_ref", Value::text(provenance.capture_ref)},
      {"content_digest", Value::text(provenance.content_digest.to_hex())},
      {"kind", Value::integer(static_cast<std::int64_t>(provenance.kind))},
      {"method", Value::text(provenance.method)},
      {"origin", Value::text(provenance.origin)},
  });
}

/// A server plus the thread running its accept loop. The destructor stops the
/// server and joins the loop, so a failing REQUIRE in a test body can never
/// leave a joinable thread or a running server behind.
class ServerHarness {
 public:
  ServerHarness(trxreg::Registry& registry, trxreg::wire::ServerOptions options)
      : server_(registry, std::move(options)) {}

  ~ServerHarness() { static_cast<void>(stop()); }

  ServerHarness(const ServerHarness&) = delete;
  ServerHarness& operator=(const ServerHarness&) = delete;

  Status start() {
    const Status status = server_.start();
    if (!status.ok()) {
      return status;
    }
    runner_ = std::thread([this]() { run_status_ = server_.run(); });
    return Status::success();
  }

  /// Stop the server and join the accept loop; the returned status is the one
  /// stop() reported, so the caller can assert the teardown path.
  Status stop() {
    const Status status = server_.stop();
    if (runner_.joinable()) {
      runner_.join();
    }
    return status;
  }

  [[nodiscard]] std::uint16_t port() const { return server_.port(); }
  [[nodiscard]] bool running() const { return server_.running(); }
  [[nodiscard]] const Status& run_status() const { return run_status_; }

 private:
  trxreg::wire::Server server_;
  std::thread runner_;
  Status run_status_{};
};

void expect_server_healthy(std::uint16_t port) {
  Result<trxreg::wire::Client> client = trxreg::wire::Client::connect("127.0.0.1", port);
  CHECK(client.ok());
  if (!client.ok()) {
    return;
  }
  const Result<Value> generation = client.value().call("registry.generation", Value::object({}));
  CHECK(generation.ok());
  if (generation.ok()) {
    CHECK(generation.value().is_object());
    CHECK(generation.value().find("generation") != nullptr);
  }
  CHECK(client.value().close().ok());
}

/// What a raw peer observed after writing bytes at a server.
struct RawProbe {
  Status send_status{};
  Status end_status{};
  std::uint64_t bytes_received{0};
};

RawProbe probe_raw_bytes(std::uint16_t port, std::span<const std::byte> bytes) {
  RawProbe probe;
  Result<trxreg::net::Socket> connected = trxreg::net::Socket::connect_loopback("127.0.0.1", port);
  if (!connected.ok()) {
    probe.send_status = Status(connected.error());
    return probe;
  }
  trxreg::net::Socket socket = std::move(connected.value());
  const Result<std::uint64_t> sent = socket.send_all(bytes);
  if (!sent.ok()) {
    probe.send_status = Status(sent.error());
    static_cast<void>(socket.close());
    return probe;
  }
  probe.send_status = Status::success();
  std::array<std::byte, 256> buffer{};
  const Result<std::uint64_t> received = socket.recv_some(buffer);
  if (received.ok()) {
    probe.bytes_received = received.value();
    probe.end_status = Status::success();
  } else {
    probe.end_status = Status(received.error());
  }
  static_cast<void>(socket.close());
  return probe;
}

/// The server must refuse these bytes without answering: the stream ends with
/// zero bytes delivered, either as an orderly shutdown (Ok) or as a reset
/// (IoError). A reply would mean the frame had been accepted.
void expect_silent_close(std::uint16_t port, std::span<const std::byte> bytes, std::string_view what) {
  const RawProbe probe = probe_raw_bytes(port, bytes);
  CHECK(probe.send_status.ok());
  CHECK_EQ(probe.bytes_received, std::uint64_t{0});
  CHECK(probe.end_status.ok() || probe.end_status.code() == StatusCode::IoError);
  trxreg::test::note("wire: " + std::string(what) + " -> server closed the connection without replying (" +
                     (probe.end_status.ok() ? std::string("orderly end of stream")
                                            : std::string(trxreg::to_string(probe.end_status.code()))) +
                     ")");
}

/// A Failure document must carry ok=false, an error object with a code and a
/// message, and a code whose text maps back through status_code_from_string to
/// exactly the classification the dispatcher is expected to produce.
void check_failure(const RequestOutcome& outcome, StatusCode expected, std::string_view what) {
  CHECK_EQ(outcome.type, MessageType::Failure);
  CHECK(outcome.body.is_object());

  const Value* ok_field = outcome.body.find("ok");
  CHECK(ok_field != nullptr);
  if (ok_field != nullptr) {
    CHECK(ok_field->is_boolean());
    if (ok_field->is_boolean()) {
      CHECK_EQ(ok_field->as_boolean(), false);
    }
  }

  const Value* error = outcome.body.find("error");
  CHECK(error != nullptr);
  if (error != nullptr) {
    CHECK(error->is_object());
    const Value* message = error->find("message");
    CHECK(message != nullptr);
    if (message != nullptr) {
      CHECK(message->is_text());
    }
  }

  const std::string code_text = failure_code_text(outcome.body);
  CHECK(!code_text.empty());
  StatusCode parsed = StatusCode::Internal;
  const bool known = trxreg::status_code_from_string(code_text, parsed);
  CHECK(known);
  CHECK_EQ(parsed, expected);
  trxreg::test::note("wire: " + std::string(what) + " -> error.code=" + code_text);
}

// ---------------------------------------------------------------------------
// 1. Frame codec
// ---------------------------------------------------------------------------

TRXREG_TEST(wire_frame_codec_round_trip) {
  const FrameLimits limits{};
  const CanonicalLimits documents = CanonicalLimits::request();

  for (const MessageType type : kEveryMessageType) {
    const Value body = sample_document(7);
    const std::vector<std::byte> payload = canonical_bytes(body);
    const std::vector<std::byte> frame = trxreg::wire::encode_frame(type, 0x1234u, payload);

    CHECK_EQ(frame.size(), kHeaderBytes + payload.size() + kTrailerBytes);
    if (frame.size() != kHeaderBytes + payload.size() + kTrailerBytes) {
      continue;
    }
    CHECK_EQ(read_u32_le(frame, frame.size() - kTrailerBytes),
             trxreg::crc32c(frame.data(), frame.size() - kTrailerBytes, 0));

    const Result<trxreg::wire::FrameHeader> header = trxreg::wire::parse_frame_header(as_header(frame), limits);
    CHECK(header.ok());
    if (!header.ok()) {
      continue;
    }
    CHECK_EQ(header.value().version, trxreg::kWireProtocolVersion);
    CHECK_EQ(header.value().type, type);
    CHECK_EQ(header.value().flags, 0x1234u);
    CHECK_EQ(header.value().body_length, static_cast<std::uint32_t>(payload.size()));

    const Result<Frame> decoded = trxreg::wire::decode_frame(frame, limits, documents);
    CHECK(decoded.ok());
    if (!decoded.ok()) {
      continue;
    }
    CHECK_EQ(decoded.value().type, type);
    CHECK_EQ(decoded.value().flags, 0x1234u);
    CHECK(decoded.value().body == body);
  }

  // Every canonical document kind survives the round trip, including the
  // smallest non-empty documents.
  const Value bodies[] = {
      Value::null(),
      Value::boolean(false),
      Value::boolean(true),
      Value::integer(-1),
      Value::real(-0.5),
      Value::text(""),
      Value::object({}),
      Value::array({}),
      Value::object({{"k", Value::text("v")}}),
      sample_document(99),
  };
  for (const Value& body : bodies) {
    const std::vector<std::byte> payload = canonical_bytes(body);
    const std::vector<std::byte> frame = trxreg::wire::encode_frame(MessageType::Request, 0, payload);
    const Result<Frame> decoded = trxreg::wire::decode_frame(frame, limits, documents);
    CHECK(decoded.ok());
    if (decoded.ok()) {
      CHECK(decoded.value().body == body);
      CHECK_EQ(decoded.value().body.kind(), body.kind());
    }
  }

  // A frame body is a canonical document and every document is at least one
  // byte, so a zero-length body is refused at the header. Encoding and decoding
  // agree: an empty body is never half-accepted and then rejected deeper in the
  // stack, and a peer that sends one is dropped with a classified failure.
  const std::vector<std::byte> empty_frame =
      trxreg::wire::encode_frame(MessageType::Ping, 0, std::span<const std::byte>{});
  CHECK_EQ(empty_frame.size(), kHeaderBytes + kTrailerBytes);
  CHECK_EQ(read_u32_le(empty_frame, empty_frame.size() - kTrailerBytes),
           trxreg::crc32c(empty_frame.data(), empty_frame.size() - kTrailerBytes, 0));
  const Result<trxreg::wire::FrameHeader> empty_header =
      trxreg::wire::parse_frame_header(as_header(empty_frame), limits);
  CHECK(!empty_header.ok());
  if (!empty_header.ok()) {
    CHECK_EQ(empty_header.error().code, StatusCode::Malformed);
  }
  const Result<Frame> empty_decoded = trxreg::wire::decode_frame(empty_frame, limits, documents);
  CHECK(!empty_decoded.ok());
  if (!empty_decoded.ok()) {
    CHECK_EQ(empty_decoded.error().code, StatusCode::Malformed);
    trxreg::test::note("wire: a zero-length frame body is refused at the header with " +
                       std::string(trxreg::to_string(empty_decoded.error().code)) + ": " +
                       empty_decoded.error().message);
  }
}

TRXREG_TEST(wire_parse_frame_header_rejections) {
  const FrameLimits limits{};
  const std::uint16_t request_type = static_cast<std::uint16_t>(MessageType::Request);

  {
    std::vector<std::byte> header = header_bytes(trxreg::kWireProtocolVersion, request_type, 0, 0, 0);
    header[0] = static_cast<std::byte>('X');
    const Result<trxreg::wire::FrameHeader> parsed = trxreg::wire::parse_frame_header(as_header(header), limits);
    CHECK(!parsed.ok());
    if (!parsed.ok()) {
      CHECK_EQ(parsed.error().code, StatusCode::Malformed);
    }
  }
  {
    const std::vector<std::byte> header =
        header_bytes(static_cast<std::uint16_t>(trxreg::kWireProtocolVersion + 1), request_type, 0, 0, 0);
    const Result<trxreg::wire::FrameHeader> parsed = trxreg::wire::parse_frame_header(as_header(header), limits);
    CHECK(!parsed.ok());
    if (!parsed.ok()) {
      CHECK_EQ(parsed.error().code, StatusCode::Malformed);
    }
  }
  {
    const std::vector<std::byte> header = header_bytes(trxreg::kWireProtocolVersion, 99, 0, 0, 0);
    const Result<trxreg::wire::FrameHeader> parsed = trxreg::wire::parse_frame_header(as_header(header), limits);
    CHECK(!parsed.ok());
    if (!parsed.ok()) {
      CHECK_EQ(parsed.error().code, StatusCode::Malformed);
    }
  }
  {
    const std::vector<std::byte> header = header_bytes(trxreg::kWireProtocolVersion, request_type, 0, 1, 0);
    const Result<trxreg::wire::FrameHeader> parsed = trxreg::wire::parse_frame_header(as_header(header), limits);
    CHECK(!parsed.ok());
    if (!parsed.ok()) {
      CHECK_EQ(parsed.error().code, StatusCode::Malformed);
    }
  }

  // The body-length ceiling is checked at the header, with the configured
  // limit of 64 bytes. Note that the frame given to decode_frame below is only
  // header + trailer: the classification must be the limit refusal, not the
  // length mismatch or the checksum, which proves no body was ever considered.
  FrameLimits small;
  small.max_body_bytes = 64;
  {
    const std::vector<std::byte> header = header_bytes(trxreg::kWireProtocolVersion, request_type, 0, 0, 64);
    CHECK(trxreg::wire::parse_frame_header(as_header(header), small).ok());
  }
  {
    const std::vector<std::byte> header = header_bytes(trxreg::kWireProtocolVersion, request_type, 0, 0, 65);
    const Result<trxreg::wire::FrameHeader> parsed = trxreg::wire::parse_frame_header(as_header(header), small);
    CHECK(!parsed.ok());
    if (!parsed.ok()) {
      CHECK_EQ(parsed.error().code, StatusCode::CapacityExceeded);
    }
  }
  {
    std::vector<std::byte> header = header_bytes(trxreg::kWireProtocolVersion, request_type, 0, 0, 0xFFFFFFFFu);
    const Result<trxreg::wire::FrameHeader> parsed = trxreg::wire::parse_frame_header(as_header(header), small);
    CHECK(!parsed.ok());
    if (!parsed.ok()) {
      CHECK_EQ(parsed.error().code, StatusCode::CapacityExceeded);
      trxreg::test::note("wire: a declared 0xFFFFFFFF-byte body is refused at the header with " +
                         std::string(trxreg::to_string(parsed.error().code)) + ": " + parsed.error().message);
    }

    // Same declaration inside a complete-looking 20-byte buffer: still refused
    // as CapacityExceeded before the frame length and the CRC are examined.
    header.resize(kHeaderBytes + kTrailerBytes, std::byte{0});
    const Result<Frame> decoded = trxreg::wire::decode_frame(header, small, CanonicalLimits::request());
    CHECK(!decoded.ok());
    if (!decoded.ok()) {
      CHECK_EQ(decoded.error().code, StatusCode::CapacityExceeded);
    }
  }
}

// ---------------------------------------------------------------------------
// 2. decode_frame rejections
// ---------------------------------------------------------------------------

TRXREG_TEST(wire_decode_frame_rejections) {
  const FrameLimits limits{};
  const CanonicalLimits documents = CanonicalLimits::request();
  const Value body = sample_document(3);
  const std::vector<std::byte> payload = canonical_bytes(body);
  const std::vector<std::byte> frame = trxreg::wire::encode_frame(MessageType::Request, 0, payload);
  CHECK(trxreg::wire::decode_frame(frame, limits, documents).ok());

  // Shorter than header plus trailer.
  const std::size_t short_sizes[] = {0, kHeaderBytes, kHeaderBytes + kTrailerBytes - 1};
  for (const std::size_t size : short_sizes) {
    const std::vector<std::byte> truncated(frame.begin(), frame.begin() + static_cast<std::ptrdiff_t>(size));
    CHECK_EQ(failure_code(trxreg::wire::decode_frame(truncated, limits, documents)), StatusCode::Corrupt);
  }

  // A declared body length that disagrees with the actual frame size: one body
  // byte missing, one byte appended, and a whole second frame appended.
  {
    const std::vector<std::byte> missing(frame.begin(), frame.end() - 1);
    CHECK_EQ(failure_code(trxreg::wire::decode_frame(missing, limits, documents)), StatusCode::Corrupt);

    std::vector<std::byte> trailing = frame;
    trailing.push_back(std::byte{0x5a});
    CHECK_EQ(failure_code(trxreg::wire::decode_frame(trailing, limits, documents)), StatusCode::Corrupt);

    std::vector<std::byte> doubled = frame;
    doubled.insert(doubled.end(), frame.begin(), frame.end());
    CHECK_EQ(failure_code(trxreg::wire::decode_frame(doubled, limits, documents)), StatusCode::Corrupt);

    const std::vector<std::byte> declared_wrong =
        header_bytes(trxreg::kWireProtocolVersion, static_cast<std::uint16_t>(MessageType::Request), 0, 0,
                     static_cast<std::uint32_t>(payload.size()) + 1u);
    std::vector<std::byte> mismatched = declared_wrong;
    mismatched.insert(mismatched.end(), frame.begin() + static_cast<std::ptrdiff_t>(kHeaderBytes), frame.end());
    CHECK_EQ(failure_code(trxreg::wire::decode_frame(mismatched, limits, documents)), StatusCode::Corrupt);
  }

  // A corrupted checksum: a flipped body byte keeps the size valid, a flipped
  // trailer byte corrupts the stored checksum itself.
  {
    std::vector<std::byte> body_flip = frame;
    body_flip[kHeaderBytes] ^= std::byte{0xff};
    CHECK_EQ(failure_code(trxreg::wire::decode_frame(body_flip, limits, documents)), StatusCode::Corrupt);

    std::vector<std::byte> trailer_flip = frame;
    trailer_flip[trailer_flip.size() - 1] ^= std::byte{0x01};
    CHECK_EQ(failure_code(trxreg::wire::decode_frame(trailer_flip, limits, documents)), StatusCode::Corrupt);

    // Flipping every body byte without touching the trailer is still refused.
    std::vector<std::byte> all_flip = frame;
    for (std::size_t i = kHeaderBytes; i < all_flip.size() - kTrailerBytes; ++i) {
      all_flip[i] ^= std::byte{0x01};
    }
    CHECK_EQ(failure_code(trxreg::wire::decode_frame(all_flip, limits, documents)), StatusCode::Corrupt);
  }
}

// ---------------------------------------------------------------------------
// 3. read_frame / write_frame over a real loopback socket
// ---------------------------------------------------------------------------

TRXREG_TEST(wire_loopback_socket_exchange) {
  // Only loopback literals may be connected, and the refusal is classified
  // before any name resolution or socket is created.
  REQUIRE_FAILS(trxreg::net::Socket::connect_loopback("192.0.2.1", 9), StatusCode::Refused);
  REQUIRE_FAILS(trxreg::net::Socket::connect_loopback("0.0.0.0", 9), StatusCode::Refused);
  REQUIRE_FAILS(trxreg::net::Socket::connect_loopback("localhost", 9), StatusCode::Refused);

  const FrameLimits limits{};
  const CanonicalLimits documents = CanonicalLimits::request();

  Result<trxreg::net::Listener> bound = trxreg::net::Listener::bind_loopback(0);
  REQUIRE_OK(bound);
  CHECK_NE(bound.value().port(), static_cast<std::uint16_t>(0));

  struct PeerResult {
    bool accepted{false};
    Status read_status{};
    Frame received{};
    Status write_status{};
  };
  PeerResult peer;

  std::thread worker([&bound, &peer, &limits, &documents]() {
    Result<trxreg::net::Socket> accepted = bound.value().accept();
    if (!accepted.ok()) {
      peer.read_status = Status(accepted.error());
      return;
    }
    peer.accepted = true;
    trxreg::net::Socket peer_socket = std::move(accepted.value());
    const Result<Frame> frame = trxreg::wire::read_frame(peer_socket, limits, documents);
    if (!frame.ok()) {
      peer.read_status = Status(frame.error());
      static_cast<void>(peer_socket.close());
      return;
    }
    peer.read_status = Status::success();
    peer.received = frame.value();
    const Value reply = Value::object({
        {"echo", frame.value().body},
        {"ok", Value::boolean(true)},
    });
    peer.write_status = trxreg::wire::write_frame(peer_socket, MessageType::Response, 0, reply, limits);
    static_cast<void>(peer_socket.close());
  });

  // Closes the listener (unblocking a pending accept) and joins the worker on
  // any exit path; the client socket is declared after this guard, so it is
  // closed first and the worker can never be left blocked in a read.
  struct PeerGuard {
    trxreg::net::Listener& listener;
    std::thread& thread;
    ~PeerGuard() {
      static_cast<void>(listener.close());
      if (thread.joinable()) {
        thread.join();
      }
    }
  };
  PeerGuard guard{bound.value(), worker};

  Result<trxreg::net::Socket> connected = trxreg::net::Socket::connect_loopback("127.0.0.1", bound.value().port());
  REQUIRE_OK(connected);
  trxreg::net::Socket socket = std::move(connected.value());

  const Value request = sample_document(42);
  const Value expected_reply = Value::object({{"echo", request}, {"ok", Value::boolean(true)}});
  REQUIRE_OK(trxreg::wire::write_frame(socket, MessageType::Request, 0, request, limits));
  const Result<Frame> response = trxreg::wire::read_frame(socket, limits, documents);
  CHECK(response.ok());

  worker.join();

  CHECK(peer.accepted);
  REQUIRE_OK(peer.read_status);
  CHECK_EQ(peer.received.type, MessageType::Request);
  CHECK_EQ(peer.received.flags, 0);
  CHECK(peer.received.body == request);
  trxreg::test::note("wire: loopback peer received the sent document byte-for-byte");
  REQUIRE_OK(peer.write_status);
  if (response.ok()) {
    CHECK_EQ(response.value().type, MessageType::Response);
    CHECK(response.value().body == expected_reply);
  }
  REQUIRE_OK(socket.close());
}

// ---------------------------------------------------------------------------
// 4. Client against an in-process Server
// ---------------------------------------------------------------------------

TRXREG_TEST(wire_client_server_request_flow) {
  trxreg::Registry registry;
  trxreg::wire::ServerOptions options;
  options.port = 0;
  options.bind_address = "127.0.0.1";

  ServerHarness harness(registry, options);
  REQUIRE_OK(harness.start());
  CHECK_NE(harness.port(), static_cast<std::uint16_t>(0));
  CHECK(harness.running());

  Result<trxreg::wire::Client> connected = trxreg::wire::Client::connect("127.0.0.1", harness.port());
  REQUIRE_OK(connected);
  trxreg::wire::Client client = std::move(connected.value());

  const Result<Value> hello = client.hello(4242);
  REQUIRE_OK(hello);
  const Value* protocol = hello.value().find("protocol");
  CHECK(protocol != nullptr);
  if (protocol != nullptr) {
    CHECK(protocol->is_integer());
    CHECK_EQ(protocol->as_integer(), static_cast<std::int64_t>(trxreg::kWireProtocolVersion));
  }
  const Value* version = hello.value().find("version");
  CHECK(version != nullptr);
  if (version != nullptr) {
    CHECK(version->is_text());
    CHECK_EQ(version->as_text(), std::string(trxreg::version_string()));
  }
  const Value* incarnation = hello.value().find("registry_incarnation");
  CHECK(incarnation != nullptr);
  if (incarnation != nullptr) {
    CHECK_EQ(incarnation->as_integer(), static_cast<std::int64_t>(registry.registry_incarnation()));
  }

  const trxreg::RegistryStats expected = registry.stats();
  const Result<Value> stats = client.call("registry.stats", Value::object({}));
  REQUIRE_OK(stats);
  CHECK(stats.value().is_object());
  const Value* modules = stats.value().find("modules");
  CHECK(modules != nullptr);
  if (modules != nullptr) {
    CHECK(modules->is_integer());
    CHECK_EQ(modules->as_integer(), static_cast<std::int64_t>(expected.modules));
  }
  const Value* sources = stats.value().find("sources");
  CHECK(sources != nullptr);
  if (sources != nullptr) {
    CHECK_EQ(sources->as_integer(), static_cast<std::int64_t>(expected.sources));
  }
  const Value* ports = stats.value().find("ports");
  CHECK(ports != nullptr);
  if (ports != nullptr) {
    CHECK_EQ(ports->as_integer(), static_cast<std::int64_t>(expected.ports));
  }
  const Value* digest = stats.value().find("state_digest");
  CHECK(digest != nullptr);
  if (digest != nullptr) {
    CHECK(digest->is_text());
    CHECK_EQ(digest->as_text().size(), std::size_t{64});
  }

  const Result<Value> unknown = client.call("wire.no_such_operation", Value::object({}));
  CHECK(!unknown.ok());
  if (!unknown.ok()) {
    CHECK_EQ(unknown.error().code, StatusCode::Unsupported);
    CHECK(unknown.error().message.find("wire.no_such_operation") != std::string::npos);
    trxreg::test::note("wire: unknown op over the wire -> " + std::string(trxreg::to_string(unknown.error().code)) +
                       ": " + unknown.error().message);
  }

  // The same refusal seen as raw bytes on a second connection: a Failure frame
  // whose body carries ok=false and error.code="unsupported".
  {
    Result<trxreg::net::Socket> raw_connected = trxreg::net::Socket::connect_loopback("127.0.0.1", harness.port());
    REQUIRE_OK(raw_connected);
    trxreg::net::Socket raw = std::move(raw_connected.value());
    REQUIRE_OK(trxreg::wire::write_frame(
        raw, MessageType::Request, 0,
        Value::object({{"id", Value::integer(1)}, {"op", Value::text("wire.no_such_operation")}}), FrameLimits{}));
    const Result<Frame> failure = trxreg::wire::read_frame(raw, FrameLimits{}, CanonicalLimits::request());
    CHECK(failure.ok());
    if (failure.ok()) {
      CHECK_EQ(failure.value().type, MessageType::Failure);
      const Value* ok_field = failure.value().body.find("ok");
      CHECK(ok_field != nullptr);
      if (ok_field != nullptr) {
        CHECK(ok_field->is_boolean());
        if (ok_field->is_boolean()) {
          CHECK_EQ(ok_field->as_boolean(), false);
        }
      }
      CHECK_EQ(failure_code_text(failure.value().body), std::string("unsupported"));
      const Value* error = failure.value().body.find("error");
      CHECK(error != nullptr);
      if (error != nullptr) {
        const Value* message = error->find("message");
        CHECK(message != nullptr);
        if (message != nullptr && message->is_text()) {
          CHECK(message->as_text().find("wire.no_such_operation") != std::string::npos);
        }
      }
    }
    REQUIRE_OK(raw.close());
  }

  // The failed request left the connection usable.
  const Result<Value> generation = client.call("registry.generation", Value::object({}));
  REQUIRE_OK(generation);
  const Value* generation_field = generation.value().find("generation");
  CHECK(generation_field != nullptr);
  if (generation_field != nullptr) {
    CHECK_EQ(generation_field->as_integer(), static_cast<std::int64_t>(registry.generation().value()));
  }

  // stop() runs while the client connection is still open, so it must unblock
  // and join a worker sitting in a read, then close the listener under the
  // accept loop. The destructor performs exactly this stop() again.
  const Status stopped = harness.stop();
  CHECK(stopped.ok());
  CHECK(!harness.running());
  CHECK(harness.run_status().ok());
  CHECK(harness.stop().ok());
  REQUIRE_OK(client.close());
}

// ---------------------------------------------------------------------------
// 5. dispatch() classification
// ---------------------------------------------------------------------------

TRXREG_TEST(wire_dispatch_classification) {
  trxreg::Registry registry;
  const CanonicalLimits documents = CanonicalLimits::request();
  const std::uint64_t generation_before = registry.generation().value();

  // A successful request is a Response document with ok=true, so the Failure
  // assertions below are not vacuous.
  const RequestOutcome ping = trxreg::wire::dispatch(
      registry, Value::object({{"id", Value::integer(1)}, {"op", Value::text("ping")}, {"params", Value::object({})}}),
      documents);
  CHECK_EQ(ping.type, MessageType::Response);
  const Value* ping_ok = ping.body.find("ok");
  CHECK(ping_ok != nullptr);
  if (ping_ok != nullptr && ping_ok->is_boolean()) {
    CHECK_EQ(ping_ok->as_boolean(), true);
  }

  const RequestOutcome unknown_op = trxreg::wire::dispatch(
      registry,
      Value::object({{"id", Value::integer(11)}, {"op", Value::text("totally.unknown")}, {"params", Value::object({})}}),
      documents);
  check_failure(unknown_op, StatusCode::Unsupported, "unknown op");
  const Value* unknown_id = unknown_op.body.find("id");
  CHECK(unknown_id != nullptr);
  if (unknown_id != nullptr && unknown_id->is_integer()) {
    CHECK_EQ(unknown_id->as_integer(), std::int64_t{11});
  }

  const RequestOutcome not_an_object = trxreg::wire::dispatch(registry, Value::integer(5), documents);
  check_failure(not_an_object, StatusCode::Malformed, "request is not an object");

  const RequestOutcome array_request = trxreg::wire::dispatch(registry, Value::array({}), documents);
  check_failure(array_request, StatusCode::Malformed, "request is an array");

  const RequestOutcome missing_op =
      trxreg::wire::dispatch(registry, Value::object({{"id", Value::integer(12)}}), documents);
  check_failure(missing_op, StatusCode::Malformed, "missing op");
  const Value* missing_op_id = missing_op.body.find("id");
  CHECK(missing_op_id != nullptr);
  if (missing_op_id != nullptr && missing_op_id->is_integer()) {
    CHECK_EQ(missing_op_id->as_integer(), std::int64_t{12});
  }

  const RequestOutcome non_text_op =
      trxreg::wire::dispatch(registry, Value::object({{"id", Value::integer(13)}, {"op", Value::integer(7)}}),
                             documents);
  check_failure(non_text_op, StatusCode::Malformed, "op is not text");

  const RequestOutcome empty_op =
      trxreg::wire::dispatch(registry, Value::object({{"id", Value::integer(14)}, {"op", Value::text("")}}),
                             documents);
  check_failure(empty_op, StatusCode::Malformed, "op is empty");

  // An unknown mutation policy is rejected before the registry is touched, so
  // the generation must be unchanged afterwards.
  const RequestOutcome unknown_policy = trxreg::wire::dispatch(
      registry,
      Value::object({{"id", Value::integer(15)},
                     {"op", Value::text("module.register")},
                     {"params", Value::object({{"key", Value::text("wire/module-1")},
                                               {"policy", Value::text("definitely-not-a-policy")},
                                               {"provenance", provenance_document()}})}}),
      documents);
  check_failure(unknown_policy, StatusCode::InvalidArgument, "unknown mutation policy");
  CHECK_EQ(registry.generation().value(), generation_before);

  // Every failure document produced above classified itself: check_failure
  // mapped each error.code text back through status_code_from_string.
}

// ---------------------------------------------------------------------------
// 6. Hostile and malformed frames against a live server
// ---------------------------------------------------------------------------

TRXREG_TEST(wire_hostile_frames_are_contained) {
  trxreg::Registry registry;
  trxreg::wire::ServerOptions options;
  options.port = 0;

  ServerHarness harness(registry, options);
  REQUIRE_OK(harness.start());
  const std::uint16_t port = harness.port();

  const FrameLimits limits{};
  const CanonicalLimits documents = CanonicalLimits::request();

  // 6a. Bytes that are not a frame at all.
  {
    std::vector<std::byte> garbage;
    const std::string_view text = "this is not a TRXF frame at all, not even close";
    garbage.reserve(text.size());
    for (const char character : text) {
      garbage.push_back(static_cast<std::byte>(static_cast<unsigned char>(character)));
    }
    expect_silent_close(port, garbage, "bytes that are not a frame");
    expect_server_healthy(port);
  }

  // 6b. A well-formed frame with a corrupted checksum.
  {
    const std::vector<std::byte> good =
        trxreg::wire::encode_frame(MessageType::Request, 0, canonical_bytes(sample_document(1)));
    std::vector<std::byte> bad_crc = good;
    bad_crc[bad_crc.size() - 1] ^= std::byte{0x01};
    CHECK_EQ(failure_code(trxreg::wire::decode_frame(bad_crc, limits, documents)), StatusCode::Corrupt);
    expect_silent_close(port, bad_crc, "a frame with a bad CRC");
    expect_server_healthy(port);
  }

  // 6c. A frame with a valid checksum whose body is not a canonical document.
  {
    const std::vector<std::byte> raw_body{std::byte{0xff}, std::byte{0xff}, std::byte{0xff}};
    const std::vector<std::byte> not_a_document =
        trxreg::wire::encode_frame(MessageType::Request, 0, raw_body);
    CHECK_EQ(failure_code(trxreg::wire::decode_frame(not_a_document, limits, documents)), StatusCode::Malformed);
    expect_silent_close(port, not_a_document, "a frame whose body is not a document");
    expect_server_healthy(port);
  }

  // 6d. Only the header is sent, declaring a 4 GiB body. The server must refuse
  // the declaration and close; it must not wait for (or allocate) the body.
  {
    const std::vector<std::byte> header =
        header_bytes(trxreg::kWireProtocolVersion, static_cast<std::uint16_t>(MessageType::Request), 0, 0,
                     0xFFFFFFFFu);
    CHECK_EQ(header.size(), kHeaderBytes);
    expect_silent_close(port, header, "a header declaring a 4 GiB body");
    expect_server_healthy(port);
  }

  // 6e. A small, valid frame carrying a document nested far past the request
  // depth limit: the refusal is about nesting, not about bytes.
  {
    Value deep = Value::null();
    for (int i = 0; i < 40; ++i) {
      deep = Value::array({deep});
    }
    const std::vector<std::byte> payload = canonical_bytes(deep);
    CHECK(payload.size() < 128);
    const std::vector<std::byte> frame = trxreg::wire::encode_frame(MessageType::Request, 0, payload);
    const Result<Frame> decoded = trxreg::wire::decode_frame(frame, limits, documents);
    CHECK(!decoded.ok());
    if (!decoded.ok()) {
      CHECK_EQ(decoded.error().code, StatusCode::CapacityExceeded);
    }
    expect_silent_close(port, frame, "a frame nested 40 levels deep");
    expect_server_healthy(port);
  }

  // 6f. A frame whose body decodes into a document that is not an object: the
  // server answers with a classified Failure and keeps the connection.
  {
    Result<trxreg::net::Socket> connected = trxreg::net::Socket::connect_loopback("127.0.0.1", port);
    REQUIRE_OK(connected);
    trxreg::net::Socket socket = std::move(connected.value());

    REQUIRE_OK(trxreg::wire::write_frame(socket, MessageType::Request, 0, Value::text("not an object"), limits));
    const Result<Frame> reply = trxreg::wire::read_frame(socket, limits, documents);
    CHECK(reply.ok());
    if (reply.ok()) {
      CHECK_EQ(reply.value().type, MessageType::Failure);
      CHECK_EQ(failure_code_text(reply.value().body), std::string("malformed"));
    }

    // The hostile-but-decodable request did not tear the connection down.
    REQUIRE_OK(trxreg::wire::write_frame(socket, MessageType::Ping, 0,
                                         Value::object({{"op", Value::text("ping")}}), limits));
    const Result<Frame> pong = trxreg::wire::read_frame(socket, limits, documents);
    CHECK(pong.ok());
    if (pong.ok()) {
      CHECK_EQ(pong.value().type, MessageType::Pong);
    }
    REQUIRE_OK(socket.close());
  }

  // 6g. Only a successful ping is acknowledged as a pong. A ping whose body is
  // not a valid request keeps its failure classification, so a client that keys
  // off the frame type cannot read a failed round trip as a healthy one.
  {
    Result<trxreg::net::Socket> connected = trxreg::net::Socket::connect_loopback("127.0.0.1", port);
    REQUIRE_OK(connected);
    trxreg::net::Socket socket = std::move(connected.value());
    REQUIRE_OK(trxreg::wire::write_frame(socket, MessageType::Ping, 0, Value::object({}), limits));
    const Result<Frame> reply = trxreg::wire::read_frame(socket, limits, documents);
    CHECK(reply.ok());
    if (reply.ok()) {
      CHECK_EQ(reply.value().type, MessageType::Failure);
      const Value* ok_field = reply.value().body.find("ok");
      CHECK(ok_field != nullptr);
      if (ok_field != nullptr && ok_field->is_boolean()) {
        CHECK_EQ(ok_field->as_boolean(), false);
      }
      trxreg::test::note("wire: a ping without an op is answered with a failure frame carrying error.code=" +
                         failure_code_text(reply.value().body));
    }
    REQUIRE_OK(socket.close());
  }

  // 6h. A well-formed ping is acknowledged as a pong.
  {
    Result<trxreg::net::Socket> connected = trxreg::net::Socket::connect_loopback("127.0.0.1", port);
    REQUIRE_OK(connected);
    trxreg::net::Socket socket = std::move(connected.value());
    REQUIRE_OK(trxreg::wire::write_frame(
        socket, MessageType::Ping, 0,
        Value::object({{"id", Value::integer(1)}, {"op", Value::text("ping")}}), limits));
    const Result<Frame> reply = trxreg::wire::read_frame(socket, limits, documents);
    CHECK(reply.ok());
    if (reply.ok()) {
      CHECK_EQ(reply.value().type, MessageType::Pong);
      const Value* ok_field = reply.value().body.find("ok");
      REQUIRE(ok_field != nullptr);
      CHECK_EQ(ok_field->as_boolean(), true);
    }
    REQUIRE_OK(socket.close());
  }

  CHECK(harness.running());
  CHECK(harness.run_status().ok());
  REQUIRE_OK(harness.stop());
}

// ---------------------------------------------------------------------------
// 7. Bounded requests per connection
// ---------------------------------------------------------------------------

TRXREG_TEST(wire_server_bounds_requests_per_connection) {
  trxreg::Registry registry;
  trxreg::wire::ServerOptions options;
  options.port = 0;
  options.max_requests_per_connection = 3;

  ServerHarness harness(registry, options);
  REQUIRE_OK(harness.start());

  Result<trxreg::wire::Client> connected = trxreg::wire::Client::connect("127.0.0.1", harness.port());
  REQUIRE_OK(connected);
  trxreg::wire::Client client = std::move(connected.value());

  int served = 0;
  for (int i = 0; i < 3; ++i) {
    const Result<Value> response = client.call("registry.generation", Value::object({}));
    CHECK(response.ok());
    if (!response.ok()) {
      trxreg::test::note("wire: request " + std::to_string(i + 1) + " failed unexpectedly: " +
                         std::string(trxreg::to_string(response.error().code)) + ": " + response.error().message);
      break;
    }
    ++served;
  }
  CHECK_EQ(served, 3);

  if (served == 3) {
    const Result<Value> fourth = client.call("registry.generation", Value::object({}));
    CHECK(!fourth.ok());
    if (!fourth.ok()) {
      const bool classified =
          fourth.error().code == StatusCode::IoError || fourth.error().code == StatusCode::Corrupt;
      CHECK(classified);
      trxreg::test::note("wire: request 4 of max_requests_per_connection=3 -> " +
                         std::string(trxreg::to_string(fourth.error().code)) + ": " + fourth.error().message);
    }
  }

  // The server is still healthy: the bound applies to one connection only.
  expect_server_healthy(harness.port());
  CHECK(harness.running());
  REQUIRE_OK(harness.stop());
  CHECK(harness.run_status().ok());
}

}  // namespace

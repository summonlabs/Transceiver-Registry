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

#include "trxreg/wire.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include "codec.hpp"
#include "value_fields.hpp"

namespace trxreg::wire {
namespace {

using detail::get_array;
using detail::get_array_or;
using detail::get_boolean_or;
using detail::get_integer;
using detail::get_integer_or;
using detail::get_text;
using detail::get_text_or;
using detail::get_unsigned;
using detail::get_unsigned_or;

constexpr std::uint16_t kReservedFlags = 0;

void append_u16(std::vector<std::byte>& out, std::uint16_t value) {
  out.push_back(static_cast<std::byte>(value & 0xffu));
  out.push_back(static_cast<std::byte>((value >> 8u) & 0xffu));
}

void append_u32(std::vector<std::byte>& out, std::uint32_t value) {
  for (std::size_t i = 0; i < 4; ++i) {
    out.push_back(static_cast<std::byte>((value >> (8u * i)) & 0xffu));
  }
}

std::uint16_t read_u16(std::span<const std::byte> data, std::size_t offset) {
  return static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(data[offset]) |
                                    (static_cast<std::uint16_t>(std::to_integer<std::uint8_t>(data[offset + 1])) << 8u));
}

std::uint32_t read_u32(std::span<const std::byte> data, std::size_t offset) {
  std::uint32_t value = 0;
  for (std::size_t i = 0; i < 4; ++i) {
    value |= static_cast<std::uint32_t>(std::to_integer<std::uint8_t>(data[offset + i])) << (8u * i);
  }
  return value;
}

Value error_document(const Error& error) {
  return codec::object({{"code", Value::text(std::string(to_string(error.code)))},
                        {"message", Value::text(error.message)}});
}

Value make_response(std::uint64_t id, Value result) {
  return codec::object({{"id", Value::integer(static_cast<std::int64_t>(id))},
                        {"ok", Value::boolean(true)},
                        {"result", std::move(result)}});
}

Value make_failure(std::uint64_t id, const Error& error) {
  return codec::object({{"error", error_document(error)},
                        {"id", Value::integer(static_cast<std::int64_t>(id))},
                        {"ok", Value::boolean(false)}});
}

Result<std::uint64_t> request_id(const Value& request) {
  TRXREG_TRY_ASSIGN(id, get_unsigned(request, "id"));
  return id;
}

Result<std::string> request_op(const Value& request) {
  TRXREG_TRY_ASSIGN(op, get_text(request, "op"));
  if (op.empty() || op.size() > 64) {
    return make_error(StatusCode::Malformed, "request op must be a short non-empty name");
  }
  return op;
}

const Value& params_of(const Value& request) {
  const Value* params = request.find("params");
  return params != nullptr ? *params : request;
}

Result<AuthorityToken> read_authority_param(const Value& params) {
  const Value* authority = params.find("authority");
  if (authority == nullptr) {
    return make_error(StatusCode::InvalidArgument, "request is missing its authority token");
  }
  return codec::decode<AuthorityToken>(*authority);
}

Result<MutationPolicy> read_policy_param(const Value& params) {
  const std::string text = get_text_or(params, "policy", "require_generation");
  if (text == "require_generation") {
    return MutationPolicy::RequireGeneration;
  }
  if (text == "auto_retry") {
    return MutationPolicy::AutoRetry;
  }
  return make_error(StatusCode::InvalidArgument, "unknown mutation policy");
}

Result<ModuleHandle> read_module_handle(const Value& params) {
  const Value* handle = params.find("module");
  if (handle == nullptr) {
    return make_error(StatusCode::InvalidArgument, "request is missing its module handle");
  }
  return codec::decode<ModuleHandle>(*handle);
}

Result<ModuleHandle> read_module_reference(const Value& params) {
  ModuleHandle handle;
  TRXREG_TRY_ASSIGN(uid, get_unsigned(params, "uid"));
  TRXREG_TRY_ASSIGN(incarnation, get_unsigned(params, "incarnation"));
  if (uid == 0 || incarnation == 0 || incarnation > 0xFFFFFFFFull) {
    return make_error(StatusCode::InvalidArgument, "module reference is out of range");
  }
  handle.uid = ModuleUid{uid};
  handle.incarnation = IncarnationId{static_cast<std::uint32_t>(incarnation)};
  handle.generation = Generation{get_unsigned_or(params, "generation", 0)};
  return handle;
}

Value encode_sample_list(const std::vector<HealthSample>& samples) {
  Value::Array array;
  array.reserve(samples.size());
  for (const HealthSample& sample : samples) {
    array.push_back(codec::encode(sample));
  }
  return Value::array(std::move(array));
}

Value encode_claim_list(const std::vector<IdentityClaim>& claims) {
  Value::Array array;
  array.reserve(claims.size());
  for (const IdentityClaim& claim : claims) {
    array.push_back(codec::encode(claim));
  }
  return Value::array(std::move(array));
}

Value encode_declaration_list(const std::vector<CapabilityDeclaration>& declarations) {
  Value::Array array;
  array.reserve(declarations.size());
  for (const CapabilityDeclaration& declaration : declarations) {
    array.push_back(codec::encode(declaration));
  }
  return Value::array(std::move(array));
}

Value encode_event_list(const std::vector<LifecycleEvent>& events) {
  Value::Array array;
  array.reserve(events.size());
  for (const LifecycleEvent& event : events) {
    array.push_back(codec::encode(event));
  }
  return Value::array(std::move(array));
}

}  // namespace

std::string_view to_string(MessageType type) noexcept {
  switch (type) {
    case MessageType::Hello:
      return "hello";
    case MessageType::HelloAck:
      return "hello_ack";
    case MessageType::Request:
      return "request";
    case MessageType::Response:
      return "response";
    case MessageType::Failure:
      return "failure";
    case MessageType::Ping:
      return "ping";
    case MessageType::Pong:
      return "pong";
    case MessageType::Shutdown:
      return "shutdown";
  }
  return "unknown";
}

bool message_type_from_string(std::string_view text, MessageType& out) noexcept {
  static constexpr MessageType kAll[] = {MessageType::Hello,   MessageType::HelloAck, MessageType::Request,
                                         MessageType::Response, MessageType::Failure, MessageType::Ping,
                                         MessageType::Pong,   MessageType::Shutdown};
  for (const MessageType candidate : kAll) {
    if (to_string(candidate) == text) {
      out = candidate;
      return true;
    }
  }
  return false;
}

Result<FrameHeader> parse_frame_header(std::span<const std::byte, kFrameHeaderBytes> header,
                                       const FrameLimits& limits) {
  if (std::memcmp(header.data(), kFrameMagic, sizeof(kFrameMagic)) != 0) {
    return make_error(StatusCode::Malformed, "frame magic does not match");
  }
  const std::uint16_t version = read_u16(header, 4);
  if (version != kWireProtocolVersion) {
    return make_error(StatusCode::Malformed, "unsupported wire protocol version");
  }
  const std::uint16_t type_raw = read_u16(header, 6);
  FrameHeader parsed;
  parsed.version = version;
  if (!message_type_from_string("", parsed.type)) {
    parsed.type = MessageType::Request;
  }
  switch (type_raw) {
    case 1:
      parsed.type = MessageType::Hello;
      break;
    case 2:
      parsed.type = MessageType::HelloAck;
      break;
    case 3:
      parsed.type = MessageType::Request;
      break;
    case 4:
      parsed.type = MessageType::Response;
      break;
    case 5:
      parsed.type = MessageType::Failure;
      break;
    case 6:
      parsed.type = MessageType::Ping;
      break;
    case 7:
      parsed.type = MessageType::Pong;
      break;
    case 8:
      parsed.type = MessageType::Shutdown;
      break;
    default:
      return make_error(StatusCode::Malformed, "unknown frame message type");
  }
  parsed.flags = read_u16(header, 8);
  if (read_u16(header, 10) != kReservedFlags) {
    return make_error(StatusCode::Malformed, "frame reserved field must be zero");
  }
  parsed.body_length = read_u32(header, 12);
  if (parsed.body_length > limits.max_body_bytes) {
    return make_error(StatusCode::CapacityExceeded, "frame body exceeds the configured limit");
  }
  if (parsed.body_length == 0) {
    // A frame body is a canonical document, and every document is at least one
    // byte. Refusing the header keeps encode and decode symmetric: an empty body
    // can never be half-accepted and then fail deeper in the stack.
    return make_error(StatusCode::Malformed, "a frame body must carry a canonical document");
  }
  return parsed;
}

std::vector<std::byte> encode_frame(MessageType type, std::uint16_t flags, std::span<const std::byte> body) {
  std::vector<std::byte> frame;
  frame.reserve(kFrameHeaderBytes + body.size() + kFrameTrailerBytes);
  for (const char magic : kFrameMagic) {
    frame.push_back(static_cast<std::byte>(static_cast<unsigned char>(magic)));
  }
  append_u16(frame, kWireProtocolVersion);
  append_u16(frame, static_cast<std::uint16_t>(type));
  append_u16(frame, flags);
  append_u16(frame, kReservedFlags);
  append_u32(frame, static_cast<std::uint32_t>(body.size()));
  frame.insert(frame.end(), body.begin(), body.end());
  append_u32(frame, crc32c(frame));
  return frame;
}

Result<Frame> decode_frame(std::span<const std::byte> frame_bytes, const FrameLimits& limits,
                           CanonicalLimits document_limits) {
  if (frame_bytes.size() < kFrameHeaderBytes + kFrameTrailerBytes) {
    return make_error(StatusCode::Corrupt, "frame is shorter than its header and checksum");
  }
  const std::span<const std::byte, kFrameHeaderBytes> header = frame_bytes.first<kFrameHeaderBytes>();
  TRXREG_TRY_ASSIGN(parsed_header, parse_frame_header(header, limits));
  const std::size_t expected = kFrameHeaderBytes + parsed_header.body_length + kFrameTrailerBytes;
  if (frame_bytes.size() != expected) {
    return make_error(StatusCode::Corrupt, "frame length does not match its declared body length");
  }
  const std::span<const std::byte> checksummed = frame_bytes.first(frame_bytes.size() - kFrameTrailerBytes);
  const std::uint32_t stored = read_u32(frame_bytes, frame_bytes.size() - kFrameTrailerBytes);
  if (crc32c(checksummed.data(), checksummed.size(), 0) != stored) {
    return make_error(StatusCode::Corrupt, "frame failed its integrity check");
  }
  Frame frame;
  frame.type = parsed_header.type;
  frame.flags = parsed_header.flags;
  const auto body = frame_bytes.subspan(kFrameHeaderBytes, parsed_header.body_length);
  CanonicalReader reader(body, document_limits);
  TRXREG_TRY_ASSIGN(document, reader.read_document());
  frame.body = std::move(document);
  return frame;
}

Result<Frame> read_frame(net::Socket& socket, const FrameLimits& limits, CanonicalLimits document_limits) {
  std::array<std::byte, kFrameHeaderBytes> header{};
  std::size_t filled = 0;
  while (filled < header.size()) {
    TRXREG_TRY_ASSIGN(received, socket.recv_some(std::span<std::byte>(header.data() + filled, header.size() - filled)));
    if (received == 0) {
      return make_error(StatusCode::IoError, filled == 0 ? "the peer closed the connection"
                                                         : "the peer closed the connection mid-frame");
    }
    filled += static_cast<std::size_t>(received);
  }
  std::span<const std::byte, kFrameHeaderBytes> header_span(header.data(), header.size());
  TRXREG_TRY_ASSIGN(parsed_header, parse_frame_header(header_span, limits));

  // The body is bounded by the frame limit before this allocation, and the
  // buffer is allocated once: a peer trickling bytes cannot amplify allocations.
  const std::size_t remaining = static_cast<std::size_t>(parsed_header.body_length) + kFrameTrailerBytes;
  std::vector<std::byte> frame(kFrameHeaderBytes + remaining);
  std::memcpy(frame.data(), header.data(), kFrameHeaderBytes);
  std::size_t received_total = 0;
  while (received_total < remaining) {
    std::span<std::byte> target(frame.data() + kFrameHeaderBytes + received_total, remaining - received_total);
    TRXREG_TRY_ASSIGN(received, socket.recv_some(target));
    if (received == 0) {
      return make_error(StatusCode::Corrupt, "the peer closed the connection mid-frame");
    }
    received_total += static_cast<std::size_t>(received);
  }
  return decode_frame(frame, limits, document_limits);
}

Status write_frame(net::Socket& socket, MessageType type, std::uint16_t flags, const Value& body,
                   const FrameLimits& limits) {
  CanonicalWriter writer;
  writer.write_value(body);
  if (writer.failed()) {
    return Status(StatusCode::Internal, "the frame body contains a value with no canonical encoding");
  }
  std::vector<std::byte> payload = std::move(writer).take();
  if (payload.size() > limits.max_body_bytes) {
    return Status(StatusCode::CapacityExceeded, "response body exceeds the configured frame limit");
  }
  const std::vector<std::byte> frame = encode_frame(type, flags, payload);
  TRXREG_TRY_ASSIGN(sent, socket.send_all(frame));
  if (sent != frame.size()) {
    return Status(StatusCode::IoError, "the frame was only partially written");
  }
  return ok_status();
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

Result<Client> Client::connect(const std::string& host, std::uint16_t port, FrameLimits limits) {
  TRXREG_TRY_ASSIGN(socket, net::Socket::connect_loopback(host, port));
  Client client;
  client.socket_ = std::move(socket);
  client.limits_ = limits;
  return client;
}

Result<Value> Client::exchange(const Value& request) {
  const Status written = write_frame(socket_, MessageType::Request, 0, request, limits_);
  if (!written.ok()) {
    return written.error();
  }
  TRXREG_TRY_ASSIGN(frame, read_frame(socket_, limits_, CanonicalLimits::request()));
  if (frame.type != MessageType::Response && frame.type != MessageType::Failure) {
    return make_error(StatusCode::Malformed, "the server sent a non-response frame");
  }
  return frame.body;
}

Result<Value> Client::call(std::string_view op, Value parameters) {
  const std::uint64_t id = next_request_id_++;
  Value request = codec::object({{"id", Value::integer(static_cast<std::int64_t>(id))},
                                 {"op", Value::text(std::string(op))},
                                 {"params", std::move(parameters)}});
  TRXREG_TRY_ASSIGN(response, exchange(request));
  TRXREG_TRY_ASSIGN(response_id, get_unsigned(response, "id"));
  if (response_id != id) {
    return make_error(StatusCode::Malformed, "the response does not match the request id");
  }
  TRXREG_TRY_ASSIGN(ok, detail::get_boolean(response, "ok"));
  if (!ok) {
    const Value* error = response.find("error");
    if (error == nullptr) {
      return make_error(StatusCode::Internal, "the server reported a failure without a classification");
    }
    const std::string code_text = get_text_or(*error, "code", "internal");
    StatusCode code = StatusCode::Internal;
    if (!status_code_from_string(code_text, code)) {
      return make_error(StatusCode::Internal, "the server reported an unknown failure classification");
    }
    return make_error(code, get_text_or(*error, "message", ""));
  }
  const Value* result = response.find("result");
  if (result == nullptr) {
    return make_error(StatusCode::Malformed, "the response carries neither a result nor an error");
  }
  return *result;
}

Result<Value> Client::hello(std::uint32_t client_incarnation) {
  return call("hello", codec::object({{"client_incarnation", Value::integer(client_incarnation)}}));
}

Status Client::close() { return socket_.close(); }

// ---------------------------------------------------------------------------
// Request dispatch
// ---------------------------------------------------------------------------

RequestOutcome dispatch(Registry& registry, const Value& request, CanonicalLimits document_limits) {
  RequestOutcome outcome;
  outcome.type = MessageType::Response;
  const std::uint64_t id = get_unsigned_or(request, "id", 0);
  if (!request.is_object()) {
    outcome.type = MessageType::Failure;
    outcome.body = make_failure(id, make_error(StatusCode::Malformed, "a request must be a canonical object"));
    return outcome;
  }
  const Result<std::string> op = request_op(request);
  if (!op.ok()) {
    outcome.type = MessageType::Failure;
    outcome.body = make_failure(id, op.error());
    return outcome;
  }
  const Value& params = params_of(request);
  static_cast<void>(document_limits);

  const auto succeed = [&outcome, id](Value result) {
    outcome.type = MessageType::Response;
    outcome.body = make_response(id, std::move(result));
  };
  const auto fail = [&outcome, id](const Error& error) {
    outcome.type = MessageType::Failure;
    outcome.body = make_failure(id, error);
  };

  const std::string& name = op.value();

  if (name == "hello" || name == "ping") {
    succeed(codec::object({{"protocol", Value::integer(kWireProtocolVersion)},
                           {"registry_incarnation",
                            Value::integer(static_cast<std::int64_t>(registry.registry_incarnation()))},
                           {"version", Value::text(std::string(version_string()))}}));
    return outcome;
  }
  if (name == "registry.stats") {
    succeed(codec::encode(registry.stats()));
    return outcome;
  }
  if (name == "registry.generation") {
    succeed(codec::object({{"generation", Value::integer(static_cast<std::int64_t>(registry.generation().value()))}}));
    return outcome;
  }
  if (name == "registry.save") {
    const std::string path = get_text_or(params, "path", "");
    if (path.empty()) {
      fail(make_error(StatusCode::InvalidArgument, "registry.save requires a path"));
      return outcome;
    }
    const Status status = registry.save(path);
    if (!status.ok()) {
      fail(status.error());
      return outcome;
    }
    succeed(codec::object({{"saved", Value::boolean(true)}}));
    return outcome;
  }
  if (name == "source.register") {
    SourceDescriptor descriptor;
    const Result<std::string> source_name = get_text(params, "name");
    if (!source_name.ok()) {
      fail(source_name.error());
      return outcome;
    }
    descriptor.name = source_name.value();
    descriptor.description = get_text_or(params, "description", "");
    descriptor.instance_id = get_text_or(params, "instance_id", "");
    const std::string kind_text = get_text_or(params, "kind", "synthetic");
    EvidenceKind kind = EvidenceKind::Synthetic;
    if (kind_text == "real") {
      kind = EvidenceKind::Real;
    } else if (kind_text == "synthetic") {
      kind = EvidenceKind::Synthetic;
    } else if (kind_text == "unsupported") {
      kind = EvidenceKind::Unsupported;
    } else {
      fail(make_error(StatusCode::InvalidArgument, "unknown evidence kind"));
      return outcome;
    }
    descriptor.declared_kind = kind;
    const Result<SourceHandle> handle = registry.register_source(descriptor);
    if (!handle.ok()) {
      fail(handle.error());
      return outcome;
    }
    succeed(codec::encode(handle.value()));
    return outcome;
  }
  if (name == "module.register") {
    ModuleRegistration registration;
    const Result<std::string> key_text = get_text(params, "key");
    if (!key_text.ok()) {
      fail(key_text.error());
      return outcome;
    }
    const Result<ModuleKey> key = ModuleKey::parse(key_text.value(), "module key");
    if (!key.ok()) {
      fail(key.error());
      return outcome;
    }
    registration.key = key.value();
    const std::string intent_text = get_text_or(params, "intent", "current");
    if (!register_intent_from_string(intent_text, registration.intent)) {
      fail(make_error(StatusCode::InvalidArgument, "unknown module registration intent"));
      return outcome;
    }
    const Value::Array* identity = get_array_or(params, "identity");
    if (identity != nullptr) {
      for (const Value& entry : *identity) {
        const Result<IdentityFieldValue> decoded = codec::decode<IdentityFieldValue>(entry);
        if (!decoded.ok()) {
          fail(decoded.error());
          return outcome;
        }
        registration.identity.push_back(decoded.value());
      }
    }
    const Value* provenance = params.find("provenance");
    if (provenance == nullptr) {
      fail(make_error(StatusCode::InvalidArgument, "module.register requires provenance"));
      return outcome;
    }
    const Result<Provenance> decoded_provenance = codec::decode<Provenance>(*provenance);
    if (!decoded_provenance.ok()) {
      fail(decoded_provenance.error());
      return outcome;
    }
    registration.provenance = decoded_provenance.value();
    const Result<MutationPolicy> policy = read_policy_param(params);
    if (!policy.ok()) {
      fail(policy.error());
      return outcome;
    }
    registration.policy = policy.value();
    registration.expected_generation = Generation{get_unsigned_or(params, "expected_generation", 0)};
    const Result<AuthorityToken> authority = read_authority_param(params);
    if (!authority.ok()) {
      fail(authority.error());
      return outcome;
    }
    const Result<ModuleHandle> handle = registry.register_module(registration, authority.value());
    if (!handle.ok()) {
      fail(handle.error());
      return outcome;
    }
    succeed(codec::encode(handle.value()));
    return outcome;
  }
  if (name == "module.identity" || name == "module.capabilities" || name == "health.report" ||
      name == "evidence.summary" || name == "lifecycle.state" || name == "lifecycle.history" ||
      name == "attachment.get") {
    if (name == "attachment.get") {
      const Result<std::string> slot_text = get_text(params, "slot");
      if (!slot_text.ok()) {
        fail(slot_text.error());
        return outcome;
      }
      const Result<SlotKey> slot = SlotKey::parse(slot_text.value(), "slot key");
      if (!slot.ok()) {
        fail(slot.error());
        return outcome;
      }
      const Result<AttachmentRecord> attachment = registry.attachment_of_slot(slot.value());
      if (!attachment.ok()) {
        fail(attachment.error());
        return outcome;
      }
      succeed(codec::encode(attachment.value()));
      return outcome;
    }
    const Result<ModuleHandle> handle = read_module_reference(params);
    if (!handle.ok()) {
      fail(handle.error());
      return outcome;
    }
    if (name == "module.identity") {
      const Result<IdentityView> view = registry.identity(handle.value());
      if (!view.ok()) {
        fail(view.error());
        return outcome;
      }
      succeed(codec::encode(view.value()));
      return outcome;
    }
    if (name == "module.capabilities") {
      const Result<CapabilityView> view = registry.capabilities(handle.value());
      if (!view.ok()) {
        fail(view.error());
        return outcome;
      }
      succeed(codec::encode(view.value()));
      return outcome;
    }
    if (name == "health.report") {
      const Result<HealthReport> report = registry.health(handle.value());
      if (!report.ok()) {
        fail(report.error());
        return outcome;
      }
      succeed(codec::encode(report.value()));
      return outcome;
    }
    if (name == "evidence.summary") {
      const Result<EvidenceSummary> summary = registry.evidence_summary(handle.value());
      if (!summary.ok()) {
        fail(summary.error());
        return outcome;
      }
      succeed(codec::encode(summary.value()));
      return outcome;
    }
    if (name == "lifecycle.state") {
      const Result<LifecycleState> state = registry.lifecycle_state(handle.value());
      if (!state.ok()) {
        fail(state.error());
        return outcome;
      }
      succeed(codec::object({{"state", Value::text(std::string(to_string(state.value())))}}));
      return outcome;
    }
    const Result<std::vector<LifecycleEvent>> events = registry.lifecycle_history(handle.value());
    if (!events.ok()) {
      fail(events.error());
      return outcome;
    }
    succeed(codec::object({{"events", encode_event_list(events.value())}}));
    return outcome;
  }
  if (name == "identity.update") {
    const Result<AuthorityToken> authority = read_authority_param(params);
    if (!authority.ok()) {
      fail(authority.error());
      return outcome;
    }
    const Result<ModuleHandle> handle = read_module_handle(params);
    if (!handle.ok()) {
      fail(handle.error());
      return outcome;
    }
    IdentityFieldValue value;
    const std::string field_text = get_text_or(params, "field", "");
    if (!identity_field_from_string(field_text, value.field)) {
      fail(make_error(StatusCode::InvalidArgument, "unknown identity field"));
      return outcome;
    }
    value.subkey = get_text_or(params, "subkey", "");
    value.value = get_text_or(params, "value", "");
    const Value* provenance = params.find("provenance");
    if (provenance == nullptr) {
      fail(make_error(StatusCode::InvalidArgument, "identity.update requires provenance"));
      return outcome;
    }
    const Result<Provenance> decoded = codec::decode<Provenance>(*provenance);
    if (!decoded.ok()) {
      fail(decoded.error());
      return outcome;
    }
    const Result<MutationPolicy> policy = read_policy_param(params);
    if (!policy.ok()) {
      fail(policy.error());
      return outcome;
    }
    const Status status = registry.update_identity(authority.value(), handle.value(), value, decoded.value(), policy.value());
    if (!status.ok()) {
      fail(status.error());
      return outcome;
    }
    succeed(codec::object({{"updated", Value::boolean(true)}}));
    return outcome;
  }
  if (name == "capability.publish" || name == "port.capability.publish") {
    const Result<AuthorityToken> authority = read_authority_param(params);
    if (!authority.ok()) {
      fail(authority.error());
      return outcome;
    }
    CapabilityKey key = CapabilityKey::Unknown;
    const std::string key_text = get_text_or(params, "key", "");
    if (!capability_key_from_string(key_text, key)) {
      fail(make_error(StatusCode::InvalidArgument, "unknown capability key"));
      return outcome;
    }
    const Value* value_document = params.find("value");
    if (value_document == nullptr) {
      fail(make_error(StatusCode::InvalidArgument, "capability publication requires a value"));
      return outcome;
    }
    CapabilityValue value;
    const Result<CapabilityValue> decoded_value = read_canonical(*value_document, value);
    if (!decoded_value.ok()) {
      fail(decoded_value.error());
      return outcome;
    }
    const Value* provenance = params.find("provenance");
    if (provenance == nullptr) {
      fail(make_error(StatusCode::InvalidArgument, "capability publication requires provenance"));
      return outcome;
    }
    const Result<Provenance> decoded_provenance = codec::decode<Provenance>(*provenance);
    if (!decoded_provenance.ok()) {
      fail(decoded_provenance.error());
      return outcome;
    }
    const Result<MutationPolicy> policy = read_policy_param(params);
    if (!policy.ok()) {
      fail(policy.error());
      return outcome;
    }
    const std::string subkey = get_text_or(params, "subkey", "");
    if (name == "capability.publish") {
      const Result<ModuleHandle> handle = read_module_handle(params);
      if (!handle.ok()) {
        fail(handle.error());
        return outcome;
      }
      const Status status = registry.publish_capability(authority.value(), handle.value(), key, subkey,
                                                        decoded_value.value(), decoded_provenance.value(), policy.value());
      if (!status.ok()) {
        fail(status.error());
        return outcome;
      }
    } else {
      const std::string port_text = get_text_or(params, "port", "");
      const Result<PortKey> port = PortKey::parse(port_text, "port key");
      if (!port.ok()) {
        fail(port.error());
        return outcome;
      }
      const Status status = registry.publish_port_capability(authority.value(), port.value(), key, subkey,
                                                             decoded_value.value(), decoded_provenance.value(),
                                                             policy.value());
      if (!status.ok()) {
        fail(status.error());
        return outcome;
      }
    }
    succeed(codec::object({{"published", Value::boolean(true)}}));
    return outcome;
  }
  if (name == "port.capabilities") {
    const std::string port_text = get_text_or(params, "port", "");
    const Result<PortKey> port = PortKey::parse(port_text, "port key");
    if (!port.ok()) {
      fail(port.error());
      return outcome;
    }
    const Result<CapabilityView> view = registry.port_capabilities(port.value());
    if (!view.ok()) {
      fail(view.error());
      return outcome;
    }
    succeed(codec::encode(view.value()));
    return outcome;
  }
  if (name == "attachment.attach") {
    const Result<AuthorityToken> authority = read_authority_param(params);
    if (!authority.ok()) {
      fail(authority.error());
      return outcome;
    }
    const Result<ModuleHandle> handle = read_module_handle(params);
    if (!handle.ok()) {
      fail(handle.error());
      return outcome;
    }
    const std::string slot_text = get_text_or(params, "slot", "");
    const Result<SlotKey> slot = SlotKey::parse(slot_text, "slot key");
    if (!slot.ok()) {
      fail(slot.error());
      return outcome;
    }
    const Result<MutationPolicy> policy = read_policy_param(params);
    if (!policy.ok()) {
      fail(policy.error());
      return outcome;
    }
    const std::uint64_t port_index = get_unsigned_or(params, "port_index", 0);
    if (port_index > 255) {
      fail(make_error(StatusCode::InvalidArgument, "port index is out of range"));
      return outcome;
    }
    const Result<AttachmentRecord> attachment = registry.attach(authority.value(), handle.value(), slot.value(),
                                                                static_cast<std::uint32_t>(port_index), policy.value());
    if (!attachment.ok()) {
      fail(attachment.error());
      return outcome;
    }
    succeed(codec::encode(attachment.value()));
    return outcome;
  }
  if (name == "attachment.detach") {
    const Result<AuthorityToken> authority = read_authority_param(params);
    if (!authority.ok()) {
      fail(authority.error());
      return outcome;
    }
    const std::string slot_text = get_text_or(params, "slot", "");
    const Result<SlotKey> slot = SlotKey::parse(slot_text, "slot key");
    if (!slot.ok()) {
      fail(slot.error());
      return outcome;
    }
    const Result<MutationPolicy> policy = read_policy_param(params);
    if (!policy.ok()) {
      fail(policy.error());
      return outcome;
    }
    const Status status = registry.detach(authority.value(), slot.value(), policy.value());
    if (!status.ok()) {
      fail(status.error());
      return outcome;
    }
    succeed(codec::object({{"detached", Value::boolean(true)}}));
    return outcome;
  }
  if (name == "health.ingest") {
    const Result<AuthorityToken> authority = read_authority_param(params);
    if (!authority.ok()) {
      fail(authority.error());
      return outcome;
    }
    const Result<ModuleHandle> handle = read_module_handle(params);
    if (!handle.ok()) {
      fail(handle.error());
      return outcome;
    }
    const Value* sample = params.find("sample");
    if (sample == nullptr) {
      fail(make_error(StatusCode::InvalidArgument, "health.ingest requires a sample"));
      return outcome;
    }
    const Result<HealthSampleInput> decoded = codec::decode<HealthSampleInput>(*sample);
    if (!decoded.ok()) {
      fail(decoded.error());
      return outcome;
    }
    const Result<MutationPolicy> policy = read_policy_param(params);
    if (!policy.ok()) {
      fail(policy.error());
      return outcome;
    }
    const Status status = registry.ingest_health(authority.value(), handle.value(), decoded.value(), policy.value());
    if (!status.ok()) {
      fail(status.error());
      return outcome;
    }
    succeed(codec::object({{"accepted", Value::boolean(true)}}));
    return outcome;
  }
  if (name == "health.threshold.publish") {
    const Result<AuthorityToken> authority = read_authority_param(params);
    if (!authority.ok()) {
      fail(authority.error());
      return outcome;
    }
    const Value* threshold = params.find("threshold");
    if (threshold == nullptr) {
      fail(make_error(StatusCode::InvalidArgument, "health.threshold.publish requires a threshold"));
      return outcome;
    }
    const Result<HealthThreshold> decoded = codec::decode<HealthThreshold>(*threshold);
    if (!decoded.ok()) {
      fail(decoded.error());
      return outcome;
    }
    const Result<MutationPolicy> policy = read_policy_param(params);
    if (!policy.ok()) {
      fail(policy.error());
      return outcome;
    }
    const Status status = registry.publish_threshold(authority.value(), decoded.value(), policy.value());
    if (!status.ok()) {
      fail(status.error());
      return outcome;
    }
    succeed(codec::object({{"published", Value::boolean(true)}}));
    return outcome;
  }
  if (name == "health.samples") {
    const Result<ModuleHandle> handle = read_module_reference(params);
    if (!handle.ok()) {
      fail(handle.error());
      return outcome;
    }
    SampleQuery query;
    const std::string metric_text = get_text_or(params, "metric", "unknown");
    if (!health_metric_from_string(metric_text, query.metric)) {
      fail(make_error(StatusCode::InvalidArgument, "unknown health metric"));
      return outcome;
    }
    query.all_lanes = get_boolean_or(params, "all_lanes", true);
    const std::uint64_t lane = get_unsigned_or(params, "lane", kModuleLane);
    if (lane > 65535) {
      fail(make_error(StatusCode::InvalidArgument, "lane index is out of range"));
      return outcome;
    }
    query.lane = static_cast<std::uint16_t>(lane);
    query.limit = get_unsigned_or(params, "limit", 64);
    if (query.limit > 4096) {
      fail(make_error(StatusCode::CapacityExceeded, "sample query limit is too large"));
      return outcome;
    }
    query.include_superseded = get_boolean_or(params, "include_superseded", false);
    const Result<std::vector<HealthSample>> samples = registry.samples(handle.value(), query);
    if (!samples.ok()) {
      fail(samples.error());
      return outcome;
    }
    succeed(codec::object({{"samples", encode_sample_list(samples.value())}}));
    return outcome;
  }
  if (name == "evidence.claims") {
    const Result<ModuleHandle> handle = read_module_reference(params);
    if (!handle.ok()) {
      fail(handle.error());
      return outcome;
    }
    ClaimQuery query;
    const std::string field_text = get_text_or(params, "field", "unknown");
    if (!identity_field_from_string(field_text, query.field)) {
      fail(make_error(StatusCode::InvalidArgument, "unknown identity field"));
      return outcome;
    }
    query.limit = get_unsigned_or(params, "limit", 64);
    if (query.limit > 4096) {
      fail(make_error(StatusCode::CapacityExceeded, "claim query limit is too large"));
      return outcome;
    }
    query.include_superseded = get_boolean_or(params, "include_superseded", true);
    const Result<std::vector<IdentityClaim>> claims = registry.claim_history(handle.value(), query);
    if (!claims.ok()) {
      fail(claims.error());
      return outcome;
    }
    succeed(codec::object({{"claims", encode_claim_list(claims.value())}}));
    return outcome;
  }
  if (name == "evidence.declarations") {
    const Result<ModuleHandle> handle = read_module_reference(params);
    if (!handle.ok()) {
      fail(handle.error());
      return outcome;
    }
    DeclarationQuery query;
    const std::string key_text = get_text_or(params, "key", "unknown");
    if (!capability_key_from_string(key_text, query.key)) {
      fail(make_error(StatusCode::InvalidArgument, "unknown capability key"));
      return outcome;
    }
    query.limit = get_unsigned_or(params, "limit", 64);
    if (query.limit > 4096) {
      fail(make_error(StatusCode::CapacityExceeded, "declaration query limit is too large"));
      return outcome;
    }
    query.include_superseded = get_boolean_or(params, "include_superseded", true);
    const Result<std::vector<CapabilityDeclaration>> declarations =
        registry.declaration_history(handle.value(), query);
    if (!declarations.ok()) {
      fail(declarations.error());
      return outcome;
    }
    succeed(codec::object({{"declarations", encode_declaration_list(declarations.value())}}));
    return outcome;
  }
  if (name == "compat.rule.publish") {
    const Result<AuthorityToken> authority = read_authority_param(params);
    if (!authority.ok()) {
      fail(authority.error());
      return outcome;
    }
    const Value* rule = params.find("rule");
    if (rule == nullptr) {
      fail(make_error(StatusCode::InvalidArgument, "compat.rule.publish requires a rule"));
      return outcome;
    }
    const Result<CompatRule> decoded = codec::decode<CompatRule>(*rule);
    if (!decoded.ok()) {
      fail(decoded.error());
      return outcome;
    }
    const Result<MutationPolicy> policy = read_policy_param(params);
    if (!policy.ok()) {
      fail(policy.error());
      return outcome;
    }
    const Result<CompatRuleHandle> handle = registry.publish_rule(authority.value(), decoded.value(), policy.value());
    if (!handle.ok()) {
      fail(handle.error());
      return outcome;
    }
    succeed(codec::object({{"generation", Value::integer(static_cast<std::int64_t>(handle.value().generation.value()))},
                           {"id", Value::integer(static_cast<std::int64_t>(handle.value().id.value()))}}));
    return outcome;
  }
  if (name == "compat.query") {
    CompatQuery query;
    const std::string port_text = get_text_or(params, "port", "");
    const Result<PortKey> port = PortKey::parse(port_text, "port key");
    if (!port.ok()) {
      fail(port.error());
      return outcome;
    }
    query.port = port.value();
    const Result<ModuleHandle> handle = read_module_reference(params);
    if (!handle.ok()) {
      fail(handle.error());
      return outcome;
    }
    query.uid = handle.value().uid;
    query.incarnation = handle.value().incarnation;
    query.require_latest_generation = get_boolean_or(params, "require_latest_generation", true);
    query.expected_generation = Generation{get_unsigned_or(params, "expected_generation", 0)};
    query.explain = get_boolean_or(params, "explain", true);
    const Result<CompatDecision> decision = registry.query_compatibility(query);
    if (!decision.ok()) {
      fail(decision.error());
      return outcome;
    }
    succeed(codec::encode(decision.value()));
    return outcome;
  }
  if (name == "lifecycle.transition" || name == "lifecycle.reconcile") {
    const Result<AuthorityToken> authority = read_authority_param(params);
    if (!authority.ok()) {
      fail(authority.error());
      return outcome;
    }
    const Result<ModuleHandle> handle = read_module_handle(params);
    if (!handle.ok()) {
      fail(handle.error());
      return outcome;
    }
    const Result<MutationPolicy> policy = read_policy_param(params);
    if (!policy.ok()) {
      fail(policy.error());
      return outcome;
    }
    if (name == "lifecycle.reconcile") {
      const Result<LifecycleEvent> event = registry.reconcile_lifecycle(authority.value(), handle.value(), policy.value());
      if (!event.ok()) {
        fail(event.error());
        return outcome;
      }
      succeed(codec::encode(event.value()));
      return outcome;
    }
    LifecycleState target = LifecycleState::Registered;
    const std::string state_text = get_text_or(params, "state", "");
    if (!lifecycle_state_from_string(state_text, target)) {
      fail(make_error(StatusCode::InvalidArgument, "unknown lifecycle state"));
      return outcome;
    }
    const Result<LifecycleEvent> event = registry.transition(authority.value(), handle.value(), target,
                                                            get_text_or(params, "reason", ""), policy.value());
    if (!event.ok()) {
      fail(event.error());
      return outcome;
    }
    succeed(codec::encode(event.value()));
    return outcome;
  }

  fail(make_error(StatusCode::Unsupported, "unknown request operation '" + name + "'"));
  return outcome;
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

struct Server::Connection {
  net::Socket socket;
  mutable std::mutex mutex;
  bool closed{false};

  void close() {
    std::unique_lock<std::mutex> lock(mutex);
    if (closed) {
      return;
    }
    closed = true;
    socket.shutdown_both();
    static_cast<void>(socket.close());
  }
};

Server::Server(Registry& registry, ServerOptions options) : registry_(registry), options_(std::move(options)) {}

Server::~Server() { static_cast<void>(stop()); }

Status Server::start() {
  const Status init = net::initialize();
  if (!init.ok()) {
    return init;
  }
  TRXREG_TRY_ASSIGN(listener, net::Listener::bind_loopback_address(options_.bind_address, options_.port, 32));
  listener_ = std::move(listener);
  port_ = listener_.port();
  stopping_.store(false);
  running_.store(true);
  if (!options_.ready_file.empty()) {
    std::FILE* file = std::fopen(options_.ready_file.c_str(), "wb");
    if (file == nullptr) {
      return Status(StatusCode::IoError, "cannot write the server ready file");
    }
    const std::string line = "port=" + std::to_string(port_) + "\n";
    static_cast<void>(std::fwrite(line.data(), 1, line.size(), file));
    static_cast<void>(std::fclose(file));
  }
  return ok_status();
}

Status Server::run() {
  if (!running_.load()) {
    return Status(StatusCode::Refused, "the server is not started");
  }
  while (!stopping_.load()) {
    Result<net::Socket> accepted = listener_.accept();
    if (!accepted.ok()) {
      if (stopping_.load()) {
        break;
      }
      if (accepted.error().code == StatusCode::Refused || accepted.error().code == StatusCode::IoError) {
        if (!listener_.valid()) {
          break;
        }
      }
      continue;
    }
    auto connection = std::make_shared<Connection>();
    connection->socket = std::move(accepted.value());
    {
      std::unique_lock<std::mutex> lock(connections_mutex_);
      connections_.push_back(connection);
      const std::size_t active = connections_.size();
      if (active > options_.max_connections) {
        connections_.pop_back();
        connection->close();
        continue;
      }
    }
    std::unique_lock<std::mutex> lock(worker_mutex_);
    workers_.emplace_back([this, connection]() { serve_connection(connection); });
  }
  running_.store(false);
  return ok_status();
}

void Server::serve_connection(std::shared_ptr<Connection> connection) {
  std::uint32_t served = 0;
  while (!stopping_.load() && served < options_.max_requests_per_connection) {
    Result<Frame> frame = read_frame(connection->socket, options_.frame_limits, options_.document_limits);
    if (!frame.ok()) {
      break;
    }
    if (frame.value().type == MessageType::Shutdown) {
      break;
    }
    if (frame.value().type != MessageType::Request && frame.value().type != MessageType::Ping &&
        frame.value().type != MessageType::Hello) {
      const Value failure = make_failure(0, make_error(StatusCode::Malformed, "the server only accepts requests"));
      static_cast<void>(write_frame(connection->socket, MessageType::Failure, 0, failure, options_.frame_limits));
      break;
    }
    const RequestOutcome outcome = dispatch(registry_, frame.value().body, options_.document_limits);
    // Only a *successful* ping is acknowledged as a pong; a failed one keeps its
    // failure classification so a client cannot read it as a healthy round trip.
    const MessageType type = frame.value().type == MessageType::Ping && outcome.type == MessageType::Response
                                 ? MessageType::Pong
                                 : outcome.type;
    if (!write_frame(connection->socket, type, 0, outcome.body, options_.frame_limits).ok()) {
      break;
    }
    ++served;
  }
  connection->close();
  std::unique_lock<std::mutex> lock(connections_mutex_);
  connections_.erase(std::remove(connections_.begin(), connections_.end(), connection), connections_.end());
}

Status Server::stop() {
  stopping_.store(true);
  static_cast<void>(listener_.close());
  std::vector<std::shared_ptr<Connection>> connections;
  {
    std::unique_lock<std::mutex> lock(connections_mutex_);
    connections = connections_;
  }
  for (const std::shared_ptr<Connection>& connection : connections) {
    connection->close();
  }
  std::vector<std::thread> workers;
  {
    std::unique_lock<std::mutex> lock(worker_mutex_);
    workers.swap(workers_);
  }
  for (std::thread& worker : workers) {
    if (worker.joinable()) {
      worker.join();
    }
  }
  running_.store(false);
  return ok_status();
}

}  // namespace trxreg::wire

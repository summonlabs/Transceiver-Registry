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
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>

namespace trxreg {

/// Typed failure classification for every runtime boundary.
///
/// The set is deliberately explicit: no failure is collapsed into a generic
/// "error" that a caller could mistake for success, and no distinct refusal
/// reason is folded into another.
enum class StatusCode : std::uint16_t {
  Ok = 0,
  /// A caller-supplied argument failed validation (empty, too long, wrong shape).
  InvalidArgument,
  /// The referenced entity does not exist in the registry.
  NotFound,
  /// The request contradicts existing authoritative state.
  Conflict,
  /// The authority token (source incarnation) is no longer current.
  StaleAuthority,
  /// The caller fenced its mutation against a registry generation that is no longer current.
  StaleGeneration,
  /// The module incarnation referenced by the caller has been replaced.
  StaleIncarnation,
  /// Evidence or a referenced entity belongs to a fenced (superseded) incarnation.
  Fenced,
  /// A bounded capacity would be exceeded by this request.
  CapacityExceeded,
  /// An externally supplied payload is malformed.
  Malformed,
  /// An externally supplied payload is truncated or fails its integrity check.
  Corrupt,
  /// The requested operation or attribute is not modelled by this runtime.
  Unsupported,
  /// The registry refuses the request on policy grounds (state machine, ordering, ...).
  Refused,
  /// A filesystem or socket operation failed.
  IoError,
  /// An observation timestamp is implausible relative to the current clock.
  ClockSkew,
  /// The requested lifecycle transition is not permitted from the current state.
  InvalidTransition,
  /// The registry cannot answer because its knowledge is not closed.
  KnowledgeOpen,
  /// An internal invariant was violated (defect indicator, never returned for user input).
  Internal,
};

std::string_view to_string(StatusCode code) noexcept;
bool status_code_from_string(std::string_view text, StatusCode& out) noexcept;

/// A classified failure with a human-readable message.
struct Error {
  StatusCode code{StatusCode::Internal};
  std::string message;
};

Error make_error(StatusCode code, std::string message);

/// Success-or-failure with no payload.
class Status {
 public:
  Status() noexcept = default;
  Status(StatusCode code, std::string message) : error_{code, std::move(message)} {}
  Status(const Error& error) : error_(error) {}                 // NOLINT(google-explicit-constructor)
  Status(Error&& error) : error_(std::move(error)) {}           // NOLINT(google-explicit-constructor)

  [[nodiscard]] bool ok() const noexcept { return error_.code == StatusCode::Ok; }
  [[nodiscard]] explicit operator bool() const noexcept { return ok(); }
  [[nodiscard]] StatusCode code() const noexcept { return error_.code; }
  [[nodiscard]] const std::string& message() const noexcept { return error_.message; }
  [[nodiscard]] const Error& error() const noexcept { return error_; }

  static Status success() noexcept { return Status{}; }

 private:
  Error error_{StatusCode::Ok, {}};
};

// The compiler cannot know that every path returns; keep the success object
// cheap to construct and cheap to test.
inline Status ok_status() noexcept { return Status{}; }

/// Success-or-failure carrying a value of type T.
template <class T>
class [[nodiscard]] Result {
 public:
  Result(T value) : storage_(std::in_place_index<0>, std::move(value)) {}  // NOLINT(google-explicit-constructor)
  Result(Error error) : storage_(std::in_place_index<1>, std::move(error)) {}  // NOLINT(google-explicit-constructor)
  Result(StatusCode code, std::string message) : storage_(std::in_place_index<1>, Error{code, std::move(message)}) {}
  /// Propagate a failed Status. Precondition: the status is not Ok; an Ok status
  /// is turned into an Internal error rather than into a fake success value.
  Result(const Status& status)
      : storage_(std::in_place_index<1>,
                 status.ok() ? Error{StatusCode::Internal, "an ok status was converted into a failure"}
                             : status.error()) {}

  [[nodiscard]] bool ok() const noexcept { return storage_.index() == 0; }
  [[nodiscard]] explicit operator bool() const noexcept { return ok(); }

  [[nodiscard]] const T& value() const& { return std::get<0>(storage_); }
  [[nodiscard]] T& value() & { return std::get<0>(storage_); }
  [[nodiscard]] T&& value() && { return std::get<0>(std::move(storage_)); }

  [[nodiscard]] const Error& error() const& { return std::get<1>(storage_); }

  [[nodiscard]] const T& operator*() const& { return value(); }
  [[nodiscard]] T& operator*() & { return value(); }
  [[nodiscard]] const T* operator->() const { return &value(); }
  [[nodiscard]] T* operator->() { return &value(); }

  /// Map the success value while preserving the failure.
  template <class F>
  auto transform(F&& fn) const& -> Result<std::invoke_result_t<F, const T&>> {
    using U = std::invoke_result_t<F, const T&>;
    if (!ok()) {
      return Result<U>(error());
    }
    return Result<U>(fn(value()));
  }

 private:
  std::variant<T, Error> storage_;
};

/// Convenience constructors.
template <class T>
Result<std::decay_t<T>> make_result(T&& value) {
  return Result<std::decay_t<T>>(std::forward<T>(value));
}

}  // namespace trxreg

/// Propagate a failed Result out of the current function, which must return
/// either Status or Result<U>.
#define TRXREG_TRY(expr)                                   \
  do {                                                     \
    const auto trxreg_try_status = (expr);                 \
    if (!trxreg_try_status.ok()) {                         \
      return Status(trxreg_try_status.error());            \
    }                                                      \
  } while (false)

/// Propagate a failed Result and bind its value to a new variable.
#define TRXREG_TRY_ASSIGN(name, expr)                     \
  auto trxreg_try_result_##name = (expr);                 \
  if (!trxreg_try_result_##name.ok()) {                   \
    return Status(trxreg_try_result_##name.error());      \
  }                                                       \
  auto& name = trxreg_try_result_##name.value()

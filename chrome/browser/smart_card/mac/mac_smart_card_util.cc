// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/smart_card/mac/mac_smart_card_util.h"

#include <PCSC/winscard.h>

#include <string_view>

namespace smart_card::mac {

using device::mojom::SmartCardConnectionState;
using device::mojom::SmartCardDisposition;
using device::mojom::SmartCardError;
using device::mojom::SmartCardProtocol;
using device::mojom::SmartCardProtocols;
using device::mojom::SmartCardReaderStateFlags;
using device::mojom::SmartCardReaderStateFlagsPtr;
using device::mojom::SmartCardShareMode;

SmartCardError SmartCardErrorFromPcscResult(int32_t pcsc_result) {
  switch (static_cast<uint32_t>(pcsc_result)) {
    case SCARD_W_REMOVED_CARD:
      return SmartCardError::kRemovedCard;
    case SCARD_W_RESET_CARD:
      return SmartCardError::kResetCard;
    case SCARD_W_UNPOWERED_CARD:
      return SmartCardError::kUnpoweredCard;
    case SCARD_W_UNRESPONSIVE_CARD:
      return SmartCardError::kUnresponsiveCard;
    case SCARD_W_UNSUPPORTED_CARD:
      return SmartCardError::kUnsupportedCard;
    case SCARD_E_READER_UNAVAILABLE:
      return SmartCardError::kReaderUnavailable;
    case SCARD_E_SHARING_VIOLATION:
      return SmartCardError::kSharingViolation;
    case SCARD_E_NOT_TRANSACTED:
      return SmartCardError::kNotTransacted;
    case SCARD_E_NO_SMARTCARD:
      return SmartCardError::kNoSmartcard;
    case SCARD_E_PROTO_MISMATCH:
      return SmartCardError::kProtoMismatch;
    case SCARD_E_SYSTEM_CANCELLED:
      return SmartCardError::kSystemCancelled;
    case SCARD_E_NOT_READY:
      return SmartCardError::kNotReady;
    case SCARD_E_CANCELLED:
      return SmartCardError::kCancelled;
    case SCARD_E_INSUFFICIENT_BUFFER:
      return SmartCardError::kInsufficientBuffer;
    case SCARD_E_INVALID_HANDLE:
      return SmartCardError::kInvalidHandle;
    case SCARD_E_INVALID_PARAMETER:
      return SmartCardError::kInvalidParameter;
    case SCARD_E_INVALID_VALUE:
      return SmartCardError::kInvalidValue;
    case SCARD_E_NO_MEMORY:
      return SmartCardError::kNoMemory;
    case SCARD_E_TIMEOUT:
      return SmartCardError::kTimeout;
    case SCARD_E_UNKNOWN_READER:
      return SmartCardError::kUnknownReader;
    case SCARD_E_NO_READERS_AVAILABLE:
      return SmartCardError::kNoReadersAvailable;
    case SCARD_E_SERVICE_STOPPED:
      return SmartCardError::kServiceStopped;
    case SCARD_E_NO_SERVICE:
      return SmartCardError::kNoService;
    case SCARD_F_COMM_ERROR:
      return SmartCardError::kCommError;
    case SCARD_F_INTERNAL_ERROR:
      return SmartCardError::kInternalError;
    case SCARD_E_UNKNOWN_CARD:
      return SmartCardError::kUnknownCard;
    case SCARD_E_SERVER_TOO_BUSY:
      return SmartCardError::kServerTooBusy;
    // Note: On macOS PCSC.framework, SCARD_E_UNSUPPORTED_FEATURE is aliased
    // to SCARD_E_UNEXPECTED (0x8010001F).
    case SCARD_E_UNEXPECTED:
      return SmartCardError::kUnexpected;
    case SCARD_P_SHUTDOWN:
      return SmartCardError::kShutdown;
    default:
      return SmartCardError::kUnknown;
  }
}

uint32_t PcscShareModeFromMojo(SmartCardShareMode share_mode) {
  switch (share_mode) {
    case SmartCardShareMode::kShared:
      return SCARD_SHARE_SHARED;
    case SmartCardShareMode::kExclusive:
      return SCARD_SHARE_EXCLUSIVE;
    case SmartCardShareMode::kDirect:
      return SCARD_SHARE_DIRECT;
  }
}

uint32_t PcscProtocolsFromMojo(const SmartCardProtocols& protocols) {
  uint32_t result = SCARD_PROTOCOL_UNDEFINED;
  if (protocols.t0) {
    result |= SCARD_PROTOCOL_T0;
  }
  if (protocols.t1) {
    result |= SCARD_PROTOCOL_T1;
  }
  if (protocols.raw) {
    result |= SCARD_PROTOCOL_RAW;
  }
  return result;
}

SmartCardProtocol MojoProtocolFromPcsc(uint32_t pcsc_protocol) {
  switch (pcsc_protocol) {
    case SCARD_PROTOCOL_T0:
      return SmartCardProtocol::kT0;
    case SCARD_PROTOCOL_T1:
      return SmartCardProtocol::kT1;
    case SCARD_PROTOCOL_RAW:
      return SmartCardProtocol::kRaw;
    default:
      return SmartCardProtocol::kUndefined;
  }
}

uint32_t PcscDispositionFromMojo(SmartCardDisposition disposition) {
  switch (disposition) {
    case SmartCardDisposition::kLeave:
      return SCARD_LEAVE_CARD;
    case SmartCardDisposition::kReset:
      return SCARD_RESET_CARD;
    case SmartCardDisposition::kUnpower:
      return SCARD_UNPOWER_CARD;
    case SmartCardDisposition::kEject:
      return SCARD_EJECT_CARD;
  }
}

SmartCardConnectionState MojoConnectionStateFromPcsc(uint32_t pcsc_state) {
  // macOS PCSC returns SCARD_* state flags as a bitmask; report the most
  // specific state present.
  if (pcsc_state & SCARD_SPECIFIC) {
    return SmartCardConnectionState::kSpecific;
  }
  if (pcsc_state & SCARD_NEGOTIABLE) {
    return SmartCardConnectionState::kNegotiable;
  }
  if (pcsc_state & SCARD_POWERED) {
    return SmartCardConnectionState::kPowered;
  }
  if (pcsc_state & SCARD_SWALLOWED) {
    return SmartCardConnectionState::kSwallowed;
  }
  if (pcsc_state & SCARD_PRESENT) {
    return SmartCardConnectionState::kPresent;
  }
  return SmartCardConnectionState::kAbsent;
}

uint32_t PcscReaderStateFlagsFromMojo(const SmartCardReaderStateFlags& flags,
                                      uint16_t count) {
  uint32_t result = static_cast<uint32_t>(count) << 16;
  if (flags.ignore) {
    result |= SCARD_STATE_IGNORE;
  }
  if (flags.changed) {
    result |= SCARD_STATE_CHANGED;
  }
  if (flags.unknown) {
    result |= SCARD_STATE_UNKNOWN;
  }
  if (flags.unavailable) {
    result |= SCARD_STATE_UNAVAILABLE;
  }
  if (flags.empty) {
    result |= SCARD_STATE_EMPTY;
  }
  if (flags.present) {
    result |= SCARD_STATE_PRESENT;
  }
  if (flags.exclusive) {
    result |= SCARD_STATE_EXCLUSIVE;
  }
  if (flags.inuse) {
    result |= SCARD_STATE_INUSE;
  }
  if (flags.mute) {
    result |= SCARD_STATE_MUTE;
  }
  if (flags.unpowered) {
    result |= SCARD_STATE_UNPOWERED;
  }
  return result;
}

SmartCardReaderStateFlagsPtr MojoReaderStateFlagsFromPcsc(uint32_t pcsc_state) {
  auto flags = SmartCardReaderStateFlags::New();
  const uint32_t lower = pcsc_state & 0xFFFF;
  flags->unaware = (lower == SCARD_STATE_UNAWARE);
  flags->ignore = (lower & SCARD_STATE_IGNORE) != 0;
  flags->changed = (lower & SCARD_STATE_CHANGED) != 0;
  flags->unknown = (lower & SCARD_STATE_UNKNOWN) != 0;
  flags->unavailable = (lower & SCARD_STATE_UNAVAILABLE) != 0;
  flags->empty = (lower & SCARD_STATE_EMPTY) != 0;
  flags->present = (lower & SCARD_STATE_PRESENT) != 0;
  flags->exclusive = (lower & SCARD_STATE_EXCLUSIVE) != 0;
  flags->inuse = (lower & SCARD_STATE_INUSE) != 0;
  flags->mute = (lower & SCARD_STATE_MUTE) != 0;
  flags->unpowered = (lower & SCARD_STATE_UNPOWERED) != 0;
  return flags;
}

uint16_t MojoEventCountFromPcsc(uint32_t pcsc_state) {
  return static_cast<uint16_t>((pcsc_state >> 16) & 0xFFFF);
}

std::vector<std::string> ParsePcscMultiString(base::span<const char> buffer) {
  std::vector<std::string> result;
  size_t pos = 0;
  while (pos < buffer.size()) {
    if (buffer[pos] == '\0') {
      break;
    }
    size_t end = pos;
    while (end < buffer.size() && buffer[end] != '\0') {
      ++end;
    }
    result.emplace_back(buffer.subspan(pos, end - pos).data(), end - pos);
    pos = end + 1;
  }
  return result;
}

}  // namespace smart_card::mac

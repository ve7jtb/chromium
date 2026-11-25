// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/smart_card/pcsc/pcsc_smart_card_util.h"

#include <string_view>

#include "chrome/browser/smart_card/pcsc/pcsc_constants.h"

namespace smart_card::pcsc {

using device::mojom::SmartCardConnectionState;
using device::mojom::SmartCardDisposition;
using device::mojom::SmartCardError;
using device::mojom::SmartCardProtocol;
using device::mojom::SmartCardProtocols;
using device::mojom::SmartCardReaderStateFlags;
using device::mojom::SmartCardReaderStateFlagsPtr;
using device::mojom::SmartCardShareMode;

SmartCardError SmartCardErrorFromPcscResult(uint32_t pcsc_result) {
  switch (pcsc_result) {
    case kSCardWRemovedCard:
      return SmartCardError::kRemovedCard;
    case kSCardWResetCard:
      return SmartCardError::kResetCard;
    case kSCardWUnpoweredCard:
      return SmartCardError::kUnpoweredCard;
    case kSCardWUnresponsiveCard:
      return SmartCardError::kUnresponsiveCard;
    case kSCardWUnsupportedCard:
      return SmartCardError::kUnsupportedCard;
    case kSCardEReaderUnavailable:
      return SmartCardError::kReaderUnavailable;
    case kSCardESharingViolation:
      return SmartCardError::kSharingViolation;
    case kSCardENotTransacted:
      return SmartCardError::kNotTransacted;
    case kSCardENoSmartcard:
      return SmartCardError::kNoSmartcard;
    case kSCardEProtoMismatch:
      return SmartCardError::kProtoMismatch;
    case kSCardESystemCancelled:
      return SmartCardError::kSystemCancelled;
    case kSCardENotReady:
      return SmartCardError::kNotReady;
    case kSCardECancelled:
      return SmartCardError::kCancelled;
    case kSCardEInsufficientBuffer:
      return SmartCardError::kInsufficientBuffer;
    case kSCardEInvalidHandle:
      return SmartCardError::kInvalidHandle;
    case kSCardEInvalidParameter:
      return SmartCardError::kInvalidParameter;
    case kSCardEInvalidValue:
      return SmartCardError::kInvalidValue;
    case kSCardENoMemory:
      return SmartCardError::kNoMemory;
    case kSCardETimeout:
      return SmartCardError::kTimeout;
    case kSCardEUnknownReader:
      return SmartCardError::kUnknownReader;
    case kSCardENoReadersAvailable:
      return SmartCardError::kNoReadersAvailable;
    case kSCardEServiceStopped:
      return SmartCardError::kServiceStopped;
    case kSCardENoService:
      return SmartCardError::kNoService;
    case kSCardFCommError:
      return SmartCardError::kCommError;
    case kSCardFInternalError:
      return SmartCardError::kInternalError;
    case kSCardEUnknownCard:
      return SmartCardError::kUnknownCard;
    case kSCardEServerTooBusy:
      return SmartCardError::kServerTooBusy;
    case kSCardEUnexpected:
      return SmartCardError::kUnexpected;
    case kSCardEUnsupportedFeature:
      return SmartCardError::kUnsupportedFeature;
    case kSCardPShutdown:
      return SmartCardError::kShutdown;
    default:
      return SmartCardError::kUnknown;
  }
}

uint32_t PcscShareModeFromMojo(SmartCardShareMode share_mode) {
  switch (share_mode) {
    case SmartCardShareMode::kShared:
      return kSCardShareShared;
    case SmartCardShareMode::kExclusive:
      return kSCardShareExclusive;
    case SmartCardShareMode::kDirect:
      return kSCardShareDirect;
  }
}

uint32_t PcscProtocolsFromMojo(const SmartCardProtocols& protocols) {
  uint32_t result = kSCardProtocolUndefined;
  if (protocols.t0) {
    result |= kSCardProtocolT0;
  }
  if (protocols.t1) {
    result |= kSCardProtocolT1;
  }
  if (protocols.raw) {
    result |= kSCardProtocolRaw;
  }
  return result;
}

SmartCardProtocol MojoProtocolFromPcsc(uint32_t pcsc_protocol) {
  switch (pcsc_protocol) {
    case kSCardProtocolT0:
      return SmartCardProtocol::kT0;
    case kSCardProtocolT1:
      return SmartCardProtocol::kT1;
    case kSCardProtocolRaw:
      return SmartCardProtocol::kRaw;
    default:
      return SmartCardProtocol::kUndefined;
  }
}

uint32_t PcscDispositionFromMojo(SmartCardDisposition disposition) {
  switch (disposition) {
    case SmartCardDisposition::kLeave:
      return kSCardLeaveCard;
    case SmartCardDisposition::kReset:
      return kSCardResetCard;
    case SmartCardDisposition::kUnpower:
      return kSCardUnpowerCard;
    case SmartCardDisposition::kEject:
      return kSCardEjectCard;
  }
}

SmartCardConnectionState MojoConnectionStateFromPcsc(uint32_t pcsc_state) {
  // Canonical PC/SC state flags form a bitmask; report the most specific state
  // present.
  if (pcsc_state & kSCardSpecific) {
    return SmartCardConnectionState::kSpecific;
  }
  if (pcsc_state & kSCardNegotiable) {
    return SmartCardConnectionState::kNegotiable;
  }
  if (pcsc_state & kSCardPowered) {
    return SmartCardConnectionState::kPowered;
  }
  if (pcsc_state & kSCardSwallowed) {
    return SmartCardConnectionState::kSwallowed;
  }
  if (pcsc_state & kSCardPresent) {
    return SmartCardConnectionState::kPresent;
  }
  return SmartCardConnectionState::kAbsent;
}

uint32_t PcscReaderStateFlagsFromMojo(const SmartCardReaderStateFlags& flags,
                                      uint16_t count) {
  uint32_t result = static_cast<uint32_t>(count) << 16;
  if (flags.ignore) {
    result |= kSCardStateIgnore;
  }
  if (flags.changed) {
    result |= kSCardStateChanged;
  }
  if (flags.unknown) {
    result |= kSCardStateUnknown;
  }
  if (flags.unavailable) {
    result |= kSCardStateUnavailable;
  }
  if (flags.empty) {
    result |= kSCardStateEmpty;
  }
  if (flags.present) {
    result |= kSCardStatePresent;
  }
  if (flags.exclusive) {
    result |= kSCardStateExclusive;
  }
  if (flags.inuse) {
    result |= kSCardStateInUse;
  }
  if (flags.mute) {
    result |= kSCardStateMute;
  }
  if (flags.unpowered) {
    result |= kSCardStateUnpowered;
  }
  return result;
}

SmartCardReaderStateFlagsPtr MojoReaderStateFlagsFromPcsc(uint32_t pcsc_state) {
  auto flags = SmartCardReaderStateFlags::New();
  const uint32_t lower = pcsc_state & 0xFFFF;
  flags->unaware = (lower == kSCardStateUnaware);
  flags->ignore = (lower & kSCardStateIgnore) != 0;
  flags->changed = (lower & kSCardStateChanged) != 0;
  flags->unknown = (lower & kSCardStateUnknown) != 0;
  flags->unavailable = (lower & kSCardStateUnavailable) != 0;
  flags->empty = (lower & kSCardStateEmpty) != 0;
  flags->present = (lower & kSCardStatePresent) != 0;
  flags->exclusive = (lower & kSCardStateExclusive) != 0;
  flags->inuse = (lower & kSCardStateInUse) != 0;
  flags->mute = (lower & kSCardStateMute) != 0;
  flags->unpowered = (lower & kSCardStateUnpowered) != 0;
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

}  // namespace smart_card::pcsc

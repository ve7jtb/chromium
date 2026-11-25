// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_SMART_CARD_PCSC_PCSC_CONSTANTS_H_
#define CHROME_BROWSER_SMART_CARD_PCSC_PCSC_CONSTANTS_H_

#include <cstddef>
#include <cstdint>

namespace smart_card::pcsc {

// Canonical PC/SC numeric constants shared across macOS, Linux (pcsc-lite),
// and Windows (WinSCard). Platform-specific differences (such as Windows
// SCARD_PROTOCOL_RAW and SCardStatus state enum values) are normalized at the
// PcscApi boundary.

inline constexpr uint32_t kSCardSSuccess = 0x00000000;

// Context scopes.
inline constexpr uint32_t kSCardScopeSystem = 0x0002;

// Share modes.
inline constexpr uint32_t kSCardShareExclusive = 0x0001;
inline constexpr uint32_t kSCardShareShared = 0x0002;
inline constexpr uint32_t kSCardShareDirect = 0x0003;

// Protocols (canonical pcsc-lite/macOS values; PcscApi translates kSCardProtocolRaw
// to Windows SCARD_PROTOCOL_RAW (0x00010000) on Windows).
inline constexpr uint32_t kSCardProtocolUndefined = 0x0000;
inline constexpr uint32_t kSCardProtocolT0 = 0x0001;
inline constexpr uint32_t kSCardProtocolT1 = 0x0002;
inline constexpr uint32_t kSCardProtocolRaw = 0x0004;

// Dispositions.
inline constexpr uint32_t kSCardLeaveCard = 0x0000;
inline constexpr uint32_t kSCardResetCard = 0x0001;
inline constexpr uint32_t kSCardUnpowerCard = 0x0002;
inline constexpr uint32_t kSCardEjectCard = 0x0003;

// Connection state flags (canonical pcsc-lite/macOS bitmask; PcscApi converts
// Windows SCardStatus sequential enum values to this bitmask).
inline constexpr uint32_t kSCardUnknown = 0x0001;
inline constexpr uint32_t kSCardAbsent = 0x0002;
inline constexpr uint32_t kSCardPresent = 0x0004;
inline constexpr uint32_t kSCardSwallowed = 0x0008;
inline constexpr uint32_t kSCardPowered = 0x0010;
inline constexpr uint32_t kSCardNegotiable = 0x0020;
inline constexpr uint32_t kSCardSpecific = 0x0040;

// Reader state flags for SCardGetStatusChange.
inline constexpr uint32_t kSCardStateUnaware = 0x0000;
inline constexpr uint32_t kSCardStateIgnore = 0x0001;
inline constexpr uint32_t kSCardStateChanged = 0x0002;
inline constexpr uint32_t kSCardStateUnknown = 0x0004;
inline constexpr uint32_t kSCardStateUnavailable = 0x0008;
inline constexpr uint32_t kSCardStateEmpty = 0x0010;
inline constexpr uint32_t kSCardStatePresent = 0x0020;
inline constexpr uint32_t kSCardStateExclusive = 0x0080;
inline constexpr uint32_t kSCardStateInUse = 0x0100;
inline constexpr uint32_t kSCardStateMute = 0x0200;
inline constexpr uint32_t kSCardStateUnpowered = 0x0400;

inline constexpr uint32_t kSCardInfinite = 0xFFFFFFFF;
inline constexpr size_t kMaxAtrSize = 33;

// PC/SC error codes (identical across Windows, macOS, and pcsc-lite).
inline constexpr uint32_t kSCardFInternalError = 0x80100001;
inline constexpr uint32_t kSCardECancelled = 0x80100002;
inline constexpr uint32_t kSCardEInvalidHandle = 0x80100003;
inline constexpr uint32_t kSCardEInvalidParameter = 0x80100004;
inline constexpr uint32_t kSCardENoMemory = 0x80100006;
inline constexpr uint32_t kSCardEInsufficientBuffer = 0x80100008;
inline constexpr uint32_t kSCardEUnknownReader = 0x80100009;
inline constexpr uint32_t kSCardETimeout = 0x8010000A;
inline constexpr uint32_t kSCardESharingViolation = 0x8010000B;
inline constexpr uint32_t kSCardENoSmartcard = 0x8010000C;
inline constexpr uint32_t kSCardEUnknownCard = 0x8010000D;
inline constexpr uint32_t kSCardEProtoMismatch = 0x8010000F;
inline constexpr uint32_t kSCardENotReady = 0x80100010;
inline constexpr uint32_t kSCardEInvalidValue = 0x80100011;
inline constexpr uint32_t kSCardESystemCancelled = 0x80100012;
inline constexpr uint32_t kSCardFCommError = 0x80100013;
inline constexpr uint32_t kSCardENotTransacted = 0x80100016;
inline constexpr uint32_t kSCardEReaderUnavailable = 0x80100017;
inline constexpr uint32_t kSCardPShutdown = 0x80100018;
inline constexpr uint32_t kSCardENoService = 0x8010001D;
inline constexpr uint32_t kSCardEServiceStopped = 0x8010001E;
inline constexpr uint32_t kSCardEUnexpected = 0x8010001F;
inline constexpr uint32_t kSCardEUnsupportedFeature = 0x80100022;
inline constexpr uint32_t kSCardENoReadersAvailable = 0x8010002E;
inline constexpr uint32_t kSCardEServerTooBusy = 0x80100031;

inline constexpr uint32_t kSCardWUnsupportedCard = 0x80100065;
inline constexpr uint32_t kSCardWUnresponsiveCard = 0x80100066;
inline constexpr uint32_t kSCardWUnpoweredCard = 0x80100067;
inline constexpr uint32_t kSCardWResetCard = 0x80100068;
inline constexpr uint32_t kSCardWRemovedCard = 0x80100069;

}  // namespace smart_card::pcsc

#endif  // CHROME_BROWSER_SMART_CARD_PCSC_PCSC_CONSTANTS_H_

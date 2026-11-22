// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/smart_card/mac/mac_smart_card_util.h"

#include <PCSC/winscard.h>

#include <string>
#include <vector>

#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace smart_card::mac {
namespace {

using device::mojom::SmartCardConnectionState;
using device::mojom::SmartCardDisposition;
using device::mojom::SmartCardError;
using device::mojom::SmartCardProtocol;
using device::mojom::SmartCardProtocols;
using device::mojom::SmartCardReaderStateFlags;
using device::mojom::SmartCardShareMode;
using testing::ElementsAre;
using testing::IsEmpty;

TEST(MacSmartCardUtilTest, ErrorMapping) {
  EXPECT_EQ(SmartCardErrorFromPcscResult(SCARD_E_NO_READERS_AVAILABLE),
            SmartCardError::kNoReadersAvailable);
  EXPECT_EQ(SmartCardErrorFromPcscResult(SCARD_E_CANCELLED),
            SmartCardError::kCancelled);
  EXPECT_EQ(SmartCardErrorFromPcscResult(SCARD_E_TIMEOUT),
            SmartCardError::kTimeout);
  EXPECT_EQ(SmartCardErrorFromPcscResult(SCARD_W_REMOVED_CARD),
            SmartCardError::kRemovedCard);
  EXPECT_EQ(SmartCardErrorFromPcscResult(SCARD_E_SHARING_VIOLATION),
            SmartCardError::kSharingViolation);
  EXPECT_EQ(SmartCardErrorFromPcscResult(SCARD_E_INVALID_HANDLE),
            SmartCardError::kInvalidHandle);
  EXPECT_EQ(SmartCardErrorFromPcscResult(static_cast<int32_t>(0x8010FFFF)),
            SmartCardError::kUnknown);
}

TEST(MacSmartCardUtilTest, ShareModeAndDisposition) {
  EXPECT_EQ(PcscShareModeFromMojo(SmartCardShareMode::kShared),
            static_cast<uint32_t>(SCARD_SHARE_SHARED));
  EXPECT_EQ(PcscShareModeFromMojo(SmartCardShareMode::kExclusive),
            static_cast<uint32_t>(SCARD_SHARE_EXCLUSIVE));
  EXPECT_EQ(PcscShareModeFromMojo(SmartCardShareMode::kDirect),
            static_cast<uint32_t>(SCARD_SHARE_DIRECT));

  EXPECT_EQ(PcscDispositionFromMojo(SmartCardDisposition::kLeave),
            static_cast<uint32_t>(SCARD_LEAVE_CARD));
  EXPECT_EQ(PcscDispositionFromMojo(SmartCardDisposition::kReset),
            static_cast<uint32_t>(SCARD_RESET_CARD));
  EXPECT_EQ(PcscDispositionFromMojo(SmartCardDisposition::kUnpower),
            static_cast<uint32_t>(SCARD_UNPOWER_CARD));
  EXPECT_EQ(PcscDispositionFromMojo(SmartCardDisposition::kEject),
            static_cast<uint32_t>(SCARD_EJECT_CARD));
}

TEST(MacSmartCardUtilTest, ProtocolsAndConnectionState) {
  auto protos = SmartCardProtocols::New(/*t0=*/true, /*t1=*/true, /*raw=*/false);
  EXPECT_EQ(PcscProtocolsFromMojo(*protos),
            static_cast<uint32_t>(SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1));
  EXPECT_EQ(MojoProtocolFromPcsc(SCARD_PROTOCOL_T0), SmartCardProtocol::kT0);
  EXPECT_EQ(MojoProtocolFromPcsc(SCARD_PROTOCOL_T1), SmartCardProtocol::kT1);
  EXPECT_EQ(MojoProtocolFromPcsc(SCARD_PROTOCOL_RAW), SmartCardProtocol::kRaw);
  EXPECT_EQ(MojoProtocolFromPcsc(SCARD_PROTOCOL_UNDEFINED),
            SmartCardProtocol::kUndefined);

  EXPECT_EQ(MojoConnectionStateFromPcsc(SCARD_PRESENT | SCARD_POWERED |
                                        SCARD_SPECIFIC),
            SmartCardConnectionState::kSpecific);
  EXPECT_EQ(MojoConnectionStateFromPcsc(SCARD_ABSENT),
            SmartCardConnectionState::kAbsent);
}

TEST(MacSmartCardUtilTest, ReaderStateFlagsAndCount) {
  auto flags = SmartCardReaderStateFlags::New();
  flags->present = true;
  flags->inuse = true;
  uint32_t pcsc = PcscReaderStateFlagsFromMojo(*flags, /*count=*/7);
  EXPECT_EQ(pcsc, (7u << 16) | SCARD_STATE_PRESENT | SCARD_STATE_INUSE);

  auto roundtrip = MojoReaderStateFlagsFromPcsc(pcsc);
  EXPECT_FALSE(roundtrip->unaware);
  EXPECT_TRUE(roundtrip->present);
  EXPECT_TRUE(roundtrip->inuse);
  EXPECT_FALSE(roundtrip->empty);
  EXPECT_EQ(MojoEventCountFromPcsc(pcsc), 7u);
}

TEST(MacSmartCardUtilTest, ParseMultiString) {
  constexpr char kTwoReaders[] =
      "Yubico YubiKey OTP+FIDO+CCID\0Second Reader\0\0";
  auto parsed =
      ParsePcscMultiString(base::span_with_nul_from_cstring(kTwoReaders));
  EXPECT_THAT(parsed,
              ElementsAre("Yubico YubiKey OTP+FIDO+CCID", "Second Reader"));

  constexpr char kEmpty[] = "\0";
  EXPECT_THAT(ParsePcscMultiString(base::span_with_nul_from_cstring(kEmpty)),
              IsEmpty());
}

}  // namespace
}  // namespace smart_card::mac

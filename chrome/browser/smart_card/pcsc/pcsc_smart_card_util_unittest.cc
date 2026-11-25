// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/smart_card/pcsc/pcsc_smart_card_util.h"

#include <string>
#include <vector>

#include "chrome/browser/smart_card/pcsc/pcsc_constants.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace smart_card::pcsc {
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

TEST(PcscSmartCardUtilTest, ErrorMapping) {
  EXPECT_EQ(SmartCardErrorFromPcscResult(kSCardENoReadersAvailable),
            SmartCardError::kNoReadersAvailable);
  EXPECT_EQ(SmartCardErrorFromPcscResult(kSCardECancelled),
            SmartCardError::kCancelled);
  EXPECT_EQ(SmartCardErrorFromPcscResult(kSCardETimeout),
            SmartCardError::kTimeout);
  EXPECT_EQ(SmartCardErrorFromPcscResult(kSCardWRemovedCard),
            SmartCardError::kRemovedCard);
  EXPECT_EQ(SmartCardErrorFromPcscResult(kSCardESharingViolation),
            SmartCardError::kSharingViolation);
  EXPECT_EQ(SmartCardErrorFromPcscResult(kSCardEInvalidHandle),
            SmartCardError::kInvalidHandle);
  EXPECT_EQ(SmartCardErrorFromPcscResult(kSCardEUnexpected),
            SmartCardError::kUnexpected);
  EXPECT_EQ(SmartCardErrorFromPcscResult(kSCardEUnsupportedFeature),
            SmartCardError::kUnsupportedFeature);
  EXPECT_EQ(SmartCardErrorFromPcscResult(0x8010FFFF),
            SmartCardError::kUnknown);
}

TEST(PcscSmartCardUtilTest, ShareModeAndDisposition) {
  EXPECT_EQ(PcscShareModeFromMojo(SmartCardShareMode::kShared),
            kSCardShareShared);
  EXPECT_EQ(PcscShareModeFromMojo(SmartCardShareMode::kExclusive),
            kSCardShareExclusive);
  EXPECT_EQ(PcscShareModeFromMojo(SmartCardShareMode::kDirect),
            kSCardShareDirect);

  EXPECT_EQ(PcscDispositionFromMojo(SmartCardDisposition::kLeave),
            kSCardLeaveCard);
  EXPECT_EQ(PcscDispositionFromMojo(SmartCardDisposition::kReset),
            kSCardResetCard);
  EXPECT_EQ(PcscDispositionFromMojo(SmartCardDisposition::kUnpower),
            kSCardUnpowerCard);
  EXPECT_EQ(PcscDispositionFromMojo(SmartCardDisposition::kEject),
            kSCardEjectCard);
}

TEST(PcscSmartCardUtilTest, ProtocolsAndConnectionState) {
  auto protos =
      SmartCardProtocols::New(/*t0=*/true, /*t1=*/true, /*raw=*/false);
  EXPECT_EQ(PcscProtocolsFromMojo(*protos),
            kSCardProtocolT0 | kSCardProtocolT1);
  EXPECT_EQ(MojoProtocolFromPcsc(kSCardProtocolT0), SmartCardProtocol::kT0);
  EXPECT_EQ(MojoProtocolFromPcsc(kSCardProtocolT1), SmartCardProtocol::kT1);
  EXPECT_EQ(MojoProtocolFromPcsc(kSCardProtocolRaw), SmartCardProtocol::kRaw);
  EXPECT_EQ(MojoProtocolFromPcsc(kSCardProtocolUndefined),
            SmartCardProtocol::kUndefined);

  EXPECT_EQ(MojoConnectionStateFromPcsc(kSCardPresent | kSCardPowered |
                                        kSCardSpecific),
            SmartCardConnectionState::kSpecific);
  EXPECT_EQ(MojoConnectionStateFromPcsc(kSCardAbsent),
            SmartCardConnectionState::kAbsent);
}

TEST(PcscSmartCardUtilTest, ReaderStateFlagsAndCount) {
  auto flags = SmartCardReaderStateFlags::New();
  flags->present = true;
  flags->inuse = true;
  uint32_t pcsc = PcscReaderStateFlagsFromMojo(*flags, /*count=*/7);
  EXPECT_EQ(pcsc, (7u << 16) | kSCardStatePresent | kSCardStateInUse);

  auto roundtrip = MojoReaderStateFlagsFromPcsc(pcsc);
  EXPECT_FALSE(roundtrip->unaware);
  EXPECT_TRUE(roundtrip->present);
  EXPECT_TRUE(roundtrip->inuse);
  EXPECT_FALSE(roundtrip->empty);
  EXPECT_EQ(MojoEventCountFromPcsc(pcsc), 7u);
}

TEST(PcscSmartCardUtilTest, ParseMultiString) {
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
}  // namespace smart_card::pcsc

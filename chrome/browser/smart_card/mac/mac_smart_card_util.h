// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_SMART_CARD_MAC_MAC_SMART_CARD_UTIL_H_
#define CHROME_BROWSER_SMART_CARD_MAC_MAC_SMART_CARD_UTIL_H_

#include <cstdint>
#include <string>
#include <vector>

#include "base/containers/span.h"
#include "services/device/public/mojom/smart_card.mojom.h"

namespace smart_card::mac {

device::mojom::SmartCardError SmartCardErrorFromPcscResult(int32_t pcsc_result);

uint32_t PcscShareModeFromMojo(device::mojom::SmartCardShareMode share_mode);

uint32_t PcscProtocolsFromMojo(
    const device::mojom::SmartCardProtocols& protocols);

device::mojom::SmartCardProtocol MojoProtocolFromPcsc(uint32_t pcsc_protocol);

uint32_t PcscDispositionFromMojo(
    device::mojom::SmartCardDisposition disposition);

device::mojom::SmartCardConnectionState MojoConnectionStateFromPcsc(
    uint32_t pcsc_state);

uint32_t PcscReaderStateFlagsFromMojo(
    const device::mojom::SmartCardReaderStateFlags& flags,
    uint16_t count);

device::mojom::SmartCardReaderStateFlagsPtr MojoReaderStateFlagsFromPcsc(
    uint32_t pcsc_state);

uint16_t MojoEventCountFromPcsc(uint32_t pcsc_state);

// Parses a PC/SC multi-string (NUL-separated, double-NUL-terminated).
std::vector<std::string> ParsePcscMultiString(base::span<const char> buffer);

}  // namespace smart_card::mac

#endif  // CHROME_BROWSER_SMART_CARD_MAC_MAC_SMART_CARD_UTIL_H_

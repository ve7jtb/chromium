// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_SMART_CARD_MAC_MAC_SMART_CARD_CONTEXT_FACTORY_H_
#define CHROME_BROWSER_SMART_CARD_MAC_MAC_SMART_CARD_CONTEXT_FACTORY_H_

#include "mojo/public/cpp/bindings/pending_remote.h"
#include "services/device/public/mojom/smart_card.mojom.h"

namespace smart_card::mac {

// Creates a self-owned SmartCardContextFactory backed by macOS PCSC.framework.
mojo::PendingRemote<device::mojom::SmartCardContextFactory>
CreateMacSmartCardContextFactory();

}  // namespace smart_card::mac

#endif  // CHROME_BROWSER_SMART_CARD_MAC_MAC_SMART_CARD_CONTEXT_FACTORY_H_

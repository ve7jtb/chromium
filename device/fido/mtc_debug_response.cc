// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "device/fido/mtc_debug_response.h"

namespace device {

MtcDebugResponse::MtcDebugResponse() = default;

MtcDebugResponse::MtcDebugResponse(std::vector<uint8_t> in_pub_key)
    : pub_key(std::move(in_pub_key)) {}

MtcDebugResponse::~MtcDebugResponse() = default;

MtcDebugResponse::MtcDebugResponse(MtcDebugResponse&&) = default;

MtcDebugResponse& MtcDebugResponse::operator=(MtcDebugResponse&&) = default;

}  // namespace device

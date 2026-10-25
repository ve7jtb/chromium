// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef DEVICE_FIDO_MTC_DEBUG_RESPONSE_H_
#define DEVICE_FIDO_MTC_DEBUG_RESPONSE_H_

#include <stdint.h>

#include <optional>
#include <string>
#include <vector>

#include "base/component_export.h"

namespace device {

// The response to an MTC Debug extension (mtcDebug) request during MakeCredential.
struct COMPONENT_EXPORT(DEVICE_FIDO) MtcDebugResponse {
  MtcDebugResponse();
  explicit MtcDebugResponse(std::vector<uint8_t> pub_key);
  ~MtcDebugResponse();

  MtcDebugResponse(MtcDebugResponse&&);
  MtcDebugResponse& operator=(MtcDebugResponse&&);
  MtcDebugResponse(const MtcDebugResponse&) = delete;
  MtcDebugResponse& operator=(const MtcDebugResponse&) = delete;

  // The canonical CBOR-encoded COSE_Key of the active attestation public key.
  std::vector<uint8_t> pub_key;

  // Optional device physical serial number (Enterprise attestation only).
  std::optional<std::string> device_serial;

  // Optional Unix timestamps defining key validity period.
  std::optional<uint64_t> not_before;
  std::optional<uint64_t> not_after;

  // Optional authenticator firmware version (CTAP 2.3 parameter 0x0E).
  std::optional<uint32_t> firmware_version;

  // Optional binary RFC 9162 Merkle tree inclusion proof.
  std::optional<std::vector<uint8_t>> mtc_proof;

  // Optional 32-byte expected Landmark or Trust Anchor Merkle root hash.
  std::optional<std::vector<uint8_t>> root_hash;
};

}  // namespace device

#endif  // DEVICE_FIDO_MTC_DEBUG_RESPONSE_H_

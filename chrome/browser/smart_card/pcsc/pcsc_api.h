// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_SMART_CARD_PCSC_PCSC_API_H_
#define CHROME_BROWSER_SMART_CARD_PCSC_PCSC_API_H_

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "base/containers/span.h"
#include "base/no_destructor.h"

namespace smart_card::pcsc {

// Opaque handle types large enough to hold SCARDCONTEXT and SCARDHANDLE on
// macOS (32-bit), Linux pcsc-lite (64-bit long), and Windows (ULONG_PTR).
using PcscContext = uintptr_t;
using PcscCard = uintptr_t;

enum class PcscProtocolPci {
  kT0,
  kT1,
  kRaw,
};

struct PcscReaderState {
  PcscReaderState();
  PcscReaderState(const PcscReaderState&);
  PcscReaderState& operator=(const PcscReaderState&);
  PcscReaderState(PcscReaderState&&) noexcept;
  PcscReaderState& operator=(PcscReaderState&&) noexcept;
  ~PcscReaderState();

  std::string reader;
  uint32_t current_state = 0;
  uint32_t event_state = 0;
  std::vector<uint8_t> atr;
};

// Cross-platform thin wrapper around the OS PC/SC implementation:
// - macOS: PCSC.framework (<PCSC/winscard.h>)
// - Windows: winscard.lib (<winscard.h>, Unicode W entry points)
// - Linux: dynamically loaded libpcsclite.so.1 via base::LoadNativeLibrary
//
// All methods are blocking and must be called on a MayBlock() thread pool
// sequence. Return values are canonical PC/SC status codes (kSCardSSuccess on
// success).
class PcscApi {
 public:
  static const PcscApi& Get();

  uint32_t EstablishContext(uint32_t scope, PcscContext* out_context) const;
  uint32_t ReleaseContext(PcscContext context) const;
  uint32_t ListReaders(PcscContext context,
                       std::vector<std::string>* out_readers) const;
  uint32_t GetStatusChange(PcscContext context,
                           uint32_t timeout_ms,
                           std::vector<PcscReaderState>* states) const;
  uint32_t Cancel(PcscContext context) const;
  uint32_t Connect(PcscContext context,
                   const std::string& reader,
                   uint32_t share_mode,
                   uint32_t preferred_protocols,
                   PcscCard* out_card,
                   uint32_t* out_active_protocol) const;
  uint32_t Disconnect(PcscCard card, uint32_t disposition) const;
  uint32_t Transmit(PcscCard card,
                    PcscProtocolPci pci,
                    base::span<const uint8_t> send_buf,
                    std::vector<uint8_t>* out_recv_buf) const;
  uint32_t Control(PcscCard card,
                   uint32_t control_code,
                   base::span<const uint8_t> send_buf,
                   std::vector<uint8_t>* out_recv_buf) const;
  uint32_t GetAttrib(PcscCard card,
                     uint32_t attr_id,
                     std::vector<uint8_t>* out_attr) const;
  uint32_t SetAttrib(PcscCard card,
                     uint32_t attr_id,
                     base::span<const uint8_t> attr) const;
  uint32_t Status(PcscCard card,
                  std::string* out_reader_name,
                  uint32_t* out_state,
                  uint32_t* out_protocol,
                  std::vector<uint8_t>* out_atr) const;
  uint32_t BeginTransaction(PcscCard card) const;
  uint32_t EndTransaction(PcscCard card, uint32_t disposition) const;

 private:
  friend class base::NoDestructor<PcscApi>;

  PcscApi();
  ~PcscApi();

  struct PlatformState;
  std::unique_ptr<PlatformState> state_;
};

}  // namespace smart_card::pcsc

#endif  // CHROME_BROWSER_SMART_CARD_PCSC_PCSC_API_H_

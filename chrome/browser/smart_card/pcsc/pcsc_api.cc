// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/smart_card/pcsc/pcsc_api.h"

#include <algorithm>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "base/containers/span.h"
#include "base/no_destructor.h"
#include "build/build_config.h"
#include "chrome/browser/smart_card/pcsc/pcsc_constants.h"
#include "chrome/browser/smart_card/pcsc/pcsc_smart_card_util.h"

#if BUILDFLAG(IS_MAC)
#include <PCSC/winscard.h>
#elif BUILDFLAG(IS_WIN)
#include <windows.h>
#include <winscard.h>

#include "base/strings/utf_string_conversions.h"
#elif BUILDFLAG(IS_LINUX)
#include "base/files/file_path.h"
#include "base/memory/raw_ptr_exclusion.h"
#include "base/native_library.h"
#endif

namespace smart_card::pcsc {

namespace {

// Extended-length ISO 7816-4 APDU response: up to 65536 data bytes + 2 SW bytes.
constexpr uint32_t kMaxApduResponseSize = 65538;

#if BUILDFLAG(IS_WIN)
uint32_t WinProtocolsFromCanonical(uint32_t canonical) {
  uint32_t win = SCARD_PROTOCOL_UNDEFINED;
  if (canonical & kSCardProtocolT0) {
    win |= SCARD_PROTOCOL_T0;
  }
  if (canonical & kSCardProtocolT1) {
    win |= SCARD_PROTOCOL_T1;
  }
  if (canonical & kSCardProtocolRaw) {
    win |= SCARD_PROTOCOL_RAW;
  }
  return win;
}

uint32_t CanonicalProtocolFromWin(DWORD win_protocol) {
  switch (win_protocol) {
    case SCARD_PROTOCOL_T0:
      return kSCardProtocolT0;
    case SCARD_PROTOCOL_T1:
      return kSCardProtocolT1;
    case SCARD_PROTOCOL_RAW:
      return kSCardProtocolRaw;
    default:
      return kSCardProtocolUndefined;
  }
}

uint32_t CanonicalStateFromWin(DWORD win_state) {
  switch (win_state) {
    case SCARD_SPECIFIC:
      return kSCardSpecific;
    case SCARD_NEGOTIABLE:
      return kSCardNegotiable;
    case SCARD_POWERED:
      return kSCardPowered;
    case SCARD_SWALLOWED:
      return kSCardSwallowed;
    case SCARD_PRESENT:
      return kSCardPresent;
    case SCARD_ABSENT:
      return kSCardAbsent;
    default:
      return kSCardUnknown;
  }
}

std::vector<std::string> ParsePcscMultiStringW(base::span<const wchar_t> buf) {
  std::vector<std::string> result;
  size_t pos = 0;
  while (pos < buf.size()) {
    if (buf[pos] == L'\0') {
      break;
    }
    size_t end = pos;
    while (end < buf.size() && buf[end] != L'\0') {
      ++end;
    }
    result.push_back(base::WideToUTF8(
        std::wstring_view(buf.subspan(pos, end - pos).data(), end - pos)));
    pos = end + 1;
  }
  return result;
}
#endif  // BUILDFLAG(IS_WIN)

#if BUILDFLAG(IS_LINUX)
// Linux pcsc-lite ABI types (from <PCSC/pcsclite.h> and <PCSC/wintypes.h>).
// On 64-bit Linux, pcsc-lite defines LONG as `long` and DWORD as `unsigned long`
// (both 64-bit), and SCARDCONTEXT/SCARDHANDLE as `long`.
using PcscLiteLong = long;
using PcscLiteDword = unsigned long;
using PcscLiteContext = long;
using PcscLiteHandle = long;

struct PcscLiteIoRequest {
  PcscLiteDword dwProtocol;
  PcscLiteDword cbPciLength;
};

struct PcscLiteReaderState {
  const char* szReader;
  // C ABI struct passed directly to libpcsclite.so.1; cannot use raw_ptr.
  RAW_PTR_EXCLUSION void* pvUserData;
  PcscLiteDword dwCurrentState;
  PcscLiteDword dwEventState;
  PcscLiteDword cbAtr;
  unsigned char rgbAtr[kMaxAtrSize];
};

using FnEstablishContext = PcscLiteLong (*)(PcscLiteDword dwScope,
                                            const void* pvReserved1,
                                            const void* pvReserved2,
                                            PcscLiteContext* phContext);
using FnReleaseContext = PcscLiteLong (*)(PcscLiteContext hContext);
using FnListReaders = PcscLiteLong (*)(PcscLiteContext hContext,
                                       const char* mszGroups,
                                       char* mszReaders,
                                       PcscLiteDword* pcchReaders);
using FnGetStatusChange = PcscLiteLong (*)(PcscLiteContext hContext,
                                           PcscLiteDword dwTimeout,
                                           PcscLiteReaderState* rgReaderStates,
                                           PcscLiteDword cReaders);
using FnCancel = PcscLiteLong (*)(PcscLiteContext hContext);
using FnConnect = PcscLiteLong (*)(PcscLiteContext hContext,
                                   const char* szReader,
                                   PcscLiteDword dwShareMode,
                                   PcscLiteDword dwPreferredProtocols,
                                   PcscLiteHandle* phCard,
                                   PcscLiteDword* pdwActiveProtocol);
using FnDisconnect = PcscLiteLong (*)(PcscLiteHandle hCard,
                                      PcscLiteDword dwDisposition);
using FnTransmit = PcscLiteLong (*)(PcscLiteHandle hCard,
                                    const PcscLiteIoRequest* pioSendPci,
                                    const unsigned char* pbSendBuffer,
                                    PcscLiteDword cbSendLength,
                                    PcscLiteIoRequest* pioRecvPci,
                                    unsigned char* pbRecvBuffer,
                                    PcscLiteDword* pcbRecvLength);
using FnControl = PcscLiteLong (*)(PcscLiteHandle hCard,
                                   PcscLiteDword dwControlCode,
                                   const void* pbSendBuffer,
                                   PcscLiteDword cbSendLength,
                                   void* pbRecvBuffer,
                                   PcscLiteDword cbRecvLength,
                                   PcscLiteDword* lpBytesReturned);
using FnGetAttrib = PcscLiteLong (*)(PcscLiteHandle hCard,
                                     PcscLiteDword dwAttrId,
                                     unsigned char* pbAttr,
                                     PcscLiteDword* pcbAttrLen);
using FnSetAttrib = PcscLiteLong (*)(PcscLiteHandle hCard,
                                     PcscLiteDword dwAttrId,
                                     const unsigned char* pbAttr,
                                     PcscLiteDword cbAttrLen);
using FnStatus = PcscLiteLong (*)(PcscLiteHandle hCard,
                                  char* mszReaderName,
                                  PcscLiteDword* pcchReaderLen,
                                  PcscLiteDword* pdwState,
                                  PcscLiteDword* pdwProtocol,
                                  unsigned char* pbAtr,
                                  PcscLiteDword* pcbAtrLen);
using FnBeginTransaction = PcscLiteLong (*)(PcscLiteHandle hCard);
using FnEndTransaction = PcscLiteLong (*)(PcscLiteHandle hCard,
                                          PcscLiteDword dwDisposition);
#endif  // BUILDFLAG(IS_LINUX)

}  // namespace

PcscReaderState::PcscReaderState() = default;
PcscReaderState::PcscReaderState(const PcscReaderState&) = default;
PcscReaderState& PcscReaderState::operator=(const PcscReaderState&) = default;
PcscReaderState::PcscReaderState(PcscReaderState&&) noexcept = default;
PcscReaderState& PcscReaderState::operator=(PcscReaderState&&) noexcept =
    default;
PcscReaderState::~PcscReaderState() = default;

struct PcscApi::PlatformState {
#if BUILDFLAG(IS_LINUX)
  base::NativeLibrary library = nullptr;
  bool loaded = false;
  FnEstablishContext establish_context = nullptr;
  FnReleaseContext release_context = nullptr;
  FnListReaders list_readers = nullptr;
  FnGetStatusChange get_status_change = nullptr;
  FnCancel cancel = nullptr;
  FnConnect connect = nullptr;
  FnDisconnect disconnect = nullptr;
  FnTransmit transmit = nullptr;
  FnControl control = nullptr;
  FnGetAttrib get_attrib = nullptr;
  FnSetAttrib set_attrib = nullptr;
  FnStatus status = nullptr;
  FnBeginTransaction begin_transaction = nullptr;
  FnEndTransaction end_transaction = nullptr;
#endif
};

// static
const PcscApi& PcscApi::Get() {
  static base::NoDestructor<PcscApi> instance;
  return *instance;
}

PcscApi::PcscApi() : state_(std::make_unique<PlatformState>()) {
#if BUILDFLAG(IS_LINUX)
  base::NativeLibraryLoadError error;
  state_->library = base::LoadNativeLibrary(
      base::FilePath(FILE_PATH_LITERAL("libpcsclite.so.1")), &error);
  if (!state_->library) {
    state_->library = base::LoadNativeLibrary(
        base::FilePath(FILE_PATH_LITERAL("libpcsclite.so")), &error);
  }
  if (!state_->library) {
    return;
  }

  auto load = [this](const char* name) {
    return base::GetFunctionPointerFromNativeLibrary(state_->library, name);
  };
  state_->establish_context =
      reinterpret_cast<FnEstablishContext>(load("SCardEstablishContext"));
  state_->release_context =
      reinterpret_cast<FnReleaseContext>(load("SCardReleaseContext"));
  state_->list_readers =
      reinterpret_cast<FnListReaders>(load("SCardListReaders"));
  state_->get_status_change =
      reinterpret_cast<FnGetStatusChange>(load("SCardGetStatusChange"));
  state_->cancel = reinterpret_cast<FnCancel>(load("SCardCancel"));
  state_->connect = reinterpret_cast<FnConnect>(load("SCardConnect"));
  state_->disconnect = reinterpret_cast<FnDisconnect>(load("SCardDisconnect"));
  state_->transmit = reinterpret_cast<FnTransmit>(load("SCardTransmit"));
  state_->control = reinterpret_cast<FnControl>(load("SCardControl"));
  state_->get_attrib = reinterpret_cast<FnGetAttrib>(load("SCardGetAttrib"));
  state_->set_attrib = reinterpret_cast<FnSetAttrib>(load("SCardSetAttrib"));
  state_->status = reinterpret_cast<FnStatus>(load("SCardStatus"));
  state_->begin_transaction =
      reinterpret_cast<FnBeginTransaction>(load("SCardBeginTransaction"));
  state_->end_transaction =
      reinterpret_cast<FnEndTransaction>(load("SCardEndTransaction"));

  state_->loaded =
      state_->establish_context && state_->release_context &&
      state_->list_readers && state_->get_status_change && state_->cancel &&
      state_->connect && state_->disconnect && state_->transmit &&
      state_->control && state_->get_attrib && state_->set_attrib &&
      state_->status && state_->begin_transaction && state_->end_transaction;
#endif
}

PcscApi::~PcscApi() {
#if BUILDFLAG(IS_LINUX)
  if (state_ && state_->library) {
    base::UnloadNativeLibrary(state_->library);
  }
#endif
}

uint32_t PcscApi::EstablishContext(uint32_t scope,
                                   PcscContext* out_context) const {
#if BUILDFLAG(IS_MAC)
  SCARDCONTEXT ctx = 0;
  int32_t rv = SCardEstablishContext(scope, nullptr, nullptr, &ctx);
  if (rv == SCARD_S_SUCCESS) {
    *out_context = static_cast<PcscContext>(static_cast<uint32_t>(ctx));
  }
  return static_cast<uint32_t>(rv);
#elif BUILDFLAG(IS_WIN)
  SCARDCONTEXT ctx = 0;
  LONG rv = SCardEstablishContext(scope, nullptr, nullptr, &ctx);
  if (rv == SCARD_S_SUCCESS) {
    *out_context = static_cast<PcscContext>(ctx);
  }
  return static_cast<uint32_t>(rv);
#elif BUILDFLAG(IS_LINUX)
  if (!state_->loaded) {
    return kSCardENoService;
  }
  PcscLiteContext ctx = 0;
  PcscLiteLong rv = state_->establish_context(scope, nullptr, nullptr, &ctx);
  if (rv == static_cast<PcscLiteLong>(kSCardSSuccess)) {
    *out_context = static_cast<PcscContext>(ctx);
  }
  return static_cast<uint32_t>(rv);
#endif
}

uint32_t PcscApi::ReleaseContext(PcscContext context) const {
#if BUILDFLAG(IS_MAC)
  return static_cast<uint32_t>(
      SCardReleaseContext(static_cast<SCARDCONTEXT>(context)));
#elif BUILDFLAG(IS_WIN)
  return static_cast<uint32_t>(
      SCardReleaseContext(static_cast<SCARDCONTEXT>(context)));
#elif BUILDFLAG(IS_LINUX)
  if (!state_->loaded) {
    return kSCardENoService;
  }
  return static_cast<uint32_t>(
      state_->release_context(static_cast<PcscLiteContext>(context)));
#endif
}

uint32_t PcscApi::ListReaders(PcscContext context,
                              std::vector<std::string>* out_readers) const {
  out_readers->clear();
#if BUILDFLAG(IS_MAC)
  auto ctx = static_cast<SCARDCONTEXT>(context);
  uint32_t len = 0;
  int32_t rv = SCardListReaders(ctx, nullptr, nullptr, &len);
  if (rv != SCARD_S_SUCCESS) {
    return static_cast<uint32_t>(rv);
  }
  if (len == 0) {
    return kSCardSSuccess;
  }
  std::vector<char> buf(len);
  rv = SCardListReaders(ctx, nullptr, buf.data(), &len);
  if (rv != SCARD_S_SUCCESS) {
    return static_cast<uint32_t>(rv);
  }
  buf.resize(std::min<size_t>(len, buf.size()));
  *out_readers = ParsePcscMultiString(buf);
  return kSCardSSuccess;
#elif BUILDFLAG(IS_WIN)
  auto ctx = static_cast<SCARDCONTEXT>(context);
  DWORD len = 0;
  LONG rv = SCardListReadersW(ctx, nullptr, nullptr, &len);
  if (rv != SCARD_S_SUCCESS) {
    return static_cast<uint32_t>(rv);
  }
  if (len == 0) {
    return kSCardSSuccess;
  }
  std::vector<wchar_t> buf(len);
  rv = SCardListReadersW(ctx, nullptr, buf.data(), &len);
  if (rv != SCARD_S_SUCCESS) {
    return static_cast<uint32_t>(rv);
  }
  buf.resize(std::min<size_t>(len, buf.size()));
  *out_readers = ParsePcscMultiStringW(buf);
  return kSCardSSuccess;
#elif BUILDFLAG(IS_LINUX)
  if (!state_->loaded) {
    return kSCardENoService;
  }
  auto ctx = static_cast<PcscLiteContext>(context);
  PcscLiteDword len = 0;
  PcscLiteLong rv = state_->list_readers(ctx, nullptr, nullptr, &len);
  if (rv != static_cast<PcscLiteLong>(kSCardSSuccess)) {
    return static_cast<uint32_t>(rv);
  }
  if (len == 0) {
    return kSCardSSuccess;
  }
  std::vector<char> buf(len);
  rv = state_->list_readers(ctx, nullptr, buf.data(), &len);
  if (rv != static_cast<PcscLiteLong>(kSCardSSuccess)) {
    return static_cast<uint32_t>(rv);
  }
  buf.resize(std::min<size_t>(len, buf.size()));
  *out_readers = ParsePcscMultiString(buf);
  return kSCardSSuccess;
#endif
}

uint32_t PcscApi::GetStatusChange(PcscContext context,
                                  uint32_t timeout_ms,
                                  std::vector<PcscReaderState>* states) const {
  if (states->empty()) {
    return kSCardSSuccess;
  }
#if BUILDFLAG(IS_MAC)
  std::vector<SCARD_READERSTATE> pcsc_states;
  pcsc_states.reserve(states->size());
  for (const auto& s : *states) {
    SCARD_READERSTATE st = {};
    st.szReader = s.reader.c_str();
    st.dwCurrentState = s.current_state;
    pcsc_states.push_back(st);
  }
  int32_t rv = SCardGetStatusChange(static_cast<SCARDCONTEXT>(context),
                                    timeout_ms, pcsc_states.data(),
                                    static_cast<uint32_t>(pcsc_states.size()));
  if (rv != SCARD_S_SUCCESS) {
    return static_cast<uint32_t>(rv);
  }
  for (size_t i = 0; i < pcsc_states.size(); ++i) {
    const auto& st = pcsc_states[i];
    (*states)[i].event_state = st.dwEventState;
    const size_t atr_len = std::min<size_t>(st.cbAtr, MAX_ATR_SIZE);
    auto atr_span = base::span(st.rgbAtr).first(atr_len);
    (*states)[i].atr.assign(atr_span.begin(), atr_span.end());
  }
  return kSCardSSuccess;
#elif BUILDFLAG(IS_WIN)
  std::vector<std::wstring> wide_names;
  wide_names.reserve(states->size());
  std::vector<SCARD_READERSTATEW> pcsc_states;
  pcsc_states.reserve(states->size());
  for (const auto& s : *states) {
    wide_names.push_back(base::UTF8ToWide(s.reader));
    SCARD_READERSTATEW st = {};
    st.szReader = wide_names.back().c_str();
    st.dwCurrentState = s.current_state;
    pcsc_states.push_back(st);
  }
  LONG rv = SCardGetStatusChangeW(static_cast<SCARDCONTEXT>(context),
                                  timeout_ms, pcsc_states.data(),
                                  static_cast<DWORD>(pcsc_states.size()));
  if (rv != SCARD_S_SUCCESS) {
    return static_cast<uint32_t>(rv);
  }
  for (size_t i = 0; i < pcsc_states.size(); ++i) {
    const auto& st = pcsc_states[i];
    (*states)[i].event_state = static_cast<uint32_t>(st.dwEventState);
    const size_t atr_len =
        std::min<size_t>(st.cbAtr, std::size(st.rgbAtr));
    auto atr_span = base::span(st.rgbAtr).first(atr_len);
    (*states)[i].atr.assign(atr_span.begin(), atr_span.end());
  }
  return kSCardSSuccess;
#elif BUILDFLAG(IS_LINUX)
  if (!state_->loaded) {
    return kSCardENoService;
  }
  std::vector<PcscLiteReaderState> pcsc_states;
  pcsc_states.reserve(states->size());
  for (const auto& s : *states) {
    PcscLiteReaderState st = {};
    st.szReader = s.reader.c_str();
    st.dwCurrentState = s.current_state;
    pcsc_states.push_back(st);
  }
  PcscLiteLong rv = state_->get_status_change(
      static_cast<PcscLiteContext>(context), timeout_ms, pcsc_states.data(),
      static_cast<PcscLiteDword>(pcsc_states.size()));
  if (rv != static_cast<PcscLiteLong>(kSCardSSuccess)) {
    return static_cast<uint32_t>(rv);
  }
  for (size_t i = 0; i < pcsc_states.size(); ++i) {
    const auto& st = pcsc_states[i];
    (*states)[i].event_state = static_cast<uint32_t>(st.dwEventState);
    const size_t atr_len = std::min<size_t>(st.cbAtr, kMaxAtrSize);
    auto atr_span = base::span(st.rgbAtr).first(atr_len);
    (*states)[i].atr.assign(atr_span.begin(), atr_span.end());
  }
  return kSCardSSuccess;
#endif
}

uint32_t PcscApi::Cancel(PcscContext context) const {
#if BUILDFLAG(IS_MAC)
  return static_cast<uint32_t>(SCardCancel(static_cast<SCARDCONTEXT>(context)));
#elif BUILDFLAG(IS_WIN)
  return static_cast<uint32_t>(SCardCancel(static_cast<SCARDCONTEXT>(context)));
#elif BUILDFLAG(IS_LINUX)
  if (!state_->loaded) {
    return kSCardENoService;
  }
  return static_cast<uint32_t>(
      state_->cancel(static_cast<PcscLiteContext>(context)));
#endif
}

uint32_t PcscApi::Connect(PcscContext context,
                          const std::string& reader,
                          uint32_t share_mode,
                          uint32_t preferred_protocols,
                          PcscCard* out_card,
                          uint32_t* out_active_protocol) const {
#if BUILDFLAG(IS_MAC)
  SCARDHANDLE handle = 0;
  uint32_t active_proto = SCARD_PROTOCOL_UNDEFINED;
  int32_t rv = SCardConnect(static_cast<SCARDCONTEXT>(context), reader.c_str(),
                            share_mode, preferred_protocols, &handle,
                            &active_proto);
  if (rv == SCARD_S_SUCCESS) {
    *out_card = static_cast<PcscCard>(static_cast<uint32_t>(handle));
    *out_active_protocol = active_proto;
  }
  return static_cast<uint32_t>(rv);
#elif BUILDFLAG(IS_WIN)
  SCARDHANDLE handle = 0;
  DWORD active_proto = SCARD_PROTOCOL_UNDEFINED;
  std::wstring wide_reader = base::UTF8ToWide(reader);
  LONG rv = SCardConnectW(
      static_cast<SCARDCONTEXT>(context), wide_reader.c_str(), share_mode,
      WinProtocolsFromCanonical(preferred_protocols), &handle, &active_proto);
  if (rv == SCARD_S_SUCCESS) {
    *out_card = static_cast<PcscCard>(handle);
    *out_active_protocol = CanonicalProtocolFromWin(active_proto);
  }
  return static_cast<uint32_t>(rv);
#elif BUILDFLAG(IS_LINUX)
  if (!state_->loaded) {
    return kSCardENoService;
  }
  PcscLiteHandle handle = 0;
  PcscLiteDword active_proto = kSCardProtocolUndefined;
  PcscLiteLong rv = state_->connect(static_cast<PcscLiteContext>(context),
                                    reader.c_str(), share_mode,
                                    preferred_protocols, &handle,
                                    &active_proto);
  if (rv == static_cast<PcscLiteLong>(kSCardSSuccess)) {
    *out_card = static_cast<PcscCard>(handle);
    *out_active_protocol = static_cast<uint32_t>(active_proto);
  }
  return static_cast<uint32_t>(rv);
#endif
}

uint32_t PcscApi::Disconnect(PcscCard card, uint32_t disposition) const {
#if BUILDFLAG(IS_MAC)
  return static_cast<uint32_t>(
      SCardDisconnect(static_cast<SCARDHANDLE>(card), disposition));
#elif BUILDFLAG(IS_WIN)
  return static_cast<uint32_t>(
      SCardDisconnect(static_cast<SCARDHANDLE>(card), disposition));
#elif BUILDFLAG(IS_LINUX)
  if (!state_->loaded) {
    return kSCardENoService;
  }
  return static_cast<uint32_t>(
      state_->disconnect(static_cast<PcscLiteHandle>(card), disposition));
#endif
}

uint32_t PcscApi::Transmit(PcscCard card,
                           PcscProtocolPci pci,
                           base::span<const uint8_t> send_buf,
                           std::vector<uint8_t>* out_recv_buf) const {
  out_recv_buf->assign(kMaxApduResponseSize, 0);
#if BUILDFLAG(IS_MAC)
  LPCSCARD_IO_REQUEST send_pci = SCARD_PCI_T1;
  switch (pci) {
    case PcscProtocolPci::kT0:
      send_pci = SCARD_PCI_T0;
      break;
    case PcscProtocolPci::kT1:
      send_pci = SCARD_PCI_T1;
      break;
    case PcscProtocolPci::kRaw:
      send_pci = SCARD_PCI_RAW;
      break;
  }
  uint32_t recv_len = static_cast<uint32_t>(out_recv_buf->size());
  int32_t rv = SCardTransmit(
      static_cast<SCARDHANDLE>(card), send_pci, send_buf.data(),
      static_cast<uint32_t>(send_buf.size()), nullptr, out_recv_buf->data(),
      &recv_len);
  if (rv != SCARD_S_SUCCESS) {
    out_recv_buf->clear();
    return static_cast<uint32_t>(rv);
  }
  out_recv_buf->resize(std::min<size_t>(recv_len, out_recv_buf->size()));
  return kSCardSSuccess;
#elif BUILDFLAG(IS_WIN)
  LPCSCARD_IO_REQUEST send_pci = SCARD_PCI_T1;
  switch (pci) {
    case PcscProtocolPci::kT0:
      send_pci = SCARD_PCI_T0;
      break;
    case PcscProtocolPci::kT1:
      send_pci = SCARD_PCI_T1;
      break;
    case PcscProtocolPci::kRaw:
      send_pci = SCARD_PCI_RAW;
      break;
  }
  DWORD recv_len = static_cast<DWORD>(out_recv_buf->size());
  LONG rv = SCardTransmit(
      static_cast<SCARDHANDLE>(card), send_pci, send_buf.data(),
      static_cast<DWORD>(send_buf.size()), nullptr, out_recv_buf->data(),
      &recv_len);
  if (rv != SCARD_S_SUCCESS) {
    out_recv_buf->clear();
    return static_cast<uint32_t>(rv);
  }
  out_recv_buf->resize(std::min<size_t>(recv_len, out_recv_buf->size()));
  return kSCardSSuccess;
#elif BUILDFLAG(IS_LINUX)
  if (!state_->loaded) {
    out_recv_buf->clear();
    return kSCardENoService;
  }
  PcscLiteDword proto = kSCardProtocolT1;
  switch (pci) {
    case PcscProtocolPci::kT0:
      proto = kSCardProtocolT0;
      break;
    case PcscProtocolPci::kT1:
      proto = kSCardProtocolT1;
      break;
    case PcscProtocolPci::kRaw:
      proto = kSCardProtocolRaw;
      break;
  }
  PcscLiteIoRequest send_pci = {proto, sizeof(PcscLiteIoRequest)};
  PcscLiteDword recv_len = static_cast<PcscLiteDword>(out_recv_buf->size());
  PcscLiteLong rv = state_->transmit(
      static_cast<PcscLiteHandle>(card), &send_pci, send_buf.data(),
      static_cast<PcscLiteDword>(send_buf.size()), nullptr,
      out_recv_buf->data(), &recv_len);
  if (rv != static_cast<PcscLiteLong>(kSCardSSuccess)) {
    out_recv_buf->clear();
    return static_cast<uint32_t>(rv);
  }
  out_recv_buf->resize(std::min<size_t>(recv_len, out_recv_buf->size()));
  return kSCardSSuccess;
#endif
}

uint32_t PcscApi::Control(PcscCard card,
                          uint32_t control_code,
                          base::span<const uint8_t> send_buf,
                          std::vector<uint8_t>* out_recv_buf) const {
  out_recv_buf->assign(kMaxApduResponseSize, 0);
#if BUILDFLAG(IS_MAC)
  uint32_t bytes_returned = 0;
  int32_t rv = SCardControl(
      static_cast<SCARDHANDLE>(card), control_code, send_buf.data(),
      static_cast<uint32_t>(send_buf.size()), out_recv_buf->data(),
      static_cast<uint32_t>(out_recv_buf->size()), &bytes_returned);
  if (rv != SCARD_S_SUCCESS) {
    out_recv_buf->clear();
    return static_cast<uint32_t>(rv);
  }
  out_recv_buf->resize(std::min<size_t>(bytes_returned, out_recv_buf->size()));
  return kSCardSSuccess;
#elif BUILDFLAG(IS_WIN)
  DWORD bytes_returned = 0;
  LONG rv = SCardControl(
      static_cast<SCARDHANDLE>(card), control_code, send_buf.data(),
      static_cast<DWORD>(send_buf.size()), out_recv_buf->data(),
      static_cast<DWORD>(out_recv_buf->size()), &bytes_returned);
  if (rv != SCARD_S_SUCCESS) {
    out_recv_buf->clear();
    return static_cast<uint32_t>(rv);
  }
  out_recv_buf->resize(std::min<size_t>(bytes_returned, out_recv_buf->size()));
  return kSCardSSuccess;
#elif BUILDFLAG(IS_LINUX)
  if (!state_->loaded) {
    out_recv_buf->clear();
    return kSCardENoService;
  }
  PcscLiteDword bytes_returned = 0;
  PcscLiteLong rv = state_->control(
      static_cast<PcscLiteHandle>(card), control_code, send_buf.data(),
      static_cast<PcscLiteDword>(send_buf.size()), out_recv_buf->data(),
      static_cast<PcscLiteDword>(out_recv_buf->size()), &bytes_returned);
  if (rv != static_cast<PcscLiteLong>(kSCardSSuccess)) {
    out_recv_buf->clear();
    return static_cast<uint32_t>(rv);
  }
  out_recv_buf->resize(std::min<size_t>(bytes_returned, out_recv_buf->size()));
  return kSCardSSuccess;
#endif
}

uint32_t PcscApi::GetAttrib(PcscCard card,
                            uint32_t attr_id,
                            std::vector<uint8_t>* out_attr) const {
  out_attr->clear();
#if BUILDFLAG(IS_MAC)
  auto handle = static_cast<SCARDHANDLE>(card);
  uint32_t len = 0;
  int32_t rv = SCardGetAttrib(handle, attr_id, nullptr, &len);
  if (rv != SCARD_S_SUCCESS) {
    return static_cast<uint32_t>(rv);
  }
  out_attr->resize(len);
  if (len > 0) {
    rv = SCardGetAttrib(handle, attr_id, out_attr->data(), &len);
    if (rv != SCARD_S_SUCCESS) {
      out_attr->clear();
      return static_cast<uint32_t>(rv);
    }
    out_attr->resize(std::min<size_t>(len, out_attr->size()));
  }
  return kSCardSSuccess;
#elif BUILDFLAG(IS_WIN)
  auto handle = static_cast<SCARDHANDLE>(card);
  DWORD len = 0;
  LONG rv = SCardGetAttrib(handle, attr_id, nullptr, &len);
  if (rv != SCARD_S_SUCCESS) {
    return static_cast<uint32_t>(rv);
  }
  out_attr->resize(len);
  if (len > 0) {
    rv = SCardGetAttrib(handle, attr_id, out_attr->data(), &len);
    if (rv != SCARD_S_SUCCESS) {
      out_attr->clear();
      return static_cast<uint32_t>(rv);
    }
    out_attr->resize(std::min<size_t>(len, out_attr->size()));
  }
  return kSCardSSuccess;
#elif BUILDFLAG(IS_LINUX)
  if (!state_->loaded) {
    return kSCardENoService;
  }
  auto handle = static_cast<PcscLiteHandle>(card);
  PcscLiteDword len = 0;
  PcscLiteLong rv = state_->get_attrib(handle, attr_id, nullptr, &len);
  if (rv != static_cast<PcscLiteLong>(kSCardSSuccess)) {
    return static_cast<uint32_t>(rv);
  }
  out_attr->resize(len);
  if (len > 0) {
    rv = state_->get_attrib(handle, attr_id, out_attr->data(), &len);
    if (rv != static_cast<PcscLiteLong>(kSCardSSuccess)) {
      out_attr->clear();
      return static_cast<uint32_t>(rv);
    }
    out_attr->resize(std::min<size_t>(len, out_attr->size()));
  }
  return kSCardSSuccess;
#endif
}

uint32_t PcscApi::SetAttrib(PcscCard card,
                            uint32_t attr_id,
                            base::span<const uint8_t> attr) const {
#if BUILDFLAG(IS_MAC)
  return static_cast<uint32_t>(
      SCardSetAttrib(static_cast<SCARDHANDLE>(card), attr_id, attr.data(),
                     static_cast<uint32_t>(attr.size())));
#elif BUILDFLAG(IS_WIN)
  return static_cast<uint32_t>(
      SCardSetAttrib(static_cast<SCARDHANDLE>(card), attr_id, attr.data(),
                     static_cast<DWORD>(attr.size())));
#elif BUILDFLAG(IS_LINUX)
  if (!state_->loaded) {
    return kSCardENoService;
  }
  return static_cast<uint32_t>(
      state_->set_attrib(static_cast<PcscLiteHandle>(card), attr_id,
                         attr.data(), static_cast<PcscLiteDword>(attr.size())));
#endif
}

uint32_t PcscApi::Status(PcscCard card,
                         std::string* out_reader_name,
                         uint32_t* out_state,
                         uint32_t* out_protocol,
                         std::vector<uint8_t>* out_atr) const {
  out_reader_name->clear();
  out_atr->assign(kMaxAtrSize, 0);
#if BUILDFLAG(IS_MAC)
  auto handle = static_cast<SCARDHANDLE>(card);
  uint32_t reader_len = 0;
  uint32_t state = 0;
  uint32_t protocol = 0;
  uint32_t atr_len = static_cast<uint32_t>(out_atr->size());
  int32_t rv = SCardStatus(handle, nullptr, &reader_len, &state, &protocol,
                           out_atr->data(), &atr_len);
  if (rv != SCARD_S_SUCCESS) {
    return static_cast<uint32_t>(rv);
  }
  std::vector<char> reader_buf(reader_len);
  atr_len = static_cast<uint32_t>(out_atr->size());
  rv = SCardStatus(handle, reader_buf.empty() ? nullptr : reader_buf.data(),
                   &reader_len, &state, &protocol, out_atr->data(), &atr_len);
  if (rv != SCARD_S_SUCCESS) {
    return static_cast<uint32_t>(rv);
  }
  reader_buf.resize(std::min<size_t>(reader_len, reader_buf.size()));
  out_atr->resize(std::min<size_t>(atr_len, out_atr->size()));
  auto readers = ParsePcscMultiString(reader_buf);
  if (!readers.empty()) {
    *out_reader_name = std::move(readers.front());
  }
  *out_state = state;
  *out_protocol = protocol;
  return kSCardSSuccess;
#elif BUILDFLAG(IS_WIN)
  auto handle = static_cast<SCARDHANDLE>(card);
  DWORD reader_len = 0;
  DWORD state = 0;
  DWORD protocol = 0;
  out_atr->assign(36, 0);
  DWORD atr_len = static_cast<DWORD>(out_atr->size());
  LONG rv = SCardStatusW(handle, nullptr, &reader_len, &state, &protocol,
                         out_atr->data(), &atr_len);
  if (rv != SCARD_S_SUCCESS) {
    return static_cast<uint32_t>(rv);
  }
  std::vector<wchar_t> reader_buf(reader_len);
  atr_len = static_cast<DWORD>(out_atr->size());
  rv = SCardStatusW(handle, reader_buf.empty() ? nullptr : reader_buf.data(),
                    &reader_len, &state, &protocol, out_atr->data(), &atr_len);
  if (rv != SCARD_S_SUCCESS) {
    return static_cast<uint32_t>(rv);
  }
  reader_buf.resize(std::min<size_t>(reader_len, reader_buf.size()));
  out_atr->resize(std::min<size_t>(atr_len, out_atr->size()));
  auto readers = ParsePcscMultiStringW(reader_buf);
  if (!readers.empty()) {
    *out_reader_name = std::move(readers.front());
  }
  *out_state = CanonicalStateFromWin(state);
  *out_protocol = CanonicalProtocolFromWin(protocol);
  return kSCardSSuccess;
#elif BUILDFLAG(IS_LINUX)
  if (!state_->loaded) {
    return kSCardENoService;
  }
  auto handle = static_cast<PcscLiteHandle>(card);
  PcscLiteDword reader_len = 0;
  PcscLiteDword state = 0;
  PcscLiteDword protocol = 0;
  PcscLiteDword atr_len = static_cast<PcscLiteDword>(out_atr->size());
  PcscLiteLong rv = state_->status(handle, nullptr, &reader_len, &state,
                                   &protocol, out_atr->data(), &atr_len);
  if (rv != static_cast<PcscLiteLong>(kSCardSSuccess)) {
    return static_cast<uint32_t>(rv);
  }
  std::vector<char> reader_buf(reader_len);
  atr_len = static_cast<PcscLiteDword>(out_atr->size());
  rv = state_->status(handle, reader_buf.empty() ? nullptr : reader_buf.data(),
                      &reader_len, &state, &protocol, out_atr->data(),
                      &atr_len);
  if (rv != static_cast<PcscLiteLong>(kSCardSSuccess)) {
    return static_cast<uint32_t>(rv);
  }
  reader_buf.resize(std::min<size_t>(reader_len, reader_buf.size()));
  out_atr->resize(std::min<size_t>(atr_len, out_atr->size()));
  auto readers = ParsePcscMultiString(reader_buf);
  if (!readers.empty()) {
    *out_reader_name = std::move(readers.front());
  }
  *out_state = static_cast<uint32_t>(state);
  *out_protocol = static_cast<uint32_t>(protocol);
  return kSCardSSuccess;
#endif
}

uint32_t PcscApi::BeginTransaction(PcscCard card) const {
#if BUILDFLAG(IS_MAC)
  return static_cast<uint32_t>(
      SCardBeginTransaction(static_cast<SCARDHANDLE>(card)));
#elif BUILDFLAG(IS_WIN)
  return static_cast<uint32_t>(
      SCardBeginTransaction(static_cast<SCARDHANDLE>(card)));
#elif BUILDFLAG(IS_LINUX)
  if (!state_->loaded) {
    return kSCardENoService;
  }
  return static_cast<uint32_t>(
      state_->begin_transaction(static_cast<PcscLiteHandle>(card)));
#endif
}

uint32_t PcscApi::EndTransaction(PcscCard card, uint32_t disposition) const {
#if BUILDFLAG(IS_MAC)
  return static_cast<uint32_t>(
      SCardEndTransaction(static_cast<SCARDHANDLE>(card), disposition));
#elif BUILDFLAG(IS_WIN)
  return static_cast<uint32_t>(
      SCardEndTransaction(static_cast<SCARDHANDLE>(card), disposition));
#elif BUILDFLAG(IS_LINUX)
  if (!state_->loaded) {
    return kSCardENoService;
  }
  return static_cast<uint32_t>(
      state_->end_transaction(static_cast<PcscLiteHandle>(card), disposition));
#endif
}

}  // namespace smart_card::pcsc

// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/smart_card/mac/mac_smart_card_context_factory.h"

#include <PCSC/winscard.h>

#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/containers/span.h"
#include "base/functional/bind.h"
#include "base/memory/ref_counted.h"
#include "base/memory/scoped_refptr.h"
#include "base/memory/weak_ptr.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/task_traits.h"
#include "base/task/thread_pool.h"
#include "base/time/time.h"
#include "chrome/browser/smart_card/mac/mac_smart_card_util.h"
#include "mojo/public/cpp/bindings/pending_associated_remote.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "mojo/public/cpp/bindings/self_owned_associated_receiver.h"
#include "mojo/public/cpp/bindings/self_owned_receiver.h"

namespace smart_card::mac {

namespace {

// Extended-length ISO 7816-4 APDU response: up to 65536 data bytes + 2 SW bytes.
constexpr uint32_t kMaxApduResponseSize = 65538;

constexpr base::TaskTraits kPcscTaskTraits = {
    base::MayBlock(), base::TaskPriority::USER_VISIBLE,
    base::TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN};

// Ref-counted owner of a PC/SC SCARDCONTEXT. Ensures SCardReleaseContext() is
// called only after all in-flight operations and child connections finish.
class ContextHandle : public base::RefCountedThreadSafe<ContextHandle> {
 public:
  explicit ContextHandle(SCARDCONTEXT handle) : handle_(handle) {}

  SCARDCONTEXT handle() const { return handle_; }

 private:
  friend class base::RefCountedThreadSafe<ContextHandle>;

  ~ContextHandle() {
    base::ThreadPool::PostTask(
        FROM_HERE, kPcscTaskTraits,
        base::BindOnce([](SCARDCONTEXT ctx) { SCardReleaseContext(ctx); },
                       handle_));
  }

  const SCARDCONTEXT handle_;
};

// Ref-counted owner of a PC/SC SCARDHANDLE. All mutations of |disconnected_|
// and PC/SC calls on |handle_| are serialized on the owning connection's
// SequencedTaskRunner.
class CardHandle : public base::RefCountedThreadSafe<CardHandle> {
 public:
  CardHandle(scoped_refptr<ContextHandle> context, SCARDHANDLE handle)
      : context_(std::move(context)), handle_(handle) {}

  SCARDHANDLE handle() const { return handle_; }
  bool is_disconnected() const { return disconnected_; }

  int32_t Disconnect(uint32_t disposition) {
    if (disconnected_) {
      return SCARD_S_SUCCESS;
    }
    disconnected_ = true;
    return SCardDisconnect(handle_, disposition);
  }

 private:
  friend class base::RefCountedThreadSafe<CardHandle>;

  ~CardHandle() = default;

  scoped_refptr<ContextHandle> context_;
  const SCARDHANDLE handle_;
  bool disconnected_ = false;
};

class MacSmartCardTransaction : public device::mojom::SmartCardTransaction {
 public:
  MacSmartCardTransaction(
      scoped_refptr<CardHandle> card,
      scoped_refptr<base::SequencedTaskRunner> card_task_runner)
      : card_(std::move(card)),
        card_task_runner_(std::move(card_task_runner)) {}

  ~MacSmartCardTransaction() override {
    if (!ended_) {
      card_task_runner_->PostTask(
          FROM_HERE, base::BindOnce(
                         [](scoped_refptr<CardHandle> card) {
                           if (!card->is_disconnected()) {
                             SCardEndTransaction(card->handle(),
                                                 SCARD_LEAVE_CARD);
                           }
                         },
                         std::move(card_)));
    }
  }

  void EndTransaction(device::mojom::SmartCardDisposition disposition,
                      EndTransactionCallback callback) override {
    if (ended_) {
      std::move(callback).Run(device::mojom::SmartCardResult::NewError(
          device::mojom::SmartCardError::kNotTransacted));
      return;
    }
    ended_ = true;
    const uint32_t pcsc_disposition = PcscDispositionFromMojo(disposition);
    card_task_runner_->PostTaskAndReplyWithResult(
        FROM_HERE,
        base::BindOnce(
            [](scoped_refptr<CardHandle> card, uint32_t disp) -> int32_t {
              if (card->is_disconnected()) {
                return static_cast<int32_t>(SCARD_E_INVALID_HANDLE);
              }
              return SCardEndTransaction(card->handle(), disp);
            },
            card_, pcsc_disposition),
        base::BindOnce(
            [](EndTransactionCallback cb, int32_t rv) {
              if (rv == SCARD_S_SUCCESS) {
                std::move(cb).Run(device::mojom::SmartCardResult::NewSuccess(
                    device::mojom::SmartCardSuccess::kOk));
              } else {
                std::move(cb).Run(device::mojom::SmartCardResult::NewError(
                    SmartCardErrorFromPcscResult(rv)));
              }
            },
            std::move(callback)));
  }

 private:
  scoped_refptr<CardHandle> card_;
  scoped_refptr<base::SequencedTaskRunner> card_task_runner_;
  bool ended_ = false;
};

class MacSmartCardConnection : public device::mojom::SmartCardConnection {
 public:
  MacSmartCardConnection(
      scoped_refptr<ContextHandle> context,
      SCARDHANDLE handle,
      mojo::PendingRemote<device::mojom::SmartCardConnectionWatcher> watcher)
      : card_(base::MakeRefCounted<CardHandle>(std::move(context), handle)),
        card_task_runner_(
            base::ThreadPool::CreateSequencedTaskRunner(kPcscTaskTraits)) {
    if (watcher.is_valid()) {
      watcher_.Bind(std::move(watcher));
      watcher_.set_disconnect_handler(
          base::BindOnce(&MacSmartCardConnection::OnWatcherDisconnected,
                         base::Unretained(this)));
    }
  }

  ~MacSmartCardConnection() override {
    card_task_runner_->PostTask(
        FROM_HERE, base::BindOnce(
                       [](scoped_refptr<CardHandle> card) {
                         card->Disconnect(SCARD_LEAVE_CARD);
                       },
                       card_));
  }

  void SetReceiver(
      mojo::SelfOwnedReceiverRef<device::mojom::SmartCardConnection> receiver) {
    receiver_ = std::move(receiver);
  }

  void Disconnect(device::mojom::SmartCardDisposition disposition,
                  DisconnectCallback callback) override {
    const uint32_t pcsc_disposition = PcscDispositionFromMojo(disposition);
    card_task_runner_->PostTaskAndReplyWithResult(
        FROM_HERE,
        base::BindOnce(
            [](scoped_refptr<CardHandle> card, uint32_t disp) -> int32_t {
              return card->Disconnect(disp);
            },
            card_, pcsc_disposition),
        base::BindOnce(
            [](DisconnectCallback cb, int32_t rv) {
              if (rv == SCARD_S_SUCCESS) {
                std::move(cb).Run(device::mojom::SmartCardResult::NewSuccess(
                    device::mojom::SmartCardSuccess::kOk));
              } else {
                std::move(cb).Run(device::mojom::SmartCardResult::NewError(
                    SmartCardErrorFromPcscResult(rv)));
              }
            },
            std::move(callback)));
  }

  void Transmit(device::mojom::SmartCardProtocol protocol,
                const std::vector<uint8_t>& data,
                TransmitCallback callback) override {
    NotifyConnectionUsed();

    LPCSCARD_IO_REQUEST send_pci = nullptr;
    switch (protocol) {
      case device::mojom::SmartCardProtocol::kT0:
        send_pci = SCARD_PCI_T0;
        break;
      case device::mojom::SmartCardProtocol::kT1:
        send_pci = SCARD_PCI_T1;
        break;
      case device::mojom::SmartCardProtocol::kRaw:
        send_pci = SCARD_PCI_RAW;
        break;
      case device::mojom::SmartCardProtocol::kUndefined:
        std::move(callback).Run(device::mojom::SmartCardDataResult::NewError(
            device::mojom::SmartCardError::kInvalidParameter));
        return;
    }

    card_task_runner_->PostTaskAndReplyWithResult(
        FROM_HERE,
        base::BindOnce(
            [](scoped_refptr<CardHandle> card, LPCSCARD_IO_REQUEST pci,
               std::vector<uint8_t> send_buf)
                -> device::mojom::SmartCardDataResultPtr {
              if (card->is_disconnected()) {
                return device::mojom::SmartCardDataResult::NewError(
                    device::mojom::SmartCardError::kInvalidHandle);
              }
              std::vector<uint8_t> recv_buf(kMaxApduResponseSize);
              uint32_t recv_len = static_cast<uint32_t>(recv_buf.size());
              int32_t rv = SCardTransmit(
                  card->handle(), pci, send_buf.data(),
                  static_cast<uint32_t>(send_buf.size()), nullptr,
                  recv_buf.data(), &recv_len);
              if (rv != SCARD_S_SUCCESS) {
                return device::mojom::SmartCardDataResult::NewError(
                    SmartCardErrorFromPcscResult(rv));
              }
              recv_buf.resize(std::min<size_t>(recv_len, recv_buf.size()));
              return device::mojom::SmartCardDataResult::NewData(
                  std::move(recv_buf));
            },
            card_, send_pci, data),
        std::move(callback));
  }

  void Control(uint32_t control_code,
               const std::vector<uint8_t>& data,
               ControlCallback callback) override {
    NotifyConnectionUsed();

    card_task_runner_->PostTaskAndReplyWithResult(
        FROM_HERE,
        base::BindOnce(
            [](scoped_refptr<CardHandle> card, uint32_t code,
               std::vector<uint8_t> send_buf)
                -> device::mojom::SmartCardDataResultPtr {
              if (card->is_disconnected()) {
                return device::mojom::SmartCardDataResult::NewError(
                    device::mojom::SmartCardError::kInvalidHandle);
              }
              std::vector<uint8_t> recv_buf(kMaxApduResponseSize);
              uint32_t bytes_returned = 0;
              int32_t rv = SCardControl(
                  card->handle(), code, send_buf.data(),
                  static_cast<uint32_t>(send_buf.size()), recv_buf.data(),
                  static_cast<uint32_t>(recv_buf.size()), &bytes_returned);
              if (rv != SCARD_S_SUCCESS) {
                return device::mojom::SmartCardDataResult::NewError(
                    SmartCardErrorFromPcscResult(rv));
              }
              recv_buf.resize(
                  std::min<size_t>(bytes_returned, recv_buf.size()));
              return device::mojom::SmartCardDataResult::NewData(
                  std::move(recv_buf));
            },
            card_, control_code, data),
        std::move(callback));
  }

  void GetAttrib(uint32_t id, GetAttribCallback callback) override {
    NotifyConnectionUsed();

    card_task_runner_->PostTaskAndReplyWithResult(
        FROM_HERE,
        base::BindOnce(
            [](scoped_refptr<CardHandle> card, uint32_t attr_id)
                -> device::mojom::SmartCardDataResultPtr {
              if (card->is_disconnected()) {
                return device::mojom::SmartCardDataResult::NewError(
                    device::mojom::SmartCardError::kInvalidHandle);
              }
              uint32_t len = 0;
              int32_t rv = SCardGetAttrib(card->handle(), attr_id, nullptr, &len);
              if (rv != SCARD_S_SUCCESS) {
                return device::mojom::SmartCardDataResult::NewError(
                    SmartCardErrorFromPcscResult(rv));
              }
              std::vector<uint8_t> attr(len);
              if (len > 0) {
                rv = SCardGetAttrib(card->handle(), attr_id, attr.data(), &len);
                if (rv != SCARD_S_SUCCESS) {
                  return device::mojom::SmartCardDataResult::NewError(
                      SmartCardErrorFromPcscResult(rv));
                }
                attr.resize(std::min<size_t>(len, attr.size()));
              }
              return device::mojom::SmartCardDataResult::NewData(
                  std::move(attr));
            },
            card_, id),
        std::move(callback));
  }

  void SetAttrib(uint32_t id,
                 const std::vector<uint8_t>& data,
                 SetAttribCallback callback) override {
    NotifyConnectionUsed();

    card_task_runner_->PostTaskAndReplyWithResult(
        FROM_HERE,
        base::BindOnce(
            [](scoped_refptr<CardHandle> card, uint32_t attr_id,
               std::vector<uint8_t> attr) -> device::mojom::SmartCardResultPtr {
              if (card->is_disconnected()) {
                return device::mojom::SmartCardResult::NewError(
                    device::mojom::SmartCardError::kInvalidHandle);
              }
              int32_t rv = SCardSetAttrib(card->handle(), attr_id, attr.data(),
                                          static_cast<uint32_t>(attr.size()));
              if (rv != SCARD_S_SUCCESS) {
                return device::mojom::SmartCardResult::NewError(
                    SmartCardErrorFromPcscResult(rv));
              }
              return device::mojom::SmartCardResult::NewSuccess(
                  device::mojom::SmartCardSuccess::kOk);
            },
            card_, id, data),
        std::move(callback));
  }

  void Status(StatusCallback callback) override {
    NotifyConnectionUsed();

    card_task_runner_->PostTaskAndReplyWithResult(
        FROM_HERE,
        base::BindOnce(
            [](scoped_refptr<CardHandle> card)
                -> device::mojom::SmartCardStatusResultPtr {
              if (card->is_disconnected()) {
                return device::mojom::SmartCardStatusResult::NewError(
                    device::mojom::SmartCardError::kInvalidHandle);
              }
              uint32_t reader_len = 0;
              uint32_t state = 0;
              uint32_t protocol = 0;
              uint32_t atr_len = MAX_ATR_SIZE;
              std::vector<uint8_t> atr(MAX_ATR_SIZE);
              int32_t rv = SCardStatus(card->handle(), nullptr, &reader_len,
                                       &state, &protocol, atr.data(), &atr_len);
              if (rv != SCARD_S_SUCCESS) {
                return device::mojom::SmartCardStatusResult::NewError(
                    SmartCardErrorFromPcscResult(rv));
              }
              std::vector<char> reader_buf(reader_len);
              atr_len = static_cast<uint32_t>(atr.size());
              rv = SCardStatus(card->handle(),
                               reader_buf.empty() ? nullptr : reader_buf.data(),
                               &reader_len, &state, &protocol, atr.data(),
                               &atr_len);
              if (rv != SCARD_S_SUCCESS) {
                return device::mojom::SmartCardStatusResult::NewError(
                    SmartCardErrorFromPcscResult(rv));
              }
              reader_buf.resize(
                  std::min<size_t>(reader_len, reader_buf.size()));
              atr.resize(std::min<size_t>(atr_len, atr.size()));
              auto readers = ParsePcscMultiString(reader_buf);
              std::string reader_name =
                  readers.empty() ? std::string() : std::move(readers.front());
              return device::mojom::SmartCardStatusResult::NewStatus(
                  device::mojom::SmartCardStatus::New(
                      std::move(reader_name),
                      MojoConnectionStateFromPcsc(state),
                      MojoProtocolFromPcsc(protocol), std::move(atr)));
            },
            card_),
        std::move(callback));
  }

  void BeginTransaction(BeginTransactionCallback callback) override {
    NotifyConnectionUsed();

    card_task_runner_->PostTaskAndReplyWithResult(
        FROM_HERE,
        base::BindOnce(
            [](scoped_refptr<CardHandle> card) -> int32_t {
              if (card->is_disconnected()) {
                return static_cast<int32_t>(SCARD_E_INVALID_HANDLE);
              }
              return SCardBeginTransaction(card->handle());
            },
            card_),
        base::BindOnce(&MacSmartCardConnection::OnBeginTransactionDone,
                       weak_factory_.GetWeakPtr(), std::move(callback)));
  }

 private:
  void NotifyConnectionUsed() {
    if (watcher_.is_bound()) {
      watcher_->NotifyConnectionUsed();
    }
  }

  void OnWatcherDisconnected() {
    card_task_runner_->PostTask(
        FROM_HERE, base::BindOnce(
                       [](scoped_refptr<CardHandle> card) {
                         card->Disconnect(SCARD_LEAVE_CARD);
                       },
                       card_));
    if (receiver_) {
      receiver_->Close();
    }
  }

  void OnBeginTransactionDone(BeginTransactionCallback callback, int32_t rv) {
    if (rv != SCARD_S_SUCCESS) {
      std::move(callback).Run(device::mojom::SmartCardTransactionResult::NewError(
          SmartCardErrorFromPcscResult(rv)));
      return;
    }
    mojo::PendingAssociatedRemote<device::mojom::SmartCardTransaction>
        tx_remote;
    mojo::MakeSelfOwnedAssociatedReceiver(
        std::make_unique<MacSmartCardTransaction>(card_, card_task_runner_),
        tx_remote.InitWithNewEndpointAndPassReceiver());
    std::move(callback).Run(
        device::mojom::SmartCardTransactionResult::NewTransaction(
            std::move(tx_remote)));
  }

  scoped_refptr<CardHandle> card_;
  scoped_refptr<base::SequencedTaskRunner> card_task_runner_;
  mojo::Remote<device::mojom::SmartCardConnectionWatcher> watcher_;
  mojo::SelfOwnedReceiverRef<device::mojom::SmartCardConnection> receiver_;
  base::WeakPtrFactory<MacSmartCardConnection> weak_factory_{this};
};

class MacSmartCardContext : public device::mojom::SmartCardContext {
 public:
  explicit MacSmartCardContext(SCARDCONTEXT context)
      : context_(base::MakeRefCounted<ContextHandle>(context)) {}

  ~MacSmartCardContext() override {
    // Unblock any in-flight SCardGetStatusChange() so it releases its ref to
    // |context_| promptly.
    base::ThreadPool::PostTask(
        FROM_HERE, kPcscTaskTraits,
        base::BindOnce(
            [](scoped_refptr<ContextHandle> ctx) {
              SCardCancel(ctx->handle());
            },
            context_));
  }

  void ListReaders(ListReadersCallback callback) override {
    base::ThreadPool::PostTaskAndReplyWithResult(
        FROM_HERE, kPcscTaskTraits,
        base::BindOnce(
            [](scoped_refptr<ContextHandle> ctx)
                -> device::mojom::SmartCardListReadersResultPtr {
              uint32_t len = 0;
              int32_t rv =
                  SCardListReaders(ctx->handle(), nullptr, nullptr, &len);
              if (rv != SCARD_S_SUCCESS) {
                return device::mojom::SmartCardListReadersResult::NewError(
                    SmartCardErrorFromPcscResult(rv));
              }
              if (len == 0) {
                return device::mojom::SmartCardListReadersResult::NewReaders(
                    {});
              }
              std::vector<char> buf(len);
              rv = SCardListReaders(ctx->handle(), nullptr, buf.data(), &len);
              if (rv != SCARD_S_SUCCESS) {
                return device::mojom::SmartCardListReadersResult::NewError(
                    SmartCardErrorFromPcscResult(rv));
              }
              buf.resize(std::min<size_t>(len, buf.size()));
              return device::mojom::SmartCardListReadersResult::NewReaders(
                  ParsePcscMultiString(buf));
            },
            context_),
        std::move(callback));
  }

  void GetStatusChange(
      base::TimeDelta timeout,
      std::vector<device::mojom::SmartCardReaderStateInPtr> reader_states,
      GetStatusChangeCallback callback) override {
    if (reader_states.empty()) {
      std::move(callback).Run(
          device::mojom::SmartCardStatusChangeResult::NewReaderStates({}));
      return;
    }

    uint32_t pcsc_timeout = INFINITE;
    if (!timeout.is_max()) {
      if (timeout.is_negative()) {
        pcsc_timeout = 0;
      } else {
        int64_t ms = timeout.InMilliseconds();
        pcsc_timeout = (ms >= static_cast<int64_t>(INFINITE))
                           ? INFINITE
                           : static_cast<uint32_t>(ms);
      }
    }

    base::ThreadPool::PostTaskAndReplyWithResult(
        FROM_HERE, kPcscTaskTraits,
        base::BindOnce(
            [](scoped_refptr<ContextHandle> ctx, uint32_t timeout_ms,
               std::vector<device::mojom::SmartCardReaderStateInPtr> states_in)
                -> device::mojom::SmartCardStatusChangeResultPtr {
              std::vector<std::string> names;
              names.reserve(states_in.size());
              std::vector<SCARD_READERSTATE> pcsc_states;
              pcsc_states.reserve(states_in.size());

              for (const auto& state_in : states_in) {
                names.push_back(state_in->reader);
                SCARD_READERSTATE st = {};
                st.szReader = names.back().c_str();
                st.dwCurrentState = PcscReaderStateFlagsFromMojo(
                    *state_in->current_state, state_in->current_count);
                pcsc_states.push_back(st);
              }

              int32_t rv = SCardGetStatusChange(
                  ctx->handle(), timeout_ms, pcsc_states.data(),
                  static_cast<uint32_t>(pcsc_states.size()));
              if (rv != SCARD_S_SUCCESS) {
                return device::mojom::SmartCardStatusChangeResult::NewError(
                    SmartCardErrorFromPcscResult(rv));
              }

              std::vector<device::mojom::SmartCardReaderStateOutPtr> states_out;
              states_out.reserve(pcsc_states.size());
              for (size_t i = 0; i < pcsc_states.size(); ++i) {
                const auto& st = pcsc_states[i];
                const size_t atr_len =
                    std::min<size_t>(st.cbAtr, MAX_ATR_SIZE);
                auto atr_span = base::span(st.rgbAtr).first(atr_len);
                std::vector<uint8_t> atr(atr_span.begin(), atr_span.end());
                states_out.push_back(device::mojom::SmartCardReaderStateOut::New(
                    names[i], MojoReaderStateFlagsFromPcsc(st.dwEventState),
                    MojoEventCountFromPcsc(st.dwEventState), std::move(atr)));
              }
              return device::mojom::SmartCardStatusChangeResult::
                  NewReaderStates(std::move(states_out));
            },
            context_, pcsc_timeout, std::move(reader_states)),
        std::move(callback));
  }

  void Cancel(CancelCallback callback) override {
    base::ThreadPool::PostTaskAndReplyWithResult(
        FROM_HERE, kPcscTaskTraits,
        base::BindOnce(
            [](scoped_refptr<ContextHandle> ctx) -> int32_t {
              return SCardCancel(ctx->handle());
            },
            context_),
        base::BindOnce(
            [](CancelCallback cb, int32_t rv) {
              if (rv == SCARD_S_SUCCESS) {
                std::move(cb).Run(device::mojom::SmartCardResult::NewSuccess(
                    device::mojom::SmartCardSuccess::kOk));
              } else {
                std::move(cb).Run(device::mojom::SmartCardResult::NewError(
                    SmartCardErrorFromPcscResult(rv)));
              }
            },
            std::move(callback)));
  }

  void Connect(
      const std::string& reader,
      device::mojom::SmartCardShareMode share_mode,
      device::mojom::SmartCardProtocolsPtr preferred_protocols,
      mojo::PendingRemote<device::mojom::SmartCardConnectionWatcher>
          connection_watcher,
      ConnectCallback callback) override {
    const uint32_t pcsc_share_mode = PcscShareModeFromMojo(share_mode);
    const uint32_t pcsc_protocols =
        preferred_protocols ? PcscProtocolsFromMojo(*preferred_protocols)
                            : SCARD_PROTOCOL_UNDEFINED;

    struct ConnectOutcome {
      int32_t rv = 0;
      SCARDHANDLE handle = 0;
      uint32_t active_protocol = SCARD_PROTOCOL_UNDEFINED;
    };

    base::ThreadPool::PostTaskAndReplyWithResult(
        FROM_HERE, kPcscTaskTraits,
        base::BindOnce(
            [](scoped_refptr<ContextHandle> ctx, std::string reader_name,
               uint32_t share, uint32_t protos) -> ConnectOutcome {
              ConnectOutcome out;
              out.rv = SCardConnect(ctx->handle(), reader_name.c_str(), share,
                                    protos, &out.handle, &out.active_protocol);
              return out;
            },
            context_, reader, pcsc_share_mode, pcsc_protocols),
        base::BindOnce(
            [](scoped_refptr<ContextHandle> ctx,
               mojo::PendingRemote<device::mojom::SmartCardConnectionWatcher>
                   watcher,
               ConnectCallback cb, ConnectOutcome out) {
              if (out.rv != SCARD_S_SUCCESS) {
                std::move(cb).Run(
                    device::mojom::SmartCardConnectResult::NewError(
                        SmartCardErrorFromPcscResult(out.rv)));
                return;
              }
              mojo::PendingRemote<device::mojom::SmartCardConnection>
                  conn_remote;
              auto conn = std::make_unique<MacSmartCardConnection>(
                  std::move(ctx), out.handle, std::move(watcher));
              auto* conn_ptr = conn.get();
              auto receiver = mojo::MakeSelfOwnedReceiver(
                  std::move(conn), conn_remote.InitWithNewPipeAndPassReceiver());
              conn_ptr->SetReceiver(std::move(receiver));
              std::move(cb).Run(
                  device::mojom::SmartCardConnectResult::NewSuccess(
                      device::mojom::SmartCardConnectSuccess::New(
                          std::move(conn_remote),
                          MojoProtocolFromPcsc(out.active_protocol))));
            },
            context_, std::move(connection_watcher), std::move(callback)));
  }

 private:
  scoped_refptr<ContextHandle> context_;
};

class MacSmartCardContextFactory
    : public device::mojom::SmartCardContextFactory {
 public:
  MacSmartCardContextFactory() = default;
  ~MacSmartCardContextFactory() override = default;

  void CreateContext(CreateContextCallback callback) override {
    struct EstablishOutcome {
      int32_t rv = 0;
      SCARDCONTEXT handle = 0;
    };

    base::ThreadPool::PostTaskAndReplyWithResult(
        FROM_HERE, kPcscTaskTraits,
        base::BindOnce([]() -> EstablishOutcome {
          EstablishOutcome out;
          out.rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, nullptr, nullptr,
                                         &out.handle);
          return out;
        }),
        base::BindOnce(
            [](CreateContextCallback cb, EstablishOutcome out) {
              if (out.rv != SCARD_S_SUCCESS) {
                std::move(cb).Run(
                    device::mojom::SmartCardCreateContextResult::NewError(
                        SmartCardErrorFromPcscResult(out.rv)));
                return;
              }
              mojo::PendingRemote<device::mojom::SmartCardContext>
                  context_remote;
              mojo::MakeSelfOwnedReceiver(
                  std::make_unique<MacSmartCardContext>(out.handle),
                  context_remote.InitWithNewPipeAndPassReceiver());
              std::move(cb).Run(
                  device::mojom::SmartCardCreateContextResult::NewContext(
                      std::move(context_remote)));
            },
            std::move(callback)));
  }
};

}  // namespace

mojo::PendingRemote<device::mojom::SmartCardContextFactory>
CreateMacSmartCardContextFactory() {
  mojo::PendingRemote<device::mojom::SmartCardContextFactory> remote;
  mojo::MakeSelfOwnedReceiver(std::make_unique<MacSmartCardContextFactory>(),
                              remote.InitWithNewPipeAndPassReceiver());
  return remote;
}

}  // namespace smart_card::mac

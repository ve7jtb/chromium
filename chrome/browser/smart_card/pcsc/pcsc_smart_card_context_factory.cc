// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/smart_card/pcsc/pcsc_smart_card_context_factory.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/functional/bind.h"
#include "base/memory/ref_counted.h"
#include "base/memory/scoped_refptr.h"
#include "base/memory/weak_ptr.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/task_traits.h"
#include "base/task/thread_pool.h"
#include "base/time/time.h"
#include "chrome/browser/smart_card/pcsc/pcsc_api.h"
#include "chrome/browser/smart_card/pcsc/pcsc_constants.h"
#include "chrome/browser/smart_card/pcsc/pcsc_smart_card_util.h"
#include "mojo/public/cpp/bindings/pending_associated_remote.h"
#include "mojo/public/cpp/bindings/remote.h"
#include "mojo/public/cpp/bindings/self_owned_associated_receiver.h"
#include "mojo/public/cpp/bindings/self_owned_receiver.h"

namespace smart_card::pcsc {

namespace {

constexpr base::TaskTraits kPcscTaskTraits = {
    base::MayBlock(), base::TaskPriority::USER_VISIBLE,
    base::TaskShutdownBehavior::CONTINUE_ON_SHUTDOWN};

// Ref-counted owner of a PC/SC SCARDCONTEXT. Ensures SCardReleaseContext() is
// called only after all in-flight operations and child connections finish.
class ContextHandle : public base::RefCountedThreadSafe<ContextHandle> {
 public:
  explicit ContextHandle(PcscContext handle) : handle_(handle) {}

  PcscContext handle() const { return handle_; }

 private:
  friend class base::RefCountedThreadSafe<ContextHandle>;

  ~ContextHandle() {
    base::ThreadPool::PostTask(
        FROM_HERE, kPcscTaskTraits,
        base::BindOnce(
            [](PcscContext ctx) { PcscApi::Get().ReleaseContext(ctx); },
            handle_));
  }

  const PcscContext handle_;
};

// Ref-counted owner of a PC/SC SCARDHANDLE. All mutations of |disconnected_|
// and PC/SC calls on |handle_| are serialized on the owning connection's
// SequencedTaskRunner.
class CardHandle : public base::RefCountedThreadSafe<CardHandle> {
 public:
  CardHandle(scoped_refptr<ContextHandle> context, PcscCard handle)
      : context_(std::move(context)), handle_(handle) {}

  PcscCard handle() const { return handle_; }
  bool is_disconnected() const { return disconnected_; }

  uint32_t Disconnect(uint32_t disposition) {
    if (disconnected_) {
      return kSCardSSuccess;
    }
    disconnected_ = true;
    return PcscApi::Get().Disconnect(handle_, disposition);
  }

 private:
  friend class base::RefCountedThreadSafe<CardHandle>;

  ~CardHandle() = default;

  scoped_refptr<ContextHandle> context_;
  const PcscCard handle_;
  bool disconnected_ = false;
};

class PcscSmartCardTransaction : public device::mojom::SmartCardTransaction {
 public:
  PcscSmartCardTransaction(
      scoped_refptr<CardHandle> card,
      scoped_refptr<base::SequencedTaskRunner> card_task_runner)
      : card_(std::move(card)),
        card_task_runner_(std::move(card_task_runner)) {}

  ~PcscSmartCardTransaction() override {
    if (!ended_) {
      card_task_runner_->PostTask(
          FROM_HERE, base::BindOnce(
                         [](scoped_refptr<CardHandle> card) {
                           if (!card->is_disconnected()) {
                             PcscApi::Get().EndTransaction(card->handle(),
                                                           kSCardLeaveCard);
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
            [](scoped_refptr<CardHandle> card, uint32_t disp) -> uint32_t {
              if (card->is_disconnected()) {
                return kSCardEInvalidHandle;
              }
              return PcscApi::Get().EndTransaction(card->handle(), disp);
            },
            card_, pcsc_disposition),
        base::BindOnce(
            [](EndTransactionCallback cb, uint32_t rv) {
              if (rv == kSCardSSuccess) {
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

class PcscSmartCardConnection : public device::mojom::SmartCardConnection {
 public:
  PcscSmartCardConnection(
      scoped_refptr<ContextHandle> context,
      PcscCard handle,
      mojo::PendingRemote<device::mojom::SmartCardConnectionWatcher> watcher)
      : card_(base::MakeRefCounted<CardHandle>(std::move(context), handle)),
        card_task_runner_(
            base::ThreadPool::CreateSequencedTaskRunner(kPcscTaskTraits)) {
    if (watcher.is_valid()) {
      watcher_.Bind(std::move(watcher));
      watcher_.set_disconnect_handler(
          base::BindOnce(&PcscSmartCardConnection::OnWatcherDisconnected,
                         base::Unretained(this)));
    }
  }

  ~PcscSmartCardConnection() override {
    card_task_runner_->PostTask(
        FROM_HERE, base::BindOnce(
                       [](scoped_refptr<CardHandle> card) {
                         card->Disconnect(kSCardLeaveCard);
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
            [](scoped_refptr<CardHandle> card, uint32_t disp) -> uint32_t {
              return card->Disconnect(disp);
            },
            card_, pcsc_disposition),
        base::BindOnce(
            [](DisconnectCallback cb, uint32_t rv) {
              if (rv == kSCardSSuccess) {
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

    PcscProtocolPci pci;
    switch (protocol) {
      case device::mojom::SmartCardProtocol::kT0:
        pci = PcscProtocolPci::kT0;
        break;
      case device::mojom::SmartCardProtocol::kT1:
        pci = PcscProtocolPci::kT1;
        break;
      case device::mojom::SmartCardProtocol::kRaw:
        pci = PcscProtocolPci::kRaw;
        break;
      case device::mojom::SmartCardProtocol::kUndefined:
        std::move(callback).Run(device::mojom::SmartCardDataResult::NewError(
            device::mojom::SmartCardError::kInvalidParameter));
        return;
    }

    card_task_runner_->PostTaskAndReplyWithResult(
        FROM_HERE,
        base::BindOnce(
            [](scoped_refptr<CardHandle> card, PcscProtocolPci send_pci,
               std::vector<uint8_t> send_buf)
                -> device::mojom::SmartCardDataResultPtr {
              if (card->is_disconnected()) {
                return device::mojom::SmartCardDataResult::NewError(
                    device::mojom::SmartCardError::kInvalidHandle);
              }
              std::vector<uint8_t> recv_buf;
              uint32_t rv = PcscApi::Get().Transmit(card->handle(), send_pci,
                                                    send_buf, &recv_buf);
              if (rv != kSCardSSuccess) {
                return device::mojom::SmartCardDataResult::NewError(
                    SmartCardErrorFromPcscResult(rv));
              }
              return device::mojom::SmartCardDataResult::NewData(
                  std::move(recv_buf));
            },
            card_, pci, data),
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
              std::vector<uint8_t> recv_buf;
              uint32_t rv = PcscApi::Get().Control(card->handle(), code,
                                                   send_buf, &recv_buf);
              if (rv != kSCardSSuccess) {
                return device::mojom::SmartCardDataResult::NewError(
                    SmartCardErrorFromPcscResult(rv));
              }
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
              std::vector<uint8_t> attr;
              uint32_t rv =
                  PcscApi::Get().GetAttrib(card->handle(), attr_id, &attr);
              if (rv != kSCardSSuccess) {
                return device::mojom::SmartCardDataResult::NewError(
                    SmartCardErrorFromPcscResult(rv));
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
              uint32_t rv =
                  PcscApi::Get().SetAttrib(card->handle(), attr_id, attr);
              if (rv != kSCardSSuccess) {
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
              std::string reader_name;
              uint32_t state = 0;
              uint32_t protocol = 0;
              std::vector<uint8_t> atr;
              uint32_t rv = PcscApi::Get().Status(
                  card->handle(), &reader_name, &state, &protocol, &atr);
              if (rv != kSCardSSuccess) {
                return device::mojom::SmartCardStatusResult::NewError(
                    SmartCardErrorFromPcscResult(rv));
              }
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
            [](scoped_refptr<CardHandle> card) -> uint32_t {
              if (card->is_disconnected()) {
                return kSCardEInvalidHandle;
              }
              return PcscApi::Get().BeginTransaction(card->handle());
            },
            card_),
        base::BindOnce(&PcscSmartCardConnection::OnBeginTransactionDone,
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
                         card->Disconnect(kSCardLeaveCard);
                       },
                       card_));
    if (receiver_) {
      receiver_->Close();
    }
  }

  void OnBeginTransactionDone(BeginTransactionCallback callback, uint32_t rv) {
    if (rv != kSCardSSuccess) {
      std::move(callback).Run(
          device::mojom::SmartCardTransactionResult::NewError(
              SmartCardErrorFromPcscResult(rv)));
      return;
    }
    mojo::PendingAssociatedRemote<device::mojom::SmartCardTransaction>
        tx_remote;
    mojo::MakeSelfOwnedAssociatedReceiver(
        std::make_unique<PcscSmartCardTransaction>(card_, card_task_runner_),
        tx_remote.InitWithNewEndpointAndPassReceiver());
    std::move(callback).Run(
        device::mojom::SmartCardTransactionResult::NewTransaction(
            std::move(tx_remote)));
  }

  scoped_refptr<CardHandle> card_;
  scoped_refptr<base::SequencedTaskRunner> card_task_runner_;
  mojo::Remote<device::mojom::SmartCardConnectionWatcher> watcher_;
  mojo::SelfOwnedReceiverRef<device::mojom::SmartCardConnection> receiver_;
  base::WeakPtrFactory<PcscSmartCardConnection> weak_factory_{this};
};

class PcscSmartCardContext : public device::mojom::SmartCardContext {
 public:
  explicit PcscSmartCardContext(PcscContext context)
      : context_(base::MakeRefCounted<ContextHandle>(context)) {}

  ~PcscSmartCardContext() override {
    // Unblock any in-flight SCardGetStatusChange() so it releases its ref to
    // |context_| promptly.
    base::ThreadPool::PostTask(
        FROM_HERE, kPcscTaskTraits,
        base::BindOnce(
            [](scoped_refptr<ContextHandle> ctx) {
              PcscApi::Get().Cancel(ctx->handle());
            },
            context_));
  }

  void ListReaders(ListReadersCallback callback) override {
    base::ThreadPool::PostTaskAndReplyWithResult(
        FROM_HERE, kPcscTaskTraits,
        base::BindOnce(
            [](scoped_refptr<ContextHandle> ctx)
                -> device::mojom::SmartCardListReadersResultPtr {
              std::vector<std::string> readers;
              uint32_t rv =
                  PcscApi::Get().ListReaders(ctx->handle(), &readers);
              if (rv != kSCardSSuccess) {
                return device::mojom::SmartCardListReadersResult::NewError(
                    SmartCardErrorFromPcscResult(rv));
              }
              return device::mojom::SmartCardListReadersResult::NewReaders(
                  std::move(readers));
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

    uint32_t pcsc_timeout = kSCardInfinite;
    if (!timeout.is_max()) {
      if (timeout.is_negative()) {
        pcsc_timeout = 0;
      } else {
        int64_t ms = timeout.InMilliseconds();
        pcsc_timeout = (ms >= static_cast<int64_t>(kSCardInfinite))
                           ? kSCardInfinite
                           : static_cast<uint32_t>(ms);
      }
    }

    base::ThreadPool::PostTaskAndReplyWithResult(
        FROM_HERE, kPcscTaskTraits,
        base::BindOnce(
            [](scoped_refptr<ContextHandle> ctx, uint32_t timeout_ms,
               std::vector<device::mojom::SmartCardReaderStateInPtr> states_in)
                -> device::mojom::SmartCardStatusChangeResultPtr {
              std::vector<PcscReaderState> pcsc_states;
              pcsc_states.reserve(states_in.size());
              for (const auto& state_in : states_in) {
                PcscReaderState st;
                st.reader = state_in->reader;
                st.current_state = PcscReaderStateFlagsFromMojo(
                    *state_in->current_state, state_in->current_count);
                pcsc_states.push_back(std::move(st));
              }

              uint32_t rv = PcscApi::Get().GetStatusChange(
                  ctx->handle(), timeout_ms, &pcsc_states);
              if (rv != kSCardSSuccess) {
                return device::mojom::SmartCardStatusChangeResult::NewError(
                    SmartCardErrorFromPcscResult(rv));
              }

              std::vector<device::mojom::SmartCardReaderStateOutPtr> states_out;
              states_out.reserve(pcsc_states.size());
              for (auto& st : pcsc_states) {
                states_out.push_back(device::mojom::SmartCardReaderStateOut::New(
                    std::move(st.reader),
                    MojoReaderStateFlagsFromPcsc(st.event_state),
                    MojoEventCountFromPcsc(st.event_state), std::move(st.atr)));
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
            [](scoped_refptr<ContextHandle> ctx) -> uint32_t {
              return PcscApi::Get().Cancel(ctx->handle());
            },
            context_),
        base::BindOnce(
            [](CancelCallback cb, uint32_t rv) {
              if (rv == kSCardSSuccess) {
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
                            : kSCardProtocolUndefined;

    struct ConnectOutcome {
      uint32_t rv = 0;
      PcscCard handle = 0;
      uint32_t active_protocol = kSCardProtocolUndefined;
    };

    base::ThreadPool::PostTaskAndReplyWithResult(
        FROM_HERE, kPcscTaskTraits,
        base::BindOnce(
            [](scoped_refptr<ContextHandle> ctx, std::string reader_name,
               uint32_t share, uint32_t protos) -> ConnectOutcome {
              ConnectOutcome out;
              out.rv = PcscApi::Get().Connect(ctx->handle(), reader_name, share,
                                              protos, &out.handle,
                                              &out.active_protocol);
              return out;
            },
            context_, reader, pcsc_share_mode, pcsc_protocols),
        base::BindOnce(
            [](scoped_refptr<ContextHandle> ctx,
               mojo::PendingRemote<device::mojom::SmartCardConnectionWatcher>
                   watcher,
               ConnectCallback cb, ConnectOutcome out) {
              if (out.rv != kSCardSSuccess) {
                std::move(cb).Run(
                    device::mojom::SmartCardConnectResult::NewError(
                        SmartCardErrorFromPcscResult(out.rv)));
                return;
              }
              mojo::PendingRemote<device::mojom::SmartCardConnection>
                  conn_remote;
              auto conn = std::make_unique<PcscSmartCardConnection>(
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

class PcscSmartCardContextFactory
    : public device::mojom::SmartCardContextFactory {
 public:
  PcscSmartCardContextFactory() = default;
  ~PcscSmartCardContextFactory() override = default;

  void CreateContext(CreateContextCallback callback) override {
    struct EstablishOutcome {
      uint32_t rv = 0;
      PcscContext handle = 0;
    };

    base::ThreadPool::PostTaskAndReplyWithResult(
        FROM_HERE, kPcscTaskTraits,
        base::BindOnce([]() -> EstablishOutcome {
          EstablishOutcome out;
          out.rv =
              PcscApi::Get().EstablishContext(kSCardScopeSystem, &out.handle);
          return out;
        }),
        base::BindOnce(
            [](CreateContextCallback cb, EstablishOutcome out) {
              if (out.rv != kSCardSSuccess) {
                std::move(cb).Run(
                    device::mojom::SmartCardCreateContextResult::NewError(
                        SmartCardErrorFromPcscResult(out.rv)));
                return;
              }
              mojo::PendingRemote<device::mojom::SmartCardContext>
                  context_remote;
              mojo::MakeSelfOwnedReceiver(
                  std::make_unique<PcscSmartCardContext>(out.handle),
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
CreatePcscSmartCardContextFactory() {
  mojo::PendingRemote<device::mojom::SmartCardContextFactory> remote;
  mojo::MakeSelfOwnedReceiver(std::make_unique<PcscSmartCardContextFactory>(),
                              remote.InitWithNewPipeAndPassReceiver());
  return remote;
}

}  // namespace smart_card::pcsc

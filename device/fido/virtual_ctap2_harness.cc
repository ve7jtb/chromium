// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Development-only JSON-lines/stdio transport for VirtualCtap2Device.
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/functional/bind.h"
#include "base/json/json_reader.h"
#include "base/json/json_writer.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "base/task/single_thread_task_executor.h"
#include "base/task/single_thread_task_runner.h"
#include "device/fido/virtual_ctap2_device.h"

namespace {
class Harness {
 public:
  Harness() {
    config_.ctap2_versions = {device::Ctap2Version::kCtap2_0,
                              device::Ctap2Version::kCtap2_1};
    config_.pin_support = true;
    config_.pin_uv_auth_token_support = true;
    config_.resident_key_support = true;
    config_.credential_management_support = true;
    config_.hmac_secret_support = true;
    config_.cred_protect_support = true;
    const auto* cli = base::CommandLine::ForCurrentProcess();
    config_.internal_uv_support = cli->HasSwitch("uv");
    config_.attestation_format = cli->HasSwitch("mtc") ? "mtc" : "packed";
    if (cli->HasSwitch("mldsa44")) {
      config_.batch_attestation_algorithm =
          device::CoseAlgorithmIdentifier::kMlDsa44;
    }
    Recreate(true);
  }

  void Handle(std::string line) {
    auto request = base::JSONReader::ReadDict(line, base::JSON_PARSE_RFC);
    if (!request) {
      Reply(-1, "Malformed JSON");
      return;
    }
    auto id = request->FindInt("id");
    const auto* op = request->FindString("op");
    if (!id || !op) {
      Reply(-1, "Expected integer id and string op");
      return;
    }
    if (*op == "cancel") {
      // Only cancel the specified transaction, never a later request.
      if (pending_ && request->FindInt("target") == pending_) {
        device_->Cancel(0);
      }
      Reply(*id);
      return;
    }
    if (pending_) {
      Reply(*id, "Authenticator busy");
      return;
    }
    if (*op == "fresh" || *op == "powerCycle") {
      Recreate(*op == "fresh");
      state_->last_power_cycle = base::TimeTicks::Now();
      Reply(*id);
    } else if (*op == "presence") {
      auto value = request->FindBool("enabled");
      if (!value) {
        Reply(*id, "Expected enabled boolean");
        return;
      }
      presence_ = *value;
      Reply(*id);
    } else if (*op == "uv") {
      auto value = request->FindBool("enabled");
      if (!value) {
        Reply(*id, "Expected enabled boolean");
        return;
      }
      config_.user_verification_succeeds = *value;
      Recreate(false);
      Reply(*id);
    } else if (*op == "transact") {
      const auto* hex = request->FindString("hex");
      std::vector<uint8_t> bytes;
      if (!hex || hex->size() > 131072 ||
          !base::HexStringToBytes(*hex, &bytes) || bytes.empty()) {
        Reply(*id, "Expected 1..65536 CTAP bytes as hexadecimal");
        return;
      }
      pending_ = *id;
      device_->DeviceTransact(
          std::move(bytes),
          base::BindOnce(&Harness::Complete, base::Unretained(this), *id));
    } else if (*op == "info") {
      base::DictValue result;
      result.Set("id", *id);
      result.Set("ok", true);
      result.Set("protocol", "chromium-ctap-stdio-v1");
      result.Set("format", config_.attestation_format);
      result.Set("uv", config_.internal_uv_support);
      Emit(std::move(result));
    } else {
      Reply(*id, "Unknown operation");
    }
  }

 private:
  static void Emit(base::DictValue result) {
    std::string json;
    base::JSONWriter::Write(result, &json);
    std::cout << json << std::endl;
  }
  static void Reply(int id, const char* error = nullptr) {
    base::DictValue result;
    result.Set("id", id);
    result.Set("ok", !error);
    if (error) {
      result.Set("error", error);
    }
    Emit(std::move(result));
  }
  void Complete(int id, std::optional<std::vector<uint8_t>> response) {
    pending_.reset();
    if (!response) {
      Reply(id, "Device returned no response");
      return;
    }
    base::DictValue result;
    result.Set("id", id);
    result.Set("ok", true);
    result.Set("hex", base::HexEncode(*response));
    Emit(std::move(result));
  }
  void Recreate(bool fresh) {
    device_.reset();
    if (fresh) {
      state_ = base::MakeRefCounted<device::VirtualFidoDevice::State>();
      state_->fingerprints_enrolled = config_.internal_uv_support;
    }
    state_->soft_locked = false;
    state_->pin_retries_since_insertion = 0;
    state_->simulate_press_callback = base::BindRepeating(
        [](Harness* self, device::VirtualFidoDevice*) {
          return self->presence_;
        },
        base::Unretained(this));
    device_ = std::make_unique<device::VirtualCtap2Device>(state_, config_);
  }
  bool presence_ = true;
  std::optional<int> pending_;
  device::VirtualCtap2Device::Config config_;
  scoped_refptr<device::VirtualFidoDevice::State> state_;
  std::unique_ptr<device::VirtualCtap2Device> device_;
};
}  // namespace

int main(int argc, char** argv) {
  base::AtExitManager at_exit;
  base::CommandLine::Init(argc, argv);
  base::SingleThreadTaskExecutor executor;
  base::RunLoop loop;
  Harness harness;
  auto runner = base::SingleThreadTaskRunner::GetCurrentDefault();
  std::thread input([&] {
    std::string line;
    while (std::getline(std::cin, line)) {
      if (line.size() > 140000) {
        break;
      }
      runner->PostTask(FROM_HERE, base::BindOnce(&Harness::Handle,
                                                 base::Unretained(&harness),
                                                 std::move(line)));
    }
    runner->PostTask(FROM_HERE, loop.QuitClosure());
  });
  loop.Run();
  input.join();
  return 0;
}

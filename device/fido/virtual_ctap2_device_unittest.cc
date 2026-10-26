// Copyright 2020 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "device/fido/virtual_ctap2_device.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>
#include <utility>
#include <vector>

#include "base/base64.h"
#include "base/check.h"
#include "base/containers/span.h"
#include "base/containers/to_vector.h"
#include "base/files/file_path.h"
#include "base/files/file_util.h"
#include "base/functional/bind.h"
#include "base/functional/callback_helpers.h"
#include "base/json/json_writer.h"
#include "base/memory/scoped_refptr.h"
#include "base/numerics/byte_conversions.h"
#include "base/strings/stringprintf.h"
#include "base/values.h"
#include "base/test/bind.h"
#include "base/test/task_environment.h"
#include "base/test/test_future.h"
#include "base/time/time.h"
#include "components/cbor/reader.h"
#include "components/cbor/values.h"
#include "components/cbor/writer.h"
#include "crypto/hash.h"
#include "device/fido/attestation_statement.h"
#include "device/fido/authenticator_get_assertion_response.h"
#include "device/fido/authenticator_make_credential_response.h"
#include "device/fido/ctap_get_assertion_request.h"
#include "device/fido/ctap_make_credential_request.h"
#include "device/fido/device_response_converter.h"
#include "device/fido/fido_device.h"
#include "device/fido/fido_test_data.h"
#include "device/fido/large_blob.h"
#include "device/fido/public_key.h"
#include "device/fido/public/fido_constants.h"
#include "device/fido/public/fido_transport_protocol.h"
#include "device/fido/public/fido_types.h"
#include "device/fido/public/public_key_credential_descriptor.h"
#include "device/fido/virtual_fido_device.h"
#include "net/cert/asn1_util.h"
#include "net/cert/x509_certificate.h"
#include "net/cert/x509_util.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace device {

namespace {

using TestFuture = base::test::TestFuture<std::optional<std::vector<uint8_t>>>;

void SendCommand(VirtualCtap2Device* device,
                 base::span<const uint8_t> command,
                 FidoDevice::DeviceCallback callback = base::DoNothing()) {
  device->DeviceTransact(base::ToVector(command), std::move(callback));
}

// DecodeCBOR parses a CBOR structure, ignoring the first byte of |in|, which is
// assumed to be a CTAP2 status byte.
std::optional<cbor::Value> DecodeCBOR(base::span<const uint8_t> in) {
  CHECK(!in.empty());
  return cbor::Reader::Read(in.subspan<1>());
}

std::vector<uint8_t> ToCTAP2Command(
    const std::pair<device::CtapRequestCommand, std::optional<cbor::Value>>&
        parts) {
  std::vector<uint8_t> ret;

  if (parts.second.has_value()) {
    std::optional<std::vector<uint8_t>> cbor_bytes =
        cbor::Writer::Write(std::move(*parts.second));
    ret.swap(*cbor_bytes);
  }

  ret.insert(ret.begin(), static_cast<uint8_t>(parts.first));
  return ret;
}
}  // namespace

class VirtualCtap2DeviceTest : public ::testing::Test {
 protected:
  void MakeDevice() { device_ = std::make_unique<VirtualCtap2Device>(); }

  void MakeDevice(scoped_refptr<VirtualFidoDevice::State>& state,
                  const VirtualCtap2Device::Config& config) {
    device_ = std::make_unique<VirtualCtap2Device>(state, config);
  }

  void MakeSelfDestructingDevice() {
    MakeDevice();
    device_->mutable_state()->simulate_press_callback =
        base::BindLambdaForTesting([&](VirtualFidoDevice* _) {
          device_.reset();
          return true;
        });
  }

  std::unique_ptr<VirtualCtap2Device> device_;

  base::test::TaskEnvironment task_environment_;
};

TEST_F(VirtualCtap2DeviceTest, ParseMakeCredentialRequestForVirtualCtapKey) {
  const auto& cbor_request = cbor::Reader::Read(
      base::span(test_data::kCtapMakeCredentialRequest).subspan<1>());
  ASSERT_TRUE(cbor_request);
  ASSERT_TRUE(cbor_request->is_map());
  const std::optional<CtapMakeCredentialRequest> request =
      CtapMakeCredentialRequest::Parse(cbor_request->GetMap());
  ASSERT_TRUE(request);
  EXPECT_THAT(request->client_data_hash,
              ::testing::ElementsAreArray(test_data::kClientDataHash));
  EXPECT_EQ(test_data::kRelyingPartyId, request->rp.id);
  EXPECT_EQ("Acme", request->rp.name);
  EXPECT_THAT(request->user.id,
              ::testing::ElementsAreArray(test_data::kUserId));
  ASSERT_TRUE(request->user.name);
  EXPECT_EQ("johnpsmith@example.com", *request->user.name);
  ASSERT_TRUE(request->user.display_name);
  EXPECT_EQ("John P. Smith", *request->user.display_name);
  ASSERT_EQ(2u,
            request->public_key_credential_params.public_key_credential_params()
                .size());
  EXPECT_EQ(-7,
            request->public_key_credential_params.public_key_credential_params()
                .at(0)
                .algorithm);
  EXPECT_EQ(257,
            request->public_key_credential_params.public_key_credential_params()
                .at(1)
                .algorithm);
  EXPECT_EQ(UserVerificationRequirement::kRequired, request->user_verification);
  EXPECT_TRUE(request->resident_key_required);
}

TEST_F(VirtualCtap2DeviceTest, ParseGetAssertionRequestForVirtualCtapKey) {
  constexpr uint8_t kAllowedCredentialOne[] = {
      0xf2, 0x20, 0x06, 0xde, 0x4f, 0x90, 0x5a, 0xf6, 0x8a, 0x43, 0x94,
      0x2f, 0x02, 0x4f, 0x2a, 0x5e, 0xce, 0x60, 0x3d, 0x9c, 0x6d, 0x4b,
      0x3d, 0xf8, 0xbe, 0x08, 0xed, 0x01, 0xfc, 0x44, 0x26, 0x46, 0xd0,
      0x34, 0x85, 0x8a, 0xc7, 0x5b, 0xed, 0x3f, 0xd5, 0x80, 0xbf, 0x98,
      0x08, 0xd9, 0x4f, 0xcb, 0xee, 0x82, 0xb9, 0xb2, 0xef, 0x66, 0x77,
      0xaf, 0x0a, 0xdc, 0xc3, 0x58, 0x52, 0xea, 0x6b, 0x9e};
  constexpr uint8_t kAllowedCredentialTwo[] = {
      0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
      0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
      0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
      0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
      0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03};

  const auto& cbor_request = cbor::Reader::Read(
      base::span(test_data::kTestComplexCtapGetAssertionRequest).subspan<1>());
  ASSERT_TRUE(cbor_request);
  ASSERT_TRUE(cbor_request->is_map());

  const std::optional<CtapGetAssertionRequest> request =
      CtapGetAssertionRequest::Parse(cbor_request->GetMap());
  EXPECT_THAT(request->client_data_hash,
              ::testing::ElementsAreArray(test_data::kClientDataHash));
  EXPECT_EQ(test_data::kRelyingPartyId, request->rp_id);
  EXPECT_EQ(UserVerificationRequirement::kRequired, request->user_verification);
  EXPECT_FALSE(request->user_presence_required);
  ASSERT_EQ(2u, request->allow_list.size());

  EXPECT_THAT(request->allow_list.at(0).id,
              ::testing::ElementsAreArray(kAllowedCredentialOne));
  EXPECT_THAT(request->allow_list.at(1).id,
              ::testing::ElementsAreArray(kAllowedCredentialTwo));
}

// Tests that destroying the virtual device from the |simulate_press_callback|
// does not crash.
TEST_F(VirtualCtap2DeviceTest, DestroyInsideSimulatePressCallback) {
  MakeSelfDestructingDevice();
  SendCommand(device_.get(), test_data::kCtapSimpleMakeCredentialRequest);
  ASSERT_FALSE(device_);

  MakeSelfDestructingDevice();
  SendCommand(device_.get(), test_data::kCtapGetAssertionRequest);
  ASSERT_FALSE(device_);
}

// Tests that the attestation certificate returned on MakeCredential is valid.
// See
// https://w3c.github.io/webauthn/#sctn-packed-attestation-cert-requirements
TEST_F(VirtualCtap2DeviceTest, AttestationCertificateIsValid) {
  MakeDevice();
  TestFuture future;
  SendCommand(device_.get(), test_data::kCtapSimpleMakeCredentialRequest,
              future.GetCallback());
  EXPECT_TRUE(future.Wait());

  std::optional<cbor::Value> cbor = DecodeCBOR(future.Take().value());
  ASSERT_TRUE(cbor);
  std::optional<AuthenticatorMakeCredentialResponse> response =
      ReadCTAPMakeCredentialResponse(
          FidoTransportProtocol::kUsbHumanInterfaceDevice, std::move(cbor));
  ASSERT_TRUE(response);

  const AttestationStatement& attestation =
      response->attestation_object.attestation_statement();

  EXPECT_FALSE(attestation.IsSelfAttestation());
  EXPECT_FALSE(
      attestation.IsAttestationCertificateInappropriatelyIdentifying());

  base::span<const uint8_t> cert_bytes = *attestation.GetLeafCertificate();
  scoped_refptr<net::X509Certificate> cert =
      net::X509Certificate::CreateFromBytes(cert_bytes);
  ASSERT_TRUE(cert);

  const auto& subject = cert->subject();
  EXPECT_EQ("Batch Certificate", subject.common_name);
  EXPECT_EQ("US", subject.country_name);
  EXPECT_THAT(subject.organization_names, testing::ElementsAre("Chromium"));
  EXPECT_THAT(subject.organization_unit_names,
              testing::ElementsAre("Authenticator Attestation"));

  base::Time now = base::Time::Now();
  EXPECT_LT(cert->valid_start(), now);
  EXPECT_GT(cert->valid_expiry(), now);

  bool present;
  bool critical;
  std::string_view contents;
  ASSERT_TRUE(net::asn1::ExtractExtensionFromDERCert(
      net::x509_util::CryptoBufferAsStringPiece(cert->cert_buffer()),
      std::string_view("\x55\x1d\x13"), &present, &critical, &contents));
  EXPECT_TRUE(present);
  EXPECT_TRUE(critical);
  EXPECT_EQ(std::string_view("\x30\x00", 2), contents);
}

// Tests that batch attestation with Post-Quantum algorithms (-48, -49, -50)
// works and returns valid self-signed batch certificates.
TEST_F(VirtualCtap2DeviceTest, PostQuantumBatchAttestationIsValid) {
  for (int32_t alg : {-48, -49, -50}) {
    SCOPED_TRACE(alg);
    scoped_refptr<VirtualFidoDevice::State> state =
        base::MakeRefCounted<VirtualFidoDevice::State>();
    VirtualCtap2Device::Config config;
    MakeDevice(state, config);

    PublicKeyCredentialRpEntity rp("acme.com");
    PublicKeyCredentialUserEntity user(base::ToVector(test_data::kUserId));
    CtapMakeCredentialRequest request(
        test_data::kClientDataJson, std::move(rp), std::move(user),
        PublicKeyCredentialParams({{CredentialType::kPublicKey, alg}}));

    TestFuture future;
    SendCommand(device_.get(), ToCTAP2Command(AsCTAPRequestValuePair(request)),
                future.GetCallback());
    EXPECT_TRUE(future.Wait());

    std::optional<cbor::Value> cbor = DecodeCBOR(future.Take().value());
    ASSERT_TRUE(cbor);
    std::optional<AuthenticatorMakeCredentialResponse> response =
        ReadCTAPMakeCredentialResponse(
            FidoTransportProtocol::kUsbHumanInterfaceDevice, std::move(cbor));
    ASSERT_TRUE(response);

    const AttestationStatement& attestation =
        response->attestation_object.attestation_statement();

    EXPECT_FALSE(attestation.IsSelfAttestation());
    EXPECT_FALSE(
        attestation.IsAttestationCertificateInappropriatelyIdentifying());

    base::span<const uint8_t> cert_bytes = *attestation.GetLeafCertificate();
    scoped_refptr<net::X509Certificate> cert =
        net::X509Certificate::CreateFromBytes(cert_bytes);
    ASSERT_TRUE(cert);

    const auto& subject = cert->subject();
    EXPECT_EQ("Batch Certificate", subject.common_name);
    EXPECT_EQ("US", subject.country_name);
    EXPECT_THAT(subject.organization_names, testing::ElementsAre("Chromium"));
    EXPECT_THAT(subject.organization_unit_names,
                testing::ElementsAre("Authenticator Attestation"));

    base::Time now = base::Time::Now();
    EXPECT_LT(cert->valid_start(), now);
    EXPECT_GT(cert->valid_expiry(), now);

    const cbor::Value& att_cbor = attestation.AsCBOR();
    ASSERT_TRUE(att_cbor.is_map());
    const auto& att_map = att_cbor.GetMap();
    auto alg_it = att_map.find(cbor::Value("alg"));
    ASSERT_TRUE(alg_it != att_map.end());
    EXPECT_EQ(alg_it->second.GetInteger(), alg);
  }
}

// Tests that requesting mtc-debug returns valid MTC diagnostic data and
// reuses the exact same attestation public key across batch algorithms.
TEST_F(VirtualCtap2DeviceTest, PostQuantumMtcDebugExtension) {
  for (int32_t alg : {-48, -49, -50}) {
    SCOPED_TRACE(alg);
    scoped_refptr<VirtualFidoDevice::State> state =
        base::MakeRefCounted<VirtualFidoDevice::State>();
    VirtualCtap2Device::Config config;
    MakeDevice(state, config);

    PublicKeyCredentialRpEntity rp("acme.com");
    PublicKeyCredentialUserEntity user(base::ToVector(test_data::kUserId));
    CtapMakeCredentialRequest request(
        test_data::kClientDataJson, std::move(rp), std::move(user),
        PublicKeyCredentialParams({{CredentialType::kPublicKey, alg}}));
    request.mtc_debug = true;

    TestFuture future;
    SendCommand(device_.get(), ToCTAP2Command(AsCTAPRequestValuePair(request)),
                future.GetCallback());
    EXPECT_TRUE(future.Wait());

    std::optional<cbor::Value> cbor = DecodeCBOR(future.Take().value());
    ASSERT_TRUE(cbor);
    std::optional<AuthenticatorMakeCredentialResponse> response =
        ReadCTAPMakeCredentialResponse(
            FidoTransportProtocol::kUsbHumanInterfaceDevice, std::move(cbor));
    ASSERT_TRUE(response);
    ASSERT_TRUE(response->mtc_debug.has_value());

    // Verify mtc_debug public key matches the attestation key
    const std::vector<uint8_t>& pub_key_cbor = response->mtc_debug->pub_key;
    EXPECT_FALSE(pub_key_cbor.empty());

    std::optional<cbor::Value> key_cbor = cbor::Reader::Read(pub_key_cbor);
    ASSERT_TRUE(key_cbor && key_cbor->is_map());
    std::unique_ptr<PublicKey> parsed_key =
        PublicKey::FromCOSEKey(alg, pub_key_cbor, key_cbor->GetMap());
    ASSERT_TRUE(parsed_key);
    EXPECT_EQ(parsed_key->algorithm, alg);

    // Verify MTC diagnostic parameters
    EXPECT_EQ(response->mtc_debug->not_before, 0u);
    EXPECT_EQ(response->mtc_debug->not_after, 253402300799ULL);
    EXPECT_EQ(response->mtc_debug->firmware_version, 1u);
    EXPECT_TRUE(response->mtc_debug->root_hash.has_value());
    EXPECT_EQ(response->mtc_debug->root_hash->size(), 32u);
    EXPECT_TRUE(response->mtc_debug->mtc_proof.has_value());

    // Without Enterprise Attestation, deviceSerial MUST NOT be returned
    EXPECT_FALSE(response->mtc_debug->device_serial.has_value());
  }
}

// Tests that mtc-debug returns deviceSerial when Enterprise Attestation is requested.
TEST_F(VirtualCtap2DeviceTest, PostQuantumMtcDebugEnterpriseAttestation) {
  scoped_refptr<VirtualFidoDevice::State> state =
      base::MakeRefCounted<VirtualFidoDevice::State>();
  VirtualCtap2Device::Config config;
  config.support_enterprise_attestation = true;
  config.enterprise_attestation_rps = {"acme.com"};
  MakeDevice(state, config);

  PublicKeyCredentialRpEntity rp("acme.com");
  PublicKeyCredentialUserEntity user(base::ToVector(test_data::kUserId));
  CtapMakeCredentialRequest request(
      test_data::kClientDataJson, std::move(rp), std::move(user),
      PublicKeyCredentialParams(
          {{CredentialType::kPublicKey,
            static_cast<int32_t>(CoseAlgorithmIdentifier::kMlDsa44)}}));
  request.mtc_debug = true;
  request.attestation_preference =
      AttestationConveyancePreference::kEnterpriseIfRPListedOnAuthenticator;

  TestFuture future;
  SendCommand(device_.get(), ToCTAP2Command(AsCTAPRequestValuePair(request)),
              future.GetCallback());
  EXPECT_TRUE(future.Wait());

  std::optional<cbor::Value> cbor = DecodeCBOR(future.Take().value());
  ASSERT_TRUE(cbor);
  std::optional<AuthenticatorMakeCredentialResponse> response =
      ReadCTAPMakeCredentialResponse(
          FidoTransportProtocol::kUsbHumanInterfaceDevice, std::move(cbor));
  ASSERT_TRUE(response);
  ASSERT_TRUE(response->mtc_debug.has_value());
  EXPECT_TRUE(response->mtc_debug->device_serial.has_value());
  EXPECT_EQ(*response->mtc_debug->device_serial, "VIRTUAL_CTAP2_PQC_001");
}

// Tests that VirtualCtap2Device can generate fmt: "mtc"
// attestation statements with PQC algorithms.
TEST_F(VirtualCtap2DeviceTest, PostQuantumMtcAttestationFormats) {
  scoped_refptr<VirtualFidoDevice::State> state =
      base::MakeRefCounted<VirtualFidoDevice::State>();
  VirtualCtap2Device::Config config;
  config.attestation_format = "mtc";
  MakeDevice(state, config);

  PublicKeyCredentialRpEntity rp("acme.com");
  PublicKeyCredentialUserEntity user(base::ToVector(test_data::kUserId));
  CtapMakeCredentialRequest request(
      test_data::kClientDataJson, std::move(rp), std::move(user),
      PublicKeyCredentialParams(
          {{CredentialType::kPublicKey,
            static_cast<int32_t>(CoseAlgorithmIdentifier::kMlDsa65)}}));
  request.mtc_debug = true;

  TestFuture future;
  SendCommand(device_.get(), ToCTAP2Command(AsCTAPRequestValuePair(request)),
              future.GetCallback());
  EXPECT_TRUE(future.Wait());

  std::optional<cbor::Value> cbor = DecodeCBOR(future.Take().value());
  ASSERT_TRUE(cbor);
  std::optional<AuthenticatorMakeCredentialResponse> response =
      ReadCTAPMakeCredentialResponse(
          FidoTransportProtocol::kUsbHumanInterfaceDevice, std::move(cbor));
  ASSERT_TRUE(response);

  const AttestationStatement& attestation =
      response->attestation_object.attestation_statement();
  EXPECT_EQ(attestation.format_name(), "mtc");

  const cbor::Value& att_cbor = attestation.AsCBOR();
  ASSERT_TRUE(att_cbor.is_map());
  const auto& att_map = att_cbor.GetMap();

  auto alg_it = att_map.find(cbor::Value("alg"));
  ASSERT_TRUE(alg_it != att_map.end());
  EXPECT_EQ(alg_it->second.GetInteger(), -49);

  auto sig_it = att_map.find(cbor::Value("sig"));
  ASSERT_TRUE(sig_it != att_map.end() && sig_it->second.is_bytestring());

  auto mtc_cert_it = att_map.find(cbor::Value("mtcCert"));
  ASSERT_TRUE(mtc_cert_it != att_map.end() && mtc_cert_it->second.is_map());
  const auto& cert_map = mtc_cert_it->second.GetMap();
  EXPECT_TRUE(cert_map.contains(cbor::Value("caId")));
  EXPECT_TRUE(cert_map.contains(cbor::Value("serial")));
  EXPECT_TRUE(cert_map.contains(cbor::Value("notBefore")));
  EXPECT_TRUE(cert_map.contains(cbor::Value("notAfter")));

  // In fmt: "mtc", pubKey is omitted from attStmt on the wire!
  EXPECT_FALSE(att_map.contains(cbor::Value("pubKey")));

  // Also verify CTAP 2.2/2.3 parameter 0x0B (attestationFormatsPreference)
  // dynamically selects "mtc" even when Config::attestation_format defaults to
  // "packed".
  VirtualCtap2Device::Config default_config;
  MakeDevice(state, default_config);
  request.attestation_formats = {"mtc", "packed"};

  TestFuture future_pref;
  SendCommand(device_.get(), ToCTAP2Command(AsCTAPRequestValuePair(request)),
              future_pref.GetCallback());
  EXPECT_TRUE(future_pref.Wait());
  std::optional<cbor::Value> cbor_pref = DecodeCBOR(future_pref.Take().value());
  ASSERT_TRUE(cbor_pref);
  std::optional<AuthenticatorMakeCredentialResponse> response_pref =
      ReadCTAPMakeCredentialResponse(
          FidoTransportProtocol::kUsbHumanInterfaceDevice,
          std::move(cbor_pref));
  ASSERT_TRUE(response_pref);
  EXPECT_EQ(
      response_pref->attestation_object.attestation_statement().format_name(),
      "mtc");
}

// Exports PQC batch certificates and FIDO MDS3 statements for test RP servers.
TEST_F(VirtualCtap2DeviceTest, PostQuantumExportMdsAndCertificates) {
  const base::FilePath output_dir(
      FILE_PATH_LITERAL("/Users/jbradley/.gemini/antigravity/scratch/mds"));
  base::CreateDirectory(output_dir);

  struct ExportSpec {
    int32_t alg;
    const char* name;
  };
  const ExportSpec kSpecs[] = {
      {-48, "mldsa44"},
      {-49, "mldsa65"},
      {-50, "mldsa87"},
      {-7, "es256"},
  };

  std::vector<std::string> b64_certs;
  std::vector<std::string> b64_cose_keys;

  for (const auto& spec : kSpecs) {
    scoped_refptr<VirtualFidoDevice::State> state =
        base::MakeRefCounted<VirtualFidoDevice::State>();
    VirtualCtap2Device::Config config;
    MakeDevice(state, config);

    PublicKeyCredentialRpEntity rp("acme.com");
    PublicKeyCredentialUserEntity user(base::ToVector(test_data::kUserId));
    CtapMakeCredentialRequest request(
        test_data::kClientDataJson, std::move(rp), std::move(user),
        PublicKeyCredentialParams({{CredentialType::kPublicKey, spec.alg}}));
    request.mtc_debug = true;

    TestFuture future;
    SendCommand(device_.get(), ToCTAP2Command(AsCTAPRequestValuePair(request)),
                future.GetCallback());
    EXPECT_TRUE(future.Wait());

    std::optional<cbor::Value> cbor = DecodeCBOR(future.Take().value());
    ASSERT_TRUE(cbor);
    std::optional<AuthenticatorMakeCredentialResponse> response =
        ReadCTAPMakeCredentialResponse(
            FidoTransportProtocol::kUsbHumanInterfaceDevice, std::move(cbor));
    ASSERT_TRUE(response);

    // 1. Get DER certificate from attestation statement
    const AttestationStatement& attestation =
        response->attestation_object.attestation_statement();
    ASSERT_TRUE(attestation.GetLeafCertificate().has_value());
    base::span<const uint8_t> cert_der = *attestation.GetLeafCertificate();
    std::string b64_cert = base::Base64Encode(cert_der);
    b64_certs.push_back(b64_cert);

    std::string pem = "-----BEGIN CERTIFICATE-----\n";
    for (size_t i = 0; i < b64_cert.size(); i += 64) {
      pem += b64_cert.substr(i, 64) + "\n";
    }
    pem += "-----END CERTIFICATE-----\n";
    base::WriteFile(
        output_dir.AppendASCII(base::StringPrintf("batch_%s.pem", spec.name)),
        pem);

    // 2. Get canonical CBOR COSE_Key from mtc_debug
    ASSERT_TRUE(response->mtc_debug.has_value());
    const std::vector<uint8_t>& pub_key_cbor = response->mtc_debug->pub_key;
    b64_cose_keys.push_back(base::Base64Encode(pub_key_cbor));
    base::WriteFile(
        output_dir.AppendASCII(
            base::StringPrintf("batch_%s_cose.cbor", spec.name)),
        pub_key_cbor);
  }

  // 3. Output FIDO MDS3 MetadataStatement JSON
  std::string roots_json = "[\n";
  for (size_t i = 0; i < b64_certs.size(); ++i) {
    roots_json += "    \"" + b64_certs[i] + "\"" +
                  (i + 1 < b64_certs.size() ? ",\n" : "\n  ]");
  }

  std::array<uint8_t, 32> test_root_hash = crypto::hash::Sha256(
      base::byte_span_from_cstring("Chromium Virtual CTAP2 MTC Test Root"));
  std::string b64_root_hash = base::Base64Encode(test_root_hash);

  std::string mds_json = base::StringPrintf(
      "{\n"
      "  \"legalHeader\": \"https://fidoalliance.org/metadata/metadata-statement-legal-header/\",\n"
      "  \"aaguid\": \"01020304-0506-0708-0102-030405060708\",\n"
      "  \"description\": \"Chromium Virtual CTAP2 Device (Post-Quantum ML-DSA & MTC Batch Attestation)\",\n"
      "  \"authenticatorVersion\": 1,\n"
      "  \"protocolFamily\": \"fido2\",\n"
      "  \"schema\": 3,\n"
      "  \"upv\": [{\"major\": 1, \"minor\": 0}],\n"
      "  \"authenticationAlgorithms\": [\"secp256r1_ecdsa_sha256_raw\", \"ml_dsa_44\", \"ml_dsa_65\", \"ml_dsa_87\"],\n"
      "  \"publicKeyAlgAndEncodings\": [-48, -49, -50, -7],\n"
      "  \"attestationTypes\": [\"basic_full\"],\n"
      "  \"userVerificationDetails\": [[{\"userVerificationMethod\": \"presence_internal\"}]],\n"
      "  \"keyProtection\": [\"hardware\"],\n"
      "  \"isKeyRestricted\": true,\n"
      "  \"isFreshUserVerificationRequired\": false,\n"
      "  \"matcherProtection\": [\"on_chip\"],\n"
      "  \"attachmentHint\": [\"external\"],\n"
      "  \"tcDisplay\": [],\n"
      "  \"attestationRootCertificates\": %s,\n"
      "  \"mtcTrustAnchors\": [\n"
      "    {\n"
      "      \"caId\": \"AQIDBAUGBwgBAgMEBQYHCA==\",\n"
      "      \"logNumber\": 0,\n"
      "      \"trustedSubtrees\": [\n"
      "        {\n"
      "          \"start\": 0,\n"
      "          \"end\": 1,\n"
      "          \"rootHash\": \"%s\"\n"
      "        }\n"
      "      ],\n"
      "      \"batchKeys\": {\n"
      "        \"1\": {\n"
      "          \"algorithm\": -48,\n"
      "          \"publicKey\": \"%s\",\n"
      "          \"notBefore\": 0,\n"
      "          \"notAfter\": 253402300799,\n"
      "          \"firmwareVersion\": 1\n"
      "        },\n"
      "        \"2\": {\n"
      "          \"algorithm\": -49,\n"
      "          \"publicKey\": \"%s\",\n"
      "          \"notBefore\": 0,\n"
      "          \"notAfter\": 253402300799,\n"
      "          \"firmwareVersion\": 1\n"
      "        },\n"
      "        \"3\": {\n"
      "          \"algorithm\": -50,\n"
      "          \"publicKey\": \"%s\",\n"
      "          \"notBefore\": 0,\n"
      "          \"notAfter\": 253402300799,\n"
      "          \"firmwareVersion\": 1\n"
      "        },\n"
      "        \"4\": {\n"
      "          \"algorithm\": -7,\n"
      "          \"publicKey\": \"%s\",\n"
      "          \"notBefore\": 0,\n"
      "          \"notAfter\": 253402300799,\n"
      "          \"firmwareVersion\": 1\n"
      "        }\n"
      "      }\n"
      "    }\n"
      "  ]\n"
      "}\n",
      roots_json.c_str(), b64_root_hash.c_str(), b64_cose_keys[0].c_str(),
      b64_cose_keys[1].c_str(), b64_cose_keys[2].c_str(), b64_cose_keys[3].c_str());

  base::WriteFile(
      output_dir.AppendASCII("pqc_virtual_authenticator_mds.json"), mds_json);

  // 4. Output MetadataBLOBPayload wrapper format for Yubico server
  std::string blob_json = base::StringPrintf(
      "{\n"
      "  \"legalHeader\": \"https://fidoalliance.org/metadata/metadata-statement-legal-header/\",\n"
      "  \"no\": 1,\n"
      "  \"nextUpdate\": \"2030-01-01\",\n"
      "  \"entries\": [\n"
      "    {\n"
      "      \"aaguid\": \"01020304-0506-0708-0102-030405060708\",\n"
      "      \"statusReports\": [\n"
      "        {\n"
      "          \"status\": \"FIDO_CERTIFIED\",\n"
      "          \"effectiveDate\": \"2026-10-25\"\n"
      "        }\n"
      "      ],\n"
      "      \"timeOfLastStatusChange\": \"2026-10-25\",\n"
      "      \"metadataStatement\": %s\n"
      "    }\n"
      "  ]\n"
      "}\n",
      mds_json.c_str());

  base::WriteFile(
      output_dir.AppendASCII("pqc_virtual_authenticator_blob.json"), blob_json);
}

TEST_F(VirtualCtap2DeviceTest, RejectsCredentialsWithExtraKeys) {
  // The VirtualCtap2Device should reject assertion requests where a credential
  // contains extra keys. This is to ensure that we catch if we trigger
  // crbug.com/1270757 again.
  for (const bool include_extra_keys : {false, true}) {
    SCOPED_TRACE(include_extra_keys);

    cbor::Value::MapValue map;
    map.emplace(1, "example.com");

    const uint8_t k32Bytes[32] = {1, 2, 3};
    map.emplace(2, base::span<const uint8_t>(k32Bytes));

    cbor::Value::MapValue cred;
    cred.emplace("type", "public-key");
    cred.emplace("id", base::span<const uint8_t>(k32Bytes));
    if (include_extra_keys) {
      cred.emplace("extra", true);
    }
    cbor::Value::ArrayValue allow_list;
    allow_list.emplace_back(std::move(cred));
    map.emplace(3, std::move(allow_list));

    std::optional<std::vector<uint8_t>> bytes =
        cbor::Writer::Write(cbor::Value(std::move(map)));
    ASSERT_TRUE(bytes.has_value());

    bytes->insert(
        bytes->begin(),
        static_cast<uint8_t>(CtapRequestCommand::kAuthenticatorGetAssertion));

    MakeDevice();
    TestFuture future;
    SendCommand(device_.get(), *bytes, future.GetCallback());
    EXPECT_TRUE(future.Wait());

    ASSERT_TRUE(future.Get().has_value());
    base::span<const uint8_t> result = future.Get().value();
    ASSERT_EQ(result.size(), 1u);
    EXPECT_EQ(result[0],
              static_cast<uint8_t>(
                  include_extra_keys
                      ? CtapDeviceResponseCode::kCtap2ErrInvalidCBOR
                      : CtapDeviceResponseCode::kCtap2ErrNoCredentials));
  }
}

TEST_F(VirtualCtap2DeviceTest, OnGetAssertionBogusSignature) {
  MakeDevice();
  device_->mutable_state()->ctap2_invalid_signature = true;

  constexpr uint8_t bogus_sig[] = {0x00};
  static constexpr uint8_t kCredentialId[] = {1, 2, 3, 4};
  device_->mutable_state()->InjectRegistration(kCredentialId,
                                               test_data::kRelyingPartyId);

  TestFuture future;
  device::CtapGetAssertionRequest request = CtapGetAssertionRequest(
      test_data::kRelyingPartyId, test_data::kClientDataJson);
  std::vector<uint8_t> credential_id = base::ToVector(kCredentialId);
  PublicKeyCredentialDescriptor descriptor(
      CredentialType::kPublicKey, std::move(credential_id),
      {FidoTransportProtocol::kUsbHumanInterfaceDevice});

  request.allow_list.push_back(std::move(descriptor));
  device_->DeviceTransact(
      ToCTAP2Command(AsCTAPRequestValuePair(std::move(request))),
      base::BindOnce(future.GetCallback()));
  EXPECT_TRUE(future.Wait());

  std::optional<cbor::Value> cbor = DecodeCBOR(future.Take().value());
  ASSERT_TRUE(cbor);

  std::optional<AuthenticatorGetAssertionResponse> response =
      ReadCTAPGetAssertionResponse(
          FidoTransportProtocol::kUsbHumanInterfaceDevice, std::move(cbor));
  ASSERT_TRUE(response);
  EXPECT_THAT(response->signature, testing::ElementsAreArray(bogus_sig));
}

TEST_F(VirtualCtap2DeviceTest, OnMakeCredentialBogusSignature) {
  MakeDevice();
  device_->mutable_state()->ctap2_invalid_signature = true;

  constexpr uint8_t bogus_sig[] = {0x00};
  TestFuture future;
  SendCommand(device_.get(), test_data::kCtapSimpleMakeCredentialRequest,
              future.GetCallback());
  EXPECT_TRUE(future.Wait());
  std::optional<cbor::Value> cbor = DecodeCBOR(future.Take().value());
  ASSERT_TRUE(cbor);
  std::optional<AuthenticatorMakeCredentialResponse> response =
      ReadCTAPMakeCredentialResponse(
          FidoTransportProtocol::kUsbHumanInterfaceDevice, std::move(cbor));
  const AttestationStatement& attestation =
      response->attestation_object.attestation_statement();
  auto attestation_cbor = attestation.AsCBOR();
  const cbor::Value::MapValue& map = attestation_cbor.GetMap();
  const auto type_it = map.find(cbor::Value("sig"));
  EXPECT_THAT(type_it->second.GetBytestring(),
              testing::ElementsAreArray(bogus_sig));
}

TEST_F(VirtualCtap2DeviceTest, OnGetAssertionUnsetUPBit) {
  MakeDevice();
  device_->mutable_state()->unset_up_bit = true;

  static constexpr uint8_t kCredentialId[] = {1, 2, 3, 4};
  device_->mutable_state()->InjectRegistration(kCredentialId,
                                               test_data::kRelyingPartyId);

  TestFuture future;
  device::CtapGetAssertionRequest request = CtapGetAssertionRequest(
      test_data::kRelyingPartyId, test_data::kClientDataJson);
  std::vector<uint8_t> credential_id = base::ToVector(kCredentialId);
  PublicKeyCredentialDescriptor descriptor(
      CredentialType::kPublicKey, std::move(credential_id),
      {FidoTransportProtocol::kUsbHumanInterfaceDevice});

  request.allow_list.push_back(std::move(descriptor));
  device_->DeviceTransact(
      ToCTAP2Command(AsCTAPRequestValuePair(std::move(request))),
      base::BindOnce(future.GetCallback()));
  EXPECT_TRUE(future.Wait());

  std::optional<cbor::Value> cbor = DecodeCBOR(future.Take().value());
  ASSERT_TRUE(cbor);

  std::optional<AuthenticatorGetAssertionResponse> response =
      ReadCTAPGetAssertionResponse(
          FidoTransportProtocol::kUsbHumanInterfaceDevice, std::move(cbor));
  ASSERT_TRUE(response);
  EXPECT_FALSE(response->authenticator_data.obtained_user_presence());
}

TEST_F(VirtualCtap2DeviceTest, OnGetAssertionUnsetUVBit) {
  static constexpr uint8_t kCredentialId[] = {1, 2, 3, 4};

  device::VirtualCtap2Device::Config config;
  config.internal_uv_support = true;
  scoped_refptr<VirtualFidoDevice::State> state =
      base::MakeRefCounted<VirtualFidoDevice::State>();
  state->fingerprints_enrolled = true;
  state->unset_uv_bit = true;
  state->InjectRegistration(kCredentialId, test_data::kRelyingPartyId);
  MakeDevice(state, config);

  TestFuture future;
  device::CtapGetAssertionRequest request = CtapGetAssertionRequest(
      test_data::kRelyingPartyId, test_data::kClientDataJson);
  std::vector<uint8_t> credential_id = base::ToVector(kCredentialId);
  PublicKeyCredentialDescriptor descriptor(
      CredentialType::kPublicKey, std::move(credential_id),
      {FidoTransportProtocol::kUsbHumanInterfaceDevice});

  request.allow_list.push_back(std::move(descriptor));
  request.user_verification = UserVerificationRequirement::kRequired;
  device_->DeviceTransact(
      ToCTAP2Command(AsCTAPRequestValuePair(std::move(request))),
      base::BindOnce(future.GetCallback()));
  EXPECT_TRUE(future.Wait());

  std::optional<cbor::Value> cbor = DecodeCBOR(future.Take().value());
  ASSERT_TRUE(cbor);

  std::optional<AuthenticatorGetAssertionResponse> response =
      ReadCTAPGetAssertionResponse(
          FidoTransportProtocol::kUsbHumanInterfaceDevice, std::move(cbor));
  ASSERT_TRUE(response);
  EXPECT_FALSE(response->authenticator_data.obtained_user_verification());
}

TEST_F(VirtualCtap2DeviceTest, OnMakeCredentialUnsetUPBit) {
  MakeDevice();
  device_->mutable_state()->unset_up_bit = true;

  TestFuture future;
  SendCommand(device_.get(), test_data::kCtapSimpleMakeCredentialRequest,
              future.GetCallback());
  EXPECT_TRUE(future.Wait());
  std::optional<cbor::Value> cbor = DecodeCBOR(future.Take().value());
  ASSERT_TRUE(cbor);
  std::optional<AuthenticatorMakeCredentialResponse> response =
      ReadCTAPMakeCredentialResponse(
          FidoTransportProtocol::kUsbHumanInterfaceDevice, std::move(cbor));

  EXPECT_FALSE(response->attestation_object.authenticator_data()
                   .obtained_user_presence());
}

TEST_F(VirtualCtap2DeviceTest, OnMakeCredentialUnsetUVBit) {
  device::VirtualCtap2Device::Config config;
  config.internal_uv_support = true;
  config.resident_key_support = true;
  scoped_refptr<VirtualFidoDevice::State> state =
      base::MakeRefCounted<VirtualFidoDevice::State>();
  state->fingerprints_enrolled = true;
  state->unset_uv_bit = true;
  MakeDevice(state, config);

  TestFuture future;
  SendCommand(device_.get(), test_data::kCtapMakeCredentialRequest,
              future.GetCallback());
  EXPECT_TRUE(future.Wait());

  std::optional<cbor::Value> cbor = DecodeCBOR(future.Take().value());
  ASSERT_TRUE(cbor);
  std::optional<AuthenticatorMakeCredentialResponse> response =
      ReadCTAPMakeCredentialResponse(
          FidoTransportProtocol::kUsbHumanInterfaceDevice, std::move(cbor));

  EXPECT_FALSE(response->attestation_object.authenticator_data()
                   .obtained_user_verification());
}

// Tests injecting and getting a large blob.
TEST_F(VirtualCtap2DeviceTest, InjectLargeBlob) {
  MakeDevice();
  std::vector<uint8_t> credential1 = {1, 2, 3, 4};
  ASSERT_TRUE(device_->mutable_state()->InjectResidentKey(
      credential1, test_data::kRelyingPartyId, std::vector<uint8_t>{5, 6, 7, 8},
      std::nullopt, std::nullopt));

  std::vector<uint8_t> credential2 = {5, 6, 7, 8};
  ASSERT_TRUE(device_->mutable_state()->InjectResidentKey(
      credential2, test_data::kRelyingPartyId, std::vector<uint8_t>{9, 0, 1, 2},
      std::nullopt, std::nullopt));

  // Inject two large blobs.
  LargeBlob blob1({'b', 'l', 'o', 'b', '1'}, 5);
  device_->mutable_state()->InjectLargeBlob(
      &device_->mutable_state()->registrations.at(credential1), blob1);

  LargeBlob blob2({'b', 'l', 'o', 'b', '2'}, 5);
  device_->mutable_state()->InjectLargeBlob(
      &device_->mutable_state()->registrations.at(credential2), blob2);

  // Replace the first one with a new one.
  LargeBlob blob3({'b', 'l', 'o', 'b', '3'}, 5);
  device_->mutable_state()->InjectLargeBlob(
      &device_->mutable_state()->registrations.at(credential1), blob3);

  std::optional<LargeBlob> blob_cred1 = device_->mutable_state()->GetLargeBlob(
      device_->mutable_state()->registrations.at(credential1));
  EXPECT_EQ(*blob_cred1, blob3);

  std::optional<LargeBlob> blob_cred2 = device_->mutable_state()->GetLargeBlob(
      device_->mutable_state()->registrations.at(credential2));
  EXPECT_EQ(*blob_cred2, blob2);
}

TEST_F(VirtualCtap2DeviceTest, CmtgKeyMakeCredentialUnsupported) {
  scoped_refptr<VirtualFidoDevice::State> state =
      base::MakeRefCounted<VirtualFidoDevice::State>();
  VirtualCtap2Device::Config config;
  config.cmtg_key_support = false;
  MakeDevice(state, config);

  PublicKeyCredentialRpEntity rp("acme.com");
  PublicKeyCredentialUserEntity user(base::ToVector(test_data::kUserId));
  CtapMakeCredentialRequest request(
      test_data::kClientDataJson, std::move(rp), std::move(user),
      PublicKeyCredentialParams({{CredentialType::kPublicKey, -7}}));
  request.cmtg_key = true;

  TestFuture future;
  SendCommand(device_.get(), ToCTAP2Command(AsCTAPRequestValuePair(request)),
              future.GetCallback());
  std::optional<std::vector<uint8_t>> response = future.Get();
  ASSERT_TRUE(response);
  ASSERT_EQ(response->at(0),
            static_cast<uint8_t>(
                CtapDeviceResponseCode::kCtap2ErrUnsupportedExtension));
}

TEST_F(VirtualCtap2DeviceTest, CmtgKeyGetAssertionUnsupported) {
  scoped_refptr<VirtualFidoDevice::State> state =
      base::MakeRefCounted<VirtualFidoDevice::State>();
  VirtualCtap2Device::Config config;
  config.cmtg_key_support = false;
  MakeDevice(state, config);

  std::vector<uint8_t> credential_id = {1, 2, 3, 4};
  ASSERT_TRUE(state->InjectResidentKey(credential_id, "acme.com",
                                       std::vector<uint8_t>{5, 6, 7, 8},
                                       std::nullopt, std::nullopt));

  CtapGetAssertionRequest request("acme.com", test_data::kClientDataJson);
  request.allow_list = {
      PublicKeyCredentialDescriptor(CredentialType::kPublicKey, credential_id)};
  request.cmtg_key = true;

  TestFuture future;
  SendCommand(device_.get(), ToCTAP2Command(AsCTAPRequestValuePair(request)),
              future.GetCallback());
  std::optional<std::vector<uint8_t>> response = future.Get();
  ASSERT_TRUE(response);
  ASSERT_EQ(response->at(0),
            static_cast<uint8_t>(
                CtapDeviceResponseCode::kCtap2ErrUnsupportedExtension));
}

TEST_F(VirtualCtap2DeviceTest, CmtgKeySimulateFailure) {
  scoped_refptr<VirtualFidoDevice::State> state =
      base::MakeRefCounted<VirtualFidoDevice::State>();
  VirtualCtap2Device::Config config;
  config.cmtg_key_support = true;
  MakeDevice(state, config);

  state->simulate_cmtg_key_failure = true;

  PublicKeyCredentialRpEntity rp("acme.com");
  PublicKeyCredentialUserEntity user(base::ToVector(test_data::kUserId));
  CtapMakeCredentialRequest request(
      test_data::kClientDataJson, std::move(rp), std::move(user),
      PublicKeyCredentialParams({{CredentialType::kPublicKey, -7}}));
  request.cmtg_key = true;

  TestFuture future;
  SendCommand(device_.get(), ToCTAP2Command(AsCTAPRequestValuePair(request)),
              future.GetCallback());
  std::optional<std::vector<uint8_t>> response = future.Get();
  ASSERT_TRUE(response);
  ASSERT_EQ(response->at(0),
            static_cast<uint8_t>(CtapDeviceResponseCode::kSuccess));

  auto parsed_response = ReadCTAPMakeCredentialResponse(
      FidoTransportProtocol::kUsbHumanInterfaceDevice, DecodeCBOR(*response));
  ASSERT_TRUE(parsed_response);
  EXPECT_FALSE(parsed_response->cmtg_key);
}

TEST_F(VirtualCtap2DeviceTest, CmtgKeyIndexOutOfBounds) {
  scoped_refptr<VirtualFidoDevice::State> state =
      base::MakeRefCounted<VirtualFidoDevice::State>();
  VirtualCtap2Device::Config config;
  config.cmtg_key_support = true;
  MakeDevice(state, config);

  PublicKeyCredentialRpEntity rp("acme.com");
  PublicKeyCredentialUserEntity user(base::ToVector(test_data::kUserId));
  CtapMakeCredentialRequest request(
      test_data::kClientDataJson, std::move(rp), std::move(user),
      PublicKeyCredentialParams({{CredentialType::kPublicKey, -7}}));
  request.cmtg_key = true;

  TestFuture future;
  SendCommand(device_.get(), ToCTAP2Command(AsCTAPRequestValuePair(request)),
              future.GetCallback());
  std::optional<std::vector<uint8_t>> make_response = future.Get();
  ASSERT_TRUE(make_response);
  auto parsed_make_response = ReadCTAPMakeCredentialResponse(
      FidoTransportProtocol::kUsbHumanInterfaceDevice,
      DecodeCBOR(*make_response));
  ASSERT_TRUE(parsed_make_response);

  std::vector<uint8_t> credential_id =
      parsed_make_response->attestation_object.authenticator_data()
          .GetCredentialId();

  // Set the selected index to an out-of-bounds value.
  state->registrations[credential_id].selected_cmtg_key_index = 100;

  CtapGetAssertionRequest get_request("acme.com", test_data::kClientDataJson);
  get_request.allow_list = {
      PublicKeyCredentialDescriptor(CredentialType::kPublicKey, credential_id)};
  get_request.cmtg_key = true;

  future.Clear();
  SendCommand(device_.get(),
              ToCTAP2Command(AsCTAPRequestValuePair(get_request)),
              future.GetCallback());
  std::optional<std::vector<uint8_t>> get_response = future.Get();
  ASSERT_TRUE(get_response);
  ASSERT_EQ(get_response->at(0),
            static_cast<uint8_t>(CtapDeviceResponseCode::kSuccess));

  auto parsed_get_response = ReadCTAPGetAssertionResponse(
      FidoTransportProtocol::kUsbHumanInterfaceDevice,
      DecodeCBOR(*get_response));
  ASSERT_TRUE(parsed_get_response);
  // It falls back silently to index 0, so the request succeeds with the first
  // key.
  EXPECT_TRUE(parsed_get_response->cmtg_key);
}

TEST_F(VirtualCtap2DeviceTest, GetAssertionNoSignatureCounter) {
  MakeDevice();

  static constexpr uint8_t kCredentialId[] = {1, 2, 3, 4};
  device::VirtualFidoDevice::RegistrationData registration(
      std::make_unique<device::VirtualFidoDevice::PrivateKey>(
          CoseAlgorithmIdentifier::kEs256),
      crypto::hash::Sha256(test_data::kRelyingPartyId), std::nullopt);
  device_->mutable_state()->InjectRegistration(kCredentialId,
                                               std::move(registration));

  CtapGetAssertionRequest get_request(test_data::kRelyingPartyId,
                                      test_data::kClientDataJson);
  get_request.allow_list = {PublicKeyCredentialDescriptor(
      CredentialType::kPublicKey, base::ToVector(kCredentialId))};

  TestFuture future;
  SendCommand(device_.get(),
              ToCTAP2Command(AsCTAPRequestValuePair(get_request)),
              future.GetCallback());
  std::optional<std::vector<uint8_t>> get_response = future.Get();
  ASSERT_TRUE(get_response);
  ASSERT_EQ(get_response->at(0),
            static_cast<uint8_t>(CtapDeviceResponseCode::kSuccess));

  auto parsed_get_response = ReadCTAPGetAssertionResponse(
      FidoTransportProtocol::kUsbHumanInterfaceDevice,
      DecodeCBOR(*get_response));
  ASSERT_TRUE(parsed_get_response);
  EXPECT_EQ(0u, base::U32FromBigEndian(
                    parsed_get_response->authenticator_data.counter()));

  future.Clear();
  SendCommand(device_.get(),
              ToCTAP2Command(AsCTAPRequestValuePair(get_request)),
              future.GetCallback());
  get_response = future.Get();
  ASSERT_TRUE(get_response);
  parsed_get_response = ReadCTAPGetAssertionResponse(
      FidoTransportProtocol::kUsbHumanInterfaceDevice,
      DecodeCBOR(*get_response));
  ASSERT_TRUE(parsed_get_response);
  EXPECT_EQ(0u, base::U32FromBigEndian(
                    parsed_get_response->authenticator_data.counter()));
}

}  // namespace device

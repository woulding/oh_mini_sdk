/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include <string>
#include "securec.h"

#include "crypto_common.h"
#include "blob.h"
#include "detailed_rsa_key_params.h"
#include "detailed_dsa_key_params.h"
#include "detailed_ecc_key_params.h"
#include "hcf_parcel.h"
#include "hcf_string.h"
#include "memory.h"
#include "object_base.h"
#include "openssl_adapter.h"
#include "openssl_common.h"
#include "params_parser.h"
#include "rsa_openssl_common.h"
#include "utils.h"

using namespace std;
using namespace testing::ext;


namespace {
class CryptoCommonCovTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoCommonCovTest::SetUpTestCase() {}

void CryptoCommonCovTest::TearDownTestCase() {}

void CryptoCommonCovTest::SetUp() {}

void CryptoCommonCovTest::TearDown() {}

constexpr uint32_t BEGIN_POS = 1;
constexpr uint32_t PARCEL_LENGTH = 1;
constexpr uint32_t PARCEL_UINT_MAX = 0xffffffffU;
constexpr uint32_t PARCEL_DEFAULT_SIZE = 16;
static const char *g_paramStr = "NULL";

static const char *GetTestClass()
{
    return g_paramStr;
}

static void DestroyTest(HcfObjectBase *self)
{
    (void)self;
    return;
}
// plugin common
// invalid digest alg
HWTEST_F(CryptoCommonCovTest, CryptoCommonTest001, TestSize.Level0)
{
    HcfResult ret = GetOpensslDigestAlg(0, nullptr);
    EXPECT_NE(ret, HCF_SUCCESS);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest002, TestSize.Level0)
{
    EVP_MD *tmp = nullptr;
    HcfResult ret = GetOpensslDigestAlg(HCF_OPENSSL_DIGEST_NONE, &tmp);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_EQ(tmp, nullptr);
}

// Get Rsa Spec String Md
HWTEST_F(CryptoCommonCovTest, CryptoCommonTest003, TestSize.Level0)
{
    HcfAlgParaValue md = HCF_OPENSSL_DIGEST_MD5;
    HcfResult ret = GetRsaSpecStringMd(md, nullptr);
    EXPECT_NE(ret, HCF_SUCCESS);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest004, TestSize.Level0)
{
    HcfAlgParaValue md = HCF_OPENSSL_DIGEST_MD5;
    char *retStr = nullptr;
    HcfResult ret = GetRsaSpecStringMd(md, &retStr);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(retStr, nullptr);

    HcfFree(retStr);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest005, TestSize.Level0)
{
    HcfAlgParaValue md = HCF_OPENSSL_DIGEST_SHA1;
    char *retStr = nullptr;
    HcfResult ret = GetRsaSpecStringMd(md, &retStr);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(retStr, nullptr);

    HcfFree(retStr);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest006, TestSize.Level0)
{
    HcfAlgParaValue md = HCF_OPENSSL_DIGEST_SHA224;
    char *retStr = nullptr;
    HcfResult ret = GetRsaSpecStringMd(md, &retStr);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(retStr, nullptr);

    HcfFree(retStr);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest007, TestSize.Level0)
{
    HcfAlgParaValue md = HCF_OPENSSL_DIGEST_SHA384;
    char *retStr = nullptr;
    HcfResult ret = GetRsaSpecStringMd(md, &retStr);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(retStr, nullptr);

    HcfFree(retStr);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest008, TestSize.Level0)
{
    HcfAlgParaValue md = HCF_OPENSSL_DIGEST_SHA512;
    char *retStr = nullptr;
    HcfResult ret = GetRsaSpecStringMd(md, &retStr);
    EXPECT_EQ(ret, HCF_SUCCESS);
    EXPECT_NE(retStr, nullptr);

    HcfFree(retStr);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest009, TestSize.Level0)
{
    HcfAlgParaValue md = HCF_OPENSSL_DIGEST_NONE;
    char *retStr = nullptr;
    HcfResult ret = GetRsaSpecStringMd(md, &retStr);
    EXPECT_NE(ret, HCF_SUCCESS);
    EXPECT_EQ(retStr, nullptr);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest010, TestSize.Level0)
{
    HcfResult ret = GetRsaSpecStringMGF(nullptr);
    EXPECT_NE(ret, HCF_SUCCESS);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest011, TestSize.Level0)
{
    HcfResult ret = GetOpensslPadding(0, nullptr);
    EXPECT_NE(ret, HCF_SUCCESS);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest016, TestSize.Level0)
{
    HcfResult ret = BigIntegerToBigNum(nullptr, nullptr);
    EXPECT_NE(ret, HCF_SUCCESS);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest017, TestSize.Level0)
{
    HcfBigInteger tmp = { .data = nullptr, .len = 0 };
    HcfResult ret = BigIntegerToBigNum(&tmp, nullptr);
    EXPECT_NE(ret, HCF_SUCCESS);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest018, TestSize.Level0)
{
    HcfResult ret = BigNumToBigInteger(nullptr, nullptr);
    EXPECT_NE(ret, HCF_SUCCESS);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest019, TestSize.Level0)
{
    BIGNUM *src = OpensslBnNew();
    HcfResult ret = BigNumToBigInteger(src, nullptr);
    EXPECT_NE(ret, HCF_SUCCESS);
    OpensslBnFree(src);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest020, TestSize.Level0)
{
    BIGNUM *src = OpensslBnNew();
    HcfBigInteger dest = { .data = nullptr, .len = 0 };
    HcfResult ret = BigNumToBigInteger(src, &dest);
    EXPECT_NE(ret, HCF_SUCCESS);
    EXPECT_EQ(dest.data, nullptr);
    OpensslBnFree(src);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest021, TestSize.Level0)
{
    RSA *rsa = OpensslRsaNew();
    HcfResult ret = DuplicateRsa(rsa, true, nullptr);
    EXPECT_NE(ret, HCF_SUCCESS);
    OpensslRsaFree(rsa);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest022, TestSize.Level0)
{
    HcfResult ret = DuplicateRsa(nullptr, true, nullptr);
    EXPECT_NE(ret, HCF_SUCCESS);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest023, TestSize.Level0)
{
    EVP_PKEY *pKey = NewEvpPkeyByRsa(nullptr, true);
    EXPECT_EQ(pKey, nullptr);
}
// openssl fail need mock

// common
// parcel
HWTEST_F(CryptoCommonCovTest, CryptoCommonTest101, TestSize.Level0)
{
    HcParcel tmp = CreateParcel(0, 0);
    EXPECT_EQ(tmp.data, nullptr);

    DeleteParcel(&tmp);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest102, TestSize.Level0)
{
    HcParcel *tmp = nullptr;
    DeleteParcel(tmp);
    EXPECT_EQ(tmp, nullptr);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest103, TestSize.Level0)
{
    uint32_t ret = GetParcelDataSize(nullptr);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest104, TestSize.Level0)
{
    HcParcel tmp = CreateParcel(0, 0);
    tmp.beginPos = BEGIN_POS;
    uint32_t ret = GetParcelDataSize(&tmp);

    EXPECT_EQ(ret, 0);
    DeleteParcel(&tmp);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest105, TestSize.Level0)
{
    const char *ret = GetParcelData(nullptr);
    EXPECT_EQ(ret, nullptr);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest106, TestSize.Level0)
{
    bool ret = ParcelWrite(nullptr, nullptr, 0);
    EXPECT_EQ(ret, false);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest107, TestSize.Level0)
{
    HcParcel tmp = CreateParcel(0, 0);
    bool ret = ParcelWrite(&tmp, nullptr, 0);
    EXPECT_EQ(ret, false);

    DeleteParcel(&tmp);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest108, TestSize.Level0)
{
    HcParcel tmp = CreateParcel(0, 0);
    int32_t src = 0;
    bool ret = ParcelWrite(&tmp, &src, 0);
    EXPECT_EQ(ret, false);

    DeleteParcel(&tmp);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest109, TestSize.Level0)
{
    HcParcel tmp = CreateParcel(0, 0);
    tmp.endPos = PARCEL_UINT_MAX;
    int32_t src = 0;
    bool ret = ParcelWrite(&tmp, &src, PARCEL_LENGTH);
    EXPECT_EQ(ret, false);

    DeleteParcel(&tmp);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest110, TestSize.Level0)
{
    HcParcel tmp = CreateParcel(PARCEL_DEFAULT_SIZE, PARCEL_DEFAULT_SIZE);
    tmp.endPos = PARCEL_DEFAULT_SIZE;
    bool ret = ParcelPopBack(&tmp, PARCEL_LENGTH);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(tmp.endPos, PARCEL_DEFAULT_SIZE - PARCEL_LENGTH);

    DeleteParcel(&tmp);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest111, TestSize.Level0)
{
    HcParcel tmp = CreateParcel(PARCEL_DEFAULT_SIZE, PARCEL_DEFAULT_SIZE);
    tmp.endPos = PARCEL_DEFAULT_SIZE;
    uint8_t src = 0;
    tmp.allocUnit = 0;
    bool ret = ParcelWrite(&tmp, &src, PARCEL_LENGTH);
    EXPECT_EQ(ret, false);

    DeleteParcel(&tmp);
}

// params.parser
HWTEST_F(CryptoCommonCovTest, CryptoCommonTest112, TestSize.Level0)
{
    HcfResult ret = ParseAndSetParameter(nullptr, nullptr, nullptr);
    EXPECT_NE(ret, HCF_SUCCESS);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest113, TestSize.Level0)
{
    const char *tmp = g_paramStr;
    HcfResult ret = ParseAndSetParameter(tmp, nullptr, nullptr);
    EXPECT_NE(ret, HCF_SUCCESS);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest114, TestSize.Level0)
{
    HcfResult ret = ParseAlgNameToParams(nullptr, nullptr);
    EXPECT_NE(ret, HCF_SUCCESS);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest115, TestSize.Level0)
{
    const char *tmp = g_paramStr;
    HcfResult ret = ParseAlgNameToParams(tmp, nullptr);
    EXPECT_NE(ret, HCF_SUCCESS);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest116, TestSize.Level0)
{
    const char *tmp = g_paramStr;
    HcfAsyKeyGenParams parma = {};
    HcfResult ret = ParseAlgNameToParams(tmp, &parma);
    EXPECT_NE(ret, HCF_SUCCESS);
}

// hcf string
HWTEST_F(CryptoCommonCovTest, CryptoCommonTest117, TestSize.Level0)
{
    HcString tmp = CreateString();
    bool ret = StringAppendPointer(&tmp, nullptr);
    EXPECT_EQ(ret, false);
    DeleteString(&tmp);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest118, TestSize.Level0)
{
    bool ret = StringAppendPointer(nullptr, nullptr);
    EXPECT_EQ(ret, false);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest119, TestSize.Level0)
{
    bool ret = StringSetPointer(nullptr, nullptr);
    EXPECT_EQ(ret, false);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest120, TestSize.Level0)
{
    bool ret = StringSetPointerWithLength(nullptr, nullptr, 0);
    EXPECT_EQ(ret, false);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest121, TestSize.Level0)
{
    HcString tmp = CreateString();
    bool ret = StringSetPointerWithLength(&tmp, nullptr, 0);
    EXPECT_EQ(ret, false);
    DeleteString(&tmp);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest122, TestSize.Level0)
{
    HcString tmp = CreateString();
    uint32_t len = strlen(g_paramStr) + 1;
    bool ret = StringSetPointerWithLength(&tmp, g_paramStr, len);
    EXPECT_EQ(ret, false);
    DeleteString(&tmp);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest123, TestSize.Level0)
{
    bool ret = StringGet(nullptr);
    EXPECT_EQ(ret, false);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest124, TestSize.Level0)
{
    uint32_t ret = StringLength(nullptr);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest125, TestSize.Level0)
{
    uint32_t ret = StringFind(nullptr, 0, 0);
    EXPECT_EQ(ret, -1);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest126, TestSize.Level0)
{
    HcString tmp = CreateString();
    bool ret = StringSubString(&tmp, 0, 0, nullptr);
    EXPECT_EQ(ret, false);
    DeleteString(&tmp);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest127, TestSize.Level0)
{
    HcString tmp = CreateString();
    HcString sub = CreateString();
    bool ret = StringSubString(&tmp, PARCEL_UINT_MAX, 0, nullptr);
    EXPECT_EQ(ret, false);
    DeleteString(&tmp);
    DeleteString(&sub);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest128, TestSize.Level0)
{
    HcString tmp = CreateString();
    int ret = StringCompare(&tmp, nullptr);
    EXPECT_EQ(ret, 0);
    DeleteString(&tmp);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest129, TestSize.Level0)
{
    int ret = StringCompare(nullptr, nullptr);
    EXPECT_EQ(ret, 0);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest130, TestSize.Level0)
{
    HcString tmp = CreateString();
    int ret = StringCompare(&tmp, g_paramStr);
    EXPECT_EQ(ret, -1);
    DeleteString(&tmp);
}

// asy parmas free
HWTEST_F(CryptoCommonCovTest, CryptoCommonTest131, TestSize.Level0)
{
    HcfDsaCommParamsSpec *spec = nullptr;
    FreeDsaCommParamsSpec(spec);
    EXPECT_EQ(spec, nullptr);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest132, TestSize.Level0)
{
    HcfDsaPubKeyParamsSpec *spec = nullptr;
    DestroyDsaPubKeySpec(spec);
    EXPECT_EQ(spec, nullptr);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest133, TestSize.Level0)
{
    HcfDsaKeyPairParamsSpec *spec = nullptr;
    DestroyDsaKeyPairSpec(spec);
    EXPECT_EQ(spec, nullptr);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest134, TestSize.Level0)
{
    HcfEccCommParamsSpec *spec = nullptr;
    FreeEccCommParamsSpec(spec);
    EXPECT_EQ(spec, nullptr);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest135, TestSize.Level0)
{
    HcfEccPubKeyParamsSpec *spec = nullptr;
    DestroyEccPubKeySpec(spec);
    EXPECT_EQ(spec, nullptr);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest136, TestSize.Level0)
{
    HcfEccPriKeyParamsSpec *spec = nullptr;
    DestroyEccPriKeySpec(spec);
    EXPECT_EQ(spec, nullptr);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest137, TestSize.Level0)
{
    HcfEccKeyPairParamsSpec *spec = nullptr;
    DestroyEccKeyPairSpec(spec);
    EXPECT_EQ(spec, nullptr);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest138, TestSize.Level0)
{
    HcfRsaCommParamsSpec *spec = nullptr;
    FreeRsaCommParamsSpec(spec);
    EXPECT_EQ(spec, nullptr);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest139, TestSize.Level0)
{
    HcfRsaPubKeyParamsSpec *spec = nullptr;
    DestroyRsaPubKeySpec(spec);
    EXPECT_EQ(spec, nullptr);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest140, TestSize.Level0)
{
    HcfRsaKeyPairParamsSpec *spec = nullptr;
    DestroyRsaKeyPairSpec(spec);
    EXPECT_EQ(spec, nullptr);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest141, TestSize.Level0)
{
    HcfBlob *blob = nullptr;
    HcfBlobDataFree(blob);
    EXPECT_EQ(blob, nullptr);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest142, TestSize.Level0)
{
    HcfBlob *blob = nullptr;
    HcfBlobDataClearAndFree(blob);
    EXPECT_EQ(blob, nullptr);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest143, TestSize.Level0)
{
    bool ret = HcfIsClassMatch(nullptr, nullptr);
    EXPECT_EQ(ret, false);
}

HWTEST_F(CryptoCommonCovTest, CryptoCommonTest144, TestSize.Level0)
{
    HcfObjectBase base = { .getClass = GetTestClass, .destroy = DestroyTest };
    bool ret = HcfIsClassMatch(&base, nullptr);
    EXPECT_EQ(ret, false);
}

HWTEST_F(CryptoCommonCovTest, HcfGetCryptoOperationErrMsgTest001, TestSize.Level0)
{
    const char *errMsg = "test error message";
    char *errMsgBuf = nullptr;
    HcfGetCryptoOperationErrMsg(HCF_SUCCESS, &errMsg, &errMsgBuf);
    EXPECT_EQ(errMsgBuf, nullptr);
    EXPECT_STREQ(errMsg, "test error message");

    errMsg = "short";
    errMsgBuf = nullptr;
    HcfGetCryptoOperationErrMsg(HCF_ERR_CRYPTO_OPERATION, &errMsg, &errMsgBuf);
    EXPECT_EQ(errMsgBuf, nullptr);

    std::string longMsg(300, 'A');
    errMsg = longMsg.c_str();
    HcfGetCryptoOperationErrMsg(HCF_ERR_CRYPTO_OPERATION, &errMsg, &errMsgBuf);
    EXPECT_EQ(errMsgBuf, nullptr);
}
}

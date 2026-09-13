/*
 * Copyright (C) 2022-2024 Huawei Device Co., Ltd.
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

#include "openssl_adapter.h"
#include "openssl_adapter_mock.h"
#include <openssl/param_build.h>

#include "log.h"
#include "result.h"

static uint32_t g_mockIndex = __INT32_MAX__;
static uint32_t g_callNum = 0;
static bool g_isRecordCallNum = false;
static bool g_isNeedSpecialMock = false;
static int g_double = 2;

bool IsNeedMock(void)
{
    if (!g_isRecordCallNum) {
        return false;
    }
    g_callNum++;
    if (g_callNum == g_mockIndex) {
        LOGD("mock malloc return NULL.");
        return true;
    }
    return false;
}

void StartRecordOpensslCallNum(void)
{
    ResetOpensslCallNum();
    g_isRecordCallNum = true;
}

void EndRecordOpensslCallNum(void)
{
    ResetOpensslCallNum();
    g_isRecordCallNum = false;
}

uint32_t GetOpensslCallNum(void)
{
    return g_callNum;
}

void ResetOpensslCallNum(void)
{
    g_callNum = 0;
    g_mockIndex = __INT32_MAX__;
}

void SetOpensslCallMockIndex(uint32_t index)
{
    g_mockIndex = index;
}

int OpensslBnModExp(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *p, BN_CTX *ctx)
{
    if (IsNeedMock()) {
        return -1;
    }
    return BN_mod_exp(r, a, b, p, ctx);
}
BIGNUM *OpensslBnDup(const BIGNUM *a)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return BN_dup(a);
}

void OpensslBnClear(BIGNUM *a)
{
    BN_clear(a);
}

void OpensslBnClearFree(BIGNUM *a)
{
    if (a != NULL) {
        BN_clear_free(a);
    }
}

void OpensslBnFree(BIGNUM *a)
{
    if (a != NULL) {
        BN_free(a);
    }
}

BIGNUM *OpensslBnNew(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return BN_new();
}

BIGNUM *OpensslBin2Bn(const unsigned char *s, int len, BIGNUM *ret)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return BN_bin2bn(s, len, ret);
}

BIGNUM *OpensslLeBin2Bn(const unsigned char *s, int len, BIGNUM *ret)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return BN_lebin2bn(s, len, ret);
}

int OpensslBn2BinPad(const BIGNUM *a, unsigned char *to, int toLen)
{
    if (IsNeedMock()) {
        return -1;
    }
    return BN_bn2binpad(a, to, toLen);
}

int OpensslBn2LeBinPad(const BIGNUM *a, unsigned char *to, int tolen)
{
    if (IsNeedMock()) {
        return -1;
    }
    return BN_bn2lebinpad(a, to, tolen);
}

BN_CTX *OpensslBnCtxNew(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return BN_CTX_new();
}

void OpensslBnCtxFree(BN_CTX *ctx)
{
    if (ctx != NULL) {
        BN_CTX_free(ctx);
    }
}

int OpensslBnNumBytes(const BIGNUM *a)
{
    if (IsNeedMock()) {
        return -1;
    }
    return BN_num_bytes(a);
}

int OpensslBnSetWord(BIGNUM *a, unsigned int w)
{
    if (IsNeedMock()) {
        return -1;
    }
    return BN_set_word(a, w);
}

unsigned int OpensslBnGetWord(const BIGNUM *a)
{
    if (IsNeedMock()) {
        return 0;
    }
    return BN_get_word(a);
}

int OpensslBnNumBits(const BIGNUM *a)
{
    if (IsNeedMock()) {
        return -1;
    }
    return BN_num_bits(a);
}

int OpensslHex2Bn(BIGNUM **a, const char *str)
{
    if (IsNeedMock()) {
        return -1;
    }
    return BN_hex2bn(a, str);
}

int OpensslBnCmp(const BIGNUM *a, const BIGNUM *b)
{
    if (IsNeedMock()) {
        return -1;
    }
    return BN_cmp(a, b);
}

EC_KEY *OpensslEcKeyNewByCurveName(int nid)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EC_KEY_new_by_curve_name(nid);
}

EC_POINT *OpensslEcPointDup(const EC_POINT *src, const EC_GROUP *group)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EC_POINT_dup(src, group);
}

int OpensslEcKeyGenerateKey(EC_KEY *eckey)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EC_KEY_generate_key(eckey);
}

int OpensslEcKeySetPublicKey(EC_KEY *key, const EC_POINT *pub)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EC_KEY_set_public_key(key, pub);
}

int OpensslEcKeySetPrivateKey(EC_KEY *key, const BIGNUM *privKey)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EC_KEY_set_private_key(key, privKey);
}

int OpensslEcKeyCheckKey(const EC_KEY *key)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EC_KEY_check_key(key);
}

const EC_POINT *OpensslEcKeyGet0PublicKey(const EC_KEY *key)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EC_KEY_get0_public_key(key);
}

const BIGNUM *OpensslEcKeyGet0PrivateKey(const EC_KEY *key)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EC_KEY_get0_private_key(key);
}

const EC_GROUP *OpensslEcKeyGet0Group(const EC_KEY *key)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EC_KEY_get0_group(key);
}

EC_GROUP *OpensslEcGroupDup(const EC_GROUP *a)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EC_GROUP_dup(a);
}

void OpensslEcGroupFree(EC_GROUP *group)
{
    if (group != NULL) {
        EC_GROUP_free(group);
    }
}

EC_KEY *OpensslEcKeyNew(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EC_KEY_new();
}

EC_KEY *OpensslEcKeyDup(const EC_KEY *ecKey)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EC_KEY_dup(ecKey);
}

int OpensslEcKeySetGroup(EC_KEY *key, const EC_GROUP *group)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EC_KEY_set_group(key, group);
}

int OpensslEcPointGetAffineCoordinatesGfp(const EC_GROUP *group, const EC_POINT *point, BIGNUM *x,
    BIGNUM *y, BN_CTX *ctx)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EC_POINT_get_affine_coordinates_GFp(group, point, x, y, ctx);
}

int OpensslEcGroupGetDegree(const EC_GROUP *group)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EC_GROUP_get_degree(group);
}

int OpensslEcGroupGetCurveGfp(const EC_GROUP *group, BIGNUM *p, BIGNUM *a, BIGNUM *b, BN_CTX *ctx)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EC_GROUP_get_curve_GFp(group, p, a, b, ctx);
}

const EC_POINT *OpensslEcGroupGet0Generator(const EC_GROUP *group)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EC_GROUP_get0_generator(group);
}

int OpensslEcGroupGetOrder(const EC_GROUP *group, BIGNUM *order, BN_CTX *ctx)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EC_GROUP_get_order(group, order, ctx);
}

int OpensslEcGroupGetCofactor(const EC_GROUP *group, BIGNUM *cofactor, BN_CTX *ctx)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EC_GROUP_get_cofactor(group, cofactor, ctx);
}

EC_GROUP *OpensslEcGroupNewCurveGfp(const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EC_GROUP_new_curve_GFp(p, a, b, ctx);
}

EC_POINT *OpensslEcPointNew(const EC_GROUP *group)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EC_POINT_new(group);
}

int OpensslEcPointCopy(EC_POINT *dst, const EC_POINT *src)
{
    if (IsNeedMock()) {
        return 0;
    }
    return EC_POINT_copy(dst, src);
}

int OpensslEcPointSetAffineCoordinatesGfp(const EC_GROUP *group, EC_POINT *point, const BIGNUM *x,
    const BIGNUM *y, BN_CTX *ctx)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EC_POINT_set_affine_coordinates_GFp(group, point, x, y, ctx);
}

int OpensslEcGroupSetGenerator(EC_GROUP *group, const EC_POINT *generator, const BIGNUM *order,
    const BIGNUM *cofactor)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EC_GROUP_set_generator(group, generator, order, cofactor);
}

void OpensslEcGroupSetCurveName(EC_GROUP *group, int nid)
{
    if (IsNeedMock()) {
        return;
    }
    EC_GROUP_set_curve_name(group, nid);
}

int OpensslEcGroupGetCurveName(const EC_GROUP *group)
{
    if (IsNeedMock()) {
        return 0;
    }
    return EC_GROUP_get_curve_name(group);
}

int OpensslEcPointMul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *gScalar, const EC_POINT *point,
    const BIGNUM *pScalar, BN_CTX *ctx)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EC_POINT_mul(group, r, gScalar, point, pScalar, ctx);
}

int OpensslI2dEcPubKey(EC_KEY *a, unsigned char **pp)
{
    if (IsNeedMock()) {
        return -1;
    }
    return i2d_EC_PUBKEY(a, pp);
}

int OpensslI2dEcPrivateKey(EC_KEY *key, unsigned char **out)
{
    if (IsNeedMock()) {
        return -1;
    }
    return i2d_ECPrivateKey(key, out);
}

EC_KEY *OpensslD2iEcPubKey(EC_KEY **a, const unsigned char **pp, long length)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return d2i_EC_PUBKEY(a, pp, length);
}

EC_KEY *OpensslD2iEcPrivateKey(EC_KEY **key, const unsigned char **in, long len)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return d2i_ECPrivateKey(key, in, len);
}

void OpensslEcKeySetAsn1Flag(EC_KEY *key, int flag)
{
    EC_KEY_set_asn1_flag(key, flag);
}

void OpensslEcKeySetEncFlags(EC_KEY *eckey, unsigned int flags)
{
    EC_KEY_set_enc_flags(eckey, flags);
}

void OpensslEcKeyFree(EC_KEY *key)
{
    if (key != NULL) {
        EC_KEY_free(key);
    }
}

void OpensslEcPointFree(EC_POINT *point)
{
    if (point != NULL) {
        EC_POINT_free(point);
    }
}

EVP_MD_CTX *OpensslEvpMdCtxNew(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_MD_CTX_new();
}

EVP_PKEY_CTX *OpensslEvpMdCtxGetPkeyCtx(EVP_MD_CTX *ctx)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_MD_CTX_get_pkey_ctx(ctx);
}

void OpensslEvpMdCtxFree(EVP_MD_CTX *ctx)
{
    if (ctx != NULL) {
        EVP_MD_CTX_free(ctx);
    }
}

int OpensslEvpDigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EVP_DigestSignInit(ctx, pctx, type, e, pkey);
}

int OpensslEvpDigestSignUpdate(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EVP_DigestSignUpdate(ctx, data, count);
}

int OpensslEvpDigestSignFinal(EVP_MD_CTX *ctx, unsigned char *sigret, size_t *siglen)
{
    if (sigret != NULL && g_isNeedSpecialMock) {
        g_callNum++;
    }
    if (IsNeedMock()) {
        if (sigret == NULL) {
            return -1;
        }
        if (g_isNeedSpecialMock) {
            int res = EVP_DigestSignFinal(ctx, sigret, siglen);
            *siglen = *siglen * g_double;
            g_isNeedSpecialMock = false;
            return res;
        }
        g_isNeedSpecialMock = true;
        return -1;
    }
    if (sigret != NULL) {
        g_callNum++;
    }
    return EVP_DigestSignFinal(ctx, sigret, siglen);
}

int OpensslEvpDigestSign(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs, size_t tbslen)
{
    if (sig != NULL && g_isNeedSpecialMock) {
        g_callNum++;
    }
    if (IsNeedMock()) {
        if (sig == NULL) {
            return -1;
        }
        if (g_isNeedSpecialMock) {
            int res = EVP_DigestSign(ctx, sig, siglen, tbs, tbslen);
            *siglen = *siglen * g_double;
            g_isNeedSpecialMock = false;
            return res;
        }
        g_isNeedSpecialMock = true;
        return -1;
    }
    if (sig != NULL) {
        g_callNum++;
    }
    return EVP_DigestSign(ctx, sig, siglen, tbs, tbslen);
}

int OpensslEvpDigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EVP_DigestVerifyInit(ctx, pctx, type, e, pkey);
}

int OpensslEvpDigestVerifyUpdate(EVP_MD_CTX *ctx, const void *data, size_t count)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EVP_DigestVerifyUpdate(ctx, data, count);
}

int OpensslEvpDigestVerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EVP_DigestVerifyFinal(ctx, sig, siglen);
}

int OpensslEvpDigestVerify(EVP_MD_CTX *ctx, unsigned char *sig, size_t siglen,
    const unsigned char *tbs, size_t tbslen)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EVP_DigestVerify(ctx, sig, siglen, tbs, tbslen);
}

int OpensslEvpPkeySignInit(EVP_PKEY_CTX *ctx)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EVP_PKEY_sign_init(ctx);
}

int OpensslEvpPkeySign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs,
    size_t tbslen)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EVP_PKEY_sign(ctx, sig, siglen, tbs, tbslen);
}

int OpensslEvpPkeyVerifyInit(EVP_PKEY_CTX *ctx)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EVP_PKEY_verify_init(ctx);
}

int OpensslEvpPkeyVerify(EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs,
    size_t tbslen)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EVP_PKEY_verify(ctx, sig, siglen, tbs, tbslen);
}

EVP_PKEY_CTX *OpensslEvpPkeyCtxNewFromPkey(OSSL_LIB_CTX *libctx,
    EVP_PKEY *pkey, const char *propquery)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_PKEY_CTX_new_from_pkey(libctx, pkey, propquery);
}

EVP_PKEY *OpensslEvpPkeyNew(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_PKEY_new();
}

EVP_PKEY *OpensslEvpPkeyNewRawPublicKey(int type, ENGINE *e, const unsigned char *pub, size_t len)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_PKEY_new_raw_public_key(type, e, pub, len);
}

EVP_PKEY *OpensslEvpPkeyNewRawPrivateKey(int type, ENGINE *e, const unsigned char *pub, size_t len)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_PKEY_new_raw_private_key(type, e, pub, len);
}

int OpensslEvpPkeyGetRawPublicKey(const EVP_PKEY *pkey, unsigned char *pub, size_t *len)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EVP_PKEY_get_raw_public_key(pkey, pub, len);
}

int OpensslEvpPkeyGetRawPrivateKey(const EVP_PKEY *pkey, unsigned char *priv, size_t *len)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EVP_PKEY_get_raw_private_key(pkey, priv, len);
}

int OpensslEvpPkeyAssignEcKey(EVP_PKEY *pkey, EC_KEY *key)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EVP_PKEY_assign_EC_KEY(pkey, key);
}

void OpensslEvpPkeyFree(EVP_PKEY *pkey)
{
    if (pkey != NULL) {
        EVP_PKEY_free(pkey);
    }
}

EVP_PKEY_CTX *OpensslEvpPkeyCtxNew(EVP_PKEY *pkey, ENGINE *e)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_PKEY_CTX_new(pkey, e);
}

int OpensslEvpPkeyDeriveInit(EVP_PKEY_CTX *ctx)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EVP_PKEY_derive_init(ctx);
}

int OpensslEvpPkeyCtxSet1Id(EVP_PKEY_CTX *ctx, const void *id, int idLen)
{
    if (id != NULL && g_isNeedSpecialMock) {
        g_callNum++;
    }
    if (IsNeedMock()) {
        if (id == NULL) {
            return -1;
        }
        if (g_isNeedSpecialMock) {
            int res = EVP_PKEY_CTX_set1_id(ctx, id, idLen);
            g_isNeedSpecialMock = false;
            return res;
        }
        g_isNeedSpecialMock = true;
        return -1;
    }
    if (id  != NULL) {
        g_callNum++;
    }
    return EVP_PKEY_CTX_set1_id(ctx, id, idLen);
}

int OpensslEvpPkeyDeriveSetPeer(EVP_PKEY_CTX *ctx, EVP_PKEY *peer)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EVP_PKEY_derive_set_peer(ctx, peer);
}

int OpensslEvpPkeyDerive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen)
{
    if (key != NULL && g_isNeedSpecialMock) {
        g_callNum++;
    }
    if (IsNeedMock()) {
        if (key == NULL) {
            return -1;
        }
        if (g_isNeedSpecialMock) {
            int res = EVP_PKEY_derive(ctx, key, keylen);
            *keylen = *keylen * g_double;
            g_isNeedSpecialMock = false;
            return res;
        }
        g_isNeedSpecialMock = true;
        return -1;
    }
    if (key != NULL) {
        g_callNum++;
    }
    return EVP_PKEY_derive(ctx, key, keylen);
}

int OpensslEvpPkeyEncrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
    const unsigned char *in, size_t inlen)
{
    return EVP_PKEY_encrypt(ctx, out, outlen, in, inlen);
}

int OpensslEvpPkeyDecrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
    const unsigned char *in, size_t inlen)
{
    return EVP_PKEY_decrypt(ctx, out, outlen, in, inlen);
}

int OpensslEvpPkeyEncryptInit(EVP_PKEY_CTX *ctx)
{
    return EVP_PKEY_encrypt_init(ctx);
}

int OpensslEvpPkeyDecryptInit(EVP_PKEY_CTX *ctx)
{
    return EVP_PKEY_decrypt_init(ctx);
}

void OpensslEvpPkeyCtxFree(EVP_PKEY_CTX *ctx)
{
    if (ctx != NULL) {
        EVP_PKEY_CTX_free(ctx);
    }
}

EVP_PKEY_CTX *OpensslEvpPkeyCtxNewId(int id, ENGINE *e)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_PKEY_CTX_new_id(id, e);
}

int OpensslEvpPkeyBaseId(EVP_PKEY *pkey)
{
    return EVP_PKEY_base_id(pkey);
}

EVP_PKEY_CTX *OpensslEvpPkeyCtxNewFromName(OSSL_LIB_CTX *libctx, const char *name, const char *propquery)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_PKEY_CTX_new_from_name(libctx, name, propquery);
}

OSSL_PARAM OpensslOsslParamConstructUtf8String(const char *key, char *buf, size_t bsize)
{
    return OSSL_PARAM_construct_utf8_string(key, buf, bsize);
}

OSSL_PARAM OpensslOsslParamConstructEnd(void)
{
    return OSSL_PARAM_construct_end();
}

int OpensslEvpPkeyGenerate(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EVP_PKEY_generate(ctx, ppkey);
}

OSSL_PARAM OpensslOsslParamConstructUint(const char *key, unsigned int *buf)
{
    return OSSL_PARAM_construct_uint(key, buf);
}

OSSL_PARAM OpensslOsslParamConstructInt(const char *key, int *buf)
{
    return OSSL_PARAM_construct_int(key, buf);
}

int OpensslEvpPkeyParamGenInit(EVP_PKEY_CTX *ctx)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EVP_PKEY_paramgen_init(ctx);
}

int OpensslEvpPkeyCtxSetDsaParamgenBits(EVP_PKEY_CTX *ctx, int nbits)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EVP_PKEY_CTX_set_dsa_paramgen_bits(ctx, nbits);
}

int OpensslEvpPkeyCtxSetParams(EVP_PKEY_CTX *ctx, const OSSL_PARAM *params)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EVP_PKEY_CTX_set_params(ctx, params);
}

int OpensslEvpPkeyParamGen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EVP_PKEY_paramgen(ctx, ppkey);
}

int OpensslEvpPkeyKeyGenInit(EVP_PKEY_CTX *ctx)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EVP_PKEY_keygen_init(ctx);
}

int OpensslEvpPkeyKeyGen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EVP_PKEY_keygen(ctx, ppkey);
}

int OpensslEvpPkeySet1Dsa(EVP_PKEY *pkey, DSA *key)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EVP_PKEY_set1_DSA(pkey, key);
}

DSA *OpensslEvpPkeyGet1Dsa(EVP_PKEY *pkey)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_PKEY_get1_DSA(pkey);
}

DSA *OpensslDsaNew(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return DSA_new();
}

void OpensslDsaFree(DSA *dsa)
{
    if (dsa != NULL) {
        DSA_free(dsa);
    }
}

int OpensslDsaUpRef(DSA *dsa)
{
    if (IsNeedMock()) {
        return -1;
    }
    return DSA_up_ref(dsa);
}

int OpensslDsaSet0Pqg(DSA *dsa, BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
    if (IsNeedMock()) {
        return -1;
    }
    return DSA_set0_pqg(dsa, p, q, g);
}

int OpensslDsaSet0Key(DSA *dsa, BIGNUM *pubKey, BIGNUM *priKey)
{
    if (IsNeedMock()) {
        return -1;
    }
    return DSA_set0_key(dsa, pubKey, priKey);
}

const BIGNUM *OpensslDsaGet0P(const DSA *dsa)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return DSA_get0_p(dsa);
}

const BIGNUM *OpensslDsaGet0Q(const DSA *dsa)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return DSA_get0_q(dsa);
}

const BIGNUM *OpensslDsaGet0G(const DSA *dsa)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return DSA_get0_g(dsa);
}

void OpensslDsaGet0Pqg(const DSA *dsa, const BIGNUM **p, const BIGNUM **q, const BIGNUM **g)
{
    if (IsNeedMock()) {
        return;
    }
    return DSA_get0_pqg(dsa, p, q, g);
}

const BIGNUM *OpensslDsaGet0PubKey(const DSA *dsa)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return DSA_get0_pub_key(dsa);
}

const BIGNUM *OpensslDsaGet0PrivKey(const DSA *dsa)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return DSA_get0_priv_key(dsa);
}

int OpensslDsaGenerateKey(DSA *a)
{
    if (IsNeedMock()) {
        return -1;
    }
    return DSA_generate_key(a);
}

DSA *OpensslD2iDsaPubKey(DSA **dsa, const unsigned char **ppin, long length)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return d2i_DSA_PUBKEY(dsa, ppin, length);
}

DSA *OpensslD2iDsaPrivateKey(DSA **dsa, const unsigned char **ppin, long length)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return d2i_DSAPrivateKey(dsa, ppin, length);
}

int OpensslI2dDsaPubkey(DSA *dsa, unsigned char **ppout)
{
    if (IsNeedMock()) {
        return -1;
    }
    return i2d_DSA_PUBKEY(dsa, ppout);
}

int OpensslI2dDsaPrivateKey(DSA *dsa, unsigned char **ppout)
{
    if (IsNeedMock()) {
        return -1;
    }
    return i2d_DSAPrivateKey(dsa, ppout);
}

int OpensslEvpPkeyCheck(EVP_PKEY_CTX *ctx)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EVP_PKEY_check(ctx);
}

EVP_PKEY *OpensslEvpPkeyDup(EVP_PKEY *a)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_PKEY_dup(a);
}

EVP_PKEY *OpensslD2iPubKey(EVP_PKEY **a, const unsigned char **pp, long length)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return d2i_PUBKEY(a, pp, length);
}

EVP_PKEY *OpensslD2iPrivateKey(int type, EVP_PKEY **a, const unsigned char **pp, long length)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return d2i_PrivateKey(type, a, pp, length);
}

int OpensslI2dPubKey(EVP_PKEY *pkey, unsigned char **ppout)
{
    if (IsNeedMock()) {
        return -1;
    }
    return i2d_PUBKEY(pkey, ppout);
}

int OpensslI2dPrivateKey(EVP_PKEY *pkey, unsigned char **ppout)
{
    if (IsNeedMock()) {
        return -1;
    }
    return i2d_PrivateKey(pkey, ppout);
}

RSA *OpensslRsaNew(void)
{
    return RSA_new();
}

void OpensslRsaFree(RSA *rsa)
{
    if (rsa != NULL) {
        RSA_free(rsa);
    }
}

int OpensslRsaGenerateMultiPrimeKey(RSA *rsa, int bits, int primes,
    BIGNUM *e, BN_GENCB *cb)
{
    return RSA_generate_multi_prime_key(rsa, bits, primes, e, cb);
}

int OpensslRsaGenerateKeyEx(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb)
{
    return RSA_generate_key_ex(rsa, bits, e, cb);
}

int OpensslRsaBits(const RSA *rsa)
{
    return RSA_bits(rsa);
}

int OpensslRsaSet0Key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d)
{
    return RSA_set0_key(r, n, e, d);
}

void OpensslRsaGet0Key(const RSA *r, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d)
{
    RSA_get0_key(r, n, e, d);
}

const BIGNUM *OpensslRsaGet0N(const RSA *d)
{
    return RSA_get0_n(d);
}

const BIGNUM *OpensslRsaGet0E(const RSA *d)
{
    return RSA_get0_e(d);
}

const BIGNUM *OpensslRsaGet0D(const RSA *d)
{
    return RSA_get0_d(d);
}

void OpensslRsaGet0Factors(const RSA *r, const BIGNUM **p, const BIGNUM **q)
{
    RSA_get0_factors(r, p, q);
}

RSA *OpensslRsaPublicKeyDup(RSA *rsa)
{
    return RSAPublicKey_dup(rsa);
}

RSA *OpensslRsaPrivateKeyDup(RSA *rsa)
{
    return RSAPrivateKey_dup(rsa);
}

RSA *OpensslD2iRsaPubKey(RSA **a, const unsigned char **pp, long length)
{
    return d2i_RSA_PUBKEY(a, pp, length);
}

int OpensslI2dRsaPubKey(RSA *a, unsigned char **pp)
{
    return i2d_RSA_PUBKEY(a, pp);
}

RSA *OpensslD2iRsaPublicKey(RSA **a, const unsigned char **pp, long length)
{
    return d2i_RSAPublicKey(a, pp, length);
}

int OpensslI2dRsaPublicKey(RSA *a, unsigned char **pp)
{
    return i2d_RSAPublicKey(a, pp);
}

RSA *OpensslD2iRsaPrivateKey(RSA **a, const unsigned char **pp, long length)
{
    return d2i_RSAPrivateKey(a, pp, length);
}

int OpensslI2dRsaPrivateKey(RSA *a, unsigned char **pp)
{
    return i2d_RSAPrivateKey(a, pp);
}

int OpensslEvpPkeyCtxSetRsaPssSaltLen(EVP_PKEY_CTX *ctx, int saltlen)
{
    return EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, saltlen);
}

int OpensslEvpPkeyCtxGetRsaPssSaltLen(EVP_PKEY_CTX *ctx, int *saltlen)
{
    return EVP_PKEY_CTX_get_rsa_pss_saltlen(ctx, saltlen);
}

int OpensslEvpPkeyCtxSetRsaPadding(EVP_PKEY_CTX *ctx, int pad)
{
    return EVP_PKEY_CTX_set_rsa_padding(ctx, pad);
}

int OpensslEvpPkeyCtxSetRsaMgf1Md(EVP_PKEY_CTX *ctx, const EVP_MD *md)
{
    return EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md);
}

int OpensslEvpPkeyCtxSetRsaOaepMd(EVP_PKEY_CTX *ctx, const EVP_MD *md)
{
    return EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md);
}

int OpensslEvpPkeyCtxSet0RsaOaepLabel(EVP_PKEY_CTX *ctx, void *label, int len)
{
    return EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, label, len);
}

int OpensslEvpPkeyCtxGet0RsaOaepLabel(EVP_PKEY_CTX *ctx, unsigned char **label)
{
    return EVP_PKEY_CTX_get0_rsa_oaep_label(ctx, label);
}

EVP_PKEY *OpensslD2iAutoPrivateKey(EVP_PKEY **a, const unsigned char **pp, long length)
{
    return d2i_AutoPrivateKey(a, pp, length);
}

struct rsa_st *OpensslEvpPkeyGet1Rsa(EVP_PKEY *pkey)
{
    return EVP_PKEY_get1_RSA(pkey);
}

int OpensslEvpPkeySet1Rsa(EVP_PKEY *pkey, struct rsa_st *key)
{
    return EVP_PKEY_set1_RSA(pkey, key);
}

int OpensslEvpPkeyAssignRsa(EVP_PKEY *pkey, struct rsa_st *key)
{
    return EVP_PKEY_assign_RSA(pkey, key);
}

BIO *OpensslBioNew(const BIO_METHOD *type)
{
    return BIO_new(type);
}

const BIO_METHOD *OpensslBioSMem(void)
{
    return BIO_s_mem();
}

int OpensslBioRead(BIO *b, void *data, int dlen)
{
    return BIO_read(b, data, dlen);
}

void OpensslBioFreeAll(BIO *a)
{
    if (a != NULL) {
        return BIO_free_all(a);
    }
}

int OpensslRandPrivBytesEx(OSSL_LIB_CTX *libCtx, unsigned char *buf, size_t num)
{
    if (IsNeedMock()) {
        return -1;
    }
    return RAND_priv_bytes_ex(libCtx, buf, num, 0);
}

int OpensslRandSetSeedSourceType(OSSL_LIB_CTX *libCtx, const char *name, const char *propq)
{
    if (IsNeedMock()) {
        return -1;
    }
    return RAND_set_seed_source_type(libCtx, name, propq);
}

void OpensslRandSeed(const void *buf, int num)
{
    RAND_seed(buf, num);
}

const EVP_MD *OpensslEvpSha1(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_sha1();
}

const EVP_MD *OpensslEvpSha224(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_sha224();
}

const EVP_MD *OpensslEvpSha256(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_sha256();
}

const EVP_MD *OpensslEvpSha384(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_sha384();
}

const EVP_MD *OpensslEvpSha512(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_sha512();
}

const EVP_MD *OpensslEvpSha3256(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_sha3_256();
}

const EVP_MD *OpensslEvpSha3384(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_sha3_384();
}

const EVP_MD *OpensslEvpSha3512(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_sha3_512();
}

const EVP_MD *OpensslEvpMd5(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_md5();
}

const EVP_MD *OpensslEvpMd2(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_md2();
}

const EVP_MD *OpensslEvpMd4(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_md4();
}

const EVP_MD *OpensslEvpRipemd160(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_ripemd160();
}

int OpensslEvpDigestFinalEx(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *size)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EVP_DigestFinal_ex(ctx, md, size);
}

int OpensslEvpMdCtxSize(const EVP_MD_CTX *ctx)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EVP_MD_CTX_size(ctx);
}

int OpensslEvpDigestInitEx(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EVP_DigestInit_ex(ctx, type, impl);
}

int OpensslHmacInitEx(HMAC_CTX *ctx, const void *key, int len, const EVP_MD *md, ENGINE *impl)
{
    if (IsNeedMock()) {
        return -1;
    }
    return HMAC_Init_ex(ctx, key, len, md, impl);
}

int OpensslHmacFinal(HMAC_CTX *ctx, unsigned char *md, unsigned int *len)
{
    if (IsNeedMock()) {
        return -1;
    }
    return HMAC_Final(ctx, md, len);
}

size_t OpensslHmacSize(const HMAC_CTX *ctx)
{
    if (IsNeedMock()) {
        return -1;
    }
    return HMAC_size(ctx);
}

void OpensslHmacCtxFree(HMAC_CTX *ctx)
{
    if (ctx != NULL) {
        HMAC_CTX_free(ctx);
    }
}

HMAC_CTX *OpensslHmacCtxNew(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return HMAC_CTX_new();
}

int OpensslPkcs5Pbkdf2Hmac(const char *pass, int passlen, const unsigned char *salt,
    int saltlen, int iter, const EVP_MD *digest, int keylen, unsigned char *out)
{
    if (IsNeedMock()) {
        return -1;
    }
    return PKCS5_PBKDF2_HMAC(pass, passlen, salt, saltlen, iter, digest, keylen, out);
}

DH *OpensslDhNew(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return DH_new();
}

int OpensslDhComputeKeyPadded(unsigned char *key, const BIGNUM *pubKey, DH *dh)
{
    if (IsNeedMock()) {
        return -1;
    }
    return DH_compute_key_padded(key, pubKey, dh);
}

void OpensslDhFree(DH *dh)
{
    if (dh != NULL) {
        return DH_free(dh);
    }
}

int OpensslDhGenerateKey(DH *dh)
{
    if (IsNeedMock()) {
        return -1;
    }
    return DH_generate_key(dh);
}

const BIGNUM *OpensslDhGet0P(const DH *dh)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return DH_get0_p(dh);
}

const BIGNUM *OpensslDhGet0Q(const DH *dh)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return DH_get0_q(dh);
}

const BIGNUM *OpensslDhGet0G(const DH *dh)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return DH_get0_g(dh);
}

void OpensslDhGet0Pqg(const DH *dh, const BIGNUM **p, const BIGNUM **q, const BIGNUM **g)
{
    if (IsNeedMock()) {
        return;
    }
    return DH_get0_pqg(dh, p, q, g);
}

long OpensslDhGetLength(const DH *dh)
{
    if (IsNeedMock()) {
        return -1;
    }
    return DH_get_length(dh);
}

int OpensslDhSetLength(DH *dh, long length)
{
    if (IsNeedMock()) {
        return -1;
    }
    return DH_set_length(dh, length);
}

const BIGNUM *OpensslDhGet0PubKey(const DH *dh)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return DH_get0_pub_key(dh);
}

const BIGNUM *OpensslDhGet0PrivKey(const DH *dh)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return DH_get0_priv_key(dh);
}

int OpensslEvpPkeySet1Dh(EVP_PKEY *pkey, DH *key)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EVP_PKEY_set1_DH(pkey, key);
}

DH *OpensslEvpPkeyGet1Dh(EVP_PKEY *pkey)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_PKEY_get1_DH(pkey);
}

int OpensslEvpPkeyAssignDh(EVP_PKEY *pkey, DH *key)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EVP_PKEY_assign_DH(pkey, key);
}

int OpensslEvpPkeyCtxSetDhParamgenPrimeLen(EVP_PKEY_CTX *ctx, int pbits)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EVP_PKEY_CTX_set_dh_paramgen_prime_len(ctx, pbits);
}

int OpensslEvpPkeyCtxSetSignatureMd(EVP_PKEY_CTX *ctx, const EVP_MD *md)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EVP_PKEY_CTX_set_signature_md(ctx, md);
}

int OpensslDhUpRef(DH *r)
{
    if (IsNeedMock()) {
        return -1;
    }
    return DH_up_ref(r);
}

int OpensslDhSet0Pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
    if (IsNeedMock()) {
        return -1;
    }
    return DH_set0_pqg(dh, p, q, g);
}

int OpensslDhSet0Key(DH *dh, BIGNUM *pubKey, BIGNUM *privKey)
{
    if (IsNeedMock()) {
        return -1;
    }
    return DH_set0_key(dh, pubKey, privKey);
}

OSSL_PARAM_BLD *OpensslOsslParamBldNew(void)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return OSSL_PARAM_BLD_new();
}

void OpensslOsslParamBldFree(OSSL_PARAM_BLD *bld)
{
    if (bld != NULL) {
        OSSL_PARAM_BLD_free(bld);
    }
}

OSSL_PARAM *OpensslOsslParamBldToParam(OSSL_PARAM_BLD *bld)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return OSSL_PARAM_BLD_to_param(bld);
}

int OpensslOsslParamBldPushUtf8String(OSSL_PARAM_BLD *bld, const char *key, const char *buf, size_t bsize)
{
    if (IsNeedMock()) {
        return -1;
    }
    return OSSL_PARAM_BLD_push_utf8_string(bld, key, buf, bsize);
}

int OpensslOsslParamBldPushOctetString(OSSL_PARAM_BLD *bld, const char *key, const void *buf, size_t bsize)
{
    if (IsNeedMock()) {
        return -1;
    }
    return OSSL_PARAM_BLD_push_octet_string(bld, key, buf, bsize);
}

int OpensslEvpPkeyCtxSetEcParamgenCurveNid(EVP_PKEY_CTX *ctx, int nid)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid);
}

int OpensslEvpPkeyFromDataInit(EVP_PKEY_CTX *ctx)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EVP_PKEY_fromdata_init(ctx);
}

int OpensslEvpPkeyFromData(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey, int selection, OSSL_PARAM params[])
{
    if (IsNeedMock()) {
        return -1;
    }
    return EVP_PKEY_fromdata(ctx, ppkey, selection, params);
}

EC_KEY *OpensslEvpPkeyGet1EcKey(EVP_PKEY *pkey)
{
    if (IsNeedMock()) {
        return NULL;
    }
    return EVP_PKEY_get1_EC_KEY(pkey);
}

void OpensslOsslParamFree(OSSL_PARAM *params)
{
    if (params != NULL) {
        OSSL_PARAM_free(params);
    }
}

int OpensslEcOct2Point(const EC_GROUP *group, EC_POINT *p, const unsigned char *buf, size_t len, BN_CTX *ctx)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EC_POINT_oct2point(group, p, buf, len, ctx);
}

int OpensslEcPointSetAffineCoordinates(const EC_GROUP *group, EC_POINT *p,
                                       const BIGNUM *x, const BIGNUM *y, BN_CTX *ctx)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EC_POINT_set_affine_coordinates(group, p, x, y, ctx);
}

int OpensslEcPointGetAffineCoordinates(const EC_GROUP *group, const EC_POINT *p,
                                       BIGNUM *x, BIGNUM *y, BN_CTX *ctx)
{
    if (IsNeedMock()) {
        return -1;
    }
    return EC_POINT_get_affine_coordinates(group, p, x, y, ctx);
}

int OpensslEvpPkeyVerifyRecoverInit(EVP_PKEY_CTX *ctx)
{
    return EVP_PKEY_verify_recover_init(ctx);
}

int OpensslEvpPkeyVerifyRecover(EVP_PKEY_CTX *ctx, unsigned char *rout, size_t *routlen, const unsigned char *sig,
    size_t siglen)
{
    return EVP_PKEY_verify_recover(ctx, rout, routlen, sig, siglen);
}

int OpensslEvpPkeySet1EcKey(EVP_PKEY *pkey, EC_KEY *key)
{
    return EVP_PKEY_set1_EC_KEY(pkey, key);
}

EC_GROUP *OpensslEcGroupNewByCurveName(int nid)
{
    return EC_GROUP_new_by_curve_name(nid);
}

int OpensslPemWriteBioRsaPublicKey(BIO *bp, RSA *x)
{
    return PEM_write_bio_RSAPublicKey(bp, x);
}

int OpensslPemWriteBioRsaPubKey(BIO *bp, RSA *x)
{
    return PEM_write_bio_RSA_PUBKEY(bp, x);
}

int OpensslOsslDecoderCtxSetPassPhrase(OSSL_DECODER_CTX *ctx, const unsigned char *kstr, size_t klen)
{
    return OSSL_DECODER_CTX_set_passphrase(ctx, kstr, klen);
}

OSSL_DECODER_CTX *OpensslOsslDecoderCtxNewForPkey(EVP_PKEY **pkey, const char *inputType,
    const char *inputStructure, const char *keytype, int selection, OSSL_LIB_CTX *libctx, const char *propquery)
{
    return OSSL_DECODER_CTX_new_for_pkey(pkey, inputType, inputStructure, keytype, selection, libctx, propquery);
}

int OpensslOsslDecoderFromData(OSSL_DECODER_CTX *ctx, const unsigned char **pdata,
    size_t *len)
{
    return OSSL_DECODER_from_data(ctx, pdata, len);
}

void OpensslOsslDecoderCtxFree(OSSL_DECODER_CTX *ctx)
{
    OSSL_DECODER_CTX_free(ctx);
}

EC_KEY *OpensslEcKeyNewbyCurveNameEx(OSSL_LIB_CTX *ctx, const char *propq, int nid)
{
    return EC_KEY_new_by_curve_name_ex(ctx, propq, nid);
}

int OpensslEvpPkeyGetOctetStringParam(const EVP_PKEY *pkey, const char *keyName, unsigned char *buf, size_t maxBufSz,
    size_t *outLen)
{
    return EVP_PKEY_get_octet_string_param(pkey, keyName, buf, maxBufSz, outLen);
}

void OpensslEcKeySetFlags(EC_KEY *key, int flags)
{
    EC_KEY_set_flags(key, flags);
}

int OpensslEvpPkeyGetBnParam(const EVP_PKEY *pkey, const char *keyName, BIGNUM **bn)
{
    return EVP_PKEY_get_bn_param(pkey, keyName, bn);
}

int OpensslAsn1OctetStringSet(ASN1_OCTET_STRING *x, const unsigned char *d, int len)
{
    return ASN1_STRING_set(x, d, len);
}

const unsigned char *OpensslAsn1StringGet0Data(ASN1_OCTET_STRING *p)
{
    return ASN1_STRING_get0_data(p);
}

int OpensslAsn1StringLength(ASN1_OCTET_STRING *p)
{
    return ASN1_STRING_length(p);
}

void OpensslMacFree(EVP_MAC *mac)
{
    EVP_MAC_free(mac);
}

const EVP_MD *OpensslEvpSm3(void)
{
    return EVP_sm3();
}

int OpensslCmacInit(EVP_MAC_CTX *ctx, const unsigned char *key, size_t keylen, const OSSL_PARAM params[])
{
    return EVP_MAC_init(ctx, key, keylen, params);
}

int OpensslCmacUpdate(EVP_MAC_CTX *ctx, const unsigned char *data, size_t datalen)
{
    return EVP_MAC_update(ctx, data, datalen);
}

int OpensslCmacFinal(EVP_MAC_CTX *ctx, unsigned char *out, size_t *outl, size_t outsize)
{
    return EVP_MAC_final(ctx, out, outl, outsize);
}

size_t OpensslCmacSize(EVP_MAC_CTX *ctx)
{
    return EVP_MAC_CTX_get_mac_size(ctx);
}

void OpensslCmacCtxFree(EVP_MAC_CTX *ctx)
{
    EVP_MAC_CTX_free(ctx);
}

void OpensslEvpMdCtxSetPkeyCtx(EVP_MD_CTX *ctx, EVP_PKEY_CTX *pctx)
{
    EVP_MD_CTX_set_pkey_ctx(ctx, pctx);
}

OSSL_ENCODER_CTX *OpensslOsslEncoderCtxNewForPkey(const EVP_PKEY *pkey, int selection,
    const char *outputType, const char *outputStruct, const char *propquery)
{
    return OSSL_ENCODER_CTX_new_for_pkey(pkey, selection, outputType, outputStruct, propquery);
}

int OpensslOsslEncoderToData(OSSL_ENCODER_CTX *ctx, unsigned char **pdata, size_t *len)
{
    return OSSL_ENCODER_to_data(ctx, pdata, len);
}

void OpensslOsslEncoderCtxFree(OSSL_ENCODER_CTX *ctx)
{
    OSSL_ENCODER_CTX_free(ctx);
}

int OpensslBioWrite(BIO *b, const void *data, int dlen)
{
    return BIO_write(b, data, dlen);
}

EVP_PKEY *OpensslPemReadBioPrivateKey(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u)
{
    return PEM_read_bio_PrivateKey(bp, x, cb, u);
}

int OpensslEvpPkeyIsA(const EVP_PKEY *pkey, const char *name)
{
    return EVP_PKEY_is_a(pkey, name);
}

EVP_KDF *OpensslEvpKdfFetch(OSSL_LIB_CTX *libctx, const char *algorithm,
    const char *properties)
{
    return EVP_KDF_fetch(libctx, algorithm, properties);
}

EVP_KDF_CTX *OpensslEvpKdfCtxNew(EVP_KDF *kdf)
{
    return EVP_KDF_CTX_new(kdf);
}

void OpensslEvpKdfFree(EVP_KDF *kdf)
{
    EVP_KDF_free(kdf);
}

int OpensslEvpKdfDerive(EVP_KDF_CTX *ctx, unsigned char *key, size_t keylen,
    const OSSL_PARAM params[])
{
    return EVP_KDF_derive(ctx, key, keylen, params);
}

void OpensslEvpKdfCtxFree(EVP_KDF_CTX *ctx)
{
    EVP_KDF_CTX_free(ctx);
}

OSSL_PARAM OpensslOsslParamConstructOctetString(const char *key, void *buf, size_t bsize)
{
    return OSSL_PARAM_construct_octet_string(key, buf, bsize);
}

OSSL_PARAM OpensslOsslParamConstructUint64(const char *key, uint64_t *buf)
{
    return OSSL_PARAM_construct_uint64(key, buf);
}

ECDSA_SIG *OpensslEcdsaSigNew()
{
    return ECDSA_SIG_new();
}

ECDSA_SIG *OpensslD2iSm2EcdsaSig(const unsigned char **inputData, int dataLen)
{
    return d2i_ECDSA_SIG(NULL, inputData, dataLen);
}

int OpensslI2dSm2EcdsaSig(ECDSA_SIG *sm2Text, unsigned char **returnData)
{
    return i2d_ECDSA_SIG(sm2Text, returnData);
}

void OpensslSm2EcdsaSigFree(ECDSA_SIG *sm2Text)
{
    return ECDSA_SIG_free(sm2Text);
}

const BIGNUM *OpensslEcdsaSigGet0r(const ECDSA_SIG *sig)
{
    return ECDSA_SIG_get0_r(sig);
}

const BIGNUM *OpensslEcdsaSigGet0s(const ECDSA_SIG *sig)
{
    return ECDSA_SIG_get0_s(sig);
}

int OpensslEcdsaSigSet0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s)
{
    return ECDSA_SIG_set0(sig, r, s);
}

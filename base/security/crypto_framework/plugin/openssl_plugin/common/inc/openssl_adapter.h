/*
 * Copyright (C) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef HCF_OPENSSL_ADAPTER_H
#define HCF_OPENSSL_ADAPTER_H

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/cmac.h>
#include <openssl/rand.h>
#include <openssl/des.h>
#include <openssl/dh.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/types.h>
#include <openssl/obj_mac.h>
#include <openssl/core_names.h>
#include <openssl/ecdsa.h>
#include <crypto/sm2.h>
#include <crypto/x509.h>

#include <openssl/asn1.h>
#include <openssl/asn1t.h>

#include <openssl/encoder.h>
#include <openssl/decoder.h>

#ifdef __cplusplus
extern "C" {
#endif

BIGNUM *OpensslBnDup(const BIGNUM *a);
void OpensslBnClear(BIGNUM *a);
void OpensslBnClearFree(BIGNUM *a);
BIGNUM *OpensslBnNew(void);
void OpensslBnFree(BIGNUM *a);
BIGNUM *OpensslBin2Bn(const unsigned char *s, int len, BIGNUM *ret);
BIGNUM *OpensslLeBin2Bn(const unsigned char *s, int len, BIGNUM *ret);
int OpensslBn2BinPad(const BIGNUM *a, unsigned char *to, int toLen);
int OpensslBn2LeBinPad(const BIGNUM *a, unsigned char *to, int toLen);
int OpensslBnModExp(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *p, BN_CTX *ctx);
BN_CTX *OpensslBnCtxNew(void);
void OpensslBnCtxFree(BN_CTX *ctx);
int OpensslBnNumBytes(const BIGNUM *a);
int OpensslBnSetWord(BIGNUM *a, unsigned int w);
unsigned int OpensslBnGetWord(const BIGNUM *a);
int OpensslBnNumBits(const BIGNUM *a);
int OpensslHex2Bn(BIGNUM **a, const char *str);
int OpensslBnCmp(const BIGNUM *a, const BIGNUM *b);

EC_KEY *OpensslEcKeyNewByCurveName(int nid);
EC_POINT *OpensslEcPointDup(const EC_POINT *src, const EC_GROUP *group);
int OpensslEcKeyGenerateKey(EC_KEY *ecKey);
int OpensslEcKeySetPublicKey(EC_KEY *key, const EC_POINT *pub);
int OpensslEcKeySetPrivateKey(EC_KEY *key, const BIGNUM *privKey);
int OpensslEcKeyCheckKey(const EC_KEY *key);
const EC_POINT *OpensslEcKeyGet0PublicKey(const EC_KEY *key);
const BIGNUM *OpensslEcKeyGet0PrivateKey(const EC_KEY *key);
const EC_GROUP *OpensslEcKeyGet0Group(const EC_KEY *key);
int OpensslI2dEcPubKey(EC_KEY *a, unsigned char **pp);
int OpensslI2dEcPrivateKey(EC_KEY *key, unsigned char **out);
EC_KEY *OpensslD2iEcPubKey(EC_KEY **a, const unsigned char **pp, long length);
EC_KEY *OpensslD2iEcPrivateKey(EC_KEY **key, const unsigned char **in, long len);
void OpensslEcKeySetAsn1Flag(EC_KEY *key, int flag);
void OpensslEcKeySetEncFlags(EC_KEY *ecKey, unsigned int flags);
void OpensslEcKeyFree(EC_KEY *key);
void OpensslEcPointFree(EC_POINT *point);
EC_GROUP *OpensslEcGroupNewCurveGfp(const BIGNUM *p, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
void OpensslEcGroupFree(EC_GROUP *group);
EC_POINT *OpensslEcPointNew(const EC_GROUP *group);
int OpensslEcPointCopy(EC_POINT *dst, const EC_POINT *src);
int OpensslEcPointSetAffineCoordinatesGfp(const EC_GROUP *group, EC_POINT *point, const BIGNUM *x,
    const BIGNUM *y, BN_CTX *ctx);
int OpensslEcGroupSetGenerator(EC_GROUP *group, const EC_POINT *generator,
    const BIGNUM *order, const BIGNUM *cofactor);
EC_KEY *OpensslEcKeyNew(void);
EC_KEY *OpensslEcKeyDup(const EC_KEY *ecKey);
int OpensslEcKeySetGroup(EC_KEY *key, const EC_GROUP *group);
int OpensslEcGroupGetCurveGfp(const EC_GROUP *group, BIGNUM *p, BIGNUM *a, BIGNUM *b, BN_CTX *ctx);
const EC_POINT *OpensslEcGroupGet0Generator(const EC_GROUP *group);
int OpensslEcPointGetAffineCoordinatesGfp(const EC_GROUP *group, const EC_POINT *point, BIGNUM *x,
    BIGNUM *y, BN_CTX *ctx);
int OpensslEcGroupGetOrder(const EC_GROUP *group, BIGNUM *order, BN_CTX *ctx);
int OpensslEcGroupGetCofactor(const EC_GROUP *group, BIGNUM *cofactor, BN_CTX *ctx);
int OpensslEcGroupGetDegree(const EC_GROUP *group);
EC_GROUP *OpensslEcGroupDup(const EC_GROUP *a);
void OpensslEcGroupSetCurveName(EC_GROUP *group, int nid);
int OpensslEcGroupGetCurveName(const EC_GROUP *group);
int OpensslEcPointMul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *gScalar, const EC_POINT *point,
    const BIGNUM *pScalar, BN_CTX *ctx);

EVP_MD_CTX *OpensslEvpMdCtxNew(void);
void OpensslEvpMdCtxFree(EVP_MD_CTX *ctx);
void OpensslEvpMdCtxSetPkeyCtx(EVP_MD_CTX *ctx, EVP_PKEY_CTX *pctx);
EVP_PKEY_CTX *OpensslEvpMdCtxGetPkeyCtx(EVP_MD_CTX *ctx);
int OpensslEvpDigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
int OpensslEvpDigestSignUpdate(EVP_MD_CTX *ctx, const void *data, size_t count);
int OpensslEvpDigestSignFinal(EVP_MD_CTX *ctx, unsigned char *sigret, size_t *siglen);
int OpensslEvpDigestSign(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen,
    const unsigned char *tbs, size_t tbslen);
int OpensslEvpDigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
int OpensslEvpDigestVerifyUpdate(EVP_MD_CTX *ctx, const void *data, size_t count);
int OpensslEvpDigestVerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen);
int OpensslEvpDigestVerify(EVP_MD_CTX *ctx, unsigned char *sig, size_t siglen,
    const unsigned char *tbs, size_t tbslen);
int OpensslEvpPkeySignInit(EVP_PKEY_CTX *ctx);
int OpensslEvpPkeySign(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, const unsigned char *tbs,
    size_t tbslen);
int OpensslEvpPkeyVerifyInit(EVP_PKEY_CTX *ctx);
int OpensslEvpPkeyVerify(EVP_PKEY_CTX *ctx, const unsigned char *sig, size_t siglen, const unsigned char *tbs,
    size_t tbslen);

EVP_PKEY *OpensslEvpPkeyNew(void);
EVP_PKEY *OpensslEvpPkeyNewRawPublicKey(int type, ENGINE *e, const unsigned char *pub, size_t len);
EVP_PKEY *OpensslEvpPkeyNewRawPrivateKey(int type, ENGINE *e, const unsigned char *pub, size_t len);
int OpensslEvpPkeyGetRawPublicKey(const EVP_PKEY *pkey, unsigned char *pub, size_t *len);
int OpensslEvpPkeyGetRawPrivateKey(const EVP_PKEY *pkey, unsigned char *priv, size_t *len);
int OpensslEvpPkeyAssignEcKey(EVP_PKEY *pkey, EC_KEY *key);
int OpensslEvpPkeySet1EcKey(EVP_PKEY *pkey, EC_KEY *key);
void OpensslEvpPkeyFree(EVP_PKEY *pkey);
EVP_PKEY_CTX *OpensslEvpPkeyCtxNewFromPkey(OSSL_LIB_CTX *libctx,
    EVP_PKEY *pkey, const char *propquery);
EVP_PKEY_CTX *OpensslEvpPkeyCtxNew(EVP_PKEY *pkey, ENGINE *e);
int OpensslEvpPkeyDeriveInit(EVP_PKEY_CTX *ctx);
int OpensslEvpPkeyDeriveSetPeer(EVP_PKEY_CTX *ctx, EVP_PKEY *peer);
int OpensslEvpPkeyDerive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *keylen);
void OpensslEvpPkeyCtxFree(EVP_PKEY_CTX *ctx);

// new added
int OpensslEvpPkeyEncrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
    const unsigned char *in, size_t inlen);
int OpensslEvpPkeyDecrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
    const unsigned char *in, size_t inlen);
int OpensslEvpPkeyEncryptInit(EVP_PKEY_CTX *ctx);
int OpensslEvpPkeyDecryptInit(EVP_PKEY_CTX *ctx);

EVP_PKEY_CTX *OpensslEvpPkeyCtxNewId(int id, ENGINE *e);
int OpensslEvpPkeyBaseId(EVP_PKEY *pkey);
EVP_PKEY_CTX *OpensslEvpPkeyCtxNewFromName(OSSL_LIB_CTX *libctx, const char *name, const char *propquery);
int OpensslEvpPkeyVerifyRecoverInit(EVP_PKEY_CTX *ctx);
int OpensslEvpPkeyVerifyRecover(EVP_PKEY_CTX *ctx, unsigned char *rout, size_t *routlen, const unsigned char *sig,
    size_t siglen);
OSSL_PARAM OpensslOsslParamConstructUtf8String(const char *key, char *buf, size_t bsize);
OSSL_PARAM OpensslOsslParamConstructOctetString(const char *key, void *buf, size_t bsize);
OSSL_PARAM OpensslOsslParamConstructEnd(void);
OSSL_PARAM OpensslOsslParamConstructUint(const char *key, unsigned int *buf);
OSSL_PARAM OpensslOsslParamConstructInt(const char *key, int *buf);
OSSL_PARAM OpensslOsslParamConstructUint64(const char *key, uint64_t *buf);
int OpensslEvpPkeyGenerate(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey);
int OpensslEvpPkeyCtxSet1Id(EVP_PKEY_CTX *ctx, const void *id, int idLen);
int OpensslEvpPkeyParamGenInit(EVP_PKEY_CTX *ctx);
int OpensslEvpPkeyCtxSetDsaParamgenBits(EVP_PKEY_CTX *ctx, int nbits);
int OpensslEvpPkeyCtxSetParams(EVP_PKEY_CTX *ctx, const OSSL_PARAM *params);
int OpensslEvpPkeyParamGen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey);
int OpensslEvpPkeyKeyGenInit(EVP_PKEY_CTX *ctx);
int OpensslEvpPkeyKeyGen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey);
int OpensslEvpPkeySet1Dsa(EVP_PKEY *pkey, DSA *key);
DSA *OpensslEvpPkeyGet1Dsa(EVP_PKEY *pkey);
DSA *OpensslDsaNew(void);
void OpensslDsaFree(DSA *dsa);
int OpensslDsaUpRef(DSA *dsa);
int OpensslDsaSet0Pqg(DSA *dsa, BIGNUM *p, BIGNUM *q, BIGNUM *g);
int OpensslDsaSet0Key(DSA *dsa, BIGNUM *pubKey, BIGNUM *priKey);
const BIGNUM *OpensslDsaGet0P(const DSA *dsa);
const BIGNUM *OpensslDsaGet0Q(const DSA *dsa);
const BIGNUM *OpensslDsaGet0G(const DSA *dsa);
void OpensslDsaGet0Pqg(const DSA *dsa, const BIGNUM **p, const BIGNUM **q, const BIGNUM **g);
const BIGNUM *OpensslDsaGet0PubKey(const DSA *dsa);
const BIGNUM *OpensslDsaGet0PrivKey(const DSA *dsa);
int OpensslDsaBits(const DSA *dsa);
int OpensslDsaGenerateKey(DSA *a);
DSA *OpensslD2iDsaPubKey(DSA **dsa, const unsigned char **ppin, long length);
DSA *OpensslD2iDsaPrivateKey(DSA **dsa, const unsigned char **ppin, long length);
int OpensslI2dDsaPubkey(DSA *dsa, unsigned char **ppout);
int OpensslI2dDsaPrivateKey(DSA *dsa, unsigned char **ppout);

int OpensslEvpPkeyCheck(EVP_PKEY_CTX *ctx);
EVP_PKEY *OpensslEvpPkeyDup(EVP_PKEY *a);
EVP_PKEY *OpensslD2iPubKey(EVP_PKEY **a, const unsigned char **pp, long length);
EVP_PKEY *OpensslD2iPrivateKey(int type, EVP_PKEY **a, const unsigned char **pp, long length);
int OpensslI2dPubKey(EVP_PKEY *pkey, unsigned char **ppout);
int OpensslI2dPrivateKey(EVP_PKEY *pkey, unsigned char **ppout);
RSA *OpensslRsaNew(void);
void OpensslRsaFree(RSA *rsa);
int OpensslRsaGenerateMultiPrimeKey(RSA *rsa, int bits, int primes,
    BIGNUM *e, BN_GENCB *cb);
int OpensslRsaGenerateKeyEx(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);
int OpensslRsaBits(const RSA *rsa);
int OpensslRsaSet0Key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d);
void OpensslRsaGet0Key(const RSA *r, const BIGNUM **n, const BIGNUM **e, const BIGNUM **d);
const BIGNUM *OpensslRsaGet0N(const RSA *d);
const BIGNUM *OpensslRsaGet0E(const RSA *d);
const BIGNUM *OpensslRsaGet0D(const RSA *d);
void OpensslRsaGet0Factors(const RSA *r, const BIGNUM **p, const BIGNUM **q);
RSA *OpensslRsaPublicKeyDup(RSA *rsa);
RSA *OpensslRsaPrivateKeyDup(RSA *rsa);
RSA *OpensslD2iRsaPubKey(RSA **a, const unsigned char **pp, long length);
int OpensslI2dRsaPubKey(RSA *a, unsigned char **pp);
RSA *OpensslD2iRsaPublicKey(RSA **a, const unsigned char **pp, long length);
int OpensslI2dRsaPublicKey(RSA *a, unsigned char **pp);
RSA *OpensslD2iRsaPrivateKey(RSA **a, const unsigned char **pp, long length);
int OpensslI2dRsaPrivateKey(RSA *a, unsigned char **pp);
int OpensslEvpPkeyCtxSetRsaPssSaltLen(EVP_PKEY_CTX *ctx, int saltlen);
int OpensslEvpPkeyCtxGetRsaPssSaltLen(EVP_PKEY_CTX *ctx, int *saltlen);
int OpensslEvpPkeyCtxSetRsaPadding(EVP_PKEY_CTX *ctx, int pad);
int OpensslEvpPkeyCtxSetRsaMgf1Md(EVP_PKEY_CTX *ctx, const EVP_MD *md);
int OpensslEvpPkeyCtxSetRsaOaepMd(EVP_PKEY_CTX *ctx, const EVP_MD *md);
int OpensslEvpPkeyCtxSet0RsaOaepLabel(EVP_PKEY_CTX *ctx, void *label, int len);
int OpensslEvpPkeyCtxGet0RsaOaepLabel(EVP_PKEY_CTX *ctx, unsigned char **label);
EVP_PKEY *OpensslD2iAutoPrivateKey(EVP_PKEY **a, const unsigned char **pp, long length);
struct rsa_st *OpensslEvpPkeyGet1Rsa(EVP_PKEY *pkey);
int OpensslEvpPkeySet1Rsa(EVP_PKEY *pkey, struct rsa_st *key);
int OpensslEvpPkeyAssignRsa(EVP_PKEY *pkey, struct rsa_st *key);
int OpensslPemWriteBioRsaPublicKey(BIO *bp, RSA *x);
int OpensslPemWriteBioRsaPubKey(BIO *bp, RSA *x);
EVP_PKEY *OpensslPemReadBioPrivateKey(BIO *bp, EVP_PKEY **x, pem_password_cb *cb, void *u);

// BIO
BIO *OpensslBioNew(const BIO_METHOD *type);
const BIO_METHOD *OpensslBioSMem(void);
int OpensslBioWrite(BIO *b, const void *data, int dlen);
int OpensslBioRead(BIO *b, void *data, int dlen);
void OpensslBioFreeAll(BIO *a);

int OpensslRandPrivBytesEx(OSSL_LIB_CTX *libCtx, unsigned char *buf, size_t num);
int OpensslRandSetSeedSourceType(OSSL_LIB_CTX *libCtx, const char *name, const char *proPq);
void OpensslRandSeed(const void *buf, int num);

const EVP_MD *OpensslEvpSha1(void);
const EVP_MD *OpensslEvpSha3256(void);
const EVP_MD *OpensslEvpSha3384(void);
const EVP_MD *OpensslEvpSha3512(void);
const EVP_MD *OpensslEvpSha224(void);
const EVP_MD *OpensslEvpSha256(void);
const EVP_MD *OpensslEvpSha384(void);
const EVP_MD *OpensslEvpSha512(void);
const EVP_MD *OpensslEvpMd2(void);
const EVP_MD *OpensslEvpMd4(void);
const EVP_MD *OpensslEvpRipemd160(void);
const EVP_MD *OpensslEvpMd5(void);
const EVP_MD *OpensslEvpSm3(void);
int OpensslEvpDigestFinalEx(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *size);
int OpensslEvpMdCtxSize(const EVP_MD_CTX *ctx);
int OpensslEvpDigestInitEx(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);

int OpensslHmacInitEx(HMAC_CTX *ctx, const void *key, int len, const EVP_MD *md, ENGINE *impl);
int OpensslHmacFinal(HMAC_CTX *ctx, unsigned char *md, unsigned int *len);
size_t OpensslHmacSize(const HMAC_CTX *ctx);
void OpensslHmacCtxFree(HMAC_CTX *ctx);
HMAC_CTX *OpensslHmacCtxNew(void);

int OpensslCmacInit(EVP_MAC_CTX *ctx, const unsigned char *key, size_t keylen, const OSSL_PARAM params[]);
int OpensslCmacUpdate(EVP_MAC_CTX *ctx, const unsigned char *data, size_t datalen);
int OpensslCmacFinal(EVP_MAC_CTX *ctx, unsigned char *out, size_t *outl, size_t outsize);
size_t OpensslCmacSize(EVP_MAC_CTX *ctx);
void OpensslCmacCtxFree(EVP_MAC_CTX *ctx);
EVP_MAC_CTX *OpensslCmacCtxNew(EVP_MAC *mac);
void OpensslMacFree(EVP_MAC *mac);

void OpensslEvpCipherCtxFree(EVP_CIPHER_CTX *ctx);
const EVP_CIPHER *OpensslEvpAes128Ecb(void);
const EVP_CIPHER *OpensslEvpAes192Ecb(void);
const EVP_CIPHER *OpensslEvpAes256Ecb(void);
const EVP_CIPHER *OpensslEvpAes128Cbc(void);
const EVP_CIPHER *OpensslEvpAes192Cbc(void);
const EVP_CIPHER *OpensslEvpAes256Cbc(void);
const EVP_CIPHER *OpensslEvpAes128Ctr(void);
const EVP_CIPHER *OpensslEvpAes192Ctr(void);
const EVP_CIPHER *OpensslEvpAes256Ctr(void);
const EVP_CIPHER *OpensslEvpAes128Ofb(void);
const EVP_CIPHER *OpensslEvpAes192Ofb(void);
const EVP_CIPHER *OpensslEvpAes256Ofb(void);
const EVP_CIPHER *OpensslEvpAes128Cfb(void);
const EVP_CIPHER *OpensslEvpAes192Cfb(void);
const EVP_CIPHER *OpensslEvpAes256Cfb(void);
const EVP_CIPHER *OpensslEvpAes128Cfb1(void);
const EVP_CIPHER *OpensslEvpAes192Cfb1(void);
const EVP_CIPHER *OpensslEvpAes256Cfb1(void);
const EVP_CIPHER *OpensslEvpAes128Cfb128(void);
const EVP_CIPHER *OpensslEvpAes192Cfb128(void);
const EVP_CIPHER *OpensslEvpAes256Cfb128(void);
const EVP_CIPHER *OpensslEvpAes128Cfb8(void);
const EVP_CIPHER *OpensslEvpAes192Cfb8(void);
const EVP_CIPHER *OpensslEvpAes256Cfb8(void);
const EVP_CIPHER *OpensslEvpAes128Ccm(void);
const EVP_CIPHER *OpensslEvpAes192Ccm(void);
const EVP_CIPHER *OpensslEvpAes256Ccm(void);
const EVP_CIPHER *OpensslEvpAes128Gcm(void);
const EVP_CIPHER *OpensslEvpAes192Gcm(void);
const EVP_CIPHER *OpensslEvpAes256Gcm(void);
const EVP_CIPHER *OpensslEvpAes128Wrap(void);
const EVP_CIPHER *OpensslEvpAes192Wrap(void);
const EVP_CIPHER *OpensslEvpAes256Wrap(void);
const EVP_CIPHER *OpensslEvpAes128Xts(void);
const EVP_CIPHER *OpensslEvpAes256Xts(void);
const EVP_CIPHER *OpensslEvpSm4Ecb(void);
const EVP_CIPHER *OpensslEvpSm4Cbc(void);
const EVP_CIPHER *OpensslEvpSm4Cfb(void);
const EVP_CIPHER *OpensslEvpSm4Cfb128(void);
const EVP_CIPHER *OpensslEvpSm4Ctr(void);
const EVP_CIPHER *OpensslEvpSm4Ofb(void);
const EVP_CIPHER *OpensslEvpDesEde3Ecb(void);
const EVP_CIPHER *OpensslEvpDesEde3Cbc(void);
const EVP_CIPHER *OpensslEvpDesEde3Ofb(void);
const EVP_CIPHER *OpensslEvpDesEde3Cfb64(void);
const EVP_CIPHER *OpensslEvpDesEde3Cfb1(void);
const EVP_CIPHER *OpensslEvpDesEde3Cfb8(void);
const EVP_CIPHER *OpensslEvpDesEcb(void);
const EVP_CIPHER *OpensslEvpDesCbc(void);
const EVP_CIPHER *OpensslEvpDesOfb(void);
const EVP_CIPHER *OpensslEvpDesCfb64(void);
const EVP_CIPHER *OpensslEvpDesCfb1(void);
const EVP_CIPHER *OpensslEvpDesCfb8(void);
const EVP_CIPHER *OpensslEvpChaCha20(void);
const EVP_CIPHER *OpensslEvpChaCha20Poly1305(void);
EVP_CIPHER *OpensslEvpCipherFetch(OSSL_LIB_CTX *ctx, const char *algorithm, const char *properties);
void OpensslEvpCipherFree(EVP_CIPHER *cipher);
EVP_CIPHER_CTX *OpensslEvpCipherCtxNew(void);
int OpensslEvpCipherInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
    const unsigned char *key, const unsigned char *iv, int enc);
int OpensslEvpCipherCtxSetPadding(EVP_CIPHER_CTX *ctx, int pad);
int OpensslEvpCipherCtxSetKeyLength(EVP_CIPHER_CTX *ctx, int keylen);

int OpensslEvpCipherFinalEx(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
int OpensslEvpCipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);

int OpensslSm2CipherTextSize(const EC_KEY *key, const EVP_MD *digest, size_t msgLen, size_t *cipherTextSize);
int OpensslSm2PlainTextSize(const unsigned char *cipherText, size_t cipherTextSize, size_t *plainTextSize);
int OpensslOsslSm2Encrypt(const EC_KEY *key, const EVP_MD *digest, const uint8_t *msg,
    size_t msgLen, uint8_t *cipherTextBuf, size_t *cipherTextLen);

int OpensslOsslSm2Decrypt(const EC_KEY *key, const EVP_MD *digest, const uint8_t *cipherText,
    size_t cipherTextLen, uint8_t *plainTextBuf, size_t *plainTextLen);

int OpensslPkcs5Pbkdf2Hmac(const char *pass, int passlen, const unsigned char *salt,
    int saltlen, int iter, const EVP_MD *digest, int keylen, unsigned char *out);

EC_GROUP *OpensslEcGroupNewByCurveName(int nid);

int OpensslEvpEncryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher,
    const unsigned char *key, const unsigned char *iv);
int OpensslEvpCipherCtxCtrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);

DH *OpensslDhNew(void);
int OpensslDhComputeKeyPadded(unsigned char *key, const BIGNUM *pubKey, DH *dh);
void OpensslDhFree(DH *dh);
int OpensslDhGenerateKey(DH *dh);
const BIGNUM *OpensslDhGet0P(const DH *dh);
const BIGNUM *OpensslDhGet0Q(const DH *dh);
const BIGNUM *OpensslDhGet0G(const DH *dh);
void OpensslDhGet0Pqg(const DH *dh, const BIGNUM **p, const BIGNUM **q, const BIGNUM **g);
long OpensslDhGetLength(const DH *dh);
int OpensslDhSetLength(DH *dh, long length);
int OpensslDhBits(const DH *dh);
const BIGNUM *OpensslDhGet0PubKey(const DH *dh);
const BIGNUM *OpensslDhGet0PrivKey(const DH *dh);
int OpensslEvpPkeySet1Dh(EVP_PKEY *pkey, DH *key);
int OpensslEvpPkeyAssignDh(EVP_PKEY *pkey, DH *key);
struct dh_st *OpensslEvpPkeyGet1Dh(EVP_PKEY *pkey);
int OpensslEvpPkeyIsA(const EVP_PKEY *pkey, const char *name);
int OpensslEvpPkeyCtxSetDhParamgenPrimeLen(EVP_PKEY_CTX *ctx, int pbits);
int OpensslEvpPkeyCtxSetSignatureMd(EVP_PKEY_CTX *ctx, const EVP_MD *md);
int OpensslDhUpRef(DH *r);
int OpensslDhSet0Pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g);
int OpensslDhSet0Key(DH *dh, BIGNUM *pubKey, BIGNUM *privKey);
EVP_KDF *OpensslEvpKdfFetch(OSSL_LIB_CTX *libctx, const char *algorithm,
    const char *properties);
EVP_KDF_CTX *OpensslEvpKdfCtxNew(EVP_KDF *kdf);
void OpensslEvpKdfFree(EVP_KDF *kdf);
void OpensslEvpKdfCtxFree(EVP_KDF_CTX *ctx);
int OpensslEvpKdfDerive(EVP_KDF_CTX *ctx, unsigned char *key, size_t keylen,
    const OSSL_PARAM params[]);

// SM2 ASN1
typedef struct Sm2CipherTextSt Sm2CipherText;
DECLARE_ASN1_FUNCTIONS(Sm2CipherText)

struct Sm2CipherTextSt {
    BIGNUM *c1X;
    BIGNUM *c1Y;
    ASN1_OCTET_STRING *c3;
    ASN1_OCTET_STRING *c2;
};

typedef struct ECDSA_SIG_st ECDSA_SIG;

ECDSA_SIG *OpensslEcdsaSigNew();
ECDSA_SIG *OpensslD2iSm2EcdsaSig(const unsigned char **inputData, int dataLen);
int OpensslI2dSm2EcdsaSig(ECDSA_SIG *sm2Text, unsigned char **returnData);
void OpensslSm2EcdsaSigFree(ECDSA_SIG *sm2Text);
const BIGNUM *OpensslEcdsaSigGet0r(const ECDSA_SIG *sig);
const BIGNUM *OpensslEcdsaSigGet0s(const ECDSA_SIG *sig);
int OpensslEcdsaSigSet0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s);

void OpensslSm2CipherTextFree(struct Sm2CipherTextSt *sm2Text);
struct Sm2CipherTextSt *OpensslD2iSm2CipherText(const uint8_t *ciphertext, size_t cipherTextLen);
void OpensslAsn1OctetStringFree(ASN1_OCTET_STRING *field);
ASN1_OCTET_STRING *OpensslAsn1OctetStringNew(void);
int OpensslAsn1OctetStringSet(ASN1_OCTET_STRING *x, const unsigned char *d, int len);
struct Sm2CipherTextSt *OpensslSm2CipherTextNew(void);
int OpensslI2dSm2CipherText(struct Sm2CipherTextSt *sm2Text, unsigned char **returnData);
int OpensslAsn1StringLength(ASN1_OCTET_STRING *p);
const unsigned char *OpensslAsn1StringGet0Data(ASN1_OCTET_STRING *p);

OSSL_PARAM_BLD *OpensslOsslParamBldNew(void);
void OpensslOsslParamBldFree(OSSL_PARAM_BLD *bld);
OSSL_PARAM *OpensslOsslParamBldToParam(OSSL_PARAM_BLD *bld);
int OpensslOsslParamBldPushUtf8String(OSSL_PARAM_BLD *bld, const char *key, const char *buf, size_t bsize);
int OpensslOsslParamBldPushOctetString(OSSL_PARAM_BLD *bld, const char *key, const void *buf, size_t bsize);
int OpensslEvpPkeyCtxSetEcParamgenCurveNid(EVP_PKEY_CTX *ctx, int nid);
int OpensslEvpPkeyFromDataInit(EVP_PKEY_CTX *ctx);
int OpensslEvpPkeyFromData(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey, int selection, OSSL_PARAM params[]);
EC_KEY *OpensslEvpPkeyGet1EcKey(EVP_PKEY *pkey);
void OpensslOsslParamFree(OSSL_PARAM *params);
int OpensslEcOct2Point(const EC_GROUP *group, EC_POINT *p, const unsigned char *buf, size_t len, BN_CTX *ctx);
int OpensslEcPointSetAffineCoordinates(const EC_GROUP *group, EC_POINT *p,
    const BIGNUM *x, const BIGNUM *y, BN_CTX *ctx);
int OpensslEcPointGetAffineCoordinates(const EC_GROUP *group, const EC_POINT *p,
    BIGNUM *x, BIGNUM *y, BN_CTX *ctx);
OSSL_ENCODER_CTX *OpensslOsslEncoderCtxNewForPkey(const EVP_PKEY *pkey, int selection,
    const char *outputType, const char *outputStruct, const char *propquery);
int OpensslOsslEncoderToData(OSSL_ENCODER_CTX *ctx, unsigned char **pdata, size_t *len);
int OpensslOsslDecoderCtxSetPassPhrase(OSSL_DECODER_CTX *ctx, const unsigned char *kstr, size_t klen);
void OpensslOsslEncoderCtxFree(OSSL_ENCODER_CTX *ctx);
OSSL_DECODER_CTX *OpensslOsslDecoderCtxNewForPkey(EVP_PKEY **pkey, const char *inputType,
    const char *inputStructure, const char *keytype, int selection, OSSL_LIB_CTX *libctx, const char *propquery);
int OpensslOsslDecoderFromData(OSSL_DECODER_CTX *ctx, const unsigned char **pdata,
    size_t *len);
void OpensslOsslDecoderCtxFree(OSSL_DECODER_CTX *ctx);
EC_KEY *OpensslEcKeyNewbyCurveNameEx(OSSL_LIB_CTX *ctx, const char *propq, int nid);
int OpensslEvpPkeyGetOctetStringParam(const EVP_PKEY *pkey, const char *keyName, unsigned char *buf, size_t maxBufSz,
    size_t *outLen);
void OpensslEcKeySetFlags(EC_KEY *key, int flags);
int OpensslEvpPkeyGetBnParam(const EVP_PKEY *pkey, const char *keyName, BIGNUM **bn);

#ifdef __cplusplus
}
#endif

#endif

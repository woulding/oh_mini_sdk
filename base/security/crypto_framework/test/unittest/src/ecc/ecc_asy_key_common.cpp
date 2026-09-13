/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#include <string>
#include "securec.h"

#include "asy_key_generator.h"
#include "detailed_ecc_key_params.h"
#include "ecc_asy_key_common.h"
#include "ecc_asy_key_generator_openssl.h"
#include "ecc_openssl_common.h"
#include "ecc_openssl_common_param_spec.h"
#include "ecc_common.h"
#include "blob.h"
#include "memory_mock.h"
#include "openssl_adapter_mock.h"
#include "openssl_class.h"
#include "openssl_common.h"
#include "params_parser.h"

static const bool IS_BIG_ENDIAN = IsBigEndian();

HcfResult ConstructEcc192CommParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccCommParamsSpec *eccCommSpec = &g_ecc192CommSpec;
    HcfECField *tmpField = reinterpret_cast<HcfECField *>(&g_fieldFp);

    eccCommSpec->base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccCommSpec->base.specType = HCF_COMMON_PARAMS_SPEC;
    eccCommSpec->field = tmpField;
    eccCommSpec->field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    (reinterpret_cast<HcfECFieldFp *>(eccCommSpec->field))->p.data =
        (IS_BIG_ENDIAN ? g_ecc192CorrectBigP : g_ecc192CorrectLittleP);
    (reinterpret_cast<HcfECFieldFp *>(eccCommSpec->field))->p.len = NID_SECP192R1_LEN;
    eccCommSpec->a.data = (IS_BIG_ENDIAN ? g_ecc192CorrectBigA : g_ecc192CorrectLittleA);
    eccCommSpec->a.len = NID_SECP192R1_LEN;
    eccCommSpec->b.data = (IS_BIG_ENDIAN ? g_ecc192CorrectBigB : g_ecc192CorrectLittleB);
    eccCommSpec->b.len = NID_SECP192R1_LEN;
    eccCommSpec->g.x.data = (IS_BIG_ENDIAN ? g_ecc192CorrectBigGX : g_ecc192CorrectLittleGX);
    eccCommSpec->g.x.len = NID_SECP192R1_LEN;
    eccCommSpec->g.y.data = (IS_BIG_ENDIAN ? g_ecc192CorrectBigGY : g_ecc192CorrectLittleGY);
    eccCommSpec->g.y.len = NID_SECP192R1_LEN;
    eccCommSpec->n.data = (IS_BIG_ENDIAN ? g_ecc192CorrectBigN : g_ecc192CorrectLittleN);
    eccCommSpec->n.len = NID_SECP192R1_LEN;
    eccCommSpec->h = g_ecc192CorrectH;

    *spec = reinterpret_cast<HcfAsyKeyParamsSpec *>(eccCommSpec);
    return HCF_SUCCESS;
}

HcfResult ConstructEcc224CommParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccCommParamsSpec *eccCommSpec = &g_ecc224CommSpec;
    HcfECField *tmpField = reinterpret_cast<HcfECField *>(&g_fieldFp);

    eccCommSpec->base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccCommSpec->base.specType = HCF_COMMON_PARAMS_SPEC;
    eccCommSpec->field = tmpField;
    eccCommSpec->field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    (reinterpret_cast<HcfECFieldFp *>(eccCommSpec->field))->p.data =
        (IS_BIG_ENDIAN ? g_ecc224CorrectBigP : g_ecc224CorrectLittleP);
    (reinterpret_cast<HcfECFieldFp *>(eccCommSpec->field))->p.len = NID_secp224r1_len;
    eccCommSpec->a.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigA : g_ecc224CorrectLittleA);
    eccCommSpec->a.len = NID_secp224r1_len;
    eccCommSpec->b.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigB : g_ecc224CorrectLittleB);
    eccCommSpec->b.len = NID_secp224r1_len;
    eccCommSpec->g.x.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigGX : g_ecc224CorrectLittleGX);
    eccCommSpec->g.x.len = NID_secp224r1_len;
    eccCommSpec->g.y.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigGY : g_ecc224CorrectLittleGY);
    eccCommSpec->g.y.len = NID_secp224r1_len;
    eccCommSpec->n.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigN : g_ecc224CorrectLittleN);
    eccCommSpec->n.len = NID_secp224r1_len;
    eccCommSpec->h = g_ecc224CorrectH;

    *spec = reinterpret_cast<HcfAsyKeyParamsSpec *>(eccCommSpec);
    return HCF_SUCCESS;
}

HcfResult ConstructEcc224PubKeyParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccPubKeyParamsSpec *eccPubKeySpec = &g_ecc224PubKeySpec;
    HcfECField *tmpField = reinterpret_cast<HcfECField *>(&g_fieldFp);

    eccPubKeySpec->base.base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccPubKeySpec->base.base.specType = HCF_PUBLIC_KEY_SPEC;
    eccPubKeySpec->base.field = tmpField;
    eccPubKeySpec->base.field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    (reinterpret_cast<HcfECFieldFp *>(eccPubKeySpec->base.field))->p.data =
        (IS_BIG_ENDIAN ? g_ecc224CorrectBigP : g_ecc224CorrectLittleP);
    (reinterpret_cast<HcfECFieldFp *>(eccPubKeySpec->base.field))->p.len = NID_secp224r1_len;
    eccPubKeySpec->base.a.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigA : g_ecc224CorrectLittleA);
    eccPubKeySpec->base.a.len = NID_secp224r1_len;
    eccPubKeySpec->base.b.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigB : g_ecc224CorrectLittleB);
    eccPubKeySpec->base.b.len = NID_secp224r1_len;
    eccPubKeySpec->base.g.x.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigGX : g_ecc224CorrectLittleGX);
    eccPubKeySpec->base.g.x.len = NID_secp224r1_len;
    eccPubKeySpec->base.g.y.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigGY : g_ecc224CorrectLittleGY);
    eccPubKeySpec->base.g.y.len = NID_secp224r1_len;
    eccPubKeySpec->base.n.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigN : g_ecc224CorrectLittleN);
    eccPubKeySpec->base.n.len = NID_secp224r1_len;
    eccPubKeySpec->base.h = g_ecc224CorrectH;
    eccPubKeySpec->pk.x.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigPkX : g_ecc224CorrectLittlePkX);
    eccPubKeySpec->pk.x.len = NID_secp224r1_len;
    eccPubKeySpec->pk.y.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigPkY : g_ecc224CorrectLittlePkY);
    eccPubKeySpec->pk.y.len = NID_secp224r1_len;

    *spec = reinterpret_cast<HcfAsyKeyParamsSpec *>(eccPubKeySpec);
    return HCF_SUCCESS;
}

HcfResult ConstructEcc224PriKeyParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccPriKeyParamsSpec *eccPriKeySpec = &g_ecc224PriKeySpec;
    HcfECField *tmpField = reinterpret_cast<HcfECField *>(&g_fieldFp);

    eccPriKeySpec->base.base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccPriKeySpec->base.base.specType = HCF_PRIVATE_KEY_SPEC;
    eccPriKeySpec->base.field = tmpField;
    eccPriKeySpec->base.field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    (reinterpret_cast<HcfECFieldFp *>(eccPriKeySpec->base.field))->p.data =
        (IS_BIG_ENDIAN ? g_ecc224CorrectBigP : g_ecc224CorrectLittleP);
    (reinterpret_cast<HcfECFieldFp *>(eccPriKeySpec->base.field))->p.len = NID_secp224r1_len;
    eccPriKeySpec->base.a.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigA : g_ecc224CorrectLittleA);
    eccPriKeySpec->base.a.len = NID_secp224r1_len;
    eccPriKeySpec->base.b.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigB : g_ecc224CorrectLittleB);
    eccPriKeySpec->base.b.len = NID_secp224r1_len;
    eccPriKeySpec->base.g.x.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigGX : g_ecc224CorrectLittleGX);
    eccPriKeySpec->base.g.x.len = NID_secp224r1_len;
    eccPriKeySpec->base.g.y.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigGY : g_ecc224CorrectLittleGY);
    eccPriKeySpec->base.g.y.len = NID_secp224r1_len;
    eccPriKeySpec->base.n.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigN : g_ecc224CorrectLittleN);
    eccPriKeySpec->base.n.len = NID_secp224r1_len;
    eccPriKeySpec->base.h = g_ecc224CorrectH;
    eccPriKeySpec->sk.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigSk : g_ecc224CorrectLittleSk);
    eccPriKeySpec->sk.len = NID_secp224r1_len;

    *spec = reinterpret_cast<HcfAsyKeyParamsSpec *>(eccPriKeySpec);
    return HCF_SUCCESS;
}

HcfResult ConstructEcc224KeyPairParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccKeyPairParamsSpec *eccKeyPairSpec = &g_ecc224KeyPairSpec;
    HcfECField *tmpField = reinterpret_cast<HcfECField *>(&g_fieldFp);

    eccKeyPairSpec->base.base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccKeyPairSpec->base.base.specType = HCF_KEY_PAIR_SPEC;
    eccKeyPairSpec->base.field = tmpField;
    eccKeyPairSpec->base.field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    (reinterpret_cast<HcfECFieldFp *>(eccKeyPairSpec->base.field))->p.data =
        (IS_BIG_ENDIAN ? g_ecc224CorrectBigP : g_ecc224CorrectLittleP);
    (reinterpret_cast<HcfECFieldFp *>(eccKeyPairSpec->base.field))->p.len = NID_secp224r1_len;
    eccKeyPairSpec->base.a.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigA : g_ecc224CorrectLittleA);
    eccKeyPairSpec->base.a.len = NID_secp224r1_len;
    eccKeyPairSpec->base.b.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigB : g_ecc224CorrectLittleB);
    eccKeyPairSpec->base.b.len = NID_secp224r1_len;
    eccKeyPairSpec->base.g.x.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigGX : g_ecc224CorrectLittleGX);
    eccKeyPairSpec->base.g.x.len = NID_secp224r1_len;
    eccKeyPairSpec->base.g.y.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigGY : g_ecc224CorrectLittleGY);
    eccKeyPairSpec->base.g.y.len = NID_secp224r1_len;
    eccKeyPairSpec->base.n.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigN : g_ecc224CorrectLittleN);
    eccKeyPairSpec->base.n.len = NID_secp224r1_len;
    eccKeyPairSpec->base.h = g_ecc224CorrectH;
    eccKeyPairSpec->pk.x.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigPkX : g_ecc224CorrectLittlePkX);
    eccKeyPairSpec->pk.x.len = NID_secp224r1_len;
    eccKeyPairSpec->pk.y.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigPkY : g_ecc224CorrectLittlePkY);
    eccKeyPairSpec->pk.y.len = NID_secp224r1_len;
    eccKeyPairSpec->sk.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigSk : g_ecc224CorrectLittleSk);
    eccKeyPairSpec->sk.len = NID_secp224r1_len;

    *spec = reinterpret_cast<HcfAsyKeyParamsSpec *>(eccKeyPairSpec);
    return HCF_SUCCESS;
}

HcfResult ConstructEcc256CommParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccCommParamsSpec *eccCommSpec = &g_ecc256CommSpec;
    HcfECField *tmpField = reinterpret_cast<HcfECField *>(&g_fieldFp);

    eccCommSpec->base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccCommSpec->base.specType = HCF_COMMON_PARAMS_SPEC;
    eccCommSpec->field = tmpField;
    eccCommSpec->field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    (reinterpret_cast<HcfECFieldFp *>(eccCommSpec->field))->p.data =
        (IS_BIG_ENDIAN ? g_ecc256CorrectBigP : g_ecc256CorrectLittleP);
    (reinterpret_cast<HcfECFieldFp *>(eccCommSpec->field))->p.len = NID_X9_62_prime256v1_len;
    eccCommSpec->a.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigA : g_ecc256CorrectLittleA);
    eccCommSpec->a.len = NID_X9_62_prime256v1_len;
    eccCommSpec->b.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigB : g_ecc256CorrectLittleB);
    eccCommSpec->b.len = NID_X9_62_prime256v1_len;
    eccCommSpec->g.x.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigGX : g_ecc256CorrectLittleGX);
    eccCommSpec->g.x.len = NID_X9_62_prime256v1_len;
    eccCommSpec->g.y.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigGY : g_ecc256CorrectLittleGY);
    eccCommSpec->g.y.len = NID_X9_62_prime256v1_len;
    eccCommSpec->n.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigN : g_ecc256CorrectLittleN);
    eccCommSpec->n.len = NID_X9_62_prime256v1_len;
    eccCommSpec->h = g_ecc256CorrectH;

    *spec = reinterpret_cast<HcfAsyKeyParamsSpec *>(eccCommSpec);
    return HCF_SUCCESS;
}

HcfResult ConstructEcc256PubKeyParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccPubKeyParamsSpec *eccPubKeySpec = &g_ecc256PubKeySpec;
    HcfECField *tmpField = reinterpret_cast<HcfECField *>(&g_fieldFp);

    eccPubKeySpec->base.base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccPubKeySpec->base.base.specType = HCF_PUBLIC_KEY_SPEC;
    eccPubKeySpec->base.field = tmpField;
    eccPubKeySpec->base.field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    (reinterpret_cast<HcfECFieldFp *>(eccPubKeySpec->base.field))->p.data =
        (IS_BIG_ENDIAN ? g_ecc256CorrectBigP : g_ecc256CorrectLittleP);
    (reinterpret_cast<HcfECFieldFp *>(eccPubKeySpec->base.field))->p.len = NID_X9_62_prime256v1_len;
    eccPubKeySpec->base.a.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigA : g_ecc256CorrectLittleA);
    eccPubKeySpec->base.a.len = NID_X9_62_prime256v1_len;
    eccPubKeySpec->base.b.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigB : g_ecc256CorrectLittleB);
    eccPubKeySpec->base.b.len = NID_X9_62_prime256v1_len;
    eccPubKeySpec->base.g.x.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigGX : g_ecc256CorrectLittleGX);
    eccPubKeySpec->base.g.x.len = NID_X9_62_prime256v1_len;
    eccPubKeySpec->base.g.y.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigGY : g_ecc256CorrectLittleGY);
    eccPubKeySpec->base.g.y.len = NID_X9_62_prime256v1_len;
    eccPubKeySpec->base.n.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigN : g_ecc256CorrectLittleN);
    eccPubKeySpec->base.n.len = NID_X9_62_prime256v1_len;
    eccPubKeySpec->base.h = g_ecc256CorrectH;
    eccPubKeySpec->pk.x.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigPkX : g_ecc256CorrectLittlePkX);
    eccPubKeySpec->pk.x.len = NID_X9_62_prime256v1_len;
    eccPubKeySpec->pk.y.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigPkY : g_ecc256CorrectLittlePkY);
    eccPubKeySpec->pk.y.len = NID_X9_62_prime256v1_len;

    *spec = reinterpret_cast<HcfAsyKeyParamsSpec *>(eccPubKeySpec);
    return HCF_SUCCESS;
}

HcfResult ConstructEcc256PriKeyParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccPriKeyParamsSpec *eccPriKeySpec = &g_ecc256PriKeySpec;
    HcfECField *tmpField = reinterpret_cast<HcfECField *>(&g_fieldFp);

    eccPriKeySpec->base.base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccPriKeySpec->base.base.specType = HCF_PRIVATE_KEY_SPEC;
    eccPriKeySpec->base.field = tmpField;
    eccPriKeySpec->base.field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    (reinterpret_cast<HcfECFieldFp *>(eccPriKeySpec->base.field))->p.data =
        (IS_BIG_ENDIAN ? g_ecc256CorrectBigP : g_ecc256CorrectLittleP);
    (reinterpret_cast<HcfECFieldFp *>(eccPriKeySpec->base.field))->p.len = NID_X9_62_prime256v1_len;
    eccPriKeySpec->base.a.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigA : g_ecc256CorrectLittleA);
    eccPriKeySpec->base.a.len = NID_X9_62_prime256v1_len;
    eccPriKeySpec->base.b.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigB : g_ecc256CorrectLittleB);
    eccPriKeySpec->base.b.len = NID_X9_62_prime256v1_len;
    eccPriKeySpec->base.g.x.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigGX : g_ecc256CorrectLittleGX);
    eccPriKeySpec->base.g.x.len = NID_X9_62_prime256v1_len;
    eccPriKeySpec->base.g.y.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigGY : g_ecc256CorrectLittleGY);
    eccPriKeySpec->base.g.y.len = NID_X9_62_prime256v1_len;
    eccPriKeySpec->base.n.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigN : g_ecc256CorrectLittleN);
    eccPriKeySpec->base.n.len = NID_X9_62_prime256v1_len;
    eccPriKeySpec->base.h = g_ecc256CorrectH;
    eccPriKeySpec->sk.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigSk : g_ecc256CorrectLittleSk);
    eccPriKeySpec->sk.len = NID_X9_62_prime256v1_len;

    *spec = reinterpret_cast<HcfAsyKeyParamsSpec *>(eccPriKeySpec);
    return HCF_SUCCESS;
}

HcfResult ConstructEcc256KeyPairParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccKeyPairParamsSpec *eccKeyPairSpec = &g_ecc256KeyPairSpec;
    HcfECField *tmpField = reinterpret_cast<HcfECField *>(&g_fieldFp);

    eccKeyPairSpec->base.base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccKeyPairSpec->base.base.specType = HCF_KEY_PAIR_SPEC;
    eccKeyPairSpec->base.field = tmpField;
    eccKeyPairSpec->base.field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    (reinterpret_cast<HcfECFieldFp *>(eccKeyPairSpec->base.field))->p.data =
        (IS_BIG_ENDIAN ? g_ecc256CorrectBigP : g_ecc256CorrectLittleP);
    (reinterpret_cast<HcfECFieldFp *>(eccKeyPairSpec->base.field))->p.len = NID_X9_62_prime256v1_len;
    eccKeyPairSpec->base.a.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigA : g_ecc256CorrectLittleA);
    eccKeyPairSpec->base.a.len = NID_X9_62_prime256v1_len;
    eccKeyPairSpec->base.b.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigB : g_ecc256CorrectLittleB);
    eccKeyPairSpec->base.b.len = NID_X9_62_prime256v1_len;
    eccKeyPairSpec->base.g.x.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigGX : g_ecc256CorrectLittleGX);
    eccKeyPairSpec->base.g.x.len = NID_X9_62_prime256v1_len;
    eccKeyPairSpec->base.g.y.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigGY : g_ecc256CorrectLittleGY);
    eccKeyPairSpec->base.g.y.len = NID_X9_62_prime256v1_len;
    eccKeyPairSpec->base.n.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigN : g_ecc256CorrectLittleN);
    eccKeyPairSpec->base.n.len = NID_X9_62_prime256v1_len;
    eccKeyPairSpec->base.h = g_ecc256CorrectH;
    eccKeyPairSpec->pk.x.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigPkX : g_ecc256CorrectLittlePkX);
    eccKeyPairSpec->pk.x.len = NID_X9_62_prime256v1_len;
    eccKeyPairSpec->pk.y.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigPkY : g_ecc256CorrectLittlePkY);
    eccKeyPairSpec->pk.y.len = NID_X9_62_prime256v1_len;
    eccKeyPairSpec->sk.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigSk : g_ecc256CorrectLittleSk);
    eccKeyPairSpec->sk.len = NID_X9_62_prime256v1_len;

    *spec = reinterpret_cast<HcfAsyKeyParamsSpec *>(eccKeyPairSpec);
    return HCF_SUCCESS;
}

HcfResult ConstructEcc384CommParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccCommParamsSpec *eccCommSpec = &g_ecc384CommSpec;
    HcfECField *tmpField = reinterpret_cast<HcfECField *>(&g_fieldFp);

    eccCommSpec->base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccCommSpec->base.specType = HCF_COMMON_PARAMS_SPEC;
    eccCommSpec->field = tmpField;
    eccCommSpec->field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    (reinterpret_cast<HcfECFieldFp *>(eccCommSpec->field))->p.data =
        (IS_BIG_ENDIAN ? g_ecc384CorrectBigP : g_ecc384CorrectLittleP);
    (reinterpret_cast<HcfECFieldFp *>(eccCommSpec->field))->p.len = NID_secp384r1_len;
    eccCommSpec->a.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigA : g_ecc384CorrectLittleA);
    eccCommSpec->a.len = NID_secp384r1_len;
    eccCommSpec->b.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigB : g_ecc384CorrectLittleB);
    eccCommSpec->b.len = NID_secp384r1_len;
    eccCommSpec->g.x.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigGX : g_ecc384CorrectLittleGX);
    eccCommSpec->g.x.len = NID_secp384r1_len;
    eccCommSpec->g.y.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigGY : g_ecc384CorrectLittleGY);
    eccCommSpec->g.y.len = NID_secp384r1_len;
    eccCommSpec->n.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigN : g_ecc384CorrectLittleN);
    eccCommSpec->n.len = NID_secp384r1_len;
    eccCommSpec->h = g_ecc384CorrectH;

    *spec = reinterpret_cast<HcfAsyKeyParamsSpec *>(eccCommSpec);
    return HCF_SUCCESS;
}

HcfResult ConstructEcc384PubKeyParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccPubKeyParamsSpec *eccPubKeySpec = &g_ecc384PubKeySpec;
    HcfECField *tmpField = reinterpret_cast<HcfECField *>(&g_fieldFp);

    eccPubKeySpec->base.base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccPubKeySpec->base.base.specType = HCF_PUBLIC_KEY_SPEC;
    eccPubKeySpec->base.field = tmpField;
    eccPubKeySpec->base.field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    (reinterpret_cast<HcfECFieldFp *>(eccPubKeySpec->base.field))->p.data =
        (IS_BIG_ENDIAN ? g_ecc384CorrectBigP : g_ecc384CorrectLittleP);
    (reinterpret_cast<HcfECFieldFp *>(eccPubKeySpec->base.field))->p.len = NID_secp384r1_len;
    eccPubKeySpec->base.a.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigA : g_ecc384CorrectLittleA);
    eccPubKeySpec->base.a.len = NID_secp384r1_len;
    eccPubKeySpec->base.b.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigB : g_ecc384CorrectLittleB);
    eccPubKeySpec->base.b.len = NID_secp384r1_len;
    eccPubKeySpec->base.g.x.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigGX : g_ecc384CorrectLittleGX);
    eccPubKeySpec->base.g.x.len = NID_secp384r1_len;
    eccPubKeySpec->base.g.y.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigGY : g_ecc384CorrectLittleGY);
    eccPubKeySpec->base.g.y.len = NID_secp384r1_len;
    eccPubKeySpec->base.n.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigN : g_ecc384CorrectLittleN);
    eccPubKeySpec->base.n.len = NID_secp384r1_len;
    eccPubKeySpec->base.h = g_ecc384CorrectH;
    eccPubKeySpec->pk.x.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigPkX : g_ecc384CorrectLittlePkX);
    eccPubKeySpec->pk.x.len = NID_secp384r1_len;
    eccPubKeySpec->pk.y.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigPkY : g_ecc384CorrectLittlePkY);
    eccPubKeySpec->pk.y.len = NID_secp384r1_len;

    *spec = reinterpret_cast<HcfAsyKeyParamsSpec *>(eccPubKeySpec);
    return HCF_SUCCESS;
}

HcfResult ConstructEcc384PriKeyParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccPriKeyParamsSpec *eccPriKeySpec = &g_ecc384PriKeySpec;
    HcfECField *tmpField = reinterpret_cast<HcfECField *>(&g_fieldFp);

    eccPriKeySpec->base.base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccPriKeySpec->base.base.specType = HCF_PRIVATE_KEY_SPEC;
    eccPriKeySpec->base.field = tmpField;
    eccPriKeySpec->base.field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    (reinterpret_cast<HcfECFieldFp *>(eccPriKeySpec->base.field))->p.data =
        (IS_BIG_ENDIAN ? g_ecc384CorrectBigP : g_ecc384CorrectLittleP);
    (reinterpret_cast<HcfECFieldFp *>(eccPriKeySpec->base.field))->p.len = NID_secp384r1_len;
    eccPriKeySpec->base.a.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigA : g_ecc384CorrectLittleA);
    eccPriKeySpec->base.a.len = NID_secp384r1_len;
    eccPriKeySpec->base.b.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigB : g_ecc384CorrectLittleB);
    eccPriKeySpec->base.b.len = NID_secp384r1_len;
    eccPriKeySpec->base.g.x.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigGX : g_ecc384CorrectLittleGX);
    eccPriKeySpec->base.g.x.len = NID_secp384r1_len;
    eccPriKeySpec->base.g.y.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigGY : g_ecc384CorrectLittleGY);
    eccPriKeySpec->base.g.y.len = NID_secp384r1_len;
    eccPriKeySpec->base.n.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigN : g_ecc384CorrectLittleN);
    eccPriKeySpec->base.n.len = NID_secp384r1_len;
    eccPriKeySpec->base.h = g_ecc384CorrectH;
    eccPriKeySpec->sk.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigSk : g_ecc384CorrectLittleSk);
    eccPriKeySpec->sk.len = NID_secp384r1_len;

    *spec = reinterpret_cast<HcfAsyKeyParamsSpec *>(eccPriKeySpec);
    return HCF_SUCCESS;
}

HcfResult ConstructEcc384KeyPairParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccKeyPairParamsSpec *eccKeyPairSpec = &g_ecc384KeyPairSpec;
    HcfECField *tmpField = reinterpret_cast<HcfECField *>(&g_fieldFp);

    eccKeyPairSpec->base.base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccKeyPairSpec->base.base.specType = HCF_KEY_PAIR_SPEC;
    eccKeyPairSpec->base.field = tmpField;
    eccKeyPairSpec->base.field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    (reinterpret_cast<HcfECFieldFp *>(eccKeyPairSpec->base.field))->p.data =
        (IS_BIG_ENDIAN ? g_ecc384CorrectBigP : g_ecc384CorrectLittleP);
    (reinterpret_cast<HcfECFieldFp *>(eccKeyPairSpec->base.field))->p.len = NID_secp384r1_len;
    eccKeyPairSpec->base.a.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigA : g_ecc384CorrectLittleA);
    eccKeyPairSpec->base.a.len = NID_secp384r1_len;
    eccKeyPairSpec->base.b.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigB : g_ecc384CorrectLittleB);
    eccKeyPairSpec->base.b.len = NID_secp384r1_len;
    eccKeyPairSpec->base.g.x.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigGX : g_ecc384CorrectLittleGX);
    eccKeyPairSpec->base.g.x.len = NID_secp384r1_len;
    eccKeyPairSpec->base.g.y.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigGY : g_ecc384CorrectLittleGY);
    eccKeyPairSpec->base.g.y.len = NID_secp384r1_len;
    eccKeyPairSpec->base.n.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigN : g_ecc384CorrectLittleN);
    eccKeyPairSpec->base.n.len = NID_secp384r1_len;
    eccKeyPairSpec->base.h = g_ecc384CorrectH;
    eccKeyPairSpec->pk.x.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigPkX : g_ecc384CorrectLittlePkX);
    eccKeyPairSpec->pk.x.len = NID_secp384r1_len;
    eccKeyPairSpec->pk.y.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigPkY : g_ecc384CorrectLittlePkY);
    eccKeyPairSpec->pk.y.len = NID_secp384r1_len;
    eccKeyPairSpec->sk.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigSk : g_ecc384CorrectLittleSk);
    eccKeyPairSpec->sk.len = NID_secp384r1_len;

    *spec = reinterpret_cast<HcfAsyKeyParamsSpec *>(eccKeyPairSpec);
    return HCF_SUCCESS;
}

HcfResult ConstructEcc521CommParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccCommParamsSpec *eccCommSpec = &g_ecc521CommSpec;
    HcfECField *tmpField = reinterpret_cast<HcfECField *>(&g_fieldFp);

    eccCommSpec->base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccCommSpec->base.specType = HCF_COMMON_PARAMS_SPEC;
    eccCommSpec->field = tmpField;
    eccCommSpec->field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    (reinterpret_cast<HcfECFieldFp *>(eccCommSpec->field))->p.data =
        (IS_BIG_ENDIAN ? g_ecc521CorrectBigP : g_ecc521CorrectLittleP);
    (reinterpret_cast<HcfECFieldFp *>(eccCommSpec->field))->p.len = NID_secp521r1_len;
    eccCommSpec->a.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigA : g_ecc521CorrectLittleA);
    eccCommSpec->a.len = NID_secp521r1_len;
    eccCommSpec->b.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigB : g_ecc521CorrectLittleB);
    eccCommSpec->b.len = NID_secp521r1_len;
    eccCommSpec->g.x.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigGX : g_ecc521CorrectLittleGX);
    eccCommSpec->g.x.len = NID_secp521r1_len;
    eccCommSpec->g.y.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigGY : g_ecc521CorrectLittleGY);
    eccCommSpec->g.y.len = NID_secp521r1_len;
    eccCommSpec->n.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigN : g_ecc521CorrectLittleN);
    eccCommSpec->n.len = NID_secp521r1_len;
    eccCommSpec->h = g_ecc521CorrectH;

    *spec = reinterpret_cast<HcfAsyKeyParamsSpec *>(eccCommSpec);
    return HCF_SUCCESS;
}

HcfResult ConstructEcc521PubKeyParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccPubKeyParamsSpec *eccPubKeySpec = &g_ecc521PubKeySpec;
    HcfECField *tmpField = reinterpret_cast<HcfECField *>(&g_fieldFp);

    eccPubKeySpec->base.base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccPubKeySpec->base.base.specType = HCF_PUBLIC_KEY_SPEC;
    eccPubKeySpec->base.field = tmpField;
    eccPubKeySpec->base.field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    (reinterpret_cast<HcfECFieldFp *>(eccPubKeySpec->base.field))->p.data =
        (IS_BIG_ENDIAN ? g_ecc521CorrectBigP : g_ecc521CorrectLittleP);
    (reinterpret_cast<HcfECFieldFp *>(eccPubKeySpec->base.field))->p.len = NID_secp521r1_len;
    eccPubKeySpec->base.a.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigA : g_ecc521CorrectLittleA);
    eccPubKeySpec->base.a.len = NID_secp521r1_len;
    eccPubKeySpec->base.b.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigB : g_ecc521CorrectLittleB);
    eccPubKeySpec->base.b.len = NID_secp521r1_len;
    eccPubKeySpec->base.g.x.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigGX : g_ecc521CorrectLittleGX);
    eccPubKeySpec->base.g.x.len = NID_secp521r1_len;
    eccPubKeySpec->base.g.y.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigGY : g_ecc521CorrectLittleGY);
    eccPubKeySpec->base.g.y.len = NID_secp521r1_len;
    eccPubKeySpec->base.n.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigN : g_ecc521CorrectLittleN);
    eccPubKeySpec->base.n.len = NID_secp521r1_len;
    eccPubKeySpec->base.h = g_ecc521CorrectH;
    eccPubKeySpec->pk.x.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigPkX : g_ecc521CorrectLittlePkX);
    eccPubKeySpec->pk.x.len = NID_secp521r1_len;
    eccPubKeySpec->pk.y.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigPkY : g_ecc521CorrectLittlePkY);
    eccPubKeySpec->pk.y.len = NID_secp521r1_len;

    *spec = reinterpret_cast<HcfAsyKeyParamsSpec *>(eccPubKeySpec);
    return HCF_SUCCESS;
}

HcfResult ConstructEcc521PriKeyParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccPriKeyParamsSpec *eccPriKeySpec = &g_ecc521PriKeySpec;
    HcfECField *tmpField = (HcfECField *)(&g_fieldFp);

    eccPriKeySpec->base.base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccPriKeySpec->base.base.specType = HCF_PRIVATE_KEY_SPEC;
    eccPriKeySpec->base.field = tmpField;
    eccPriKeySpec->base.field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    (reinterpret_cast<HcfECFieldFp *>(eccPriKeySpec->base.field))->p.data =
        (IS_BIG_ENDIAN ? g_ecc521CorrectBigP : g_ecc521CorrectLittleP);
    (reinterpret_cast<HcfECFieldFp *>(eccPriKeySpec->base.field))->p.len = NID_secp521r1_len;
    eccPriKeySpec->base.a.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigA : g_ecc521CorrectLittleA);
    eccPriKeySpec->base.a.len = NID_secp521r1_len;
    eccPriKeySpec->base.b.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigB : g_ecc521CorrectLittleB);
    eccPriKeySpec->base.b.len = NID_secp521r1_len;
    eccPriKeySpec->base.g.x.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigGX : g_ecc521CorrectLittleGX);
    eccPriKeySpec->base.g.x.len = NID_secp521r1_len;
    eccPriKeySpec->base.g.y.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigGY : g_ecc521CorrectLittleGY);
    eccPriKeySpec->base.g.y.len = NID_secp521r1_len;
    eccPriKeySpec->base.n.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigN : g_ecc521CorrectLittleN);
    eccPriKeySpec->base.n.len = NID_secp521r1_len;
    eccPriKeySpec->base.h = g_ecc521CorrectH;
    eccPriKeySpec->sk.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigSk : g_ecc521CorrectLittleSk);
    eccPriKeySpec->sk.len = NID_secp521r1_len;

    *spec = reinterpret_cast<HcfAsyKeyParamsSpec *>(eccPriKeySpec);
    return HCF_SUCCESS;
}

HcfResult ConstructEcc521KeyPairParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccKeyPairParamsSpec *eccKeyPairSpec = &g_ecc521KeyPairSpec;
    HcfECField *tmpField = reinterpret_cast<HcfECField *>(&g_fieldFp);

    eccKeyPairSpec->base.base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccKeyPairSpec->base.base.specType = HCF_KEY_PAIR_SPEC;
    eccKeyPairSpec->base.field = tmpField;
    eccKeyPairSpec->base.field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    (reinterpret_cast<HcfECFieldFp *>(eccKeyPairSpec->base.field))->p.data =
        (IS_BIG_ENDIAN ? g_ecc521CorrectBigP : g_ecc521CorrectLittleP);
    (reinterpret_cast<HcfECFieldFp *>(eccKeyPairSpec->base.field))->p.len = NID_secp521r1_len;
    eccKeyPairSpec->base.a.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigA : g_ecc521CorrectLittleA);
    eccKeyPairSpec->base.a.len = NID_secp521r1_len;
    eccKeyPairSpec->base.b.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigB : g_ecc521CorrectLittleB);
    eccKeyPairSpec->base.b.len = NID_secp521r1_len;
    eccKeyPairSpec->base.g.x.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigGX : g_ecc521CorrectLittleGX);
    eccKeyPairSpec->base.g.x.len = NID_secp521r1_len;
    eccKeyPairSpec->base.g.y.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigGY : g_ecc521CorrectLittleGY);
    eccKeyPairSpec->base.g.y.len = NID_secp521r1_len;
    eccKeyPairSpec->base.n.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigN : g_ecc521CorrectLittleN);
    eccKeyPairSpec->base.n.len = NID_secp521r1_len;
    eccKeyPairSpec->base.h = g_ecc521CorrectH;
    eccKeyPairSpec->pk.x.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigPkX : g_ecc521CorrectLittlePkX);
    eccKeyPairSpec->pk.x.len = NID_secp521r1_len;
    eccKeyPairSpec->pk.y.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigPkY : g_ecc521CorrectLittlePkY);
    eccKeyPairSpec->pk.y.len = NID_secp521r1_len;
    eccKeyPairSpec->sk.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigSk : g_ecc521CorrectLittleSk);
    eccKeyPairSpec->sk.len = NID_secp521r1_len;

    *spec = reinterpret_cast<HcfAsyKeyParamsSpec *>(eccKeyPairSpec);
    return HCF_SUCCESS;
}

HcfResult ConstructEcc224ErrCommParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccCommParamsSpec *eccCommSpec = &g_ecc224CommSpec;
    HcfECField *tmpField = reinterpret_cast<HcfECField *>(&g_fieldFp);

    eccCommSpec->base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccCommSpec->base.specType = HCF_COMMON_PARAMS_SPEC;
    eccCommSpec->field = tmpField;
    eccCommSpec->field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    (reinterpret_cast<HcfECFieldFp *>(eccCommSpec->field))->p.data =
        (IS_BIG_ENDIAN ? g_ecc224CorrectBigP : g_ecc224CorrectLittleP);
    (reinterpret_cast<HcfECFieldFp *>(eccCommSpec->field))->p.len = NID_secp224r1_len;
    eccCommSpec->a.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigA : g_ecc224CorrectLittleA);
    eccCommSpec->a.len = NID_secp224r1_len;
    eccCommSpec->b.data = nullptr;
    eccCommSpec->b.len = 0;
    eccCommSpec->g.x.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigGX : g_ecc224CorrectLittleGX);
    eccCommSpec->g.x.len = NID_secp224r1_len;
    eccCommSpec->g.y.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigGY : g_ecc224CorrectLittleGY);
    eccCommSpec->g.y.len = NID_secp224r1_len;
    eccCommSpec->n.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigN : g_ecc224CorrectLittleN);
    eccCommSpec->n.len = NID_secp224r1_len;
    eccCommSpec->h = g_ecc224CorrectH;

    *spec = reinterpret_cast<HcfAsyKeyParamsSpec *>(eccCommSpec);
    return HCF_SUCCESS;
}

HcfResult ConstructEcc256ErrCommParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccCommParamsSpec *eccCommSpec = &g_ecc256CommSpec;
    HcfECField *tmpField = reinterpret_cast<HcfECField *>(&g_fieldFp);

    eccCommSpec->base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccCommSpec->base.specType = HCF_COMMON_PARAMS_SPEC;
    eccCommSpec->field = tmpField;
    eccCommSpec->field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    (reinterpret_cast<HcfECFieldFp *>(eccCommSpec->field))->p.data =
        (IS_BIG_ENDIAN ? g_ecc256CorrectBigP : g_ecc256CorrectLittleP);
    (reinterpret_cast<HcfECFieldFp *>(eccCommSpec->field))->p.len = NID_X9_62_prime256v1_len;
    eccCommSpec->a.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigA : g_ecc256CorrectLittleA);
    eccCommSpec->a.len = NID_X9_62_prime256v1_len;
    eccCommSpec->b.data = 0;
    eccCommSpec->b.len = 0;
    eccCommSpec->g.x.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigGX : g_ecc256CorrectLittleGX);
    eccCommSpec->g.x.len = NID_X9_62_prime256v1_len;
    eccCommSpec->g.y.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigGY : g_ecc256CorrectLittleGY);
    eccCommSpec->g.y.len = NID_X9_62_prime256v1_len;
    eccCommSpec->n.data = (IS_BIG_ENDIAN ? g_ecc256CorrectBigN : g_ecc256CorrectLittleN);
    eccCommSpec->n.len = NID_X9_62_prime256v1_len;
    eccCommSpec->h = g_ecc256CorrectH;

    *spec = reinterpret_cast<HcfAsyKeyParamsSpec *>(eccCommSpec);
    return HCF_SUCCESS;
}

HcfResult ConstructEcc384ErrCommParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccCommParamsSpec *eccCommSpec = &g_ecc384CommSpec;
    HcfECField *tmpField = reinterpret_cast<HcfECField *>(&g_fieldFp);

    eccCommSpec->base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccCommSpec->base.specType = HCF_COMMON_PARAMS_SPEC;
    eccCommSpec->field = tmpField;
    eccCommSpec->field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    (reinterpret_cast<HcfECFieldFp *>(eccCommSpec->field))->p.data =
        (IS_BIG_ENDIAN ? g_ecc384CorrectBigP : g_ecc384CorrectLittleP);
    (reinterpret_cast<HcfECFieldFp *>(eccCommSpec->field))->p.len = NID_secp384r1_len;
    eccCommSpec->a.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigA : g_ecc384CorrectLittleA);
    eccCommSpec->a.len = NID_secp384r1_len;
    eccCommSpec->b.data = nullptr;
    eccCommSpec->b.len = 0;
    eccCommSpec->g.x.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigGX : g_ecc384CorrectLittleGX);
    eccCommSpec->g.x.len = NID_secp384r1_len;
    eccCommSpec->g.y.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigGY : g_ecc384CorrectLittleGY);
    eccCommSpec->g.y.len = NID_secp384r1_len;
    eccCommSpec->n.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigN : g_ecc384CorrectLittleN);
    eccCommSpec->n.len = NID_secp384r1_len;
    eccCommSpec->h = g_ecc384CorrectH;

    *spec = reinterpret_cast<HcfAsyKeyParamsSpec *>(eccCommSpec);
    return HCF_SUCCESS;
}

HcfResult ConstructEcc521ErrCommParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccCommParamsSpec *eccCommSpec = &g_ecc521CommSpec;
    HcfECField *tmpField = reinterpret_cast<HcfECField *>(&g_fieldFp);

    eccCommSpec->base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccCommSpec->base.specType = HCF_COMMON_PARAMS_SPEC;
    eccCommSpec->field = tmpField;
    eccCommSpec->field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    (reinterpret_cast<HcfECFieldFp *>(eccCommSpec->field))->p.data =
        (IS_BIG_ENDIAN ? g_ecc521CorrectBigP : g_ecc521CorrectLittleP);
    (reinterpret_cast<HcfECFieldFp *>(eccCommSpec->field))->p.len = NID_secp521r1_len;
    eccCommSpec->a.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigA : g_ecc521CorrectLittleA);
    eccCommSpec->a.len = NID_secp521r1_len;
    eccCommSpec->b.data = nullptr;
    eccCommSpec->b.len = 0;
    eccCommSpec->g.x.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigGX : g_ecc521CorrectLittleGX);
    eccCommSpec->g.x.len = NID_secp521r1_len;
    eccCommSpec->g.y.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigGY : g_ecc521CorrectLittleGY);
    eccCommSpec->g.y.len = NID_secp521r1_len;
    eccCommSpec->n.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigN : g_ecc521CorrectLittleN);
    eccCommSpec->n.len = NID_secp521r1_len;
    eccCommSpec->h = g_ecc521CorrectH;

    *spec = reinterpret_cast<HcfAsyKeyParamsSpec *>(eccCommSpec);
    return HCF_SUCCESS;
}

HcfResult ConstructEcc384ErrKeyPairParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccKeyPairParamsSpec *eccKeyPairSpec = &g_ecc384KeyPairSpec;
    HcfECField *tmpField = reinterpret_cast<HcfECField *>(&g_fieldFp);

    eccKeyPairSpec->base.base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccKeyPairSpec->base.base.specType = HCF_KEY_PAIR_SPEC;
    eccKeyPairSpec->base.field = tmpField;
    eccKeyPairSpec->base.field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    (reinterpret_cast<HcfECFieldFp *>(eccKeyPairSpec->base.field))->p.data =
        (IS_BIG_ENDIAN ? g_ecc384CorrectBigP : g_ecc384CorrectLittleP);
    (reinterpret_cast<HcfECFieldFp *>(eccKeyPairSpec->base.field))->p.len = NID_secp384r1_len;
    eccKeyPairSpec->base.a.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigA : g_ecc384CorrectLittleA);
    eccKeyPairSpec->base.a.len = NID_secp384r1_len;
    eccKeyPairSpec->base.g.x.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigGX : g_ecc384CorrectLittleGX);
    eccKeyPairSpec->base.g.x.len = NID_secp384r1_len;
    eccKeyPairSpec->base.g.y.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigGY : g_ecc384CorrectLittleGY);
    eccKeyPairSpec->base.g.y.len = NID_secp384r1_len;
    eccKeyPairSpec->base.n.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigN : g_ecc384CorrectLittleN);
    eccKeyPairSpec->base.n.len = NID_secp384r1_len;
    eccKeyPairSpec->base.h = g_ecc384CorrectH;
    eccKeyPairSpec->pk.x.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigPkX : g_ecc384CorrectLittlePkX);
    eccKeyPairSpec->pk.x.len = NID_secp384r1_len;
    eccKeyPairSpec->pk.y.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigPkY : g_ecc384CorrectLittlePkY);
    eccKeyPairSpec->pk.y.len = NID_secp384r1_len;
    eccKeyPairSpec->sk.data = (IS_BIG_ENDIAN ? g_ecc384CorrectBigSk : g_ecc384CorrectLittleSk);
    eccKeyPairSpec->sk.len = NID_secp384r1_len;

    *spec = reinterpret_cast<HcfAsyKeyParamsSpec *>(eccKeyPairSpec);
    return HCF_SUCCESS;
}

HcfResult ConstructEcc521ErrKeyPairParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccKeyPairParamsSpec *eccKeyPairSpec = &g_ecc521KeyPairSpec;
    HcfECField *tmpField = reinterpret_cast<HcfECField *>(&g_fieldFp);

    eccKeyPairSpec->base.base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccKeyPairSpec->base.base.specType = HCF_KEY_PAIR_SPEC;
    eccKeyPairSpec->base.field = tmpField;
    eccKeyPairSpec->base.field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    (reinterpret_cast<HcfECFieldFp *>(eccKeyPairSpec->base.field))->p.data =
        (IS_BIG_ENDIAN ? g_ecc521CorrectBigP : g_ecc521CorrectLittleP);
    (reinterpret_cast<HcfECFieldFp *>(eccKeyPairSpec->base.field))->p.len = NID_secp521r1_len;
    eccKeyPairSpec->base.a.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigA : g_ecc521CorrectLittleA);
    eccKeyPairSpec->base.a.len = NID_secp521r1_len;
    eccKeyPairSpec->base.b.data = nullptr;
    eccKeyPairSpec->base.b.len = 0;
    eccKeyPairSpec->base.g.x.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigGX : g_ecc521CorrectLittleGX);
    eccKeyPairSpec->base.g.x.len = NID_secp521r1_len;
    eccKeyPairSpec->base.g.y.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigGY : g_ecc521CorrectLittleGY);
    eccKeyPairSpec->base.g.y.len = NID_secp521r1_len;
    eccKeyPairSpec->base.n.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigN : g_ecc521CorrectLittleN);
    eccKeyPairSpec->base.n.len = NID_secp521r1_len;
    eccKeyPairSpec->base.h = g_ecc521CorrectH;
    eccKeyPairSpec->pk.x.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigPkX : g_ecc521CorrectLittlePkX);
    eccKeyPairSpec->pk.x.len = NID_secp521r1_len;
    eccKeyPairSpec->pk.y.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigPkY : g_ecc521CorrectLittlePkY);
    eccKeyPairSpec->pk.y.len = NID_secp521r1_len;
    eccKeyPairSpec->sk.data = (IS_BIG_ENDIAN ? g_ecc521CorrectBigSk : g_ecc521CorrectLittleSk);
    eccKeyPairSpec->sk.len = NID_secp521r1_len;

    *spec = reinterpret_cast<HcfAsyKeyParamsSpec *>(eccKeyPairSpec);
    return HCF_SUCCESS;
}

HcfResult ConstructEcc224ErrPubKeyParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccPubKeyParamsSpec *eccPubKeySpec = &g_ecc224PubKeySpec;
    HcfECField *tmpField = reinterpret_cast<HcfECField *>(&g_fieldFp);

    eccPubKeySpec->base.base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccPubKeySpec->base.base.specType = HCF_PUBLIC_KEY_SPEC;
    eccPubKeySpec->base.field = tmpField;
    eccPubKeySpec->base.field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    (reinterpret_cast<HcfECFieldFp *>(eccPubKeySpec->base.field))->p.data =
        (IS_BIG_ENDIAN ? g_ecc224CorrectBigP : g_ecc224CorrectLittleP);
    (reinterpret_cast<HcfECFieldFp *>(eccPubKeySpec->base.field))->p.len = NID_secp224r1_len;
    eccPubKeySpec->base.a.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigA : g_ecc224CorrectLittleA);
    eccPubKeySpec->base.a.len = NID_secp224r1_len;
    eccPubKeySpec->base.b.data = nullptr;
    eccPubKeySpec->base.b.len = 0;
    eccPubKeySpec->base.g.x.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigGX : g_ecc224CorrectLittleGX);
    eccPubKeySpec->base.g.x.len = NID_secp224r1_len;
    eccPubKeySpec->base.g.y.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigGY : g_ecc224CorrectLittleGY);
    eccPubKeySpec->base.g.y.len = NID_secp224r1_len;
    eccPubKeySpec->base.n.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigN : g_ecc224CorrectLittleN);
    eccPubKeySpec->base.n.len = NID_secp224r1_len;
    eccPubKeySpec->base.h = g_ecc224CorrectH;
    eccPubKeySpec->pk.x.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigPkX : g_ecc224CorrectLittlePkX);
    eccPubKeySpec->pk.x.len = NID_secp224r1_len;
    eccPubKeySpec->pk.y.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigPkY : g_ecc224CorrectLittlePkY);
    eccPubKeySpec->pk.y.len = NID_secp224r1_len;

    *spec = reinterpret_cast<HcfAsyKeyParamsSpec *>(eccPubKeySpec);
    return HCF_SUCCESS;
}

HcfResult ConstructEcc224ErrPriKeyParamsSpec(HcfAsyKeyParamsSpec **spec)
{
    HcfEccPriKeyParamsSpec *eccPriKeySpec = &g_ecc224PriKeySpec;
    HcfECField *tmpField = reinterpret_cast<HcfECField *>(&g_fieldFp);

    eccPriKeySpec->base.base.algName = const_cast<char *>(g_eccAlgName.c_str());
    eccPriKeySpec->base.base.specType = HCF_PRIVATE_KEY_SPEC;
    eccPriKeySpec->base.field = tmpField;
    eccPriKeySpec->base.field->fieldType = const_cast<char *>(g_eccFieldType.c_str());
    (reinterpret_cast<HcfECFieldFp *>(eccPriKeySpec->base.field))->p.data =
        (IS_BIG_ENDIAN ? g_ecc224CorrectBigP : g_ecc224CorrectLittleP);
    (reinterpret_cast<HcfECFieldFp *>(eccPriKeySpec->base.field))->p.len = NID_secp224r1_len;
    eccPriKeySpec->base.a.data = nullptr;
    eccPriKeySpec->base.a.len = 0;
    eccPriKeySpec->base.b.data = nullptr;
    eccPriKeySpec->base.b.len = 0;
    eccPriKeySpec->base.g.x.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigGX : g_ecc224CorrectLittleGX);
    eccPriKeySpec->base.g.x.len = NID_secp224r1_len;
    eccPriKeySpec->base.g.y.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigGY : g_ecc224CorrectLittleGY);
    eccPriKeySpec->base.g.y.len = NID_secp224r1_len;
    eccPriKeySpec->base.n.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigN : g_ecc224CorrectLittleN);
    eccPriKeySpec->base.n.len = NID_secp224r1_len;
    eccPriKeySpec->base.h = g_ecc224CorrectH;
    eccPriKeySpec->sk.data = (IS_BIG_ENDIAN ? g_ecc224CorrectBigSk : g_ecc224CorrectLittleSk);
    eccPriKeySpec->sk.len = NID_secp224r1_len;

    *spec = reinterpret_cast<HcfAsyKeyParamsSpec *>(eccPriKeySpec);
    return HCF_SUCCESS;
}

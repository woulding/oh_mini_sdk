/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "ani_asy_key_generator_by_spec.h"
#include "ani_key_pair.h"
#include "ani_pri_key.h"
#include "ani_pub_key.h"
#include "detailed_dsa_key_params.h"
#include "detailed_ecc_key_params.h"
#include "detailed_rsa_key_params.h"
#include "detailed_alg_25519_key_params.h"
#include "detailed_dh_key_params.h"

namespace {
using namespace ANI::CryptoFramework;

union AsyKeySpecUnion {
    HcfDsaKeyPairParamsSpec dsaKeyPairSpec;
    HcfDsaPubKeyParamsSpec dsaPubKeySpec;
    HcfDsaCommParamsSpec dsaCommonParamsSpec;
    HcfEccKeyPairParamsSpec eccKeyPairSpec;
    HcfEccPubKeyParamsSpec eccPubKeySpec;
    HcfEccPriKeyParamsSpec eccPriKeySpec;
    HcfEccCommParamsSpec eccCommonParamsSpec;
    HcfRsaKeyPairParamsSpec rsaKeyPairSpec;
    HcfRsaPubKeyParamsSpec rsaPubKeySpec;
    HcfAlg25519KeyPairParamsSpec ed25519KeyPairSpec;
    HcfAlg25519PubKeyParamsSpec ed25519PubKeySpec;
    HcfAlg25519PriKeyParamsSpec ed25519PriKeySpec;
    HcfAlg25519KeyPairParamsSpec x25519KeyPairSpec;
    HcfAlg25519PubKeyParamsSpec x25519PubKeySpec;
    HcfAlg25519PriKeyParamsSpec x25519PriKeySpec;
    HcfDhKeyPairParamsSpec dhKeyPairSpec;
    HcfDhPubKeyParamsSpec dhPubKeySpec;
    HcfDhPriKeyParamsSpec dhPriKeySpec;
    HcfDhCommParamsSpec dhCommonParamsSpec;
};

const std::string DSA_ALG_NAME = "DSA";
const std::string ECC_ALG_NAME = "ECC";
const std::string RSA_ALG_NAME = "RSA";
const std::string DH_ALG_NAME = "DH";
const std::string ED25519_ALG_NAME = "Ed25519";
const std::string X25519_ALG_NAME = "X25519";
const std::string SM2_ALG_NAME = "SM2";

void SetDSAKeyPairParamsSpecAttribute(DSAKeyPairSpec const& dsaParams, HcfDsaKeyPairParamsSpec &dsaKeyPairSpec)
{
    dsaKeyPairSpec.base.base.specType = static_cast<HcfAsyKeySpecType>(dsaParams.base.specType.get_value());
    dsaKeyPairSpec.base.base.algName = const_cast<char *>(dsaParams.base.algName.c_str());
    ArrayU8ToBigInteger(dsaParams.params.p, dsaKeyPairSpec.base.p);
    ArrayU8ToBigInteger(dsaParams.params.q, dsaKeyPairSpec.base.q);
    ArrayU8ToBigInteger(dsaParams.params.g, dsaKeyPairSpec.base.g);
    ArrayU8ToBigInteger(dsaParams.pk, dsaKeyPairSpec.pk);
    ArrayU8ToBigInteger(dsaParams.sk, dsaKeyPairSpec.sk);
}

void SetDSAPubKeyParamsSpecAttribute(DSAPubKeySpec const& dsaParams, HcfDsaPubKeyParamsSpec &dsaPubKeySpec)
{
    dsaPubKeySpec.base.base.specType = static_cast<HcfAsyKeySpecType>(dsaParams.base.specType.get_value());
    dsaPubKeySpec.base.base.algName = const_cast<char *>(dsaParams.base.algName.c_str());
    ArrayU8ToBigInteger(dsaParams.params.p, dsaPubKeySpec.base.p);
    ArrayU8ToBigInteger(dsaParams.params.q, dsaPubKeySpec.base.q);
    ArrayU8ToBigInteger(dsaParams.params.g, dsaPubKeySpec.base.g);
    ArrayU8ToBigInteger(dsaParams.pk, dsaPubKeySpec.pk);
}

void SetDSACommonParamsSpecAttribute(DSACommonParamsSpec const& dsaParams, HcfDsaCommParamsSpec &dsaCommonParamsSpec)
{
    dsaCommonParamsSpec.base.specType = static_cast<HcfAsyKeySpecType>(dsaParams.base.specType.get_value());
    dsaCommonParamsSpec.base.algName = const_cast<char *>(dsaParams.base.algName.c_str());
    ArrayU8ToBigInteger(dsaParams.p, dsaCommonParamsSpec.p);
    ArrayU8ToBigInteger(dsaParams.q, dsaCommonParamsSpec.q);
    ArrayU8ToBigInteger(dsaParams.g, dsaCommonParamsSpec.g);
}

void SetECCKeyPairParamsSpecAttribute(ECCKeyPairSpec const& eccParams, HcfEccKeyPairParamsSpec &eccKeyPairSpec)
{
    eccKeyPairSpec.base.base.specType = static_cast<HcfAsyKeySpecType>(eccParams.base.specType.get_value());
    eccKeyPairSpec.base.base.algName = const_cast<char *>(eccParams.base.algName.c_str());
    if (eccParams.params.field.get_tag() == OptECField::tag_t::ECFIELD) {
        eccKeyPairSpec.base.field->fieldType =
            const_cast<char *>(eccParams.params.field.get_ECFIELD_ref().fieldType.c_str());
    } else if (eccParams.params.field.get_tag() == OptECField::tag_t::ECFIELDFP) {
        HcfECFieldFp* fieldFp = reinterpret_cast<HcfECFieldFp *>(eccKeyPairSpec.base.field);
        fieldFp->base.fieldType =
            const_cast<char *>(eccParams.params.field.get_ECFIELDFP_ref().base.fieldType.c_str());
        ArrayU8ToBigInteger(eccParams.params.field.get_ECFIELDFP_ref().p, fieldFp->p);
    }
    eccKeyPairSpec.base.h = eccParams.params.h;
    ArrayU8ToBigInteger(eccParams.params.a, eccKeyPairSpec.base.a);
    ArrayU8ToBigInteger(eccParams.params.b, eccKeyPairSpec.base.b);
    ArrayU8ToBigInteger(eccParams.params.g.x, eccKeyPairSpec.base.g.x);
    ArrayU8ToBigInteger(eccParams.params.g.y, eccKeyPairSpec.base.g.y);
    ArrayU8ToBigInteger(eccParams.params.n, eccKeyPairSpec.base.n);
    ArrayU8ToBigInteger(eccParams.pk.x, eccKeyPairSpec.pk.x);
    ArrayU8ToBigInteger(eccParams.pk.y, eccKeyPairSpec.pk.y);
    ArrayU8ToBigInteger(eccParams.sk, eccKeyPairSpec.sk);
}

void SetECCPubKeyParamsSpecAttribute(ECCPubKeySpec const& eccParams, HcfEccPubKeyParamsSpec &eccPubKeySpec)
{
    eccPubKeySpec.base.base.specType = static_cast<HcfAsyKeySpecType>(eccParams.base.specType.get_value());
    eccPubKeySpec.base.base.algName = const_cast<char *>(eccParams.base.algName.c_str());
    if (eccParams.params.field.get_tag() == OptECField::tag_t::ECFIELD) {
        eccPubKeySpec.base.field->fieldType =
            const_cast<char *>(eccParams.params.field.get_ECFIELD_ref().fieldType.c_str());
    } else if (eccParams.params.field.get_tag() == OptECField::tag_t::ECFIELDFP) {
        HcfECFieldFp* fieldFp = reinterpret_cast<HcfECFieldFp *>(eccPubKeySpec.base.field);
        fieldFp->base.fieldType =
            const_cast<char *>(eccParams.params.field.get_ECFIELDFP_ref().base.fieldType.c_str());
        ArrayU8ToBigInteger(eccParams.params.field.get_ECFIELDFP_ref().p, fieldFp->p);
    }
    eccPubKeySpec.base.h = eccParams.params.h;
    ArrayU8ToBigInteger(eccParams.params.a, eccPubKeySpec.base.a);
    ArrayU8ToBigInteger(eccParams.params.b, eccPubKeySpec.base.b);
    ArrayU8ToBigInteger(eccParams.params.g.x, eccPubKeySpec.base.g.x);
    ArrayU8ToBigInteger(eccParams.params.g.y, eccPubKeySpec.base.g.y);
    ArrayU8ToBigInteger(eccParams.params.n, eccPubKeySpec.base.n);
    ArrayU8ToBigInteger(eccParams.pk.x, eccPubKeySpec.pk.x);
    ArrayU8ToBigInteger(eccParams.pk.y, eccPubKeySpec.pk.y);
}

void SetECCPriKeyParamsSpecAttribute(ECCPriKeySpec const& eccParams, HcfEccPriKeyParamsSpec &eccPriKeySpec)
{
    eccPriKeySpec.base.base.specType = static_cast<HcfAsyKeySpecType>(eccParams.base.specType.get_value());
    eccPriKeySpec.base.base.algName = const_cast<char *>(eccParams.base.algName.c_str());
    if (eccParams.params.field.get_tag() == OptECField::tag_t::ECFIELD) {
        eccPriKeySpec.base.field->fieldType =
            const_cast<char *>(eccParams.params.field.get_ECFIELD_ref().fieldType.c_str());
    } else if (eccParams.params.field.get_tag() == OptECField::tag_t::ECFIELDFP) {
        HcfECFieldFp* fieldFp = reinterpret_cast<HcfECFieldFp *>(eccPriKeySpec.base.field);
        fieldFp->base.fieldType =
            const_cast<char *>(eccParams.params.field.get_ECFIELDFP_ref().base.fieldType.c_str());
        ArrayU8ToBigInteger(eccParams.params.field.get_ECFIELDFP_ref().p, fieldFp->p);
    }
    eccPriKeySpec.base.h = eccParams.params.h;
    ArrayU8ToBigInteger(eccParams.params.a, eccPriKeySpec.base.a);
    ArrayU8ToBigInteger(eccParams.params.b, eccPriKeySpec.base.b);
    ArrayU8ToBigInteger(eccParams.params.g.x, eccPriKeySpec.base.g.x);
    ArrayU8ToBigInteger(eccParams.params.g.y, eccPriKeySpec.base.g.y);
    ArrayU8ToBigInteger(eccParams.params.n, eccPriKeySpec.base.n);
    ArrayU8ToBigInteger(eccParams.sk, eccPriKeySpec.sk);
}

void SetECCCommonParamsSpecAttribute(ECCCommonParamsSpec const& eccParams, HcfEccCommParamsSpec &eccCommonParamsSpec)
{
    eccCommonParamsSpec.base.specType = static_cast<HcfAsyKeySpecType>(eccParams.base.specType.get_value());
    eccCommonParamsSpec.base.algName = const_cast<char *>(eccParams.base.algName.c_str());
    if (eccParams.field.get_tag() == OptECField::tag_t::ECFIELD) {
        eccCommonParamsSpec.field->fieldType = const_cast<char *>(eccParams.field.get_ECFIELD_ref().fieldType.c_str());
    } else if (eccParams.field.get_tag() == OptECField::tag_t::ECFIELDFP) {
        HcfECFieldFp* fieldFp = reinterpret_cast<HcfECFieldFp *>(eccCommonParamsSpec.field);
        fieldFp->base.fieldType = const_cast<char *>(eccParams.field.get_ECFIELDFP_ref().base.fieldType.c_str());
        ArrayU8ToBigInteger(eccParams.field.get_ECFIELDFP_ref().p, fieldFp->p);
    }
    eccCommonParamsSpec.h = eccParams.h;
    ArrayU8ToBigInteger(eccParams.a, eccCommonParamsSpec.a);
    ArrayU8ToBigInteger(eccParams.b, eccCommonParamsSpec.b);
    ArrayU8ToBigInteger(eccParams.g.x, eccCommonParamsSpec.g.x);
    ArrayU8ToBigInteger(eccParams.g.y, eccCommonParamsSpec.g.y);
    ArrayU8ToBigInteger(eccParams.n, eccCommonParamsSpec.n);
}

void SetRSAKeyPairParamsSpecAttribute(RSAKeyPairSpec const& rsaParams, HcfRsaKeyPairParamsSpec &rsaKeyPairSpec)
{
    rsaKeyPairSpec.base.base.specType = static_cast<HcfAsyKeySpecType>(rsaParams.base.specType.get_value());
    rsaKeyPairSpec.base.base.algName = const_cast<char *>(rsaParams.base.algName.c_str());
    ArrayU8ToBigInteger(rsaParams.params.n, rsaKeyPairSpec.base.n);
    ArrayU8ToBigInteger(rsaParams.pk, rsaKeyPairSpec.pk);
    ArrayU8ToBigInteger(rsaParams.sk, rsaKeyPairSpec.sk);
}

void SetRSAPubKeyParamsSpecAttribute(RSAPubKeySpec const& rsaParams, HcfRsaPubKeyParamsSpec &rsaPubKeySpec)
{
    rsaPubKeySpec.base.base.specType = static_cast<HcfAsyKeySpecType>(rsaParams.base.specType.get_value());
    rsaPubKeySpec.base.base.algName = const_cast<char *>(rsaParams.base.algName.c_str());
    ArrayU8ToBigInteger(rsaParams.params.n, rsaPubKeySpec.base.n);
    ArrayU8ToBigInteger(rsaParams.pk, rsaPubKeySpec.pk);
}

void SetEd25519KeyPairParamsSpecAttribute(ED25519KeyPairSpec const& ed25519Params,
    HcfAlg25519KeyPairParamsSpec &ed25519KeyPairSpec)
{
    ed25519KeyPairSpec.base.specType = static_cast<HcfAsyKeySpecType>(ed25519Params.base.specType.get_value());
    ed25519KeyPairSpec.base.algName = const_cast<char *>(ed25519Params.base.algName.c_str());
    ArrayU8ToBigInteger(ed25519Params.pk, ed25519KeyPairSpec.pk);
    ArrayU8ToBigInteger(ed25519Params.sk, ed25519KeyPairSpec.sk);
}

void SetEd25519PubKeyParamsSpecAttribute(ED25519PubKeySpec const& ed25519Params,
    HcfAlg25519PubKeyParamsSpec &ed25519PubKeySpec)
{
    ed25519PubKeySpec.base.specType = static_cast<HcfAsyKeySpecType>(ed25519Params.base.specType.get_value());
    ed25519PubKeySpec.base.algName = const_cast<char *>(ed25519Params.base.algName.c_str());
    ArrayU8ToBigInteger(ed25519Params.pk, ed25519PubKeySpec.pk);
}

void SetEd25519PriKeyParamsSpecAttribute(ED25519PriKeySpec const& ed25519Params,
    HcfAlg25519PriKeyParamsSpec &ed25519PriKeySpec)
{
    ed25519PriKeySpec.base.specType = static_cast<HcfAsyKeySpecType>(ed25519Params.base.specType.get_value());
    ed25519PriKeySpec.base.algName = const_cast<char *>(ed25519Params.base.algName.c_str());
    ArrayU8ToBigInteger(ed25519Params.sk, ed25519PriKeySpec.sk);
}

void SetX25519KeyPairParamsSpecAttribute(X25519KeyPairSpec const& x25519Params,
    HcfAlg25519KeyPairParamsSpec &x25519KeyPairSpec)
{
    x25519KeyPairSpec.base.specType = static_cast<HcfAsyKeySpecType>(x25519Params.base.specType.get_value());
    x25519KeyPairSpec.base.algName = const_cast<char *>(x25519Params.base.algName.c_str());
    ArrayU8ToBigInteger(x25519Params.pk, x25519KeyPairSpec.pk);
    ArrayU8ToBigInteger(x25519Params.sk, x25519KeyPairSpec.sk);
}

void SetX25519PubKeyParamsSpecAttribute(X25519PubKeySpec const& x25519Params,
    HcfAlg25519PubKeyParamsSpec &x25519PubKeySpec)
{
    x25519PubKeySpec.base.specType = static_cast<HcfAsyKeySpecType>(x25519Params.base.specType.get_value());
    x25519PubKeySpec.base.algName = const_cast<char *>(x25519Params.base.algName.c_str());
    ArrayU8ToBigInteger(x25519Params.pk, x25519PubKeySpec.pk);
}

void SetX25519PriKeyParamsSpecAttribute(X25519PriKeySpec const& x25519Params,
    HcfAlg25519PriKeyParamsSpec &x25519PriKeySpec)
{
    x25519PriKeySpec.base.specType = static_cast<HcfAsyKeySpecType>(x25519Params.base.specType.get_value());
    x25519PriKeySpec.base.algName = const_cast<char *>(x25519Params.base.algName.c_str());
    ArrayU8ToBigInteger(x25519Params.sk, x25519PriKeySpec.sk);
}

void SetDhKeyPairParamsSpecAttribute(DHKeyPairSpec const& dhParams, HcfDhKeyPairParamsSpec &dhKeyPairSpec)
{
    dhKeyPairSpec.base.base.specType = static_cast<HcfAsyKeySpecType>(dhParams.base.specType.get_value());
    dhKeyPairSpec.base.base.algName = const_cast<char *>(dhParams.base.algName.c_str());
    dhKeyPairSpec.base.length = dhParams.params.l;
    ArrayU8ToBigInteger(dhParams.params.p, dhKeyPairSpec.base.p);
    ArrayU8ToBigInteger(dhParams.params.g, dhKeyPairSpec.base.g);
    ArrayU8ToBigInteger(dhParams.pk, dhKeyPairSpec.pk);
    ArrayU8ToBigInteger(dhParams.sk, dhKeyPairSpec.sk);
}

void SetDhPubKeyParamsSpecAttribute(DHPubKeySpec const& dhParams, HcfDhPubKeyParamsSpec &dhPubKeySpec)
{
    dhPubKeySpec.base.base.specType = static_cast<HcfAsyKeySpecType>(dhParams.base.specType.get_value());
    dhPubKeySpec.base.base.algName = const_cast<char *>(dhParams.base.algName.c_str());
    dhPubKeySpec.base.length = dhParams.params.l;
    ArrayU8ToBigInteger(dhParams.params.p, dhPubKeySpec.base.p);
    ArrayU8ToBigInteger(dhParams.params.g, dhPubKeySpec.base.g);
    ArrayU8ToBigInteger(dhParams.pk, dhPubKeySpec.pk);
}

void SetDhPriKeyParamsSpecAttribute(DHPriKeySpec const& dhParams, HcfDhPriKeyParamsSpec &dhPriKeySpec)
{
    dhPriKeySpec.base.base.specType = static_cast<HcfAsyKeySpecType>(dhParams.base.specType.get_value());
    dhPriKeySpec.base.base.algName = const_cast<char *>(dhParams.base.algName.c_str());
    dhPriKeySpec.base.length = dhParams.params.l;
    ArrayU8ToBigInteger(dhParams.params.p, dhPriKeySpec.base.p);
    ArrayU8ToBigInteger(dhParams.params.g, dhPriKeySpec.base.g);
    ArrayU8ToBigInteger(dhParams.sk, dhPriKeySpec.sk);
}

void SetDhCommonParamsSpecAttribute(DHCommonParamsSpec const& dhParams, HcfDhCommParamsSpec &dhCommonParamsSpec)
{
    dhCommonParamsSpec.base.specType = static_cast<HcfAsyKeySpecType>(dhParams.base.specType.get_value());
    dhCommonParamsSpec.base.algName = const_cast<char *>(dhParams.base.algName.c_str());
    dhCommonParamsSpec.length = dhParams.l;
    ArrayU8ToBigInteger(dhParams.p, dhCommonParamsSpec.p);
    ArrayU8ToBigInteger(dhParams.g, dhCommonParamsSpec.g);
}

HcfAsyKeyParamsSpec* CreateDSASpec(OptAsyKeySpec const& asyKeySpec, AsyKeySpecUnion &asyKeySpecUnion)
{
    if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::DSAKEYPAIRSPEC) {
        SetDSAKeyPairParamsSpecAttribute(asyKeySpec.get_DSAKEYPAIRSPEC_ref(), asyKeySpecUnion.dsaKeyPairSpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec *>(&asyKeySpecUnion.dsaKeyPairSpec);
    } else if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::DSAPUBKEYSPEC) {
        SetDSAPubKeyParamsSpecAttribute(asyKeySpec.get_DSAPUBKEYSPEC_ref(), asyKeySpecUnion.dsaPubKeySpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec *>(&asyKeySpecUnion.dsaPubKeySpec);
    } else if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::DSACOMMONPARAMSSPEC) {
        SetDSACommonParamsSpecAttribute(asyKeySpec.get_DSACOMMONPARAMSSPEC_ref(), asyKeySpecUnion.dsaCommonParamsSpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec *>(&asyKeySpecUnion.dsaCommonParamsSpec);
    }
    return nullptr;
}

HcfAsyKeyParamsSpec* CreateECCSpec(OptAsyKeySpec const& asyKeySpec, AsyKeySpecUnion &asyKeySpecUnion,
    HcfECFieldFp &ecFieldFp)
{
    HcfECField *ecField = &ecFieldFp.base;
    if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::ECCKEYPAIRSPEC) {
        asyKeySpecUnion.eccKeyPairSpec.base.field = ecField;
        SetECCKeyPairParamsSpecAttribute(asyKeySpec.get_ECCKEYPAIRSPEC_ref(), asyKeySpecUnion.eccKeyPairSpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec *>(&asyKeySpecUnion.eccKeyPairSpec);
    } else if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::ECCPUBKEYSPEC) {
        asyKeySpecUnion.eccPubKeySpec.base.field = ecField;
        SetECCPubKeyParamsSpecAttribute(asyKeySpec.get_ECCPUBKEYSPEC_ref(), asyKeySpecUnion.eccPubKeySpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec *>(&asyKeySpecUnion.eccPubKeySpec);
    } else if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::ECCPRIKEYSPEC) {
        asyKeySpecUnion.eccPriKeySpec.base.field = ecField;
        SetECCPriKeyParamsSpecAttribute(asyKeySpec.get_ECCPRIKEYSPEC_ref(), asyKeySpecUnion.eccPriKeySpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec *>(&asyKeySpecUnion.eccPriKeySpec);
    } else if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::ECCCOMMONPARAMSSPEC) {
        asyKeySpecUnion.eccCommonParamsSpec.field = ecField;
        SetECCCommonParamsSpecAttribute(asyKeySpec.get_ECCCOMMONPARAMSSPEC_ref(), asyKeySpecUnion.eccCommonParamsSpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec *>(&asyKeySpecUnion.eccCommonParamsSpec);
    }
    return nullptr;
}

HcfAsyKeyParamsSpec* CreateRSASpec(OptAsyKeySpec const& asyKeySpec, AsyKeySpecUnion &asyKeySpecUnion)
{
    if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::RSAKEYPAIRSPEC) {
        SetRSAKeyPairParamsSpecAttribute(asyKeySpec.get_RSAKEYPAIRSPEC_ref(), asyKeySpecUnion.rsaKeyPairSpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec *>(&asyKeySpecUnion.rsaKeyPairSpec);
    } else if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::RSAPUBKEYSPEC) {
        SetRSAPubKeyParamsSpecAttribute(asyKeySpec.get_RSAPUBKEYSPEC_ref(), asyKeySpecUnion.rsaPubKeySpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec *>(&asyKeySpecUnion.rsaPubKeySpec);
    } else if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::RSACOMMONPARAMSSPEC) {
        LOGE("RSA not support comm key spec");
        return nullptr;
    }
    return nullptr;
}

HcfAsyKeyParamsSpec* CreateEd25519Spec(OptAsyKeySpec const& asyKeySpec, AsyKeySpecUnion &asyKeySpecUnion)
{
    if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::ED25519KEYPAIRSPEC) {
        SetEd25519KeyPairParamsSpecAttribute(asyKeySpec.get_ED25519KEYPAIRSPEC_ref(),
            asyKeySpecUnion.ed25519KeyPairSpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec *>(&asyKeySpecUnion.ed25519KeyPairSpec);
    } else if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::ED25519PUBKEYSPEC) {
        SetEd25519PubKeyParamsSpecAttribute(asyKeySpec.get_ED25519PUBKEYSPEC_ref(), asyKeySpecUnion.ed25519PubKeySpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec *>(&asyKeySpecUnion.ed25519PubKeySpec);
    } else if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::ED25519PRIKEYSPEC) {
        SetEd25519PriKeyParamsSpecAttribute(asyKeySpec.get_ED25519PRIKEYSPEC_ref(), asyKeySpecUnion.ed25519PriKeySpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec *>(&asyKeySpecUnion.ed25519PriKeySpec);
    }
    return nullptr;
}

HcfAsyKeyParamsSpec* CreateX25519Spec(OptAsyKeySpec const& asyKeySpec, AsyKeySpecUnion &asyKeySpecUnion)
{
    if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::X25519KEYPAIRSPEC) {
        SetX25519KeyPairParamsSpecAttribute(asyKeySpec.get_X25519KEYPAIRSPEC_ref(), asyKeySpecUnion.x25519KeyPairSpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec *>(&asyKeySpecUnion.x25519KeyPairSpec);
    } else if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::X25519PUBKEYSPEC) {
        SetX25519PubKeyParamsSpecAttribute(asyKeySpec.get_X25519PUBKEYSPEC_ref(), asyKeySpecUnion.x25519PubKeySpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec *>(&asyKeySpecUnion.x25519PubKeySpec);
    } else if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::X25519PRIKEYSPEC) {
        SetX25519PriKeyParamsSpecAttribute(asyKeySpec.get_X25519PRIKEYSPEC_ref(), asyKeySpecUnion.x25519PriKeySpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec *>(&asyKeySpecUnion.x25519PriKeySpec);
    }
    return nullptr;
}

HcfAsyKeyParamsSpec* CreateDHSpec(OptAsyKeySpec const& asyKeySpec, AsyKeySpecUnion &asyKeySpecUnion)
{
    if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::DHKEYPAIRSPEC) {
        SetDhKeyPairParamsSpecAttribute(asyKeySpec.get_DHKEYPAIRSPEC_ref(), asyKeySpecUnion.dhKeyPairSpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec *>(&asyKeySpecUnion.dhKeyPairSpec);
    } else if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::DHPUBKEYSPEC) {
        SetDhPubKeyParamsSpecAttribute(asyKeySpec.get_DHPUBKEYSPEC_ref(), asyKeySpecUnion.dhPubKeySpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec *>(&asyKeySpecUnion.dhPubKeySpec);
    } else if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::DHPRIKEYSPEC) {
        SetDhPriKeyParamsSpecAttribute(asyKeySpec.get_DHPRIKEYSPEC_ref(), asyKeySpecUnion.dhPriKeySpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec *>(&asyKeySpecUnion.dhPriKeySpec);
    } else if (asyKeySpec.get_tag() == OptAsyKeySpec::tag_t::DHCOMMONPARAMSSPEC) {
        SetDhCommonParamsSpecAttribute(asyKeySpec.get_DHCOMMONPARAMSSPEC_ref(), asyKeySpecUnion.dhCommonParamsSpec);
        return reinterpret_cast<HcfAsyKeyParamsSpec *>(&asyKeySpecUnion.dhCommonParamsSpec);
    }
    return nullptr;
}

HcfAsyKeyParamsSpec* CreateParamsSpec(OptAsyKeySpec const& asyKeySpec, AsyKeySpecUnion &asyKeySpecUnion,
    HcfECFieldFp &ecFieldFp)
{
    const std::string &algName = asyKeySpec.get_ASYKEYSPEC_ref().algName.c_str();
    if (algName == DSA_ALG_NAME) {
        return CreateDSASpec(asyKeySpec, asyKeySpecUnion);
    } else if (algName == ECC_ALG_NAME || algName == SM2_ALG_NAME) {
        return CreateECCSpec(asyKeySpec, asyKeySpecUnion, ecFieldFp);
    } else if (algName == RSA_ALG_NAME) {
        return CreateRSASpec(asyKeySpec, asyKeySpecUnion);
    } else if (algName == ED25519_ALG_NAME) {
        return CreateEd25519Spec(asyKeySpec, asyKeySpecUnion);
    } else if (algName == X25519_ALG_NAME) {
        return CreateX25519Spec(asyKeySpec, asyKeySpecUnion);
    } else if (algName == DH_ALG_NAME) {
        return CreateDHSpec(asyKeySpec, asyKeySpecUnion);
    }
    return nullptr;
}
} // namespace

namespace ANI::CryptoFramework {
AsyKeyGeneratorBySpecImpl::AsyKeyGeneratorBySpecImpl() {}

AsyKeyGeneratorBySpecImpl::AsyKeyGeneratorBySpecImpl(HcfAsyKeyGeneratorBySpec *generator) : generator_(generator) {}

AsyKeyGeneratorBySpecImpl::~AsyKeyGeneratorBySpecImpl()
{
    HcfObjDestroy(this->generator_);
    this->generator_ = nullptr;
}

KeyPair AsyKeyGeneratorBySpecImpl::GenerateKeyPairSync()
{
    if (this->generator_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "generator spec obj is nullptr!");
        return make_holder<KeyPairImpl, KeyPair>();
    }
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = this->generator_->generateKeyPair(this->generator_, &keyPair);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "generateKeyPair failed");
        return make_holder<KeyPairImpl, KeyPair>();
    }
    return make_holder<KeyPairImpl, KeyPair>(keyPair);
}

PriKey AsyKeyGeneratorBySpecImpl::GeneratePriKeySync()
{
    if (this->generator_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "generator spec obj is nullptr!");
        return make_holder<PriKeyImpl, PriKey>();
    }
    HcfPriKey *priKey = nullptr;
    HcfResult res = this->generator_->generatePriKey(this->generator_, &priKey);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "generatePriKey failed");
        return make_holder<PriKeyImpl, PriKey>();
    }
    return make_holder<PriKeyImpl, PriKey>(priKey);
}

PubKey AsyKeyGeneratorBySpecImpl::GeneratePubKeySync()
{
    if (this->generator_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "generator spec obj is nullptr!");
        return make_holder<PubKeyImpl, PubKey>();
    }
    HcfPubKey *pubKey = nullptr;
    HcfResult res = this->generator_->generatePubKey(this->generator_, &pubKey);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "generatePubKey failed");
        return make_holder<PubKeyImpl, PubKey>();
    }
    return make_holder<PubKeyImpl, PubKey>(pubKey);
}

string AsyKeyGeneratorBySpecImpl::GetAlgName()
{
    if (this->generator_ == nullptr) {
        ANI_LOGE_THROW(HCF_ERR_ANI, "generator spec obj is nullptr!");
        return "";
    }
    const char *algName = this->generator_->getAlgName(this->generator_);
    return (algName == nullptr) ? "" : string(algName);
}

AsyKeyGeneratorBySpec CreateAsyKeyGeneratorBySpec(OptAsyKeySpec const& asyKeySpec)
{
    AsyKeySpecUnion asyKeySpecUnion = {};
    HcfECFieldFp ecFieldFp = {};
    HcfAsyKeyParamsSpec *spec = CreateParamsSpec(asyKeySpec, asyKeySpecUnion, ecFieldFp);
    if (spec == nullptr) {
        ANI_LOGE_THROW(HCF_INVALID_PARAMS, "invalid asy key spec!");
        return make_holder<AsyKeyGeneratorBySpecImpl, AsyKeyGeneratorBySpec>();
    }

    HcfAsyKeyGeneratorBySpec *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorBySpecCreate(spec, &generator);
    if (res != HCF_SUCCESS) {
        ANI_LOGE_THROW(res, "create generator spec obj fail!");
        return make_holder<AsyKeyGeneratorBySpecImpl, AsyKeyGeneratorBySpec>();
    }
    return make_holder<AsyKeyGeneratorBySpecImpl, AsyKeyGeneratorBySpec>(generator);
}
} // namespace ANI::CryptoFramework

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_CreateAsyKeyGeneratorBySpec(ANI::CryptoFramework::CreateAsyKeyGeneratorBySpec);
// NOLINTEND

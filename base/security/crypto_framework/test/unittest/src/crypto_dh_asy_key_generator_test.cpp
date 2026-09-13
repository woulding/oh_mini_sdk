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
#include <cstring>

#include "asy_key_generator.h"
#include "dh_asy_key_generator_openssl.h"
#include "blob.h"
#include "detailed_ecc_key_params.h"
#include "ecc_key_util.h"
#include "ecc_openssl_common.h"
#include "ecc_openssl_common_param_spec.h"
#include "ecc_common.h"
#include "ecdsa_openssl.h"
#include "memory.h"
#include "securec.h"
#include "openssl_common.h"
#include "asy_key_params.h"
#include "params_parser.h"
#include "memory_mock.h"
#include "openssl_adapter_mock.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoDHAsyKeyGeneratorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoDHAsyKeyGeneratorTest::TearDownTestCase() {}
void CryptoDHAsyKeyGeneratorTest::SetUp() {}
void CryptoDHAsyKeyGeneratorTest::TearDown() {}

static string g_dh1536AlgoName = "DH_modp1536";
static string g_dhAlgoName = "DH";
static string g_dhpubkeyformatName = "X.509";
static string g_dhprikeyformatName = "PKCS#8";
constexpr int BIT8 = 8;
constexpr int BIT4 = 4;
constexpr int BIT2 = 2;
HcfAsyKeyGenerator *g_dh1536Generator = nullptr;
HcfKeyPair *g_dh1536KeyPair = nullptr;

static const char *GetMockClass(void)
{
    return "HcfEcc";
}
HcfObjectBase g_obj = {
    .getClass = GetMockClass,
    .destroy = nullptr
};

HcfBlob g_mockDH1536PriKeyBlob = {
    .data = nullptr,
    .len = 0
};

HcfBlob g_mockDH1536PubKeyBlob = {
    .data = nullptr,
    .len = 0
};

HcfBlob g_mockECC_BrainPool160r1PriKeyBlob = {
    .data = nullptr,
    .len = 0
};

HcfBlob g_mockECC_BrainPool160r1PubKeyBlob = {
    .data = nullptr,
    .len = 0
};

string g_modp_1536_p =
    "ffffffffffffffffca237327f1746c084abc9804670c354e7096966d9ed52907"
    "208552bb1c62f356dca3ad9683655d23fd24cf5f69163fa81c55d39a98da4836"
    "a163bf05c2007cb8ece45b3d492866517c4b1fe6ae9f24115a899fa5ee386bfb"
    "f406b7ed0bff5cb6a637ed6bf44c42e9625e7ec6e485b5766d51c2454fe1356d"
    "f25f1437302b0a6dcd3a431bef9519b38e3404dd514a08793b139b22020bbea6"
    "8a67cc7429024e0880dc1cd1c4c6628b2168c234c90fdaa2ffffffffffffffff";

string g_modp_2048_p =
    "ffffffffffffffff8aacaa6815728e5a98fa051015d22618ea956ae53995497c"
    "95581718de2bcbf66f4c52c9b5c55df0ec07a28f9b2783a2180e8603e39e772c"
    "2e36ce3b32905e46ca18217cf1746c084abc9804670c354e7096966d9ed52907"
    "208552bb1c62f356dca3ad9683655d23fd24cf5f69163fa81c55d39a98da4836"
    "a163bf05c2007cb8ece45b3d492866517c4b1fe6ae9f24115a899fa5ee386bfb"
    "f406b7ed0bff5cb6a637ed6bf44c42e9625e7ec6e485b5766d51c2454fe1356d"
    "f25f1437302b0a6dcd3a431bef9519b38e3404dd514a08793b139b22020bbea6"
    "8a67cc7429024e0880dc1cd1c4c6628b2168c234c90fdaa2ffffffffffffffff";

string g_modp_3072_p =
    "ffffffffffffffffa93ad2ca4b82d120e0fd108e43db5bfc74e5ab3108e24fa0"
    "bad946e2770988c07a615d6cbbe11757177b200c521f2b183ec86a64d8760273"
    "d98a0864f12ffa061ad2ee6bcee3d2264a25619d1e8c94e0db0933d7abf5ae8c"
    "a6e1e4c7b3970f855d060c7d8aea715758dbef0aecfb8504df1cba64a85521ab"
    "04507a33ad33170d8aaac42d15728e5a98fa051015d22618ea956ae53995497c"
    "95581718de2bcbf66f4c52c9b5c55df0ec07a28f9b2783a2180e8603e39e772c"
    "2e36ce3b32905e46ca18217cf1746c084abc9804670c354e7096966d9ed52907"
    "208552bb1c62f356dca3ad9683655d23fd24cf5f69163fa81c55d39a98da4836"
    "a163bf05c2007cb8ece45b3d492866517c4b1fe6ae9f24115a899fa5ee386bfb"
    "f406b7ed0bff5cb6a637ed6bf44c42e9625e7ec6e485b5766d51c2454fe1356d"
    "f25f1437302b0a6dcd3a431bef9519b38e3404dd514a08793b139b22020bbea6"
    "8a67cc7429024e0880dc1cd1c4c6628b2168c234c90fdaa2ffffffffffffffff";

string g_modp_4096_p =
    "ffffffffffffffff340631994df435c990a6c08f86ffb7dc8d8fddc193b4ea98"
    "d5b05aa9d00691272170481cb81bdd76cee2d7af1f612970515be7ed233ba186"
    "a090c3a299b2964f4e6bc05d287c59471fbecaa62e8efc1404de8ef9dbbbc2db"
    "2ad44ce82583e9cab6150bda1a9468346af4e23c99c32718bdba5b2688719a10"
    "a787e6d71a723c12a92108014b82d120e0fd108e43db5bfc74e5ab3108e24fa0"
    "bad946e2770988c07a615d6cbbe11757177b200c521f2b183ec86a64d8760273"
    "d98a0864f12ffa061ad2ee6bcee3d2264a25619d1e8c94e0db0933d7abf5ae8c"
    "a6e1e4c7b3970f855d060c7d8aea715758dbef0aecfb8504df1cba64a85521ab"
    "04507a33ad33170d8aaac42d15728e5a98fa051015d22618ea956ae53995497c"
    "95581718de2bcbf66f4c52c9b5c55df0ec07a28f9b2783a2180e8603e39e772c"
    "2e36ce3b32905e46ca18217cf1746c084abc9804670c354e7096966d9ed52907"
    "208552bb1c62f356dca3ad9683655d23fd24cf5f69163fa81c55d39a98da4836"
    "a163bf05c2007cb8ece45b3d492866517c4b1fe6ae9f24115a899fa5ee386bfb"
    "f406b7ed0bff5cb6a637ed6bf44c42e9625e7ec6e485b5766d51c2454fe1356d"
    "f25f1437302b0a6dcd3a431bef9519b38e3404dd514a08793b139b22020bbea6"
    "8a67cc7429024e0880dc1cd1c4c6628b2168c234c90fdaa2ffffffffffffffff";

string g_modp_6144_p =
    "ffffffffffffffff6dcc4024e694f91e0b7474d612bf2d5b3f4860ee043e8f66"
    "6e3c0468387fe8d72ef29632da56c9eca313d55ceb19ccb18a1fbff0f550aa3d"
    "b7c5da7606a1d58bf29be328a79715ee0f8037e014cc5ed2bf48e1d8cc8f6d7e"
    "2b4154aa4bd407b2ff585ac50f1d45b736cc88be23a97a7ebec7e8f359e7c97f"
    "900b1c9eb5a8403146980c82d55e702f6e74fef6f482d7ced1721d03f032ea15"
    "c64b92ec5983ca01378cd2bf6fb8f4012bd7af4233205151e6cc254bdb7f1447"
    "ced4bb1b44ce6cbacf9b14edda3edbeb865a8918179727b09027d831b06a53ed"
    "413001aee5db382fad9e530ef8ff94063dba37bdc9751e76602646dec1d4dcb2"
    "d27c702636c3fab4340284924df435c990a6c08f86ffb7dc8d8fddc193b4ea98"
    "d5b05aa9d00691272170481cb81bdd76cee2d7af1f612970515be7ed233ba186"
    "a090c3a299b2964f4e6bc05d287c59471fbecaa62e8efc1404de8ef9dbbbc2db"
    "2ad44ce82583e9cab6150bda1a9468346af4e23c99c32718bdba5b2688719a10"
    "a787e6d71a723c12a92108014b82d120e0fd108e43db5bfc74e5ab3108e24fa0"
    "bad946e2770988c07a615d6cbbe11757177b200c521f2b183ec86a64d8760273"
    "d98a0864f12ffa061ad2ee6bcee3d2264a25619d1e8c94e0db0933d7abf5ae8c"
    "a6e1e4c7b3970f855d060c7d8aea715758dbef0aecfb8504df1cba64a85521ab"
    "04507a33ad33170d8aaac42d15728e5a98fa051015d22618ea956ae53995497c"
    "95581718de2bcbf66f4c52c9b5c55df0ec07a28f9b2783a2180e8603e39e772c"
    "2e36ce3b32905e46ca18217cf1746c084abc9804670c354e7096966d9ed52907"
    "208552bb1c62f356dca3ad9683655d23fd24cf5f69163fa81c55d39a98da4836"
    "a163bf05c2007cb8ece45b3d492866517c4b1fe6ae9f24115a899fa5ee386bfb"
    "f406b7ed0bff5cb6a637ed6bf44c42e9625e7ec6e485b5766d51c2454fe1356d"
    "f25f1437302b0a6dcd3a431bef9519b38e3404dd514a08793b139b22020bbea6"
    "8a67cc7429024e0880dc1cd1c4c6628b2168c234c90fdaa2ffffffffffffffff";

string g_modp_8192_p =
    "ffffffffffffffff98edd3df60c980dd80b96e71c81f56e8765694df9e3050e2"
    "5677e9aa9558e447fc026e47c9190da6d5ee382b889a002e481c6cd74009438b"
    "eb879f92359046f41ecfa268faf36bc37ee74d73b1d510bd5ded7ea1f9ab4819"
    "0846851d64f31cc5a0255dc14597e89974ab6a36df310ee03f44f82d6d2a13f8"
    "b3a278a6062b3cf5ed5bdd3a79683303a2c087e8fa9d4b7f2f8385dd4bcbc886"
    "6cea306b3473fc641a23f0c713eb57a8a4037c0722222e04fc848ad9e3fdb8be"
    "e39d652d238f16cb2bf1c9783423b4745ae4f5683aab639c6ba424662576f693"
    "8afc47ed741fa7bf8d9dd3003bc832b673b931bad8bec4d0a932df8c38777cb6"
    "12fee5e474a3926f6dbe1159e694f91e0b7474d612bf2d5b3f4860ee043e8f66"
    "6e3c0468387fe8d72ef29632da56c9eca313d55ceb19ccb18a1fbff0f550aa3d"
    "b7c5da7606a1d58bf29be328a79715ee0f8037e014cc5ed2bf48e1d8cc8f6d7e"
    "2b4154aa4bd407b2ff585ac50f1d45b736cc88be23a97a7ebec7e8f359e7c97f"
    "900b1c9eb5a8403146980c82d55e702f6e74fef6f482d7ced1721d03f032ea15"
    "c64b92ec5983ca01378cd2bf6fb8f4012bd7af4233205151e6cc254bdb7f1447"
    "ced4bb1b44ce6cbacf9b14edda3edbeb865a8918179727b09027d831b06a53ed"
    "413001aee5db382fad9e530ef8ff94063dba37bdc9751e76602646dec1d4dcb2"
    "d27c702636c3fab4340284924df435c990a6c08f86ffb7dc8d8fddc193b4ea98"
    "d5b05aa9d00691272170481cb81bdd76cee2d7af1f612970515be7ed233ba186"
    "a090c3a299b2964f4e6bc05d287c59471fbecaa62e8efc1404de8ef9dbbbc2db"
    "2ad44ce82583e9cab6150bda1a9468346af4e23c99c32718bdba5b2688719a10"
    "a787e6d71a723c12a92108014b82d120e0fd108e43db5bfc74e5ab3108e24fa0"
    "bad946e2770988c07a615d6cbbe11757177b200c521f2b183ec86a64d8760273"
    "d98a0864f12ffa061ad2ee6bcee3d2264a25619d1e8c94e0db0933d7abf5ae8c"
    "a6e1e4c7b3970f855d060c7d8aea715758dbef0aecfb8504df1cba64a85521ab"
    "04507a33ad33170d8aaac42d15728e5a98fa051015d22618ea956ae53995497c"
    "95581718de2bcbf66f4c52c9b5c55df0ec07a28f9b2783a2180e8603e39e772c"
    "2e36ce3b32905e46ca18217cf1746c084abc9804670c354e7096966d9ed52907"
    "208552bb1c62f356dca3ad9683655d23fd24cf5f69163fa81c55d39a98da4836"
    "a163bf05c2007cb8ece45b3d492866517c4b1fe6ae9f24115a899fa5ee386bfb"
    "f406b7ed0bff5cb6a637ed6bf44c42e9625e7ec6e485b5766d51c2454fe1356d"
    "f25f1437302b0a6dcd3a431bef9519b38e3404dd514a08793b139b22020bbea6"
    "8a67cc7429024e0880dc1cd1c4c6628b2168c234c90fdaa2ffffffffffffffff";

string g_ffdhe_2048_p =
    "ffffffffffffffff61285c97886b4238c1b2effac6f34a267d1683b2c58ef183"
    "2ec220053bb5fcbc4c6fad73c3fe3b1beef281838e4f1232e98583ff9172fe9c"
    "28342f61c03404cdcdf7e2ec9e02fce1ee0a6d700b07a7c86372bb19ae56ede7"
    "de394df41d4f42a360d7f468b96adab7b2c8e3fbd108a94bb324fb61bc0ab182"
    "483a797a30acca4f36ade7351df158a1f3efe872e2a689dae0e68b77984f0c70"
    "7f57c935b557135e3ded1af3856365555f066ed02433f51fd5fd6561d3df1ed5"
    "aec4617af681b202630c75d87d2fe363249b3ef9cc939dce146433fba9e13641"
    "ce2d3695d8b9c583273d3cf1afdc5620a2bb4a9aadf85458ffffffffffffffff";

string g_ffdhe_3072_p =
    "ffffffffffffffff66c62e3725e41d2b3fd59d7c3c1b20eefa53ddef0abcd06b"
    "d5c4484e1dbf9a429b0deadaabc5219722363a0de86d2bc59c9df69e5cae82ab"
    "71f54bff64f2e21ee2d74dd3f4fd4452bc437944b4130c9385139270aefe1309"
    "c186d91c598cb0fa91f7f7ee7ad91d26d6e6c90761b46fc9f99c0238bc34f4de"
    "6519035bde355b3b611fcfdc886b4238c1b2effac6f34a267d1683b2c58ef183"
    "2ec220053bb5fcbc4c6fad73c3fe3b1beef281838e4f1232e98583ff9172fe9c"
    "28342f61c03404cdcdf7e2ec9e02fce1ee0a6d700b07a7c86372bb19ae56ede7"
    "de394df41d4f42a360d7f468b96adab7b2c8e3fbd108a94bb324fb61bc0ab182"
    "483a797a30acca4f36ade7351df158a1f3efe872e2a689dae0e68b77984f0c70"
    "7f57c935b557135e3ded1af3856365555f066ed02433f51fd5fd6561d3df1ed5"
    "aec4617af681b202630c75d87d2fe363249b3ef9cc939dce146433fba9e13641"
    "ce2d3695d8b9c583273d3cf1afdc5620a2bb4a9aadf85458ffffffffffffffff";

string g_ffdhe_4096_p =
    "ffffffffffffffff5e655f6ac68a007ef44182e14db5a8517f88a46b8ec9b55a"
    "cec97dcf0a8291cdf98d0acc2a4ecea97140003c1a1db93d33cb8b7a092999a3"
    "71ad00386dc778f9918130c4a907600a2d9e6832ed6a1e01efb4318a7135c886"
    "7e31cc7a87f55ba5550340047763cf1dd69f6d18ac7d5f42e58857b67930e9e4"
    "164df4fb6e6f52c3669e1ef125e41d2b3fd59d7c3c1b20eefa53ddef0abcd06b"
    "d5c4484e1dbf9a429b0deadaabc5219722363a0de86d2bc59c9df69e5cae82ab"
    "71f54bff64f2e21ee2d74dd3f4fd4452bc437944b4130c9385139270aefe1309"
    "c186d91c598cb0fa91f7f7ee7ad91d26d6e6c90761b46fc9f99c0238bc34f4de"
    "6519035bde355b3b611fcfdc886b4238c1b2effac6f34a267d1683b2c58ef183"
    "2ec220053bb5fcbc4c6fad73c3fe3b1beef281838e4f1232e98583ff9172fe9c"
    "28342f61c03404cdcdf7e2ec9e02fce1ee0a6d700b07a7c86372bb19ae56ede7"
    "de394df41d4f42a360d7f468b96adab7b2c8e3fbd108a94bb324fb61bc0ab182"
    "483a797a30acca4f36ade7351df158a1f3efe872e2a689dae0e68b77984f0c70"
    "7f57c935b557135e3ded1af3856365555f066ed02433f51fd5fd6561d3df1ed5"
    "aec4617af681b202630c75d87d2fe363249b3ef9cc939dce146433fba9e13641"
    "ce2d3695d8b9c583273d3cf1afdc5620a2bb4a9aadf85458ffffffffffffffff";

string g_ffdhe_6144_p =
    "ffffffffffffffffd0e40e65a40e329c7938dad4a41d570dd43161c162a69526"
    "9adb1e693fdd4a8edc6b80d65b3b71f9c6272b04ec9d1810cacef4038ccf2dd5"
    "c95b9117e49f5235b854338a505dc82d1562a84662292c316ae77f5ed72b0374"
    "462d538cf9c9091b47a67cbe0ae8db5822611682b3a739c12a281bf6eeaac023"
    "77caf99294c6651e94b2bbc1763e4e4b0077d9b4587e38da183023c37fb29f8c"
    "f9e3a26e0abec1ff350511e3a00ef092db6340d8b855322ea9a96910a52471f7"
    "4cfdb477388147fb4e46041f9b1f5c3efccfec71cdad06574c701c3ab38e8c33"
    "b1c0fd4c917bdd649b7624c83bb45432caf53ea623ba444238532a3a4e677d2c"
    "45036c7a0bfd64b65e0dd902c68a007ef44182e14db5a8517f88a46b8ec9b55a"
    "cec97dcf0a8291cdf98d0acc2a4ecea97140003c1a1db93d33cb8b7a092999a3"
    "71ad00386dc778f9918130c4a907600a2d9e6832ed6a1e01efb4318a7135c886"
    "7e31cc7a87f55ba5550340047763cf1dd69f6d18ac7d5f42e58857b67930e9e4"
    "164df4fb6e6f52c3669e1ef125e41d2b3fd59d7c3c1b20eefa53ddef0abcd06b"
    "d5c4484e1dbf9a429b0deadaabc5219722363a0de86d2bc59c9df69e5cae82ab"
    "71f54bff64f2e21ee2d74dd3f4fd4452bc437944b4130c9385139270aefe1309"
    "c186d91c598cb0fa91f7f7ee7ad91d26d6e6c90761b46fc9f99c0238bc34f4de"
    "6519035bde355b3b611fcfdc886b4238c1b2effac6f34a267d1683b2c58ef183"
    "2ec220053bb5fcbc4c6fad73c3fe3b1beef281838e4f1232e98583ff9172fe9c"
    "28342f61c03404cdcdf7e2ec9e02fce1ee0a6d700b07a7c86372bb19ae56ede7"
    "de394df41d4f42a360d7f468b96adab7b2c8e3fbd108a94bb324fb61bc0ab182"
    "483a797a30acca4f36ade7351df158a1f3efe872e2a689dae0e68b77984f0c70"
    "7f57c935b557135e3ded1af3856365555f066ed02433f51fd5fd6561d3df1ed5"
    "aec4617af681b202630c75d87d2fe363249b3ef9cc939dce146433fba9e13641"
    "ce2d3695d8b9c583273d3cf1afdc5620a2bb4a9aadf85458ffffffffffffffff";

string g_ffdhe_8192_p =
    "ffffffffffffffffc5c6424cd68c8bb7838ff88c011e2a94a9f4614e0822e506"
    "f7a8443d97d11d4930677f0da6bbfde5c1fe86fe2f741ef85d71a87efafabe1c"
    "fbe58a30ded2fbab72b0a66eb6855dfeba8a4fe81efc8ce03f2fa45783f81d4a"
    "a577e231a1fe307588d9c0a0d5b80194ad9a95f9624816cd50c1217b99e9e316"
    "0e423cfc51aa691e3826e52c1c217e6c09703fee51a8a9316a460e74bb709987"
    "9c86b022541fc68c46fd825159160cc035c35f5c2846c0ba8b75828254504ac7"
    "d2af05e429388839c01bd702cb2c0f1c7c932665555b2f74a3ab882986b63142"
    "f64b10ef0b8cc3bdedd1cc5e687feb69c9509d43fdb23fced951ae641e425a31"
    "f600c83836ad004ccff46aaaa40e329c7938dad4a41d570dd43161c162a69526"
    "9adb1e693fdd4a8edc6b80d65b3b71f9c6272b04ec9d1810cacef4038ccf2dd5"
    "c95b9117e49f5235b854338a505dc82d1562a84662292c316ae77f5ed72b0374"
    "462d538cf9c9091b47a67cbe0ae8db5822611682b3a739c12a281bf6eeaac023"
    "77caf99294c6651e94b2bbc1763e4e4b0077d9b4587e38da183023c37fb29f8c"
    "f9e3a26e0abec1ff350511e3a00ef092db6340d8b855322ea9a96910a52471f7"
    "4cfdb477388147fb4e46041f9b1f5c3efccfec71cdad06574c701c3ab38e8c33"
    "b1c0fd4c917bdd649b7624c83bb45432caf53ea623ba444238532a3a4e677d2c"
    "45036c7a0bfd64b65e0dd902c68a007ef44182e14db5a8517f88a46b8ec9b55a"
    "cec97dcf0a8291cdf98d0acc2a4ecea97140003c1a1db93d33cb8b7a092999a3"
    "71ad00386dc778f9918130c4a907600a2d9e6832ed6a1e01efb4318a7135c886"
    "7e31cc7a87f55ba5550340047763cf1dd69f6d18ac7d5f42e58857b67930e9e4"
    "164df4fb6e6f52c3669e1ef125e41d2b3fd59d7c3c1b20eefa53ddef0abcd06b"
    "d5c4484e1dbf9a429b0deadaabc5219722363a0de86d2bc59c9df69e5cae82ab"
    "71f54bff64f2e21ee2d74dd3f4fd4452bc437944b4130c9385139270aefe1309"
    "c186d91c598cb0fa91f7f7ee7ad91d26d6e6c90761b46fc9f99c0238bc34f4de"
    "6519035bde355b3b611fcfdc886b4238c1b2effac6f34a267d1683b2c58ef183"
    "2ec220053bb5fcbc4c6fad73c3fe3b1beef281838e4f1232e98583ff9172fe9c"
    "28342f61c03404cdcdf7e2ec9e02fce1ee0a6d700b07a7c86372bb19ae56ede7"
    "de394df41d4f42a360d7f468b96adab7b2c8e3fbd108a94bb324fb61bc0ab182"
    "483a797a30acca4f36ade7351df158a1f3efe872e2a689dae0e68b77984f0c70"
    "7f57c935b557135e3ded1af3856365555f066ed02433f51fd5fd6561d3df1ed5"
    "aec4617af681b202630c75d87d2fe363249b3ef9cc939dce146433fba9e13641"
    "ce2d3695d8b9c583273d3cf1afdc5620a2bb4a9aadf85458ffffffffffffffff";

static HcfResult DH1536KeyBlob(HcfBlob * priblob, HcfBlob *pubblob)
{
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = g_dh1536Generator->generateKeyPair(g_dh1536Generator, nullptr, &keyPair);
    if (res != HCF_SUCCESS) {
        return res;
    }
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &g_mockDH1536PriKeyBlob);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(keyPair);
        return res;
    }
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &g_mockDH1536PubKeyBlob);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(g_dh1536Generator);
        HcfObjDestroy(keyPair);
        return res;
    }

    HcfObjDestroy(keyPair);
    return HCF_SUCCESS;
}

static HcfResult ECC_BrainPool160r1KeyBlob(HcfBlob * priblob, HcfBlob *pubblob)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("ECC_BrainPoolP160r1", &generator);
    if (res != HCF_SUCCESS) {
        return res;
    }

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        return res;
    }
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &g_mockECC_BrainPool160r1PriKeyBlob);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        return res;
    }
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &g_mockECC_BrainPool160r1PubKeyBlob);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        return res;
    }

    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
    return HCF_SUCCESS;
}

static HcfResult HcfAsyKeyGeneratorCreateTest(const char *algName)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(algName, &generator);
    if (res == HCF_SUCCESS) {
        HcfObjDestroy(generator);
    }
    return res;
}

void CryptoDHAsyKeyGeneratorTest::SetUpTestCase()
{
    HcfResult res = HcfAsyKeyGeneratorCreate("DH_modp1536", &g_dh1536Generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(g_dh1536Generator, nullptr);
    res = g_dh1536Generator->generateKeyPair(g_dh1536Generator, nullptr, &g_dh1536KeyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(g_dh1536KeyPair, nullptr);
    res = DH1536KeyBlob(&g_mockDH1536PriKeyBlob, &g_mockDH1536PubKeyBlob);
    ASSERT_EQ(res, HCF_SUCCESS);
    res = ECC_BrainPool160r1KeyBlob(&g_mockECC_BrainPool160r1PriKeyBlob, &g_mockECC_BrainPool160r1PubKeyBlob);
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest001_1, TestSize.Level0)
{
    HcfResult res = HcfAsyKeyGeneratorCreateTest("DH_modp1536");
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest001_2, TestSize.Level0)
{
    HcfResult res = HcfAsyKeyGeneratorCreateTest("DH_modp2048");
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest001_3, TestSize.Level0)
{
    HcfResult res = HcfAsyKeyGeneratorCreateTest("DH_modp3072");
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest001_4, TestSize.Level0)
{
    HcfResult res = HcfAsyKeyGeneratorCreateTest("DH_modp4096");
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest001_5, TestSize.Level0)
{
    HcfResult res = HcfAsyKeyGeneratorCreateTest("DH_modp6144");
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest001_6, TestSize.Level0)
{
    HcfResult res = HcfAsyKeyGeneratorCreateTest("DH_modp8192");
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest001_7, TestSize.Level0)
{
    HcfResult res = HcfAsyKeyGeneratorCreateTest("DH_ffdhe2048");
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest001_8, TestSize.Level0)
{
    HcfResult res = HcfAsyKeyGeneratorCreateTest("DH_ffdhe3072");
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest001_9, TestSize.Level0)
{
    HcfResult res = HcfAsyKeyGeneratorCreateTest("DH_ffdhe4096");
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest001_10, TestSize.Level0)
{
    HcfResult res = HcfAsyKeyGeneratorCreateTest("DH_ffdhe6144");
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest001_11, TestSize.Level0)
{
    HcfResult res = HcfAsyKeyGeneratorCreateTest("DH_ffdhe8192");
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest002, TestSize.Level0)
{
    const char *className = g_dh1536Generator->base.getClass();
    ASSERT_NE(className, nullptr);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest003, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("DH_modp1536", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    generator->base.destroy((HcfObjectBase *)generator);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest004, TestSize.Level0)
{
    const char *algoName = g_dh1536Generator->getAlgoName(g_dh1536Generator);
    ASSERT_EQ(algoName, g_dh1536AlgoName);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest005, TestSize.Level0)
{
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = g_dh1536Generator->generateKeyPair(g_dh1536Generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest006, TestSize.Level0)
{
    const char *className = g_dh1536KeyPair->base.getClass();
    ASSERT_NE(className, nullptr);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest007, TestSize.Level0)
{
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = g_dh1536Generator->generateKeyPair(g_dh1536Generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->base.destroy(&(keyPair->base));
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest008, TestSize.Level0)
{
    const char *className = g_dh1536KeyPair->pubKey->base.base.getClass();
    ASSERT_NE(className, nullptr);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest009, TestSize.Level0)
{
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = g_dh1536Generator->generateKeyPair(g_dh1536Generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->pubKey->base.base.destroy(&(keyPair->pubKey->base.base));
    keyPair->pubKey = nullptr;
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest010, TestSize.Level0)
{
    const char *algorithmName = g_dh1536KeyPair->pubKey->base.getAlgorithm(&(g_dh1536KeyPair->pubKey->base));
    ASSERT_EQ(algorithmName, g_dhAlgoName);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    HcfResult res = g_dh1536KeyPair->pubKey->base.getEncoded(&(g_dh1536KeyPair->pubKey->base), &blob);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);
    HcfFree(blob.data);
    const char *formatName = g_dh1536KeyPair->pubKey->base.getFormat(&(g_dh1536KeyPair->pubKey->base));
    ASSERT_EQ(formatName, g_dhpubkeyformatName);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest011, TestSize.Level0)
{
    const char *className = g_dh1536KeyPair->priKey->base.base.getClass();
    ASSERT_NE(className, nullptr);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest012, TestSize.Level0)
{
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = g_dh1536Generator->generateKeyPair(g_dh1536Generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->base.base.destroy(&(keyPair->priKey->base.base));
    keyPair->priKey = nullptr;
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest013, TestSize.Level0)
{
    const char *algorithmName = g_dh1536KeyPair->priKey->base.getAlgorithm(&(g_dh1536KeyPair->priKey->base));
    ASSERT_EQ(algorithmName, g_dhAlgoName);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    HcfResult res = g_dh1536KeyPair->priKey->base.getEncoded(&(g_dh1536KeyPair->priKey->base), &blob);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);
    HcfFree(blob.data);
    const char *formatName = g_dh1536KeyPair->priKey->base.getFormat(&(g_dh1536KeyPair->priKey->base));
    ASSERT_EQ(formatName, g_dhprikeyformatName);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest014, TestSize.Level0)
{
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = g_dh1536Generator->generateKeyPair(g_dh1536Generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->clearMem(keyPair->priKey);
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &blob);
    ASSERT_EQ(res, HCF_ERR_CRYPTO_OPERATION);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);
    HcfFree(blob.data);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest015, TestSize.Level0)
{
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = g_dh1536Generator->convertKey(g_dh1536Generator, nullptr,
        &g_mockDH1536PubKeyBlob, &g_mockDH1536PriKeyBlob, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);
    HcfObjDestroy(keyPair);

    res = g_dh1536Generator->convertKey(g_dh1536Generator, nullptr, nullptr, &g_mockDH1536PriKeyBlob, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);
    HcfObjDestroy(keyPair);

    res = g_dh1536Generator->convertKey(g_dh1536Generator, nullptr, &g_mockDH1536PubKeyBlob, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest016, TestSize.Level0)
{
    const char *className = g_dh1536KeyPair->base.getClass();
    ASSERT_NE(className, nullptr);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest017, TestSize.Level0)
{
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = g_dh1536Generator->convertKey(g_dh1536Generator, nullptr,
        &g_mockDH1536PubKeyBlob, &g_mockDH1536PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->base.destroy(&(keyPair->base));
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest018, TestSize.Level0)
{
    const char *className = g_dh1536KeyPair->pubKey->base.base.getClass();
    ASSERT_NE(className, nullptr);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest019, TestSize.Level0)
{
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = g_dh1536Generator->convertKey(g_dh1536Generator, nullptr,
        &g_mockDH1536PubKeyBlob, &g_mockDH1536PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->pubKey->base.base.destroy(&(keyPair->pubKey->base.base));
    keyPair->pubKey = nullptr;
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest020, TestSize.Level0)
{
    const char *algorithmName = g_dh1536KeyPair->pubKey->base.getAlgorithm(&(g_dh1536KeyPair->pubKey->base));
    ASSERT_EQ(algorithmName, g_dhAlgoName);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    HcfResult res = g_dh1536KeyPair->pubKey->base.getEncoded(&(g_dh1536KeyPair->pubKey->base), &blob);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);
    HcfFree(blob.data);
    const char *formatName = g_dh1536KeyPair->pubKey->base.getFormat(&(g_dh1536KeyPair->pubKey->base));
    ASSERT_EQ(formatName, g_dhpubkeyformatName);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest021, TestSize.Level0)
{
    const char *className = g_dh1536KeyPair->priKey->base.base.getClass();
    ASSERT_NE(className, nullptr);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest022, TestSize.Level0)
{
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = g_dh1536Generator->convertKey(g_dh1536Generator, nullptr,
        &g_mockDH1536PubKeyBlob, &g_mockDH1536PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->base.base.destroy(&(keyPair->priKey->base.base));
    keyPair->priKey = nullptr;
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest023, TestSize.Level0)
{
    const char *algorithmName = g_dh1536KeyPair->priKey->base.getAlgorithm(&(g_dh1536KeyPair->priKey->base));
    ASSERT_EQ(algorithmName, g_dhAlgoName);

    HcfBlob blob = { .data = nullptr, .len = 0 };
    HcfResult res = g_dh1536KeyPair->priKey->base.getEncoded(&(g_dh1536KeyPair->priKey->base), &blob);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);
    HcfFree(blob.data);
    const char *formatName = g_dh1536KeyPair->priKey->base.getFormat(&(g_dh1536KeyPair->priKey->base));
    ASSERT_EQ(formatName, g_dhprikeyformatName);

    int32_t returnInt = 0;
    res = g_dh1536KeyPair->priKey->getAsyKeySpecInt(g_dh1536KeyPair->priKey, DH_L_NUM, &returnInt);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_EQ(returnInt, 0);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest024, TestSize.Level0)
{
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = g_dh1536Generator->convertKey(g_dh1536Generator, nullptr,
        &g_mockDH1536PubKeyBlob, &g_mockDH1536PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->clearMem(keyPair->priKey);
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &blob);
    ASSERT_EQ(res, HCF_ERR_CRYPTO_OPERATION);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);
    HcfFree(blob.data);
    HcfObjDestroy(keyPair);
}

static void MemoryMallocTestFunc(uint32_t mallocCount)
{
    for (uint32_t i = 0; i < mallocCount; i++) {
        ResetRecordMallocNum();
        SetMockMallocIndex(i);
        HcfAsyKeyGenerator *tmpGenerator = nullptr;
        HcfResult res = HcfAsyKeyGeneratorCreate("DH_modp1536", &tmpGenerator);
        if (res != HCF_SUCCESS) {
            continue;
        }
        HcfKeyPair *tmpKeyPair = nullptr;
        res = tmpGenerator->generateKeyPair(tmpGenerator, nullptr, &tmpKeyPair);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(tmpGenerator);
            continue;
        }
        HcfBlob tmpPubKeyBlob = {
            .data = nullptr,
            .len = 0
        };
        res = tmpKeyPair->pubKey->base.getEncoded(&(tmpKeyPair->pubKey->base), &tmpPubKeyBlob);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(tmpKeyPair);
            HcfObjDestroy(tmpGenerator);
            continue;
        }
        HcfBlob tmpPriKeyBlob = {
            .data = nullptr,
            .len = 0
        };
        res = tmpKeyPair->priKey->base.getEncoded(&(tmpKeyPair->priKey->base), &tmpPriKeyBlob);
        if (res != HCF_SUCCESS) {
            HcfFree(tmpPubKeyBlob.data);
            HcfObjDestroy(tmpKeyPair);
            HcfObjDestroy(tmpGenerator);
            continue;
        }
        HcfKeyPair *tmpOutKeyPair = nullptr;
        res = tmpGenerator->convertKey(tmpGenerator, nullptr, &tmpPubKeyBlob, &tmpPriKeyBlob, &tmpOutKeyPair);
        HcfFree(tmpPubKeyBlob.data);
        HcfFree(tmpPriKeyBlob.data);
        HcfObjDestroy(tmpKeyPair);
        HcfObjDestroy(tmpGenerator);
        if (res == HCF_SUCCESS) {
            HcfObjDestroy(tmpOutKeyPair);
        }
    }
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest025, TestSize.Level0)
{
    StartRecordMallocNum();
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("DH_modp1536", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob pubKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubKeyBlob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKeyBlob.data, nullptr);
    ASSERT_NE(pubKeyBlob.len, 0);

    HcfBlob priKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &priKeyBlob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKeyBlob.data, nullptr);
    ASSERT_NE(priKeyBlob.len, 0);

    HcfKeyPair *outKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &pubKeyBlob, &priKeyBlob, &outKeyPair);

    HcfFree(pubKeyBlob.data);
    HcfFree(priKeyBlob.data);
    HcfObjDestroy(outKeyPair);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);

    uint32_t mallocCount = GetMallocNum();
    MemoryMallocTestFunc(mallocCount);

    EndRecordMallocNum();
}

static void OpensslMockTestFunc(uint32_t mallocCount)
{
    for (uint32_t i = 0; i < mallocCount; i++) {
        ResetOpensslCallNum();
        SetOpensslCallMockIndex(i);
        HcfAsyKeyGenerator *tmpGenerator = nullptr;
        HcfResult res = HcfAsyKeyGeneratorCreate("DH_modp1536", &tmpGenerator);
        if (res != HCF_SUCCESS) {
            continue;
        }
        HcfKeyPair *tmpKeyPair = nullptr;
        res = tmpGenerator->generateKeyPair(tmpGenerator, nullptr, &tmpKeyPair);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(tmpGenerator);
            continue;
        }
        HcfBlob tmpPubKeyBlob = { .data = nullptr, .len = 0 };
        res = tmpKeyPair->pubKey->base.getEncoded(&(tmpKeyPair->pubKey->base), &tmpPubKeyBlob);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(tmpKeyPair);
            HcfObjDestroy(tmpGenerator);
            continue;
        }
        HcfBlob tmpPriKeyBlob = { .data = nullptr, .len = 0 };
        res = tmpKeyPair->priKey->base.getEncoded(&(tmpKeyPair->priKey->base), &tmpPriKeyBlob);
        if (res != HCF_SUCCESS) {
            HcfFree(tmpPubKeyBlob.data);
            HcfObjDestroy(tmpKeyPair);
            HcfObjDestroy(tmpGenerator);
            continue;
        }
        HcfKeyPair *tmpOutKeyPair = nullptr;
        res = tmpGenerator->convertKey(tmpGenerator, nullptr, &tmpPubKeyBlob, &tmpPriKeyBlob, &tmpOutKeyPair);
        HcfFree(tmpPubKeyBlob.data);
        HcfFree(tmpPriKeyBlob.data);
        HcfObjDestroy(tmpKeyPair);
        HcfObjDestroy(tmpGenerator);
        if (res == HCF_SUCCESS) {
            HcfObjDestroy(tmpOutKeyPair);
        }
    }
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest026, TestSize.Level0)
{
    StartRecordOpensslCallNum();
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("DH_modp1536", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob pubKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubKeyBlob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKeyBlob.data, nullptr);
    ASSERT_NE(pubKeyBlob.len, 0);

    HcfBlob priKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &priKeyBlob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(priKeyBlob.data, nullptr);
    ASSERT_NE(priKeyBlob.len, 0);

    HcfKeyPair *outKeyPair = nullptr;
    res = generator->convertKey(generator, nullptr, &pubKeyBlob, &priKeyBlob, &outKeyPair);

    HcfFree(pubKeyBlob.data);
    HcfFree(priKeyBlob.data);
    HcfObjDestroy(outKeyPair);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);

    uint32_t mallocCount = GetOpensslCallNum();
    OpensslMockTestFunc(mallocCount);

    EndRecordOpensslCallNum();
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest027, TestSize.Level0)
{
    const char *algoName1 = g_dh1536Generator->getAlgoName(nullptr);
    ASSERT_EQ(algoName1, nullptr);

    const char *algoName2 = g_dh1536Generator->getAlgoName((HcfAsyKeyGenerator *)&g_obj);
    ASSERT_EQ(algoName2, nullptr);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest028, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("DH_modp1536", &generator);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    generator->base.destroy(nullptr);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest029, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("DH_modp1536", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(generator, nullptr);

    generator->base.destroy(&g_obj);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest030, TestSize.Level0)
{
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = g_dh1536Generator->convertKey(nullptr, nullptr,
        &g_mockDH1536PubKeyBlob, &g_mockDH1536PriKeyBlob, &keyPair);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(keyPair, nullptr);

    res = g_dh1536Generator->convertKey(g_dh1536Generator, nullptr,
        &g_mockDH1536PubKeyBlob, &g_mockDH1536PriKeyBlob, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    res = g_dh1536Generator->convertKey((HcfAsyKeyGenerator *)&g_obj, nullptr, &g_mockDH1536PubKeyBlob,
        &g_mockDH1536PriKeyBlob, &keyPair);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(keyPair, nullptr);

    res = g_dh1536Generator->convertKey(g_dh1536Generator, nullptr, nullptr, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(keyPair, nullptr);

    res = g_dh1536Generator->convertKey(g_dh1536Generator, nullptr, &g_mockECC_BrainPool160r1PubKeyBlob,
        &g_mockECC_BrainPool160r1PriKeyBlob, &keyPair);
    ASSERT_EQ(res, HCF_ERR_CRYPTO_OPERATION);
    ASSERT_EQ(keyPair, nullptr);

    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest031, TestSize.Level0)
{
    const char *algorithmName = g_dh1536KeyPair->pubKey->base.getAlgorithm(nullptr);
    ASSERT_EQ(algorithmName, nullptr);

    const char *algorithmName1 = g_dh1536KeyPair->pubKey->base.getAlgorithm((HcfKey *)&g_obj);
    ASSERT_EQ(algorithmName1, nullptr);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest032, TestSize.Level0)
{
    HcfBlob blob = { .data = nullptr, .len = 0 };
    HcfResult res = g_dh1536KeyPair->pubKey->base.getEncoded(nullptr, &blob);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    res = g_dh1536KeyPair->pubKey->base.getEncoded(&(g_dh1536KeyPair->pubKey->base), nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    res = g_dh1536KeyPair->pubKey->base.getEncoded((HcfKey *)&g_obj, &blob);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);
    HcfFree(blob.data);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest033, TestSize.Level0)
{
    const char *formatName = g_dh1536KeyPair->pubKey->base.getFormat(nullptr);
    ASSERT_EQ(formatName, nullptr);

    const char *formatName1 = g_dh1536KeyPair->pubKey->base.getFormat((HcfKey *)&g_obj);
    ASSERT_EQ(formatName1, nullptr);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest034, TestSize.Level0)
{
    const char *algorithmName = g_dh1536KeyPair->priKey->base.getAlgorithm(nullptr);
    ASSERT_EQ(algorithmName, nullptr);

    const char *algorithmName1 = g_dh1536KeyPair->priKey->base.getAlgorithm((HcfKey *)&g_obj);
    ASSERT_EQ(algorithmName1, nullptr);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest035, TestSize.Level0)
{
    HcfBlob blob = { .data = nullptr, .len = 0 };
    HcfResult res = g_dh1536KeyPair->priKey->base.getEncoded(nullptr, &blob);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    res = g_dh1536KeyPair->priKey->base.getEncoded(&(g_dh1536KeyPair->priKey->base), nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    res = g_dh1536KeyPair->priKey->base.getEncoded((HcfKey *)&g_obj, &blob);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(blob.data, nullptr);
    ASSERT_EQ(blob.len, 0);

    HcfFree(blob.data);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest036, TestSize.Level0)
{
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = g_dh1536Generator->convertKey(g_dh1536Generator, nullptr,
        &g_mockDH1536PubKeyBlob, &g_mockDH1536PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    const char *formatName = formatName = keyPair->priKey->base.getFormat(nullptr);
    ASSERT_EQ(formatName, nullptr);

    const char *formatName1 = keyPair->priKey->base.getFormat((HcfKey *)&g_obj);
    ASSERT_EQ(formatName1, nullptr);

    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest037, TestSize.Level0)
{
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = g_dh1536Generator->convertKey(g_dh1536Generator, nullptr,
        &g_mockDH1536PubKeyBlob, &g_mockDH1536PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->clearMem(nullptr);
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &blob);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);
    HcfFree(blob.data);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest038, TestSize.Level0)
{
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = g_dh1536Generator->convertKey(g_dh1536Generator, nullptr,
        &g_mockDH1536PubKeyBlob, &g_mockDH1536PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->clearMem((HcfPriKey *)&g_obj);
    HcfBlob blob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->base.getEncoded(&(keyPair->priKey->base), &blob);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(blob.data, nullptr);
    ASSERT_NE(blob.len, 0);
    HcfFree(blob.data);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest039, TestSize.Level0)
{
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = g_dh1536Generator->convertKey(g_dh1536Generator, nullptr,
        &g_mockDH1536PubKeyBlob, &g_mockDH1536PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->pubKey->base.base.destroy(nullptr);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest040, TestSize.Level0)
{
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = g_dh1536Generator->convertKey(g_dh1536Generator, nullptr,
        &g_mockDH1536PubKeyBlob, &g_mockDH1536PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->pubKey->base.base.destroy(&g_obj);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest041, TestSize.Level0)
{
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = g_dh1536Generator->convertKey(g_dh1536Generator, nullptr,
        &g_mockDH1536PubKeyBlob, &g_mockDH1536PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->base.base.destroy(nullptr);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest042, TestSize.Level0)
{
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = g_dh1536Generator->convertKey(g_dh1536Generator, nullptr,
        &g_mockDH1536PubKeyBlob, &g_mockDH1536PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->priKey->base.base.destroy(&g_obj);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest043, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_DH,
        .bits = HCF_OPENSSL_DH_MODP_1536,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *returnSpi = nullptr;
    HcfResult res = HcfAsyKeyGeneratorSpiDhCreate(&params, &returnSpi);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnSpi->engineConvertKey((HcfAsyKeyGeneratorSpi *)&g_obj, nullptr, &g_mockDH1536PubKeyBlob,
        &g_mockDH1536PriKeyBlob, &keyPair);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(keyPair, nullptr);

    HcfObjDestroy(returnSpi);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest044, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_DH,
        .bits = HCF_OPENSSL_DH_MODP_1536,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *returnSpi = nullptr;
    HcfResult res = HcfAsyKeyGeneratorSpiDhCreate(&params, &returnSpi);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);

    HcfKeyPair *keyPair = nullptr;
    res = returnSpi->engineGenerateKeyPair((HcfAsyKeyGeneratorSpi *)&g_obj, &keyPair);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);
    ASSERT_EQ(keyPair, nullptr);

    HcfObjDestroy(returnSpi);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest045, TestSize.Level0)
{
    HcfAsyKeyGenParams params = {
        .algo = HCF_ALG_DH,
        .bits = HCF_OPENSSL_DH_MODP_1536,
        .primes = HCF_OPENSSL_PRIMES_2,
    };

    HcfAsyKeyGeneratorSpi *returnSpi = nullptr;
    HcfResult res = HcfAsyKeyGeneratorSpiDhCreate(&params, &returnSpi);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(returnSpi, nullptr);

    res = returnSpi->engineGenerateKeyPair(returnSpi, nullptr);
    ASSERT_EQ(res, HCF_INVALID_PARAMS);

    HcfObjDestroy(returnSpi);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest046, TestSize.Level0)
{
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = g_dh1536Generator->convertKey(g_dh1536Generator, nullptr,
        &g_mockDH1536PubKeyBlob, &g_mockDH1536PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->base.destroy(nullptr);
    HcfObjDestroy(keyPair);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest047, TestSize.Level0)
{
    HcfKeyPair *keyPair = nullptr;
    HcfResult res = g_dh1536Generator->convertKey(g_dh1536Generator, nullptr,
        &g_mockDH1536PubKeyBlob, &g_mockDH1536PriKeyBlob, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    keyPair->base.destroy(&g_obj);
    HcfObjDestroy(keyPair);
}

static char *ByteToHexString(unsigned char *byteArray, int byteArrayLen)
{
    char *hexString = static_cast<char *>(malloc(byteArrayLen * BIT2 + 1));
    if (hexString == nullptr) {
        return nullptr;
    }
    int i;
    for (i = 0; i < byteArrayLen; i++) {
        if (sprintf_s(hexString + i * BIT2, (byteArrayLen - i) * BIT2 + 1, "%02x", byteArray[i]) < 0) {
            HcfFree(hexString);
            return nullptr;
        }
    }
    hexString[byteArrayLen * BIT2] = '\0';

    char *reversedString = static_cast<char *>(malloc(byteArrayLen * BIT2 + 1));
    if (reversedString == nullptr) {
        HcfFree(hexString);
        return nullptr;
    }
    int j = 0;
    for (i = 0; i < byteArrayLen * BIT2; i += BIT8) {
        char group[BIT8 + 1];
        (void)memcpy_s(group, BIT8, hexString + i, BIT8);
        group[BIT8] = '\0';
        for (int k = 0; k < BIT4; k++) {
            char temp = group[BIT2 * k];
            group[BIT2 * k] = group[BIT2 * k + 1];
            group[BIT2 * k + 1] = temp;
        }
        (void)memcpy_s(reversedString + j, BIT8, group, BIT8);
        j += BIT8;
    }
    reversedString[j] = '\0';

    for (i = 0; i < byteArrayLen * BIT2; i += BIT8) {
        int start = i;
        int end = i + BIT8 - 1;
        if (end >= byteArrayLen * BIT2) {
            end = byteArrayLen * BIT2 - 1;
        }
        for (j = start; j < end; j++, end--) {
            char temp = reversedString[j];
            reversedString[j] = reversedString[end];
            reversedString[end] = temp;
        }
    }
    HcfFree(hexString);
    return reversedString;
}

static HcfResult DhPrimeValueCompareWithOpenssl(const char *algName, string OpensslPrime)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(algName, &generator);
    if (res != HCF_SUCCESS) {
        return res;
    }

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        return res;
    }

    HcfBigInteger returnBigInteger = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->getAsyKeySpecBigInteger(keyPair->pubKey, DH_P_BN, &returnBigInteger);
    if (res != HCF_SUCCESS) {
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        return res;
    }

    char *hexString = ByteToHexString(returnBigInteger.data, returnBigInteger.len);
    if (hexString == nullptr) {
        HcfFree(returnBigInteger.data);
        HcfObjDestroy(generator);
        HcfObjDestroy(keyPair);
        return HCF_INVALID_PARAMS;
    }
    int32_t flag = strcmp(hexString, OpensslPrime.data());
    if (flag) {
        res = HCF_INVALID_PARAMS;
    }

    HcfFree(hexString);
    HcfFree(returnBigInteger.data);
    HcfObjDestroy(generator);
    HcfObjDestroy(keyPair);
    return res;
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest048, TestSize.Level0)
{
    HcfResult res = DhPrimeValueCompareWithOpenssl("DH_modp1536", g_modp_1536_p);
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest049, TestSize.Level0)
{
    HcfResult res = DhPrimeValueCompareWithOpenssl("DH_modp2048", g_modp_2048_p);
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest050, TestSize.Level0)
{
    HcfResult res = DhPrimeValueCompareWithOpenssl("DH_modp3072", g_modp_3072_p);
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest051, TestSize.Level0)
{
    HcfResult res = DhPrimeValueCompareWithOpenssl("DH_modp4096", g_modp_4096_p);
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest052, TestSize.Level0)
{
    HcfResult res = DhPrimeValueCompareWithOpenssl("DH_modp6144", g_modp_6144_p);
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest053, TestSize.Level0)
{
    HcfResult res = DhPrimeValueCompareWithOpenssl("DH_modp8192", g_modp_8192_p);
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest054, TestSize.Level0)
{
    HcfResult res = DhPrimeValueCompareWithOpenssl("DH_ffdhe2048", g_ffdhe_2048_p);
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest055, TestSize.Level0)
{
    HcfResult res = DhPrimeValueCompareWithOpenssl("DH_ffdhe3072", g_ffdhe_3072_p);
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest056, TestSize.Level0)
{
    HcfResult res = DhPrimeValueCompareWithOpenssl("DH_ffdhe4096", g_ffdhe_4096_p);
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest057, TestSize.Level0)
{
    HcfResult res = DhPrimeValueCompareWithOpenssl("DH_ffdhe6144", g_ffdhe_6144_p);
    ASSERT_EQ(res, HCF_SUCCESS);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHAsyKeyGeneratorTest058, TestSize.Level0)
{
    HcfResult res = DhPrimeValueCompareWithOpenssl("DH_ffdhe8192", g_ffdhe_8192_p);
    ASSERT_EQ(res, HCF_SUCCESS);
}

static void OpensslMockTestFuncGetPubKey(uint32_t mallocCount)
{
    for (uint32_t i = 0; i < mallocCount; i++) {
        ResetOpensslCallNum();
        SetOpensslCallMockIndex(i);

        HcfAsyKeyGenerator *tmpGenerator = nullptr;
        HcfResult res = HcfAsyKeyGeneratorCreate("DH_modp1536", &tmpGenerator);
        if (res != HCF_SUCCESS) {
            continue;
        }

        HcfKeyPair *tmpKeyPair = nullptr;
        res = tmpGenerator->generateKeyPair(tmpGenerator, nullptr, &tmpKeyPair);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(tmpGenerator);
            continue;
        }

        HcfBlob tmpPubKeyBlob1 = { .data = nullptr, .len = 0 };
        res = tmpKeyPair->pubKey->base.getEncoded(&(tmpKeyPair->pubKey->base), &tmpPubKeyBlob1);
        if (res != HCF_SUCCESS) {
            HcfObjDestroy(tmpKeyPair);
            HcfObjDestroy(tmpGenerator);
            continue;
        }

        HcfPubKey *tmpPubKey = nullptr;
        res = tmpKeyPair->priKey->getPubKey(tmpKeyPair->priKey, &tmpPubKey);
        if (res != HCF_SUCCESS) {
            HcfFree(tmpPubKeyBlob1.data);
            HcfObjDestroy(tmpKeyPair);
            HcfObjDestroy(tmpGenerator);
            continue;
        }

        if (tmpPubKey == nullptr) {
            HcfFree(tmpPubKeyBlob1.data);
            HcfObjDestroy(tmpKeyPair);
            HcfObjDestroy(tmpGenerator);
            continue;
        }

        HcfBlob tmpPubKeyBlob = { .data = nullptr, .len = 0 };
        res = tmpPubKey->base.getEncoded(&(tmpPubKey->base), &tmpPubKeyBlob);
        if (res == HCF_SUCCESS) {
            HcfFree(tmpPubKeyBlob.data);
        }
        HcfFree(tmpPubKeyBlob1.data);
        HcfObjDestroy(tmpPubKey);
        HcfObjDestroy(tmpKeyPair);
        HcfObjDestroy(tmpGenerator);
    }
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHGetPubKeyFromOrikey, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("DH_modp1536", &generator);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob pubKeyBlob1 = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubKeyBlob1);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKeyBlob1.data, nullptr);
    ASSERT_NE(pubKeyBlob1.len, 0);

    HcfPubKey *pubKey = nullptr;
    HcfBlob pubKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getPubKey(keyPair->priKey, &pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);
    res = pubKey->base.getEncoded(&(pubKey->base), &pubKeyBlob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKeyBlob.data, nullptr);
    ASSERT_NE(pubKeyBlob.len, 0);
    EXPECT_TRUE(memcmp(pubKeyBlob.data, pubKeyBlob1.data, pubKeyBlob.len) == 0);
    HcfFree(pubKeyBlob.data);
    HcfFree(pubKeyBlob1.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHGetPubKeyFromOrikeyMockTest, TestSize.Level0)
{
    StartRecordOpensslCallNum();
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("DH_modp1536", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfBlob pubKeyBlob1 = { .data = nullptr, .len = 0 };
    res = keyPair->pubKey->base.getEncoded(&(keyPair->pubKey->base), &pubKeyBlob1);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKeyBlob1.data, nullptr);
    ASSERT_NE(pubKeyBlob1.len, 0);

    HcfPubKey *pubKey = nullptr;
    HcfBlob pubKeyBlob = { .data = nullptr, .len = 0 };
    res = keyPair->priKey->getPubKey(keyPair->priKey, &pubKey);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKey, nullptr);
    res = pubKey->base.getEncoded(&(pubKey->base), &pubKeyBlob);

    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(pubKeyBlob.data, nullptr);
    ASSERT_NE(pubKeyBlob.len, 0);
    EXPECT_TRUE(memcmp(pubKeyBlob.data, pubKeyBlob1.data, pubKeyBlob.len) == 0);
    HcfFree(pubKeyBlob.data);
    HcfFree(pubKeyBlob1.data);
    HcfObjDestroy(pubKey);
    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);

    uint32_t mallocCount = GetOpensslCallNum();
    OpensslMockTestFuncGetPubKey(mallocCount);

    EndRecordOpensslCallNum();
}

HWTEST_F(CryptoDHAsyKeyGeneratorTest, CryptoDHGetPubKeyFromOrikeyErrTest, TestSize.Level0)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate("DH_modp1536", &generator);
    ASSERT_EQ(res, HCF_SUCCESS);

    HcfKeyPair *keyPair = nullptr;
    res = generator->generateKeyPair(generator, nullptr, &keyPair);
    ASSERT_EQ(res, HCF_SUCCESS);
    ASSERT_NE(keyPair, nullptr);

    HcfPubKey *pubKey = nullptr;
    res = keyPair->priKey->getPubKey(nullptr, &pubKey);
    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(pubKey, nullptr);

    res = keyPair->priKey->getPubKey(keyPair->priKey, nullptr);
    ASSERT_NE(res, HCF_SUCCESS);

    res = keyPair->priKey->getPubKey((HcfPriKey *)&g_obj, &pubKey);
    ASSERT_NE(res, HCF_SUCCESS);
    ASSERT_EQ(pubKey, nullptr);

    HcfObjDestroy(keyPair);
    HcfObjDestroy(generator);
}
}

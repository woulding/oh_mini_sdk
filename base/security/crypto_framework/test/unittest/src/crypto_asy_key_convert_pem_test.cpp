/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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
#include "securec.h"

#include "asy_key_generator.h"
#include "asy_key_generator_spi.h"
#include "blob.h"
#include "memory.h"
#include "params_parser.h"
#include "alg_25519_asy_key_generator_openssl.h"
#include "dh_asy_key_generator_openssl.h"
#include "dsa_asy_key_generator_openssl.h"
#include "ecc_asy_key_generator_openssl.h"
#include "sm2_asy_key_generator_openssl.h"

using namespace std;
using namespace testing::ext;

namespace {
class CryptoAsyKeyConvertPemTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void CryptoAsyKeyConvertPemTest::SetUpTestCase() {}
void CryptoAsyKeyConvertPemTest::TearDownTestCase() {}
void CryptoAsyKeyConvertPemTest::SetUp() {}
void CryptoAsyKeyConvertPemTest::TearDown() {}

static string g_testSm2PriKey = "-----BEGIN PRIVATE KEY-----\n"
    "MIGIAgEAMBQGCCqBHM9VAYItBggqgRzPVQGCLQRtMGsCAQEEIA200l6+4y/sASFH\n"
    "W+v2ivubPvilyNPD5+iBSnyIb+pHoUQDQgAEylRVudZ35l9vBwX8Zeqq7m9cGTqo\n"
    "Mc7m8Lmj107pifm2Qd7kKyYiBa1568t4yEPp5KLfPs1TGgiGoLIsvJeARA==\n"
    "-----END PRIVATE KEY-----\n";

static string g_testSm2PubKey = "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEEDZi8UI/QxT70W8M3q3C7h+W+Zl6\n"
    "8rP7SLCnZXYQPNKDqZEOPi/Vq0CRS9IS438yq4ZadxpDXothWk/bPYtOog==\n"
    "-----END PUBLIC KEY-----\n";

static string g_testX25519PriKey = "-----BEGIN PRIVATE KEY-----\n"
    "MC4CAQAwBQYDK2VuBCIEIDBcZrfXH+c4pAmTEFu9yoyCEIZSiGkfIZgFy2Ov58dh\n"
    "-----END PRIVATE KEY-----\n";

static string g_testX25519PubKey = "-----BEGIN PUBLIC KEY-----\n"
    "MCowBQYDK2VuAyEA2L8/1ZjPmQi2x46Rg3+H/BLwJvmbKocfaMeWr4IuMWg=\n"
    "-----END PUBLIC KEY-----\n";

static string g_testEd25519PriKey = "-----BEGIN PRIVATE KEY-----\n"
    "MC4CAQAwBQYDK2VwBCIEIGeiM+8OWg71i9eF6Z8PszWstvLW11eJJKKo9RyHyXkV\n"
    "-----END PRIVATE KEY-----\n";

static string g_testEd25519PubKey = "-----BEGIN PUBLIC KEY-----\n"
    "MCowBQYDK2VwAyEAPfx7zgwln/YVAT0oFLCp87qNS43QBSHJ0ttb0GImUNI=\n"
    "-----END PUBLIC KEY-----\n";

static string g_testEccSecp224r1PriKey = "-----BEGIN PRIVATE KEY-----\n"
    "MHgCAQAwEAYHKoZIzj0CAQYFK4EEACEEYTBfAgEBBByoNkUhCLcFLDPh3yAnFvx9\n"
    "QRnVZJHMhTQnO1SXoTwDOgAEvc6xX46WjjwfIz+/VBVH49OCEVRrGaVGi65dTabd\n"
    "UUTvtreiwA2lW2hS2EI3LaE3VvBROnOIYqU=\n"
    "-----END PRIVATE KEY-----\n";

static string g_testEccSecp224r1PubKey = "-----BEGIN PUBLIC KEY-----\n"
    "ME4wEAYHKoZIzj0CAQYFK4EEACEDOgAEvc6xX46WjjwfIz+/VBVH49OCEVRrGaVG\n"
    "i65dTabdUUTvtreiwA2lW2hS2EI3LaE3VvBROnOIYqU=\n"
    "-----END PUBLIC KEY-----\n";

static string g_testDsa1024Prikey = "-----BEGIN PRIVATE KEY-----\n"
    "MIIBWgIBADCCATMGByqGSM44BAEwggEmAoGBAP2TzPnHnQkBvcT5LE3upXUv21Pg\n"
    "bLgrPycAMjr88vVCixnL/EnAO5HIbqmLHoum9wShT9Lb4UnBDeOB3gF/JE9xyAJ0\n"
    "ULNfWMykUr3/YudEHBi5C63gvhA80sLkB3udQxXoWdhrMDTC+JxAmOaoLJlXLOXm\n"
    "KpP9RpdGIBLfXXu1Ah0AqNktdrld7vGDCD9/JXYmfDtipMde3LDwc0luhQKBgB0+\n"
    "Sa/8d4t4KTJaBe7x3gb0SD2B9K/GoZbgS0a5nRpvwai4pqmEcU9dtwW6fwUFg4Eq\n"
    "9Kj7cJZc2k6b8b0Dwt0c/iUE+VE7cVCCsO6nh5i+r0P2Upkx+DBR8ZuRrpxQqNjl\n"
    "ES81GmQTKGtUqy3+EKXR08wcf3njBsE1hDq5nECeBB4CHHFSEVmDW3oGTmo4xStB\n"
    "hdZIq5iPeBfIGIHFt0M=\n"
    "-----END PRIVATE KEY-----\n";

static string g_testDsa1024Pubkey = "-----BEGIN PUBLIC KEY-----\n"
    "MIIBvzCCATMGByqGSM44BAEwggEmAoGBAP2TzPnHnQkBvcT5LE3upXUv21PgbLgr\n"
    "PycAMjr88vVCixnL/EnAO5HIbqmLHoum9wShT9Lb4UnBDeOB3gF/JE9xyAJ0ULNf\n"
    "WMykUr3/YudEHBi5C63gvhA80sLkB3udQxXoWdhrMDTC+JxAmOaoLJlXLOXmKpP9\n"
    "RpdGIBLfXXu1Ah0AqNktdrld7vGDCD9/JXYmfDtipMde3LDwc0luhQKBgB0+Sa/8\n"
    "d4t4KTJaBe7x3gb0SD2B9K/GoZbgS0a5nRpvwai4pqmEcU9dtwW6fwUFg4Eq9Kj7\n"
    "cJZc2k6b8b0Dwt0c/iUE+VE7cVCCsO6nh5i+r0P2Upkx+DBR8ZuRrpxQqNjlES81\n"
    "GmQTKGtUqy3+EKXR08wcf3njBsE1hDq5nECeA4GFAAKBgQDDkKC11pEMGnF93lsH\n"
    "61vLd7y2xvt6mKRw/AExsYgQBdOMJ+w2sSapEbRI/XUCX7Z4E0nN89xBl/PzbywO\n"
    "0yfRqdLTwk5RSurQW7WglYPtMzR24dPCxa9woqyo5OTSCTx0FH2BQVsNdEloYQKo\n"
    "6c4+rzj2DLaALOBrKEg9wTAmng==\n"
    "-----END PUBLIC KEY-----\n";

static string g_testDhModp1536PriKey = "-----BEGIN PRIVATE KEY-----\n"
    "MIH4AgEAMIHVBgkqhkiG9w0BAwEwgccCgcEA///////////JD9qiIWjCNMTGYouA\n"
    "3BzRKQJOCIpnzHQCC76mOxObIlFKCHmONATd75UZs806QxswKwpt8l8UN0/hNW1t\n"
    "UcJF5IW1dmJefsb0TELppjftawv/XLb0Brft7jhr+1qJn6WunyQRfEsf5kkoZlHs\n"
    "5Fs9wgB8uKFjvwWY2kg2HFXTmmkWP6j9JM9fg2VdI9yjrZYcYvNWIIVSu57VKQdw\n"
    "lpZtZww1Tkq8mATxdGwIyiNzJ///////////AgECBBsCGXIeKZHN2Qp5+JSnHAam\n"
    "RiDePOsqbd2mae8=\n"
    "-----END PRIVATE KEY-----\n";

static string g_testDhModp1536PubKey = "-----BEGIN PUBLIC KEY-----\n"
    "MIIBoDCB1QYJKoZIhvcNAQMBMIHHAoHBAP//////////yQ/aoiFowjTExmKLgNwc\n"
    "0SkCTgiKZ8x0Agu+pjsTmyJRSgh5jjQE3e+VGbPNOkMbMCsKbfJfFDdP4TVtbVHC\n"
    "ReSFtXZiXn7G9ExC6aY37WsL/1y29Aa37e44a/taiZ+lrp8kEXxLH+ZJKGZR7ORb\n"
    "PcIAfLihY78FmNpINhxV05ppFj+o/STPX4NlXSPco62WHGLzViCFUrue1SkHcJaW\n"
    "bWcMNU5KvJgE8XRsCMojcyf//////////wIBAgOBxQACgcEAuj+cH1r8RNxBPAl7\n"
    "CG76b50cbn1Rb04be/ONImxdhO9zEx/eUtnT1/3PR7j+7UNfvf6J7leQ5YorUz6F\n"
    "5anKVUURi1XljLK6GcWBtqyCP0MMuO8FX5Dk8JBlCjTzuP5ClA0gofVAfcp3FYcq\n"
    "VrSUDFn1SZt2MdkWe6zR4SDkFrlGTYa2EY5WKD5AR4piXi3m0PvPp+10oe3x6BOZ\n"
    "RBvXAtLiP0nTUnhDX2N8FdyiU9Xn9QxajBRI1Jn85v/Qwa0o\n"
    "-----END PUBLIC KEY-----\n";


static string g_testDhFfdhe2048PriKey = "-----BEGIN PRIVATE KEY-----\n"
    "MIIBPgIBADCCARcGCSqGSIb3DQEDATCCAQgCggEBAP//////////rfhUWKK7Spqv\n"
    "3FYgJz088di5xYPOLTaVqeE2QRRkM/vMk53OJJs++X0v42NjDHXY9oGyAq7EYXrT\n"
    "3x7V1f1lYSQz9R9fBm7QhWNlVT3tGvO1VxNef1fJNZhPDHDg5ot34qaJ2vPv6HId\n"
    "8VihNq3nNTCsyk9IOnl6vAqxgrMk+2HRCKlLssjj+7lq2rdg1/RoHU9Co945TfSu\n"
    "Vu3nY3K7GQsHp8juCm1wngL84c334uzANATNKDQvYZFy/pzphYP/jk8SMu7ygYPD\n"
    "/jsbTG+tczu1/LwuwiAFxY7xg30Wg7LG80omwbLv+ohrQjhhKFyX//////////8C\n"
    "AQIEHgIcC6C96/TJHrL6iOaoXiBKyamHP861V3XxMs3Fsw==\n"
    "-----END PRIVATE KEY-----\n";

static string g_testDhFfdhe2048PubKey = "-----BEGIN PUBLIC KEY-----\n"
    "MIICJTCCARcGCSqGSIb3DQEDATCCAQgCggEBAP//////////rfhUWKK7Spqv3FYg\n"
    "Jz088di5xYPOLTaVqeE2QRRkM/vMk53OJJs++X0v42NjDHXY9oGyAq7EYXrT3x7V\n"
    "1f1lYSQz9R9fBm7QhWNlVT3tGvO1VxNef1fJNZhPDHDg5ot34qaJ2vPv6HId8Vih\n"
    "Nq3nNTCsyk9IOnl6vAqxgrMk+2HRCKlLssjj+7lq2rdg1/RoHU9Co945TfSuVu3n\n"
    "Y3K7GQsHp8juCm1wngL84c334uzANATNKDQvYZFy/pzphYP/jk8SMu7ygYPD/jsb\n"
    "TG+tczu1/LwuwiAFxY7xg30Wg7LG80omwbLv+ohrQjhhKFyX//////////8CAQID\n"
    "ggEGAAKCAQEA99dycUYKbYBfecmzMQ+QnGDQ7IfF41i8GbEE6m6Lb27br7XFHxUB\n"
    "xS85SOYQGUhup5FCyftzRdx2/zYHatdg51Mn+YxgB1OEa/gTxpRY1UC49bs+p/w6\n"
    "Q8+ZRslDXnTRCGSeiw4TCzC0ynMN1i0TcTnOh33Vd8exKIg73jedgLi6//+wZjtH\n"
    "ufYua4jKKux/Qas/ILi0K1pQOZ0J4z0FuKVlLvprth8vwRF8kpLVg5q25JQ9K7do\n"
    "/BZEwcfXvd61/FoWQv75DEydiFHC/iMppwwa8QhYj5jC5C9yZLXlvoOiOB5UPkti\n"
    "59nqvRQJevtDMFX/fB9KLWVkgAIUqVLEVw==\n"
    "-----END PUBLIC KEY-----\n";

static string g_testDhFfdhe3072PriKey = "-----BEGIN PRIVATE KEY-----\n"
    "MIIBxQIBADCCAZcGCSqGSIb3DQEDATCCAYgCggGBAP//////////rfhUWKK7Spqv\n"
    "3FYgJz088di5xYPOLTaVqeE2QRRkM/vMk53OJJs++X0v42NjDHXY9oGyAq7EYXrT\n"
    "3x7V1f1lYSQz9R9fBm7QhWNlVT3tGvO1VxNef1fJNZhPDHDg5ot34qaJ2vPv6HId\n"
    "8VihNq3nNTCsyk9IOnl6vAqxgrMk+2HRCKlLssjj+7lq2rdg1/RoHU9Co945TfSu\n"
    "Vu3nY3K7GQsHp8juCm1wngL84c334uzANATNKDQvYZFy/pzphYP/jk8SMu7ygYPD\n"
    "/jsbTG+tczu1/LwuwiAFxY7xg30Wg7LG80omwbLv+ohrQjhhH8/c3jVbO2UZA1u8\n"
    "NPTe+ZwCOGG0b8nW5skHetkdJpH39+5ZjLD6wYbZHK7+EwmFE5JwtBMMk7xDeUT0\n"
    "/URS4tdN02Ty4h5x9Uv/XK6Cq5yd9p7obSvFIjY6DavFIZebDeraHb+aQtXESE4K\n"
    "vNBr+lPd7zwbIO4/1Z18JeQdK2bGLjf//////////wIBAgQlAiMDFnJti6Y7aWEb\n"
    "9//FRAcAqlpDn1l6EbzY8cpVYPS4VhG4aw==\n"
    "-----END PRIVATE KEY-----\n";

static string g_testDhFfdhe3072PubKey = "-----BEGIN PUBLIC KEY-----\n"
    "MIIDJDCCAZcGCSqGSIb3DQEDATCCAYgCggGBAP//////////rfhUWKK7Spqv3FYg\n"
    "Jz088di5xYPOLTaVqeE2QRRkM/vMk53OJJs++X0v42NjDHXY9oGyAq7EYXrT3x7V\n"
    "1f1lYSQz9R9fBm7QhWNlVT3tGvO1VxNef1fJNZhPDHDg5ot34qaJ2vPv6HId8Vih\n"
    "Nq3nNTCsyk9IOnl6vAqxgrMk+2HRCKlLssjj+7lq2rdg1/RoHU9Co945TfSuVu3n\n"
    "Y3K7GQsHp8juCm1wngL84c334uzANATNKDQvYZFy/pzphYP/jk8SMu7ygYPD/jsb\n"
    "TG+tczu1/LwuwiAFxY7xg30Wg7LG80omwbLv+ohrQjhhH8/c3jVbO2UZA1u8NPTe\n"
    "+ZwCOGG0b8nW5skHetkdJpH39+5ZjLD6wYbZHK7+EwmFE5JwtBMMk7xDeUT0/URS\n"
    "4tdN02Ty4h5x9Uv/XK6Cq5yd9p7obSvFIjY6DavFIZebDeraHb+aQtXESE4KvNBr\n"
    "+lPd7zwbIO4/1Z18JeQdK2bGLjf//////////wIBAgOCAYUAAoIBgCnL/c2/ajEL\n"
    "hD+XQUVOA96sz/Z/tB5Oimrj7EFi/F0mv4NQX3Xj+AeS1vfvEVMDuTDFWiVLIyIX\n"
    "8k+1efJf8MxZvd6ZyqyCua0LQIc1kSAr/QGqOL0sUZMlKpoyuZ8eGN0mM7JlJFag\n"
    "8yvXtreycFaoZhaHUlqfj5ICEmgALhX3FjR5H3Lm1AAdiDzAwEi9VmhdTKnt0qia\n"
    "3J20vI8n0SgtYTHssYHDJwW6n4LomLim1Jp/AqOhkXUFTyaYLW32bSXM466D06pt\n"
    "LNedT2tYNVV2oOS7mwGDJOPoJ2ON6Rh82eGuPtmeLvA+5oVaB1+isDAxNLXxCohT\n"
    "LiDZ1tDKe+/syblIMR6LCTQmb4EpgZHQsfO7BSsTHwI9/55POrTZ944rMuV7Ro3y\n"
    "aGvxMBLmuoBMKK+jkOF3NuzGxosJaKiAH2skbccdzYs1Qt401dCh0IXqCVjFIwHp\n"
    "cywQXQv6YZ0B45T9b7m6H1LjUbAfOdxjLYGe6JtJ8phBw9KTsBpCgA==\n"
    "-----END PUBLIC KEY-----\n";

static string g_testDhFfdhe4096PriKey = "-----BEGIN PRIVATE KEY-----\n"
    "MIICSwIBADCCAhcGCSqGSIb3DQEDATCCAggCggIBAP//////////rfhUWKK7Spqv\n"
    "3FYgJz088di5xYPOLTaVqeE2QRRkM/vMk53OJJs++X0v42NjDHXY9oGyAq7EYXrT\n"
    "3x7V1f1lYSQz9R9fBm7QhWNlVT3tGvO1VxNef1fJNZhPDHDg5ot34qaJ2vPv6HId\n"
    "8VihNq3nNTCsyk9IOnl6vAqxgrMk+2HRCKlLssjj+7lq2rdg1/RoHU9Co945TfSu\n"
    "Vu3nY3K7GQsHp8juCm1wngL84c334uzANATNKDQvYZFy/pzphYP/jk8SMu7ygYPD\n"
    "/jsbTG+tczu1/LwuwiAFxY7xg30Wg7LG80omwbLv+ohrQjhhH8/c3jVbO2UZA1u8\n"
    "NPTe+ZwCOGG0b8nW5skHetkdJpH39+5ZjLD6wYbZHK7+EwmFE5JwtBMMk7xDeUT0\n"
    "/URS4tdN02Ty4h5x9Uv/XK6Cq5yd9p7obSvFIjY6DavFIZebDeraHb+aQtXESE4K\n"
    "vNBr+lPd7zwbIO4/1Z18JeQdK2aeHvFub1LDFk30+3kw6eTliFe2rH1fQtafbRh3\n"
    "Y88dVQNABIf1W6V+Mcx6cTXIhu+0MYrtah4BLZ5oMqkHYAqRgTDEbcd4+XGtADgJ\n"
    "KZmjM8uLehoduT1xQAA8Kk7OqfmNCswKgpHNzsl9z47JtVp/iKRrTbWoUfRBguHG\n"
    "igB+XmVfav//////////AgECBCsCKRfw3Z6+8+P0Hn/8ftdOa3wcFp/IU7vBV5Y3\n"
    "dj1X9NSoW567eG6/s2Qs\n"
    "-----END PRIVATE KEY-----\n";

static string g_testDhFfdhe4096PubKey = "-----BEGIN PUBLIC KEY-----\n"
    "MIIEJTCCAhcGCSqGSIb3DQEDATCCAggCggIBAP//////////rfhUWKK7Spqv3FYg\n"
    "Jz088di5xYPOLTaVqeE2QRRkM/vMk53OJJs++X0v42NjDHXY9oGyAq7EYXrT3x7V\n"
    "1f1lYSQz9R9fBm7QhWNlVT3tGvO1VxNef1fJNZhPDHDg5ot34qaJ2vPv6HId8Vih\n"
    "Nq3nNTCsyk9IOnl6vAqxgrMk+2HRCKlLssjj+7lq2rdg1/RoHU9Co945TfSuVu3n\n"
    "Y3K7GQsHp8juCm1wngL84c334uzANATNKDQvYZFy/pzphYP/jk8SMu7ygYPD/jsb\n"
    "TG+tczu1/LwuwiAFxY7xg30Wg7LG80omwbLv+ohrQjhhH8/c3jVbO2UZA1u8NPTe\n"
    "+ZwCOGG0b8nW5skHetkdJpH39+5ZjLD6wYbZHK7+EwmFE5JwtBMMk7xDeUT0/URS\n"
    "4tdN02Ty4h5x9Uv/XK6Cq5yd9p7obSvFIjY6DavFIZebDeraHb+aQtXESE4KvNBr\n"
    "+lPd7zwbIO4/1Z18JeQdK2aeHvFub1LDFk30+3kw6eTliFe2rH1fQtafbRh3Y88d\n"
    "VQNABIf1W6V+Mcx6cTXIhu+0MYrtah4BLZ5oMqkHYAqRgTDEbcd4+XGtADgJKZmj\n"
    "M8uLehoduT1xQAA8Kk7OqfmNCswKgpHNzsl9z47JtVp/iKRrTbWoUfRBguHGigB+\n"
    "XmVfav//////////AgECA4ICBgACggIBAKigucWOH8I8vq12hTuGkZiJhdfksOMo\n"
    "i/9xtSf+9Ba6eLnSJUBWVO/rbEBi+iJGYwff1r8u8l7AtD2Hcw/wSPZAlt0LXXVX\n"
    "TLGk4UxQNxpMaCdsHdxCNxnPQ7HSbkig4ot96+8N2vwXgLUWcd2DIagrh1iN7OAI\n"
    "D1j/mCFDwi7gP3az5TgViowTvLi6o5JcN4oew6MMVOiv626lGzk4okaOAyjUlW10\n"
    "ZbV8j0Bk7PukOUzXCwDC6V2TxLkDUNkXwg4pDHVGYmQCO9MpECA9zrW+facYwMkg\n"
    "k8GJoQ1r7xtD+2fYpFyYhlQPZ5dO1GuCdVa1WbS2/8PRw8jZu5ckQS35OCoBB7JC\n"
    "bz1dmWRueDpi2ktpDgjxyOIN7uZQyIFIpsfapt/o0ZszkVWxJvYrR0SdU+dXMjRp\n"
    "QlPotOEVq39Hqp7hDa4YDM/Ioi8JIMhAnrynEPlPgzwU2PVelPfJ5adox5+hjG0u\n"
    "xdmMGTCI+EMUa7WluPms8movWCvFOT+AUaPS8vkRB5hHcslcWIN+8eUWQRWXuPJ0\n"
    "wDDaOWfONV+/irUnlBldB7QL8lqv+hmzqMKkT6Qq3RVcewlIBFTQ5R+T2MjB287V\n"
    "sz5ANidkSXiZAqBrOGP4izqZWyY7e0KckPFw9pPJOcImAde33iRsCS+SX2x+ik1Q\n"
    "AbVOf7Vd2viT\n"
    "-----END PUBLIC KEY-----\n";

static string g_testDhFfdhe6144PriKey = "-----BEGIN PRIVATE KEY-----\n"
    "MIIDUQIBADCCAxcGCSqGSIb3DQEDATCCAwgCggMBAP//////////rfhUWKK7Spqv\n"
    "3FYgJz088di5xYPOLTaVqeE2QRRkM/vMk53OJJs++X0v42NjDHXY9oGyAq7EYXrT\n"
    "3x7V1f1lYSQz9R9fBm7QhWNlVT3tGvO1VxNef1fJNZhPDHDg5ot34qaJ2vPv6HId\n"
    "8VihNq3nNTCsyk9IOnl6vAqxgrMk+2HRCKlLssjj+7lq2rdg1/RoHU9Co945TfSu\n"
    "Vu3nY3K7GQsHp8juCm1wngL84c334uzANATNKDQvYZFy/pzphYP/jk8SMu7ygYPD\n"
    "/jsbTG+tczu1/LwuwiAFxY7xg30Wg7LG80omwbLv+ohrQjhhH8/c3jVbO2UZA1u8\n"
    "NPTe+ZwCOGG0b8nW5skHetkdJpH39+5ZjLD6wYbZHK7+EwmFE5JwtBMMk7xDeUT0\n"
    "/URS4tdN02Ty4h5x9Uv/XK6Cq5yd9p7obSvFIjY6DavFIZebDeraHb+aQtXESE4K\n"
    "vNBr+lPd7zwbIO4/1Z18JeQdK2aeHvFub1LDFk30+3kw6eTliFe2rH1fQtafbRh3\n"
    "Y88dVQNABIf1W6V+Mcx6cTXIhu+0MYrtah4BLZ5oMqkHYAqRgTDEbcd4+XGtADgJ\n"
    "KZmjM8uLehoduT1xQAA8Kk7OqfmNCswKgpHNzsl9z47JtVp/iKRrTbWoUfRBguHG\n"
    "igB+Xg3ZAgv9ZLZFA2x6Tmd9LDhTKjojukRCyvU+pju0VDKbdiTIkXvdZLHA/Uyz\n"
    "jowzTHAcOs2tBlf8z+xxmx9cPk5GBB84gUf7TP20d6UkcfepqWkQuFUyLttjQNig\n"
    "DvCSNQUR4wq+wf/546Juf7KfjBgwI8NYfjjaAHfZtHY+TkuUsrvBlMZlHnfK+ZLu\n"
    "qsAjKigb9rOnOcEiYRaCCujbWEemfL75yQkbRi1TjNcrA3Rq539eYiksMRViqEZQ\n"
    "XcgtuFQziuSfUjXJW5EXjM8t1crO9APsnRgQxicrBFs7cfnca4DWP91KjprbHmli\n"
    "ppUm1DFhwaQdVw15ONrUpA4ynNDkDmX//////////wIBAgQxAi9TPRFZd41FTBHp\n"
    "XLtToxZ2gzSWglVgDRJXLTl9cbrJpO3q+hGp5aHn0ICfgt73Xg==\n"
    "-----END PRIVATE KEY-----\n";

static string g_testDhFfdhe6144PubKey = "-----BEGIN PUBLIC KEY-----\n"
    "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\n"
    "-----END PUBLIC KEY-----\n";

static string g_testDhFfdhe8192PriKey = "-----BEGIN PRIVATE KEY-----\n"
    "MIIEVAIBADCCBBcGCSqGSIb3DQEDATCCBAgCggQBAP//////////rfhUWKK7Spqv\n"
    "3FYgJz088di5xYPOLTaVqeE2QRRkM/vMk53OJJs++X0v42NjDHXY9oGyAq7EYXrT\n"
    "3x7V1f1lYSQz9R9fBm7QhWNlVT3tGvO1VxNef1fJNZhPDHDg5ot34qaJ2vPv6HId\n"
    "8VihNq3nNTCsyk9IOnl6vAqxgrMk+2HRCKlLssjj+7lq2rdg1/RoHU9Co945TfSu\n"
    "Vu3nY3K7GQsHp8juCm1wngL84c334uzANATNKDQvYZFy/pzphYP/jk8SMu7ygYPD\n"
    "/jsbTG+tczu1/LwuwiAFxY7xg30Wg7LG80omwbLv+ohrQjhhH8/c3jVbO2UZA1u8\n"
    "NPTe+ZwCOGG0b8nW5skHetkdJpH39+5ZjLD6wYbZHK7+EwmFE5JwtBMMk7xDeUT0\n"
    "/URS4tdN02Ty4h5x9Uv/XK6Cq5yd9p7obSvFIjY6DavFIZebDeraHb+aQtXESE4K\n"
    "vNBr+lPd7zwbIO4/1Z18JeQdK2aeHvFub1LDFk30+3kw6eTliFe2rH1fQtafbRh3\n"
    "Y88dVQNABIf1W6V+Mcx6cTXIhu+0MYrtah4BLZ5oMqkHYAqRgTDEbcd4+XGtADgJ\n"
    "KZmjM8uLehoduT1xQAA8Kk7OqfmNCswKgpHNzsl9z47JtVp/iKRrTbWoUfRBguHG\n"
    "igB+Xg3ZAgv9ZLZFA2x6Tmd9LDhTKjojukRCyvU+pju0VDKbdiTIkXvdZLHA/Uyz\n"
    "jowzTHAcOs2tBlf8z+xxmx9cPk5GBB84gUf7TP20d6UkcfepqWkQuFUyLttjQNig\n"
    "DvCSNQUR4wq+wf/546Juf7KfjBgwI8NYfjjaAHfZtHY+TkuUsrvBlMZlHnfK+ZLu\n"
    "qsAjKigb9rOnOcEiYRaCCujbWEemfL75yQkbRi1TjNcrA3Rq539eYiksMRViqEZQ\n"
    "XcgtuFQziuSfUjXJW5EXjM8t1crO9APsnRgQxicrBFs7cfnca4DWP91KjprbHmli\n"
    "ppUm1DFhwaQdVw15ONrUpA4ynM/0aqo2rQBM9gDIOB5CWjHZUa5k/bI/zslQnUNo\n"
    "f+tp7dHMXguMw732SxDvhrYxQqOriClVWy90fJMmZcssDxzAG9cCKTiIOdKvBeRU\n"
    "UErHi3WCgihGwLo1w19cWRYMwEb9glFUH8aMnIawIrtwmYdqRg50UaipMQlwP+4c\n"
    "IX5sOCblLFGqaR4OQjz8menjFlDBIXtiSBbNrZqV+dW4AZSI2cCgof4wdaV34jGD\n"
    "+B1KPy+kVx78jOC6ik/otoVd/nKwpm7e0vur++WKMPr6vhxdcah+L3Qe+MH+hv6m\n"
    "u/3lMGd/DZfRHUn3qEQ9CCLlBqn0YU4BHiqUg4/4jNaMi7fFxkJM//////////8C\n"
    "AQIENAIyNvBPpNeXtnI5saYMiXvrUSRJw7Yq6QWkYU2C9Bf6vGpP3dEsmHQVbWPe\n"
    "IEHpmLKk1g8=\n"
    "-----END PRIVATE KEY-----\n";

static string g_testDhFfdhe8192PubKey = "-----BEGIN PUBLIC KEY-----\n"
    "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\n"
    "TPUgTvYxns26sKVlFjRKqVKVCmy68iMB5Q==\n"
    "-----END PUBLIC KEY-----\n";

static string g_testDhModp2048PriKey = "-----BEGIN PRIVATE KEY-----\n"
    "MIIBPwIBADCCARcGCSqGSIb3DQEDATCCAQgCggEBAP//////////yQ/aoiFowjTE\n"
    "xmKLgNwc0SkCTgiKZ8x0Agu+pjsTmyJRSgh5jjQE3e+VGbPNOkMbMCsKbfJfFDdP\n"
    "4TVtbVHCReSFtXZiXn7G9ExC6aY37WsL/1y29Aa37e44a/taiZ+lrp8kEXxLH+ZJ\n"
    "KGZR7ORbPcIAfLihY78FmNpINhxV05ppFj+o/STPX4NlXSPco62WHGLzViCFUrue\n"
    "1SkHcJaWbWcMNU5KvJgE8XRsCMoYIXwykF5GLjbOO+OedywYDoYDmyeDouwHoo+1\n"
    "xV3wb0xSyd4ry/aVWBcYOZVJfOqVauUV0iYYmPoFEBVyjlqKrKpo//////////8C\n"
    "AQIEHwIdAPRToxgVjHMVN8nkoSWKprLl8llag1wAYmiLrng=\n"
    "-----END PRIVATE KEY-----\n";

static string g_testDhModp2048PubKey = "-----BEGIN PUBLIC KEY-----\n"
    "MIICJTCCARcGCSqGSIb3DQEDATCCAQgCggEBAP//////////yQ/aoiFowjTExmKL\n"
    "gNwc0SkCTgiKZ8x0Agu+pjsTmyJRSgh5jjQE3e+VGbPNOkMbMCsKbfJfFDdP4TVt\n"
    "bVHCReSFtXZiXn7G9ExC6aY37WsL/1y29Aa37e44a/taiZ+lrp8kEXxLH+ZJKGZR\n"
    "7ORbPcIAfLihY78FmNpINhxV05ppFj+o/STPX4NlXSPco62WHGLzViCFUrue1SkH\n"
    "cJaWbWcMNU5KvJgE8XRsCMoYIXwykF5GLjbOO+OedywYDoYDmyeDouwHoo+1xV3w\n"
    "b0xSyd4ry/aVWBcYOZVJfOqVauUV0iYYmPoFEBVyjlqKrKpo//////////8CAQID\n"
    "ggEGAAKCAQEAggsOz2iHuIXDEXGeei4/4c2E1I2gVJ/MuELlf1l2vZdnQZzldZYs\n"
    "HMDz77rfHHzXOisSpgEr7eY5lcRogtf5+cT7pBljnou/e+yKUlfdo0rrC/+koAp8\n"
    "N+hAYTkH2Fwt/oEWckcEuuYJLnU5L0j7AcWSGjZrI0driQaQM40hzgfHl7j1fRcU\n"
    "t9Tl2ycdzrV0F/C7SIa/P1qstdxTzjAZlmoWVC2W3eC5wM3b/A/tsH73C84vKpcn\n"
    "JCvcfg7HpvXmwTbywGfoXtlDgcM3GaZVFvAdqHcEdQyvWp9ePqQ23oSxC//7TgXi\n"
    "CUiaF/zepTKo3Z2aBTio3ghUCg6hfcRWdw==\n"
    "-----END PUBLIC KEY-----\n";

static string g_testDhModp3072PriKey = "-----BEGIN PRIVATE KEY-----\n"
    "MIIBxQIBADCCAZcGCSqGSIb3DQEDATCCAYgCggGBAP//////////yQ/aoiFowjTE\n"
    "xmKLgNwc0SkCTgiKZ8x0Agu+pjsTmyJRSgh5jjQE3e+VGbPNOkMbMCsKbfJfFDdP\n"
    "4TVtbVHCReSFtXZiXn7G9ExC6aY37WsL/1y29Aa37e44a/taiZ+lrp8kEXxLH+ZJ\n"
    "KGZR7ORbPcIAfLihY78FmNpINhxV05ppFj+o/STPX4NlXSPco62WHGLzViCFUrue\n"
    "1SkHcJaWbWcMNU5KvJgE8XRsCMoYIXwykF5GLjbOO+OedywYDoYDmyeDouwHoo+1\n"
    "xV3wb0xSyd4ry/aVWBcYOZVJfOqVauUV0iYYmPoFEBVyjlqKqsQtrTMXDQRQejOo\n"
    "VSGr3xy6ZOz7hQRY2+8KiupxV10GDH2zlw+FpuHkx6v1rozbCTPXHoyU4EolYZ3O\n"
    "49ImGtLua/Ev+gbZighk2HYCcz7IamRSHysYF3sgDLvhF1d6YV1sdwmIwLrZRuII\n"
    "4k+gdOWrMUPbW/zg/RCOS4LRIKk60sr//////////wIBAgQlAiMENiPbUKDmUyxx\n"
    "OFZZ2Fsb0Z4ONl0+xPwLUxWG9gmXoRLL6A==\n"
    "-----END PRIVATE KEY-----\n";

static string g_testDhModp3072PubKey = "-----BEGIN PUBLIC KEY-----\n"
    "MIIDJTCCAZcGCSqGSIb3DQEDATCCAYgCggGBAP//////////yQ/aoiFowjTExmKL\n"
    "gNwc0SkCTgiKZ8x0Agu+pjsTmyJRSgh5jjQE3e+VGbPNOkMbMCsKbfJfFDdP4TVt\n"
    "bVHCReSFtXZiXn7G9ExC6aY37WsL/1y29Aa37e44a/taiZ+lrp8kEXxLH+ZJKGZR\n"
    "7ORbPcIAfLihY78FmNpINhxV05ppFj+o/STPX4NlXSPco62WHGLzViCFUrue1SkH\n"
    "cJaWbWcMNU5KvJgE8XRsCMoYIXwykF5GLjbOO+OedywYDoYDmyeDouwHoo+1xV3w\n"
    "b0xSyd4ry/aVWBcYOZVJfOqVauUV0iYYmPoFEBVyjlqKqsQtrTMXDQRQejOoVSGr\n"
    "3xy6ZOz7hQRY2+8KiupxV10GDH2zlw+FpuHkx6v1rozbCTPXHoyU4EolYZ3O49Im\n"
    "GtLua/Ev+gbZighk2HYCcz7IamRSHysYF3sgDLvhF1d6YV1sdwmIwLrZRuII4k+g\n"
    "dOWrMUPbW/zg/RCOS4LRIKk60sr//////////wIBAgOCAYYAAoIBgQDeqifvv/RC\n"
    "T+VpuDB9QD0WHxjTgXAlhH3jwQn7rdqz7VgLOKezuiWKXRbPiAmvq7YvweHQF3m5\n"
    "mVSgcmTY7Jdea/tZS3G3/fjxzxaRuVH73E0BmbNCIeiL/KQcRLqqHJ4s486ezeoP\n"
    "MgMIuYZ/Q95otbsAbufiiI2TvFXy9M7//m097+nL3eAnMV3bomJ1vgLacO6nm3xT\n"
    "a+MfYCZFzzreTkUWrnzcvvPLdXI3cOVimqiuWhMuxd3LTAm7cnTNyCCpQQ+VwwZT\n"
    "CX1b5MBiNuEHGKqBAF65L2o1yi5kPgjq4ojiJNEjx4owoSDdZP5GG+IJPO/ccLQo\n"
    "KCnRW+zAJykpaZp7Ujpc2eNJ+IoR+uXUvhuott7CpgRAZlhTCkv7ORvYuTX8AwUo\n"
    "JJ1weksOcRxoWpLSoi4g4t90HnOeXXx0x3dqzjGlXId2VflcWNApNsHgC1Z6G+Qs\n"
    "QJTpEM684ClYVc+T8wexkX3EdfYmBiIRaUlJ7DTxQzJKhTtuP7kg4mk=\n"
    "-----END PUBLIC KEY-----\n";

static string g_testDhModp4096PriKey = "-----BEGIN PRIVATE KEY-----\n"
    "MIICSwIBADCCAhcGCSqGSIb3DQEDATCCAggCggIBAP//////////yQ/aoiFowjTE\n"
    "xmKLgNwc0SkCTgiKZ8x0Agu+pjsTmyJRSgh5jjQE3e+VGbPNOkMbMCsKbfJfFDdP\n"
    "4TVtbVHCReSFtXZiXn7G9ExC6aY37WsL/1y29Aa37e44a/taiZ+lrp8kEXxLH+ZJ\n"
    "KGZR7ORbPcIAfLihY78FmNpINhxV05ppFj+o/STPX4NlXSPco62WHGLzViCFUrue\n"
    "1SkHcJaWbWcMNU5KvJgE8XRsCMoYIXwykF5GLjbOO+OedywYDoYDmyeDouwHoo+1\n"
    "xV3wb0xSyd4ry/aVWBcYOZVJfOqVauUV0iYYmPoFEBVyjlqKqsQtrTMXDQRQejOo\n"
    "VSGr3xy6ZOz7hQRY2+8KiupxV10GDH2zlw+FpuHkx6v1rozbCTPXHoyU4EolYZ3O\n"
    "49ImGtLua/Ev+gbZighk2HYCcz7IamRSHysYF3sgDLvhF1d6YV1sdwmIwLrZRuII\n"
    "4k+gdOWrMUPbW/zg/RCOS4LRIKkhCAEacjwSp4fm14hxmhC9ulsmmcMnGGr04jwa\n"
    "lGg0thUL2iWD6coq1Ezo27vC2wTejvkujvwUH77Kpih8WUdOa8BdmbKWT6CQw6Ij\n"
    "O6GGUVvn7R9hKXDO4tevuBvddiFwSBzQBpEn1bBaqZO06piNj93Bhv+33JCmwI9N\n"
    "9DXJNAYxmf//////////AgECBCsCKRNHTBYLOilaRpAM+smrwpKazwY6qmI60sZa\n"
    "trdrzm3cdKsTGMV+G4Xj\n"
    "-----END PRIVATE KEY-----\n";

static string g_testDhModp4096PubKey = "-----BEGIN PUBLIC KEY-----\n"
    "MIIEJTCCAhcGCSqGSIb3DQEDATCCAggCggIBAP//////////yQ/aoiFowjTExmKL\n"
    "gNwc0SkCTgiKZ8x0Agu+pjsTmyJRSgh5jjQE3e+VGbPNOkMbMCsKbfJfFDdP4TVt\n"
    "bVHCReSFtXZiXn7G9ExC6aY37WsL/1y29Aa37e44a/taiZ+lrp8kEXxLH+ZJKGZR\n"
    "7ORbPcIAfLihY78FmNpINhxV05ppFj+o/STPX4NlXSPco62WHGLzViCFUrue1SkH\n"
    "cJaWbWcMNU5KvJgE8XRsCMoYIXwykF5GLjbOO+OedywYDoYDmyeDouwHoo+1xV3w\n"
    "b0xSyd4ry/aVWBcYOZVJfOqVauUV0iYYmPoFEBVyjlqKqsQtrTMXDQRQejOoVSGr\n"
    "3xy6ZOz7hQRY2+8KiupxV10GDH2zlw+FpuHkx6v1rozbCTPXHoyU4EolYZ3O49Im\n"
    "GtLua/Ev+gbZighk2HYCcz7IamRSHysYF3sgDLvhF1d6YV1sdwmIwLrZRuII4k+g\n"
    "dOWrMUPbW/zg/RCOS4LRIKkhCAEacjwSp4fm14hxmhC9ulsmmcMnGGr04jwalGg0\n"
    "thUL2iWD6coq1Ezo27vC2wTejvkujvwUH77Kpih8WUdOa8BdmbKWT6CQw6IjO6GG\n"
    "UVvn7R9hKXDO4tevuBvddiFwSBzQBpEn1bBaqZO06piNj93Bhv+33JCmwI9N9DXJ\n"
    "NAYxmf//////////AgECA4ICBgACggIBANVYMZwPOuZPzRGg5ved0+Tqqkca2zqI\n"
    "fJT91Bi/4ks8Ppxf1D7PvmNXUtxPjjrxNleDATsZOjKsjSunUB7szzGizuH6CaO9\n"
    "HFogxp/ugvSRF6GkISbcTN8Ek89iqImZkC67e48L1sgtixrd5BKMF1i5MJs7vdOj\n"
    "gH0vFCoGxPR878HnmN8E0+gS2z6JVXvgIYQApMqXuptICrGUGQrTILUDf/lDLh3l\n"
    "VMQO908GJcmGWImSheWUyNqz88eZrff4lFTRUz4jx0dKowN3SrTGNkWMcNsK7bIg\n"
    "Qe0408Ax68olQBgbKCAllfHUBGIP0XIDvvXiuqMaFni7NKsecYKCNPy2iDyzCNen\n"
    "kdvFc/buG5VUWSNjEQNfO/7K2OBZTUoofYS1/v8AXmPI1KBJB6Cd3yObVghv74lT\n"
    "Itri59BffG8HkpfI4zGVuk1nZ8sBJqqCY1ZR4Xcpj/PbcA5PioeUTKrkffsm/Xby\n"
    "1u7LEiOZFag3nJ0DArGwCtxoODdFFaF6rq5IcCcNcrP/lW9E+oY+Rus0eRN0h0w8\n"
    "MhWqJQ6y6fdPgcTvimWtUfE2o/9vXvvONJDk4bUUpRw/D24Mg4x9/0Zjp5zWaia/\n"
    "sLNTm2RLMGU0PjBGIc/33+6JFbO3t4FdsDU+mTiaissfgAnzBLEnsMjw3Du/HC9s\n"
    "L+99jo6k4lcq\n"
    "-----END PUBLIC KEY-----\n";

static string g_testDhModp6144PriKey = "-----BEGIN PRIVATE KEY-----\n"
    "MIIDUQIBADCCAxcGCSqGSIb3DQEDATCCAwgCggMBAP//////////yQ/aoiFowjTE\n"
    "xmKLgNwc0SkCTgiKZ8x0Agu+pjsTmyJRSgh5jjQE3e+VGbPNOkMbMCsKbfJfFDdP\n"
    "4TVtbVHCReSFtXZiXn7G9ExC6aY37WsL/1y29Aa37e44a/taiZ+lrp8kEXxLH+ZJ\n"
    "KGZR7ORbPcIAfLihY78FmNpINhxV05ppFj+o/STPX4NlXSPco62WHGLzViCFUrue\n"
    "1SkHcJaWbWcMNU5KvJgE8XRsCMoYIXwykF5GLjbOO+OedywYDoYDmyeDouwHoo+1\n"
    "xV3wb0xSyd4ry/aVWBcYOZVJfOqVauUV0iYYmPoFEBVyjlqKqsQtrTMXDQRQejOo\n"
    "VSGr3xy6ZOz7hQRY2+8KiupxV10GDH2zlw+FpuHkx6v1rozbCTPXHoyU4EolYZ3O\n"
    "49ImGtLua/Ev+gbZighk2HYCcz7IamRSHysYF3sgDLvhF1d6YV1sdwmIwLrZRuII\n"
    "4k+gdOWrMUPbW/zg/RCOS4LRIKkhCAEacjwSp4fm14hxmhC9ulsmmcMnGGr04jwa\n"
    "lGg0thUL2iWD6coq1Ezo27vC2wTejvkujvwUH77Kpih8WUdOa8BdmbKWT6CQw6Ij\n"
    "O6GGUVvn7R9hKXDO4tevuBvddiFwSBzQBpEn1bBaqZO06piNj93Bhv+33JCmwI9N\n"
    "9DXJNAKEkjbD+rTSfHAmwdTcsmAmRt7JdR52Pbo3vfj/lAatnlMO5ds4L0EwAa6w\n"
    "alPtkCfYMReXJ7CGWokY2j7b68+bFO1Ezmy6ztS7G9t/FEfmzCVLMyBRUSvXr0Jv\n"
    "uPQBN4zSv1mDygHGS5Ls8DLqFdFyHQP0gtfObnT+9tVecC9GmAyCtahAMZALHJ5Z\n"
    "58l/vsfo8yOpen42zIi+Dx1Ft/9YWsVL1AeyK0FUqsyPbX6/SOHYFMxe0g+AN+Cn\n"
    "lxXu8pvjKAah1Yu3xdp29VCqPYofv/DrGcyxoxPVXNpWyewu8pYyOH/o1248BGgE\n"
    "Po9mP0hg7hK/LVsLdHTW5pT5Hm3MQCT//////////wIBAgQxAi9/Au8+qm3n56dp\n"
    "3l5vq0PO5DQUxznbuMdnJu/hkHz7hSh5+MNgKQECtgnxjatsWg==\n"
    "-----END PRIVATE KEY-----\n";

static string g_testDhModp6144PubKey = "-----BEGIN PUBLIC KEY-----\n"
    "MIIGJDCCAxcGCSqGSIb3DQEDATCCAwgCggMBAP//////////yQ/aoiFowjTExmKL\n"
    "gNwc0SkCTgiKZ8x0Agu+pjsTmyJRSgh5jjQE3e+VGbPNOkMbMCsKbfJfFDdP4TVt\n"
    "bVHCReSFtXZiXn7G9ExC6aY37WsL/1y29Aa37e44a/taiZ+lrp8kEXxLH+ZJKGZR\n"
    "7ORbPcIAfLihY78FmNpINhxV05ppFj+o/STPX4NlXSPco62WHGLzViCFUrue1SkH\n"
    "cJaWbWcMNU5KvJgE8XRsCMoYIXwykF5GLjbOO+OedywYDoYDmyeDouwHoo+1xV3w\n"
    "b0xSyd4ry/aVWBcYOZVJfOqVauUV0iYYmPoFEBVyjlqKqsQtrTMXDQRQejOoVSGr\n"
    "3xy6ZOz7hQRY2+8KiupxV10GDH2zlw+FpuHkx6v1rozbCTPXHoyU4EolYZ3O49Im\n"
    "GtLua/Ev+gbZighk2HYCcz7IamRSHysYF3sgDLvhF1d6YV1sdwmIwLrZRuII4k+g\n"
    "dOWrMUPbW/zg/RCOS4LRIKkhCAEacjwSp4fm14hxmhC9ulsmmcMnGGr04jwalGg0\n"
    "thUL2iWD6coq1Ezo27vC2wTejvkujvwUH77Kpih8WUdOa8BdmbKWT6CQw6IjO6GG\n"
    "UVvn7R9hKXDO4tevuBvddiFwSBzQBpEn1bBaqZO06piNj93Bhv+33JCmwI9N9DXJ\n"
    "NAKEkjbD+rTSfHAmwdTcsmAmRt7JdR52Pbo3vfj/lAatnlMO5ds4L0EwAa6walPt\n"
    "kCfYMReXJ7CGWokY2j7b68+bFO1Ezmy6ztS7G9t/FEfmzCVLMyBRUSvXr0JvuPQB\n"
    "N4zSv1mDygHGS5Ls8DLqFdFyHQP0gtfObnT+9tVecC9GmAyCtahAMZALHJ5Z58l/\n"
    "vsfo8yOpen42zIi+Dx1Ft/9YWsVL1AeyK0FUqsyPbX6/SOHYFMxe0g+AN+CnlxXu\n"
    "8pvjKAah1Yu3xdp29VCqPYofv/DrGcyxoxPVXNpWyewu8pYyOH/o1248BGgEPo9m\n"
    "P0hg7hK/LVsLdHTW5pT5Hm3MQCT//////////wIBAgOCAwUAAoIDAGB/u7i3VHL4\n"
    "Mj1OapD7dC5GaQK1joynj/rVLiQihtgOzgEegvwFlXb+0U2s054fngWA9DdVL8WF\n"
    "sqhyd+TANDNx52utLRMOyKeovJDpdyCrFU5XOORYC/0W/sKpLhgzD+lPDayj85WK\n"
    "xrsutvS/dXQ8sBEe06YOWAEYWoCZ2PMZw7pI8fj0JTfNS0fxHCDO+1uVJeADulM+\n"
    "qKDlBHFd0blzRRfUwj/Of3CrtsBajQiH3aG05QkqJyumvMOhEUrkgBGbhnWg9Qi0\n"
    "cSZgH5vmRnGCPEvhuX5eRBDwXwTy9UxWxr4c/Y5krnmu0CmZQVNV+cZga71f7MJW\n"
    "DUXbgigcF/yZJB/6Ujj70OS7W251UMWpjAMt5pIPuYfFKQ7JyJ/u6AQkgaGcpMLu\n"
    "L66ptUJsvGqdACzAq0PieiO8aCuWBqJMKUU3zduVxjPXMjERfUNNeqbefyvmjYb6\n"
    "XjF8c/WB0d3d1FTypJ749KTUFXBrhZdOHb+xVYmK4QEdqxZ7XntG/C1GYkGnLaSs\n"
    "v7caJ68xs8eP8/0XI7Wd3q1Uxk77dSRBqmq+WsAvnwKY8P3gdbzp/L79j56WZ9Fi\n"
    "PghywBjb35CDwa514z4VUfxoeDzjBN6uESYyQf2CeQXIUECZGXepj4s21KXWNhOF\n"
    "rVgWu2PhoLIirhdwZEhFTTRAvs+LkOMsVhjkWvlS4+7aRqIiusWUl+SLtbO2Jc0n\n"
    "yBS2bVcGkLxniAnUyomou1wbAKr6AFXZQ7W9eT2wiBaHsNyiH7MdWyLw5kpAp5MZ\n"
    "wq4hKy1fJu6YDrFMWlP2UDRXyTj8G6aIdsYk1GdUOqnrB+j9q9xxo+prZ10QAIb/\n"
    "NpgJmxJa/eJChgMbwlOvfDRHBoqUDnIKOOleHwsj8CHlQiAVd+UoqPORA4jwkH3n\n"
    "L86S+1lmy3gYiDz69wauEruz7suOFdViRxA/OIoh0l+F9m7lz8YHo65zljQBdFF0\n"
    "PX+9AUeZh/diVQGs7lPp9qiXfdDZ+1l6XskgfNn1N41+RDxBrRHnWA==\n"
    "-----END PUBLIC KEY-----\n";

static string g_testDhModp8192PriKey = "-----BEGIN PRIVATE KEY-----\n"
    "MIIEVQIBADCCBBcGCSqGSIb3DQEDATCCBAgCggQBAP//////////yQ/aoiFowjTE\n"
    "xmKLgNwc0SkCTgiKZ8x0Agu+pjsTmyJRSgh5jjQE3e+VGbPNOkMbMCsKbfJfFDdP\n"
    "4TVtbVHCReSFtXZiXn7G9ExC6aY37WsL/1y29Aa37e44a/taiZ+lrp8kEXxLH+ZJ\n"
    "KGZR7ORbPcIAfLihY78FmNpINhxV05ppFj+o/STPX4NlXSPco62WHGLzViCFUrue\n"
    "1SkHcJaWbWcMNU5KvJgE8XRsCMoYIXwykF5GLjbOO+OedywYDoYDmyeDouwHoo+1\n"
    "xV3wb0xSyd4ry/aVWBcYOZVJfOqVauUV0iYYmPoFEBVyjlqKqsQtrTMXDQRQejOo\n"
    "VSGr3xy6ZOz7hQRY2+8KiupxV10GDH2zlw+FpuHkx6v1rozbCTPXHoyU4EolYZ3O\n"
    "49ImGtLua/Ev+gbZighk2HYCcz7IamRSHysYF3sgDLvhF1d6YV1sdwmIwLrZRuII\n"
    "4k+gdOWrMUPbW/zg/RCOS4LRIKkhCAEacjwSp4fm14hxmhC9ulsmmcMnGGr04jwa\n"
    "lGg0thUL2iWD6coq1Ezo27vC2wTejvkujvwUH77Kpih8WUdOa8BdmbKWT6CQw6Ij\n"
    "O6GGUVvn7R9hKXDO4tevuBvddiFwSBzQBpEn1bBaqZO06piNj93Bhv+33JCmwI9N\n"
    "9DXJNAKEkjbD+rTSfHAmwdTcsmAmRt7JdR52Pbo3vfj/lAatnlMO5ds4L0EwAa6w\n"
    "alPtkCfYMReXJ7CGWokY2j7b68+bFO1Ezmy6ztS7G9t/FEfmzCVLMyBRUSvXr0Jv\n"
    "uPQBN4zSv1mDygHGS5Ls8DLqFdFyHQP0gtfObnT+9tVecC9GmAyCtahAMZALHJ5Z\n"
    "58l/vsfo8yOpen42zIi+Dx1Ft/9YWsVL1AeyK0FUqsyPbX6/SOHYFMxe0g+AN+Cn\n"
    "lxXu8pvjKAah1Yu3xdp29VCqPYofv/DrGcyxoxPVXNpWyewu8pYyOH/o1248BGgE\n"
    "Po9mP0hg7hK/LVsLdHTW5pT5Hm2+EVl0o5JvEv7l5Dh3fLapMt+M2L7E0HO5Mbo7\n"
    "yDK2jZ3TAHQfp7+K/EftJXb2k2ukJGY6q2OcWuT1aDQjtHQr8cl4I48Wy+OdZS3j\n"
    "/bi+/ISK2SIiLgSkA3wHE+tXqBoj8Mc0c/xkbOowa0vLyIYvg4Xd+p1Lf6LAh+h5\n"
    "aDMD7VvdOgYrPPWzonimbSoT+D9E+C3fMQ7gdKtqNkWX6JmgJV3BZPMcxQhGhR35\n"
    "q0gZXe1+obHVEL1+501z+vNrwx7Pomg1kEb064efkkAJQ4tIHGzXiJoALtXuOCvJ\n"
    "GQ2m/AJuR5VY5EdWd+mqnjBQ4nZWlN/IH1bogLlucWDJgN2Y7dPf//////////8C\n"
    "AQIENQIzAL5VbOx8Gf9Okpw22McpN5hm04wj+Mok9ZB+eZuuMD9hTBw5SMrz6lP7\n"
    "m/WaPrKgRpnw\n"
    "-----END PRIVATE KEY-----\n";

static string g_testDhModp8192PubKey = "-----BEGIN PUBLIC KEY-----\n"
    "MIIIJDCCBBcGCSqGSIb3DQEDATCCBAgCggQBAP//////////yQ/aoiFowjTExmKL\n"
    "gNwc0SkCTgiKZ8x0Agu+pjsTmyJRSgh5jjQE3e+VGbPNOkMbMCsKbfJfFDdP4TVt\n"
    "bVHCReSFtXZiXn7G9ExC6aY37WsL/1y29Aa37e44a/taiZ+lrp8kEXxLH+ZJKGZR\n"
    "7ORbPcIAfLihY78FmNpINhxV05ppFj+o/STPX4NlXSPco62WHGLzViCFUrue1SkH\n"
    "cJaWbWcMNU5KvJgE8XRsCMoYIXwykF5GLjbOO+OedywYDoYDmyeDouwHoo+1xV3w\n"
    "b0xSyd4ry/aVWBcYOZVJfOqVauUV0iYYmPoFEBVyjlqKqsQtrTMXDQRQejOoVSGr\n"
    "3xy6ZOz7hQRY2+8KiupxV10GDH2zlw+FpuHkx6v1rozbCTPXHoyU4EolYZ3O49Im\n"
    "GtLua/Ev+gbZighk2HYCcz7IamRSHysYF3sgDLvhF1d6YV1sdwmIwLrZRuII4k+g\n"
    "dOWrMUPbW/zg/RCOS4LRIKkhCAEacjwSp4fm14hxmhC9ulsmmcMnGGr04jwalGg0\n"
    "thUL2iWD6coq1Ezo27vC2wTejvkujvwUH77Kpih8WUdOa8BdmbKWT6CQw6IjO6GG\n"
    "UVvn7R9hKXDO4tevuBvddiFwSBzQBpEn1bBaqZO06piNj93Bhv+33JCmwI9N9DXJ\n"
    "NAKEkjbD+rTSfHAmwdTcsmAmRt7JdR52Pbo3vfj/lAatnlMO5ds4L0EwAa6walPt\n"
    "kCfYMReXJ7CGWokY2j7b68+bFO1Ezmy6ztS7G9t/FEfmzCVLMyBRUSvXr0JvuPQB\n"
    "N4zSv1mDygHGS5Ls8DLqFdFyHQP0gtfObnT+9tVecC9GmAyCtahAMZALHJ5Z58l/\n"
    "vsfo8yOpen42zIi+Dx1Ft/9YWsVL1AeyK0FUqsyPbX6/SOHYFMxe0g+AN+CnlxXu\n"
    "8pvjKAah1Yu3xdp29VCqPYofv/DrGcyxoxPVXNpWyewu8pYyOH/o1248BGgEPo9m\n"
    "P0hg7hK/LVsLdHTW5pT5Hm2+EVl0o5JvEv7l5Dh3fLapMt+M2L7E0HO5Mbo7yDK2\n"
    "jZ3TAHQfp7+K/EftJXb2k2ukJGY6q2OcWuT1aDQjtHQr8cl4I48Wy+OdZS3j/bi+\n"
    "/ISK2SIiLgSkA3wHE+tXqBoj8Mc0c/xkbOowa0vLyIYvg4Xd+p1Lf6LAh+h5aDMD\n"
    "7VvdOgYrPPWzonimbSoT+D9E+C3fMQ7gdKtqNkWX6JmgJV3BZPMcxQhGhR35q0gZ\n"
    "Xe1+obHVEL1+501z+vNrwx7Pomg1kEb064efkkAJQ4tIHGzXiJoALtXuOCvJGQ2m\n"
    "/AJuR5VY5EdWd+mqnjBQ4nZWlN/IH1bogLlucWDJgN2Y7dPf//////////8CAQID\n"
    "ggQFAAKCBAB6skc5bwB1kCSZx9QV53rVicQu8L4Gt1qtYJoHNICF6u0H0vzM0arj\n"
    "emLcV6L1h+CVykAUoCTX3EJcClkjE4gi80A6mJ3IZ4FOZObG98lrs/Ha653WpFyG\n"
    "hYYGwHEE8i1gRwLK80cDSESkcxZJdB9BVyZpwtpUfrGbkt1Bh7fC33CYvK9Px0CZ\n"
    "8LWKii/nyn6q9d6z4veGOgcJI590NEuNnrX5FedC1UkQcG0207YOOFoSXZ5WHOvb\n"
    "m+807q8rLt4/YCpN4yzbfknxz4VQgRNchmhRQ4kGiCdmVuiAgIVF55emrNGK6Z0m\n"
    "OtnpPo5BjK75yvDfWMURGhbr1TlpK26hxsinZYhcy0KH7HjKHB4i+4MQcMgxlRfj\n"
    "8ePBYwEeJtzutP0u6BhdQ7Y2Wh+mdCi1HdvMKuspswpyPVPnvezrLh+xQ7WzatI5\n"
    "i1dATcFxfAy88Z7yCCmzXYIl1/iljzATxgORdnNtXjvtT+mcLlDBLQMrmi5ZaRn4\n"
    "wJgONdlTQlTRzopKLK5zmnZnVPNYDU2yjI6R5R5KJkI3Q+hdMrs6ssIEpkzED3g4\n"
    "kpNABcS9vzGr303mbgfs0HR0Low4NoggmTQVMhmZo1PsKt5cL5cNk60Yirzvm3S+\n"
    "k8WxVAuMwcDjBsFRO825FyaAPJ4ZnrPomQIHdsGxkLHvZWNvnryI1/GE9aWNM+5N\n"
    "Pk/uhQeatK2zV4+/AmqHEvQkQ5Khd3XIOAt8+BT344cSjCcl5bGl3nz3ry8y0mPo\n"
    "DECOvisp5hJkYeDYlW8ai45xDjklah7qekS9BBKpEHW8hMp1OojHrtnfS5MXN+Bf\n"
    "imAkw7a0n/9c8q4XfvQLDpOkyWNar+Wq9D4zfHcqu0JAneDwhnS+O1g/lCJYQygg\n"
    "pck4RkVz2K3ObjuNYc/VKmdnSZYU9bBKAXUJMOYJi2Gag6IP381tQI26VzBbwEff\n"
    "xFAsnkscbztukiknM5bCvSekWphW8t5ghMQbB6/5dROgo5+M5OdG5G2lDa1aKjmL\n"
    "urLui37vKOcfvKZm+y0DifTSt2/ljZULtJO5E+Lp/WqWTB8rJLcxFbSfgr9CqgZN\n"
    "lIyRF6Wdovi75U5eWfP0uWK7vuc2rfxQtPiEHAC16DrFqUKZN9DprNXjU5mwqf9t\n"
    "IWoeXS1uEIHZE2zQee9VPzKXQIOrXNONPdw2DY7a9d3ScFaoxDs3I7YbZ8GrjHum\n"
    "eyNf+5LGJqzuvpCzb6defkeWP8sMkdTpby4qM86OW42Jvl27Z9GsPjB3ee6YiHMj\n"
    "4BCVsldbYN4iGQqsovsXQagdVFZdHSemeuiByJTcJRKE0pPUhbCpl9ndFTQ7Ah23\n"
    "0wF19uLDbk10PhmuiWORmIO27t9Ps6iu\n"
    "-----END PUBLIC KEY-----\n";

static string g_testDsa2048Prikey = "-----BEGIN PRIVATE KEY-----\n"
    "MIICXAIBADCCAjUGByqGSM44BAEwggIoAoIBAQDPXEvnKzvLwPGASwVMsFMI4JgW\n"
    "FaKAjDi9c194Nt71Fpo3zNPNikXXKoHEqJYRF1EVzzlmkiARhE9hwAESuKgK3oJP\n"
    "/Aygovtr5+pwo16E9LqR3/t2Qp2ZENs45BGQ+DrwUr6S55T3Mo3NyMsbr3SDKsZY\n"
    "eFnsN2A67i4jbQpVvJL+fAvWUgGuEIXIa5oQJ1LokQ0iBarXVJ5tu+JLVjgqkQnW\n"
    "1iWA24xkMq2NOWUDgcWjPxrVW8TPuuaB6cKMKDT6t8zRVrCGBxThF7RBGWWWOYev\n"
    "CQ7lbSAkDYZFzKqFt4DRj3NuWXFlrqdxrOHrd74StAA7HuU8i+5T7ExI5ir7Ah0A\n"
    "+ujqphLK8rDnXYwlgVE2OouAIPaM/e7VPql9qwKCAQBeSv4sbWm4Ru6j35i2W4+a\n"
    "Fq7uSdF5P93xruLI+u4a/h7nZVHbXUP7kET5oNbbSRzmxaSQtlFhDJZMFjSHxAme\n"
    "6Cl/sa+RYK0gpDqccWo2+e1QeEv3+4t5HmYevWY7blehaB3ITySHB586E86Rl4+r\n"
    "kqvnI7Mh2wFEZGknrRi+oZLTr5PZti2nd+ouPVMNl8l3T6oZcXUO1wUSMFY3yExO\n"
    "fh66W2wqp9wvSyVUM7T06MKHQ/e6T2+7VUIXhnorDYldtkWJla4X6zuSaryFeKZo\n"
    "XPno390zxFukACbLgM5R/9RqTVynmJc4wx+ixCvei3hB2keHlenGQEVJXJtZf56m\n"
    "BB4CHDze5XQTmFMIAFjht3dyZGMtO5PqvxJOnVHwnKk=\n"
    "-----END PRIVATE KEY-----\n";

static string g_testDsa3072Prikey = "-----BEGIN PRIVATE KEY-----\n"
    "MIIDXgIBADCCAzYGByqGSM44BAEwggMpAoIBgQCjDOJwnOl9/hQ/CviGJvA3BTDA\n"
    "IqlmaFJMSQzF4rp28YzW6P2+3ssi/vzGjnA+7O1ZdZV1xchkO0sPDF9lEKGNUnRb\n"
    "eM0IgVkfV2Bdjqn7y0o+q6NoiaNLbMuyEiGaNKhzfoP9x8NDlSd+W/d4jwYg+JF0\n"
    "4gCXpNXCMatcbviDzYGbun1rL5sTKltApYKCCMtyvf9AcUsN0RyXjo9TSXP750C9\n"
    "3T6FeuCsDGXniwtIghIIDCHBOCvkHwEu/zueicAAPaHP9iipgZ3wO33ToaUdYqdl\n"
    "8OPFu9JMgKLpJNwT9PhtBf6inOsVb4udVJmXFQ7UHdszo4yDkyUW4ob8qJ1RwKyj\n"
    "q3ZfJ5Y2kilbH0Nphpyg3FJyAzDPofhj33sFUfKJkRHwOzf+xwszjKuLbLIjDHvm\n"
    "8mudFhzSFqFiKyRqS97lGcK2T4SahSn8lZ+P9kyRZuZCpXw8GJIcbLJSgZWfaQvh\n"
    "aI2WMWS8ggQwxn7gz4W5QGQ/R29dIvCZPqr3+qECHQDkpzzLWcDIHmmqIrLZH8Nt\n"
    "u+3Q0XQBQtaZOWnVAoIBgQCDuEO0G8cE7n4txT/T17RmzTEILRPc2+2mmvcPFYDc\n"
    "uS1mC8838zXU3VM1juVP/vpuTdPi01D7yQIb23jjb77n4roAwsflQvY5fc6sBBOJ\n"
    "/BjJcF9CLHRBgTXknYgN4qSZx8+X7/w8A22JEC4u6gMQKLPwnEJdK/fx51tnqVYY\n"
    "lK9sTeAuGLdsD5CbJzgqXNRlS0JGGyw2CmGQKwTPybLYQcHnB2ZnYunOSGyrsZB7\n"
    "suVlJ5OfLwdN0or06wltu9yv2Tz+74d5Kdessx4sSfgZ4yDtcXLYCKMPJjI2cLH0\n"
    "lgZ7msfBYcPmk8L8hPWq2GDWTONdpngdiEk8fRwWsHRM4jvfxoMv1lmoK7F9VTUd\n"
    "BLzgYka+/xIIfQB5VBXZrHaGQnbGLZRoWYPHeLuh21wxSwmoB8YFZQs2umOSBJm7\n"
    "sJP1UZM7DYCZSe4QRmsTrwdhlvdd4tNsxHKGnZXMQNBgSJGPL5ag5+8Z6wEPoIo4\n"
    "0EO1ILw13ufx/qBlcNZjLZQEHwIdAMr8b91HR/l73ek2RWENJsV0YLng7R1mj+Jm\n"
    "sbg=\n"
    "-----END PRIVATE KEY-----\n";

static string g_testDsa2048PubKey = "-----BEGIN PUBLIC KEY-----\n"
    "MIIDQjCCAjUGByqGSM44BAEwggIoAoIBAQDPXEvnKzvLwPGASwVMsFMI4JgWFaKA\n"
    "jDi9c194Nt71Fpo3zNPNikXXKoHEqJYRF1EVzzlmkiARhE9hwAESuKgK3oJP/Ayg\n"
    "ovtr5+pwo16E9LqR3/t2Qp2ZENs45BGQ+DrwUr6S55T3Mo3NyMsbr3SDKsZYeFns\n"
    "N2A67i4jbQpVvJL+fAvWUgGuEIXIa5oQJ1LokQ0iBarXVJ5tu+JLVjgqkQnW1iWA\n"
    "24xkMq2NOWUDgcWjPxrVW8TPuuaB6cKMKDT6t8zRVrCGBxThF7RBGWWWOYevCQ7l\n"
    "bSAkDYZFzKqFt4DRj3NuWXFlrqdxrOHrd74StAA7HuU8i+5T7ExI5ir7Ah0A+ujq\n"
    "phLK8rDnXYwlgVE2OouAIPaM/e7VPql9qwKCAQBeSv4sbWm4Ru6j35i2W4+aFq7u\n"
    "SdF5P93xruLI+u4a/h7nZVHbXUP7kET5oNbbSRzmxaSQtlFhDJZMFjSHxAme6Cl/\n"
    "sa+RYK0gpDqccWo2+e1QeEv3+4t5HmYevWY7blehaB3ITySHB586E86Rl4+rkqvn\n"
    "I7Mh2wFEZGknrRi+oZLTr5PZti2nd+ouPVMNl8l3T6oZcXUO1wUSMFY3yExOfh66\n"
    "W2wqp9wvSyVUM7T06MKHQ/e6T2+7VUIXhnorDYldtkWJla4X6zuSaryFeKZoXPno\n"
    "390zxFukACbLgM5R/9RqTVynmJc4wx+ixCvei3hB2keHlenGQEVJXJtZf56mA4IB\n"
    "BQACggEAH9bSRnDNxEOC2oQl7dUO++NWwF4hpmx7z6zeYSN/ViGaFkl0cytASaKw\n"
    "sKXtKjmwQogxNO/eE2q2R0UsB8CCtyJ6LeiIo6yv81gWopI+ZtFgr67vFHcx8q8D\n"
    "jlkmy6gvt7iB8cPn8Mp95KDPHqlqgeMguxZs5uLucRJ0WS1YFWMqTGiCuH4SYrph\n"
    "NtmTNScnlxco4vwxLWRjejWpy+PJF+6XpvSnIp88ARTrpqPEy9xcM1Cr5NJqO3qT\n"
    "C4Gyt3FtSTC/R2iRm3IrLHMoJjSdbgXnX9LhvVOOzWyPtxe78/tUh3NsC0kI0IdG\n"
    "HSTT3iq3yULgcAmq/+o02x4FYZq/2A==\n"
    "-----END PUBLIC KEY-----\n";

static string g_testDsa3072PubKey = "-----BEGIN PUBLIC KEY-----\n"
    "MIIEwzCCAzYGByqGSM44BAEwggMpAoIBgQCjDOJwnOl9/hQ/CviGJvA3BTDAIqlm\n"
    "aFJMSQzF4rp28YzW6P2+3ssi/vzGjnA+7O1ZdZV1xchkO0sPDF9lEKGNUnRbeM0I\n"
    "gVkfV2Bdjqn7y0o+q6NoiaNLbMuyEiGaNKhzfoP9x8NDlSd+W/d4jwYg+JF04gCX\n"
    "pNXCMatcbviDzYGbun1rL5sTKltApYKCCMtyvf9AcUsN0RyXjo9TSXP750C93T6F\n"
    "euCsDGXniwtIghIIDCHBOCvkHwEu/zueicAAPaHP9iipgZ3wO33ToaUdYqdl8OPF\n"
    "u9JMgKLpJNwT9PhtBf6inOsVb4udVJmXFQ7UHdszo4yDkyUW4ob8qJ1RwKyjq3Zf\n"
    "J5Y2kilbH0Nphpyg3FJyAzDPofhj33sFUfKJkRHwOzf+xwszjKuLbLIjDHvm8mud\n"
    "FhzSFqFiKyRqS97lGcK2T4SahSn8lZ+P9kyRZuZCpXw8GJIcbLJSgZWfaQvhaI2W\n"
    "MWS8ggQwxn7gz4W5QGQ/R29dIvCZPqr3+qECHQDkpzzLWcDIHmmqIrLZH8Ntu+3Q\n"
    "0XQBQtaZOWnVAoIBgQCDuEO0G8cE7n4txT/T17RmzTEILRPc2+2mmvcPFYDcuS1m\n"
    "C8838zXU3VM1juVP/vpuTdPi01D7yQIb23jjb77n4roAwsflQvY5fc6sBBOJ/BjJ\n"
    "cF9CLHRBgTXknYgN4qSZx8+X7/w8A22JEC4u6gMQKLPwnEJdK/fx51tnqVYYlK9s\n"
    "TeAuGLdsD5CbJzgqXNRlS0JGGyw2CmGQKwTPybLYQcHnB2ZnYunOSGyrsZB7suVl\n"
    "J5OfLwdN0or06wltu9yv2Tz+74d5Kdessx4sSfgZ4yDtcXLYCKMPJjI2cLH0lgZ7\n"
    "msfBYcPmk8L8hPWq2GDWTONdpngdiEk8fRwWsHRM4jvfxoMv1lmoK7F9VTUdBLzg\n"
    "Yka+/xIIfQB5VBXZrHaGQnbGLZRoWYPHeLuh21wxSwmoB8YFZQs2umOSBJm7sJP1\n"
    "UZM7DYCZSe4QRmsTrwdhlvdd4tNsxHKGnZXMQNBgSJGPL5ag5+8Z6wEPoIo40EO1\n"
    "ILw13ufx/qBlcNZjLZQDggGFAAKCAYBo6EVks/SjgbT0WYsrCIZbvKPkqccsg+Fd\n"
    "veKz9eUpJpo93EfZgDqMNka8zSzo4vO7fYJPgxw+YkPVCzdtCqxKJLvDeSsogQ/j\n"
    "1LGyuVoOdXU4E1SHgKTtkviKU2zCJoSE6/gH3i9cfaVvBpr1kiQV5isDJb02Wqh8\n"
    "bq1skTVoy+eg6x75mPrd5eRmzQiDOmWtkwfxfBC2ybeXBsS39DsqDXAfTRC0kaK8\n"
    "Od2KSM0btuZatIo28Qw65io2ABbTW973BwJ3uKhWgaVoBIwzvsyYd6FfSpWEQ36A\n"
    "u7kiGH5QltjvTVtoOlSnV8U+g2S+6X2mMhfVz6TUOWf1E4d6jLZ9Oet5gap8aJ2M\n"
    "NbYpNxnyfFIG9q0RAVqPUAddvW5hOypCeIXUuLIz2c+tHIvWcwlOomrv0e4K1jgP\n"
    "Egh1ccqwqqiM+Pz57SAIYdsN+sDxanWK9IUBpNQmCtbhRhVgt8PzbFVoBKs5wFbj\n"
    "J5CGPcuzhta1Ju41XMtRHHigBtL62r4=\n"
    "-----END PUBLIC KEY-----\n";

static string g_testEccP160r1PriKey = "-----BEGIN PRIVATE KEY-----\n"
    "MGQCAQAwFAYHKoZIzj0CAQYJKyQDAwIIAQEBBEkwRwIBAQQUASO/LfZI7/oU61jD\n"
    "jI3iN3daCsKhLAMqAAR9QXIl11ePlAzVlwjLUnkKjxX6LBAU4Q0sOo1eeDM+nEg5\n"
    "XenI3o1+\n"
    "-----END PRIVATE KEY-----\n";

static string g_testEccP160r1PubKey = "-----BEGIN PUBLIC KEY-----\n"
    "MEIwFAYHKoZIzj0CAQYJKyQDAwIIAQEBAyoABH1BciXXV4+UDNWXCMtSeQqPFfos\n"
    "EBThDSw6jV54Mz6cSDld6cjejX4=\n"
    "-----END PUBLIC KEY-----\n";

static string g_testEccP160t1PriKey = "-----BEGIN PRIVATE KEY-----\n"
    "MGQCAQAwFAYHKoZIzj0CAQYJKyQDAwIIAQECBEkwRwIBAQQU3/XiFisN/54Kj4nQ\n"
    "Bwjr1dceZQihLAMqAATKWOgm/tH+UYnAv8hs/Y/D34fMv4BwU4k3/Z+gRBKRN4cy\n"
    "ypd5NiES\n"
    "-----END PRIVATE KEY-----\n";

static string g_testEccP160t1PubKey = "-----BEGIN PUBLIC KEY-----\n"
    "MEIwFAYHKoZIzj0CAQYJKyQDAwIIAQECAyoABMpY6Cb+0f5RicC/yGz9j8Pfh8y/\n"
    "gHBTiTf9n6BEEpE3hzLKl3k2IRI=\n"
    "-----END PUBLIC KEY-----\n";

static string g_testEccP192r1PriKey = "-----BEGIN PRIVATE KEY-----\n"
    "MHACAQAwFAYHKoZIzj0CAQYJKyQDAwIIAQEDBFUwUwIBAQQYZJ2mohQak6UuCZdW\n"
    "Ox8uUsOp70Pg2T0+oTQDMgAEezNHhaP+k9qgeQ/9ZHAc/AhkWrGNJ8AjwFqrj4lc\n"
    "EyDnCz3QxK3MEmfPxkhlNXWb\n"
    "-----END PRIVATE KEY-----\n";

static string g_testEccP192r1PubKey = "-----BEGIN PUBLIC KEY-----\n"
    "MEowFAYHKoZIzj0CAQYJKyQDAwIIAQEDAzIABHszR4Wj/pPaoHkP/WRwHPwIZFqx\n"
    "jSfAI8Baq4+JXBMg5ws90MStzBJnz8ZIZTV1mw==\n"
    "-----END PUBLIC KEY-----\n";

static string g_testEccP192t1PriKey = "-----BEGIN PRIVATE KEY-----\n"
    "MHACAQAwFAYHKoZIzj0CAQYJKyQDAwIIAQEEBFUwUwIBAQQYG9Qnpo0Mnsc038+F\n"
    "8cL9eend4xNz6blPoTQDMgAECrDcmHkXtKe1+TKqYtM2jfe805qYBR7kgBWmEmJN\n"
    "KAfv8Oo+/1u/VpNe2nYBURRn\n"
    "-----END PRIVATE KEY-----\n";

static string g_testEccP192t1PubKey = "-----BEGIN PUBLIC KEY-----\n"
    "MEowFAYHKoZIzj0CAQYJKyQDAwIIAQEEAzIABAqw3Jh5F7SntfkyqmLTNo33vNOa\n"
    "mAUe5IAVphJiTSgH7/DqPv9bv1aTXtp2AVEUZw==\n"
    "-----END PUBLIC KEY-----\n";

static string g_testEccP224r1PriKey = "-----BEGIN PRIVATE KEY-----\n"
    "MHwCAQAwFAYHKoZIzj0CAQYJKyQDAwIIAQEFBGEwXwIBAQQcjRIweUszgw6kye8e\n"
    "uH+EDixtMWACgjAFKLlD86E8AzoABKJPILw4pJ703KZWzwCiU2WIZgaxlHo3M/LI\n"
    "hOuGsmvnaBmH6nfTt4E7NqHkgBnJVNTmELXpPDt2\n"
    "-----END PRIVATE KEY-----\n";

static string g_testEccP224r1PubKey = "-----BEGIN PUBLIC KEY-----\n"
    "MFIwFAYHKoZIzj0CAQYJKyQDAwIIAQEFAzoABKJPILw4pJ703KZWzwCiU2WIZgax\n"
    "lHo3M/LIhOuGsmvnaBmH6nfTt4E7NqHkgBnJVNTmELXpPDt2\n"
    "-----END PUBLIC KEY-----\n";

static string g_testEccP224t1PriKey = "-----BEGIN PRIVATE KEY-----\n"
    "MHwCAQAwFAYHKoZIzj0CAQYJKyQDAwIIAQEGBGEwXwIBAQQc0FrhunNRyAF63WWu\n"
    "RnlazhSV2vURHyWcGu6deKE8AzoABIdtC73AhzV0Jr90EHl9DHuyQfsrb9917sCj\n"
    "+4YGoKqXTKp8Ww4dc1dDIxd9FKyz9J///x1RUqUn\n"
    "-----END PRIVATE KEY-----\n";

static string g_testEccP224t1PubKey = "-----BEGIN PUBLIC KEY-----\n"
    "MFIwFAYHKoZIzj0CAQYJKyQDAwIIAQEGAzoABIdtC73AhzV0Jr90EHl9DHuyQfsr\n"
    "b9917sCj+4YGoKqXTKp8Ww4dc1dDIxd9FKyz9J///x1RUqUn\n"
    "-----END PUBLIC KEY-----\n";

static string g_testEccP256r1PriKey = "-----BEGIN PRIVATE KEY-----\n"
    "MIGIAgEAMBQGByqGSM49AgEGCSskAwMCCAEBBwRtMGsCAQEEIGEWmKHlX2Q7RNcn\n"
    "TjcbiQO83eOZdeohwj6GrZTswNZYoUQDQgAELXkxbTULz0F0MP9if30WZ2SUw3Sz\n"
    "Oht9darQcWO6fzUlHzJPAz//wv+narhYYYGO9c9K7YTGSUPA9x3G4l31rA==\n"
    "-----END PRIVATE KEY-----\n";

static string g_testEccP256r1PubKey = "-----BEGIN PUBLIC KEY-----\n"
    "MFowFAYHKoZIzj0CAQYJKyQDAwIIAQEHA0IABC15MW01C89BdDD/Yn99FmdklMN0\n"
    "szobfXWq0HFjun81JR8yTwM//8L/p2q4WGGBjvXPSu2ExklDwPcdxuJd9aw=\n"
    "-----END PUBLIC KEY-----\n";

static string g_testEccP256t1PriKey = "-----BEGIN PRIVATE KEY-----\n"
    "MIGIAgEAMBQGByqGSM49AgEGCSskAwMCCAEBCARtMGsCAQEEICKa3/xdoohLWjrn\n"
    "mR/5Iyb8yyb6FPAa9R4vTa6x53b+oUQDQgAEgeCO46sHVnF8StJg7SiKW/Nwbw76\n"
    "Nai8MrlYN8axQN9oEgwrTNVzu0M4X2fquIxI8i52Rp+/iPL50zE8UI4RKA==\n"
    "-----END PRIVATE KEY-----\n";

static string g_testEccP256t1PubKey = "-----BEGIN PUBLIC KEY-----\n"
    "MFowFAYHKoZIzj0CAQYJKyQDAwIIAQEIA0IABIHgjuOrB1ZxfErSYO0oilvzcG8O\n"
    "+jWovDK5WDfGsUDfaBIMK0zVc7tDOF9n6riMSPIudkafv4jy+dMxPFCOESg=\n"
    "-----END PUBLIC KEY-----\n";

static string g_testEccP320r1PriKey = "-----BEGIN PRIVATE KEY-----\n"
    "MIGiAgEAMBQGByqGSM49AgEGCSskAwMCCAEBCQSBhjCBgwIBAQQoQg1ccOHTcKft\n"
    "H7HYc+bMzIqlWs76bfL9ie1Z7AvZaCHTxdvkXkSnzKFUA1IABA+GdgqTHGQORU7c\n"
    "oz/8036686oDnSs8kMjNQ4GIdGHcwXiurGviJmO/T+yJAU2wqiTefWGjOpNVzOMJ\n"
    "HHnad3xgbzrevv5ajO6PUHeI14OP\n"
    "-----END PRIVATE KEY-----\n";

static string g_testEccP320r1PubKey = "-----BEGIN PUBLIC KEY-----\n"
    "MGowFAYHKoZIzj0CAQYJKyQDAwIIAQEJA1IABA+GdgqTHGQORU7coz/8036686oD\n"
    "nSs8kMjNQ4GIdGHcwXiurGviJmO/T+yJAU2wqiTefWGjOpNVzOMJHHnad3xgbzre\n"
    "vv5ajO6PUHeI14OP\n"
    "-----END PUBLIC KEY-----\n";

static string g_testEccP320t1PriKey = "-----BEGIN PRIVATE KEY-----\n"
    "MIGiAgEAMBQGByqGSM49AgEGCSskAwMCCAEBCgSBhjCBgwIBAQQoNBUB9bYEND/J\n"
    "Aa/5LWOwPFVAteMc06veS4FgGuyhTXxwGFJuwvGx56FUA1IABDdabgr6v4yG2hLZ\n"
    "2zTxP2+vKDwVJaHvBQ8StEkkfYKzKus5hUILOQTEbpi6/ODPw0ZRC1+uK87IuPMu\n"
    "1DnWIRvDUrSFCcjURCTAwudMTt5y\n"
    "-----END PRIVATE KEY-----\n";

static string g_testEccP320t1PubKey = "-----BEGIN PUBLIC KEY-----\n"
    "MGowFAYHKoZIzj0CAQYJKyQDAwIIAQEKA1IABDdabgr6v4yG2hLZ2zTxP2+vKDwV\n"
    "JaHvBQ8StEkkfYKzKus5hUILOQTEbpi6/ODPw0ZRC1+uK87IuPMu1DnWIRvDUrSF\n"
    "CcjURCTAwudMTt5y\n"
    "-----END PUBLIC KEY-----\n";

static string g_testEccP384r1PriKey = "-----BEGIN PRIVATE KEY-----\n"
    "MIG6AgEAMBQGByqGSM49AgEGCSskAwMCCAEBCwSBnjCBmwIBAQQwf+M859VdL3Cx\n"
    "DUQ6xzEpPbgmHhlMa9veRNok/VlKFwHs7gUpirvA+vzCz1sJA0ePoWQDYgAEgYsV\n"
    "W0pKIDXz4qWgvqkFLD6yB+99GvXDnMKRQPIHcSOfAnThZtr5LJH/xXMNs29aez3a\n"
    "TqgYmVtiAQgM+C6shAaqqj6qZoE0ACSgemVKHxV065JStQts9xfqhK2QOey9\n"
    "-----END PRIVATE KEY-----\n";

static string g_testEccP384r1PubKey = "-----BEGIN PUBLIC KEY-----\n"
    "MHowFAYHKoZIzj0CAQYJKyQDAwIIAQELA2IABIGLFVtKSiA18+KloL6pBSw+sgfv\n"
    "fRr1w5zCkUDyB3EjnwJ04Wba+SyR/8VzDbNvWns92k6oGJlbYgEIDPgurIQGqqo+\n"
    "qmaBNAAkoHplSh8VdOuSUrULbPcX6oStkDnsvQ==\n"
    "-----END PUBLIC KEY-----\n";

static string g_testEccP384t1PriKey = "-----BEGIN PRIVATE KEY-----\n"
    "MIG6AgEAMBQGByqGSM49AgEGCSskAwMCCAEBDASBnjCBmwIBAQQwaPOGmvKk9UPa\n"
    "GnpoWTpvs2gmq5C1CC8pMc8aVFPWY4yhUszcnYiIuIMfs+AzMo6CoWQDYgAEdemX\n"
    "VIj45zsc/28xYiSObxmuf4OskgIvBrptXx8DwJMOmZvFawXswxZErzv13gvmcPMd\n"
    "rif01/fGgrr/QTQAKx8l/5TkECkHdOflHS84Wy2h1mkbb3KFJH7Opm5JMmtw\n"
    "-----END PRIVATE KEY-----\n";

static string g_testEccP384t1PubKey = "-----BEGIN PUBLIC KEY-----\n"
    "MHowFAYHKoZIzj0CAQYJKyQDAwIIAQEMA2IABHXpl1SI+Oc7HP9vMWIkjm8Zrn+D\n"
    "rJICLwa6bV8fA8CTDpmbxWsF7MMWRK879d4L5nDzHa4n9Nf3xoK6/0E0ACsfJf+U\n"
    "5BApB3Tn5R0vOFstodZpG29yhSR+zqZuSTJrcA==\n"
    "-----END PUBLIC KEY-----\n";

static string g_testEccP512r1PriKey = "-----BEGIN PRIVATE KEY-----\n"
    "MIHsAgEAMBQGByqGSM49AgEGCSskAwMCCAEBDQSB0DCBzQIBAQRAjQ8+FR54Dggv\n"
    "o5bICxr+k+6fjjeakaYFxwaqlVtznmLdX9WqantFAld3mSRI0fEwa8quplRS/SO1\n"
    "egRx/i/CbKGBhQOBggAEdtNym0AqquTwWqRH8ardukuoopQQu3dbq30IWsZfyx/h\n"
    "ZLMNJWpLVMKcIg0F/qccFlqKvj3kMy6c7keIAMkBKXeCJ+6NKM3cgcKr1crfvagC\n"
    "mbAjSHsKXQRLIk3WCxL4xqXk+GC/Na64lsUnqDIw/ieztxmhkT9O5zLdW6qAKhI=\n"
    "-----END PRIVATE KEY-----\n";

static string g_testEccP512r1PubKey = "-----BEGIN PUBLIC KEY-----\n"
    "MIGbMBQGByqGSM49AgEGCSskAwMCCAEBDQOBggAEdtNym0AqquTwWqRH8ardukuo\n"
    "opQQu3dbq30IWsZfyx/hZLMNJWpLVMKcIg0F/qccFlqKvj3kMy6c7keIAMkBKXeC\n"
    "J+6NKM3cgcKr1crfvagCmbAjSHsKXQRLIk3WCxL4xqXk+GC/Na64lsUnqDIw/iez\n"
    "txmhkT9O5zLdW6qAKhI=\n"
    "-----END PUBLIC KEY-----\n";

static string g_testEccP512t1PriKey = "-----BEGIN PRIVATE KEY-----\n"
    "MIHsAgEAMBQGByqGSM49AgEGCSskAwMCCAEBDgSB0DCBzQIBAQRAhSMiRfKXVUGS\n"
    "hMiCfkdszV0TmdWib5WIoNFKyHQGgtt8kZcXl5NX84SsoO28leLDJ9fSd1qV/Dwq\n"
    "+INCiNKnGaGBhQOBggAEKGhHCsQ5qabxssAoCZiEZT9wxdTOliHqv+mStkwQRPZD\n"
    "Or4uSUqGTQHXUWY/9+J3fMnvws7uf9p9GnRB9rpHL2K/NkiviW+hX+ikIuyT7nGr\n"
    "jPT8olwleVaidVbgPjLtliZV98evrcZKZ/x1plcWX7l8I2Bhg5845fximjWUvQU=\n"
    "-----END PRIVATE KEY-----\n";

static string g_testEccP512t1PubKey = "-----BEGIN PUBLIC KEY-----\n"
    "MIGbMBQGByqGSM49AgEGCSskAwMCCAEBDgOBggAEKGhHCsQ5qabxssAoCZiEZT9w\n"
    "xdTOliHqv+mStkwQRPZDOr4uSUqGTQHXUWY/9+J3fMnvws7uf9p9GnRB9rpHL2K/\n"
    "NkiviW+hX+ikIuyT7nGrjPT8olwleVaidVbgPjLtliZV98evrcZKZ/x1plcWX7l8\n"
    "I2Bhg5845fximjWUvQU=\n"
    "-----END PUBLIC KEY-----\n";

static string g_testEccPrime256v1PriKey = "-----BEGIN PRIVATE KEY-----\n"
    "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgrwZLoHLb9awzKiT1\n"
    "5/FXrItjgIExhDon3mGVrVHllqahRANCAAQCOkE1Xx5YKUjKGaN86zL5JO6irKe9\n"
    "XXjC3kashJ7fYzLkrkIuHyuqEM7hvmw0F7w/DrUkonPgCN+t395C9/EW\n"
    "-----END PRIVATE KEY-----\n";

static string g_testEccPrime256v1PubKey = "-----BEGIN PUBLIC KEY-----\n"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAjpBNV8eWClIyhmjfOsy+STuoqyn\n"
    "vV14wt5GrISe32My5K5CLh8rqhDO4b5sNBe8Pw61JKJz4Ajfrd/eQvfxFg==\n"
    "-----END PUBLIC KEY-----\n";

static string g_testEccSecp384r1PriKey = "-----BEGIN PRIVATE KEY-----\n"
    "MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDBq2KueaDvMuB0n7Wd3\n"
    "s5vThqu5wxBIdN3BzE12+RzqL+Q+iqzPuHS4YE11syurz9ahZANiAAQ86CZ+Fvmm\n"
    "w36OiBIx412pYe+HWd2TBCkWr5p6tIKcdszG0AhMxPkgzjAtrSUHg+/rsd5TWSdx\n"
    "B0SmbWQTcukqrdb8ITAkgmk4HUjQ85TjWXDokYK5wXWE0fWV5BpzkZ4=\n"
    "-----END PRIVATE KEY-----\n";

static string g_testEccSecp384r1PubKey = "-----BEGIN PUBLIC KEY-----\n"
    "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEPOgmfhb5psN+jogSMeNdqWHvh1ndkwQp\n"
    "Fq+aerSCnHbMxtAITMT5IM4wLa0lB4Pv67HeU1kncQdEpm1kE3LpKq3W/CEwJIJp\n"
    "OB1I0POU41lw6JGCucF1hNH1leQac5Ge\n"
    "-----END PUBLIC KEY-----\n";

static string g_testEccSecp521r1PriKey = "-----BEGIN PRIVATE KEY-----\n"
    "MIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIByYx3SSpA7rou1Fpa\n"
    "I4ySKDxaJHPXrlM/C/0WFG9UboT6vjvpp3BA4CrkE5FH8hP3ouUbkAFDMvSJbkL1\n"
    "paUdOB2hgYkDgYYABACEkXDyF6CWltw6eN83x4x0NbZpncw2iwuZBC/nIR9+scXp\n"
    "+Gj48ft8F9Er+CrtQEvNwz1PGWVTk+dnpJ/ztlfu4ADhyb5B9GWtwNi4D+rgHtYX\n"
    "LlsthM8GGlAbuMIV0y/QTqqtwYFEJwBVwopsVn1rjWnFxIaZRcEJa6dwM58+sLYc\n"
    "Ng==\n"
    "-----END PRIVATE KEY-----\n";

static string g_testEccSecp521r1PubKey = "-----BEGIN PUBLIC KEY-----\n"
    "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAhJFw8heglpbcOnjfN8eMdDW2aZ3M\n"
    "NosLmQQv5yEffrHF6fho+PH7fBfRK/gq7UBLzcM9TxllU5PnZ6Sf87ZX7uAA4cm+\n"
    "QfRlrcDYuA/q4B7WFy5bLYTPBhpQG7jCFdMv0E6qrcGBRCcAVcKKbFZ9a41pxcSG\n"
    "mUXBCWuncDOfPrC2HDY=\n"
    "-----END PUBLIC KEY-----\n";

static void AsyKeyConvertPemTest(const char *algoName, const char *pubKey, const char *priKey)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(algoName, &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generator->convertPemKey(generator, nullptr, pubKey, priKey, &dupKeyPair);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupKeyPair, nullptr);

    HcfKeyPair *dupKeyPair2 = nullptr;
    res = generator->convertPemKey(generator, nullptr, nullptr, priKey, &dupKeyPair2);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupKeyPair2, nullptr);

    HcfKeyPair *dupKeyPair3 = nullptr;
    res = generator->convertPemKey(generator, nullptr, pubKey, nullptr, &dupKeyPair3);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(dupKeyPair3, nullptr);

    HcfObjDestroy(dupKeyPair);
    HcfObjDestroy(dupKeyPair2);
    HcfObjDestroy(dupKeyPair3);
    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsyKeyConvertPemTest, CryptoAsyKeyConvertPemTest001, TestSize.Level0)
{
    AsyKeyConvertPemTest("SM2_256", g_testSm2PubKey.c_str(), g_testSm2PriKey.c_str());
    AsyKeyConvertPemTest("X25519", g_testX25519PubKey.c_str(), g_testX25519PriKey.c_str());
    AsyKeyConvertPemTest("Ed25519", g_testEd25519PubKey.c_str(), g_testEd25519PriKey.c_str());
    AsyKeyConvertPemTest("ECC224", g_testEccSecp224r1PubKey.c_str(), g_testEccSecp224r1PriKey.c_str());
    AsyKeyConvertPemTest("DSA1024", g_testDsa1024Pubkey.c_str(), g_testDsa1024Prikey.c_str());
    AsyKeyConvertPemTest("DH_modp1536", g_testDhModp1536PubKey.c_str(), g_testDhModp1536PriKey.c_str());

    AsyKeyConvertPemTest("DH_ffdhe2048", g_testDhFfdhe2048PubKey.c_str(), g_testDhFfdhe2048PriKey.c_str());
    AsyKeyConvertPemTest("DH_ffdhe3072", g_testDhFfdhe3072PubKey.c_str(), g_testDhFfdhe3072PriKey.c_str());
    AsyKeyConvertPemTest("DH_ffdhe4096", g_testDhFfdhe4096PubKey.c_str(), g_testDhFfdhe4096PriKey.c_str());
    AsyKeyConvertPemTest("DH_ffdhe6144", g_testDhFfdhe6144PubKey.c_str(), g_testDhFfdhe6144PriKey.c_str());
    AsyKeyConvertPemTest("DH_ffdhe8192", g_testDhFfdhe8192PubKey.c_str(), g_testDhFfdhe8192PriKey.c_str());
    AsyKeyConvertPemTest("DH_modp2048", g_testDhModp2048PubKey.c_str(), g_testDhModp2048PriKey.c_str());
    AsyKeyConvertPemTest("DH_modp3072", g_testDhModp3072PubKey.c_str(), g_testDhModp3072PriKey.c_str());
    AsyKeyConvertPemTest("DH_modp4096", g_testDhModp4096PubKey.c_str(), g_testDhModp4096PriKey.c_str());
    AsyKeyConvertPemTest("DH_modp6144", g_testDhModp6144PubKey.c_str(), g_testDhModp6144PriKey.c_str());
    AsyKeyConvertPemTest("DH_modp8192", g_testDhModp8192PubKey.c_str(), g_testDhModp8192PriKey.c_str());

    AsyKeyConvertPemTest("DSA2048", g_testDsa2048PubKey.c_str(), g_testDsa2048Prikey.c_str());
    AsyKeyConvertPemTest("DSA3072", g_testDsa3072PubKey.c_str(), g_testDsa3072Prikey.c_str());

    AsyKeyConvertPemTest("ECC_BrainPoolP160r1", g_testEccP160r1PubKey.c_str(), g_testEccP160r1PriKey.c_str());
    AsyKeyConvertPemTest("ECC_BrainPoolP160t1", g_testEccP160t1PubKey.c_str(), g_testEccP160t1PriKey.c_str());
    AsyKeyConvertPemTest("ECC_BrainPoolP192r1", g_testEccP192r1PubKey.c_str(), g_testEccP192r1PriKey.c_str());
    AsyKeyConvertPemTest("ECC_BrainPoolP192t1", g_testEccP192t1PubKey.c_str(), g_testEccP192t1PriKey.c_str());
    AsyKeyConvertPemTest("ECC_BrainPoolP224r1", g_testEccP224r1PubKey.c_str(), g_testEccP224r1PriKey.c_str());
    AsyKeyConvertPemTest("ECC_BrainPoolP224t1", g_testEccP224t1PubKey.c_str(), g_testEccP224t1PriKey.c_str());
    AsyKeyConvertPemTest("ECC_BrainPoolP256r1", g_testEccP256r1PubKey.c_str(), g_testEccP256r1PriKey.c_str());
    AsyKeyConvertPemTest("ECC_BrainPoolP256t1", g_testEccP256t1PubKey.c_str(), g_testEccP256t1PriKey.c_str());
    AsyKeyConvertPemTest("ECC_BrainPoolP320r1", g_testEccP320r1PubKey.c_str(), g_testEccP320r1PriKey.c_str());
    AsyKeyConvertPemTest("ECC_BrainPoolP320t1", g_testEccP320t1PubKey.c_str(), g_testEccP320t1PriKey.c_str());
    AsyKeyConvertPemTest("ECC_BrainPoolP384r1", g_testEccP384r1PubKey.c_str(), g_testEccP384r1PriKey.c_str());
    AsyKeyConvertPemTest("ECC_BrainPoolP384t1", g_testEccP384t1PubKey.c_str(), g_testEccP384t1PriKey.c_str());
    AsyKeyConvertPemTest("ECC_BrainPoolP512r1", g_testEccP512r1PubKey.c_str(), g_testEccP512r1PriKey.c_str());
    AsyKeyConvertPemTest("ECC_BrainPoolP512t1", g_testEccP512t1PubKey.c_str(), g_testEccP512t1PriKey.c_str());
    AsyKeyConvertPemTest("ECC256", g_testEccPrime256v1PubKey.c_str(), g_testEccPrime256v1PriKey.c_str());
    AsyKeyConvertPemTest("ECC384", g_testEccSecp384r1PubKey.c_str(), g_testEccSecp384r1PriKey.c_str());
    AsyKeyConvertPemTest("ECC521", g_testEccSecp521r1PubKey.c_str(), g_testEccSecp521r1PriKey.c_str());
}

static void AsyKeyPemParamNullErrorTest(const char *algoName, const char *pubKey, const char *priKey)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(algoName, &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generator->convertPemKey(generator, nullptr, nullptr, nullptr, &dupKeyPair);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair, nullptr);

    res = generator->convertPemKey(nullptr, nullptr, pubKey, priKey, &dupKeyPair);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair, nullptr);

    res = generator->convertPemKey(generator, nullptr, pubKey, priKey, nullptr);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair, nullptr);
    HcfObjDestroy(generator);
}

// test ConvertPemKey parma is null
HWTEST_F(CryptoAsyKeyConvertPemTest, CryptoAsyKeyConvertPemTest002, TestSize.Level0)
{
    AsyKeyPemParamNullErrorTest("SM2_256", g_testSm2PubKey.c_str(), g_testSm2PriKey.c_str());
    AsyKeyPemParamNullErrorTest("X25519", g_testX25519PubKey.c_str(), g_testX25519PriKey.c_str());
    AsyKeyPemParamNullErrorTest("Ed25519", g_testEd25519PubKey.c_str(), g_testEd25519PriKey.c_str());
    AsyKeyPemParamNullErrorTest("ECC224", g_testEccSecp224r1PubKey.c_str(), g_testEccSecp224r1PriKey.c_str());
    AsyKeyPemParamNullErrorTest("DSA1024", g_testDsa1024Pubkey.c_str(), g_testDsa1024Prikey.c_str());
    AsyKeyPemParamNullErrorTest("DH_modp1536", g_testDhModp1536PubKey.c_str(), g_testDhModp1536PriKey.c_str());
}

static void AsyKeyPemParamFormatErrorTest(const char *algoName, const char *pubKey, const char *priKey)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(algoName, &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generator->convertPemKey(generator, nullptr, "pubkey", priKey, &dupKeyPair);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair, nullptr);

    res = generator->convertPemKey(generator, nullptr, pubKey, "prikey", &dupKeyPair);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair, nullptr);

    res = generator->convertPemKey(generator, nullptr, "pubkey", "prikey", &dupKeyPair);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair, nullptr);

    HcfObjDestroy(generator);
}

// test ConvertPemKey pubkey and prikey is invalid
HWTEST_F(CryptoAsyKeyConvertPemTest, CryptoAsyKeyConvertPemTest003, TestSize.Level0)
{
    AsyKeyPemParamFormatErrorTest("SM2_256", g_testSm2PubKey.c_str(), g_testSm2PriKey.c_str());
    AsyKeyPemParamFormatErrorTest("X25519", g_testX25519PubKey.c_str(), g_testX25519PriKey.c_str());
    AsyKeyPemParamFormatErrorTest("Ed25519", g_testEd25519PubKey.c_str(), g_testEd25519PriKey.c_str());
    AsyKeyPemParamFormatErrorTest("ECC224", g_testEccSecp224r1PubKey.c_str(), g_testEccSecp224r1PriKey.c_str());
    AsyKeyPemParamFormatErrorTest("DSA1024", g_testDsa1024Pubkey.c_str(), g_testDsa1024Prikey.c_str());
    AsyKeyPemParamFormatErrorTest("DH_modp1536", g_testDhModp1536PubKey.c_str(), g_testDhModp1536PriKey.c_str());
}

static void AsyKeyPemParamMatchErrorTest(const char *algoName, const char *pubKey, const char *priKey)
{
    HcfAsyKeyGenerator *generator = nullptr;
    HcfResult res = HcfAsyKeyGeneratorCreate(algoName, &generator);
    EXPECT_EQ(res, HCF_SUCCESS);
    EXPECT_NE(generator, nullptr);

    HcfKeyPair *dupKeyPair = nullptr;
    res = generator->convertPemKey(generator, nullptr, pubKey, priKey, &dupKeyPair);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair, nullptr);

    res = generator->convertPemKey(generator, nullptr, nullptr, priKey, &dupKeyPair);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair, nullptr);

    res = generator->convertPemKey(generator, nullptr, pubKey, nullptr, &dupKeyPair);
    EXPECT_NE(res, HCF_SUCCESS);
    EXPECT_EQ(dupKeyPair, nullptr);

    HcfObjDestroy(generator);
}

HWTEST_F(CryptoAsyKeyConvertPemTest, CryptoAsyKeyConvertPemTest004, TestSize.Level0)
{
    AsyKeyPemParamMatchErrorTest("SM2_256", g_testX25519PubKey.c_str(), g_testX25519PriKey.c_str());
    AsyKeyPemParamMatchErrorTest("SM2_256", g_testEd25519PubKey.c_str(), g_testEd25519PriKey.c_str());
    AsyKeyPemParamMatchErrorTest("SM2_256", g_testEccSecp224r1PubKey.c_str(), g_testEccSecp224r1PriKey.c_str());
    AsyKeyPemParamMatchErrorTest("SM2_256", g_testDsa1024Pubkey.c_str(), g_testDsa1024Prikey.c_str());
    AsyKeyPemParamMatchErrorTest("SM2_256", g_testDhModp1536PubKey.c_str(), g_testDhModp1536PriKey.c_str());
    AsyKeyPemParamMatchErrorTest("X25519", g_testSm2PubKey.c_str(), g_testSm2PriKey.c_str());
    AsyKeyPemParamMatchErrorTest("X25519", g_testEd25519PubKey.c_str(), g_testEd25519PriKey.c_str());
    AsyKeyPemParamMatchErrorTest("X25519", g_testEccSecp224r1PubKey.c_str(), g_testEccSecp224r1PriKey.c_str());
    AsyKeyPemParamMatchErrorTest("X25519", g_testDsa1024Pubkey.c_str(), g_testDsa1024Prikey.c_str());
    AsyKeyPemParamMatchErrorTest("X25519", g_testDhModp1536PubKey.c_str(), g_testDhModp1536PriKey.c_str());
    AsyKeyPemParamMatchErrorTest("Ed25519", g_testSm2PubKey.c_str(), g_testSm2PriKey.c_str());
    AsyKeyPemParamMatchErrorTest("Ed25519", g_testX25519PubKey.c_str(), g_testX25519PriKey.c_str());
    AsyKeyPemParamMatchErrorTest("Ed25519", g_testEccSecp224r1PubKey.c_str(), g_testEccSecp224r1PriKey.c_str());
    AsyKeyPemParamMatchErrorTest("Ed25519", g_testDsa1024Pubkey.c_str(), g_testDsa1024Prikey.c_str());
    AsyKeyPemParamMatchErrorTest("Ed25519", g_testDhModp1536PubKey.c_str(), g_testDhModp1536PriKey.c_str());
    AsyKeyPemParamMatchErrorTest("ECC224", g_testSm2PubKey.c_str(), g_testSm2PriKey.c_str());
    AsyKeyPemParamMatchErrorTest("ECC224", g_testX25519PubKey.c_str(), g_testX25519PriKey.c_str());
    AsyKeyPemParamMatchErrorTest("ECC224", g_testEd25519PubKey.c_str(), g_testEd25519PriKey.c_str());
    AsyKeyPemParamMatchErrorTest("ECC224", g_testDsa1024Pubkey.c_str(), g_testDsa1024Prikey.c_str());
    AsyKeyPemParamMatchErrorTest("ECC224", g_testDhModp1536PubKey.c_str(), g_testDhModp1536PriKey.c_str());
    AsyKeyPemParamMatchErrorTest("DSA1024", g_testSm2PubKey.c_str(), g_testSm2PriKey.c_str());
    AsyKeyPemParamMatchErrorTest("DSA1024", g_testX25519PubKey.c_str(), g_testX25519PriKey.c_str());
    AsyKeyPemParamMatchErrorTest("DSA1024", g_testEd25519PubKey.c_str(), g_testEd25519PriKey.c_str());
    AsyKeyPemParamMatchErrorTest("DSA1024", g_testEccSecp224r1PubKey.c_str(), g_testEccSecp224r1PriKey.c_str());
    AsyKeyPemParamMatchErrorTest("DSA1024", g_testDhModp1536PubKey.c_str(), g_testDhModp1536PriKey.c_str());
    AsyKeyPemParamMatchErrorTest("DH_modp1536", g_testSm2PubKey.c_str(), g_testSm2PriKey.c_str());
    AsyKeyPemParamMatchErrorTest("DH_modp1536", g_testX25519PubKey.c_str(), g_testX25519PriKey.c_str());
    AsyKeyPemParamMatchErrorTest("DH_modp1536", g_testEd25519PubKey.c_str(), g_testEd25519PriKey.c_str());
    AsyKeyPemParamMatchErrorTest("DH_modp1536", g_testEccSecp224r1PubKey.c_str(), g_testEccSecp224r1PriKey.c_str());
    AsyKeyPemParamMatchErrorTest("DH_modp1536", g_testDsa1024Pubkey.c_str(), g_testDsa1024Prikey.c_str());
}
}

/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef ATTEST_ERROR_CODE_H
#define ATTEST_ERROR_CODE_H

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif /* __cplusplus */

#define ATTEST_OK 0
#define ATTEST_ERR (-1)

// 网络访问相关
#define WISE_HTTPS_ERROR 4999
#define WISE_INVALID_CHALLENGE 14001
#define WISE_RETRY_CNT 1

#define IS_WISE_RETRY(d_error) ((d_error) == WISE_INVALID_CHALLENGE || (d_error) == WISE_HTTPS_ERROR)

// 设备认证结果
#define DEVICE_ATTEST_INIT (-2)
#define DEVICE_ATTEST_FAIL (-1)
#define DEVICE_ATTEST_PASS (0)

#define ERR_INVALID_PARAM 101
#define ERR_SYSTEM_CALL   102
#define ERR_OUT_CAPACITY  103

#define ERR_ATTEST_SECURITY_INVALID_ARG                  301
#define ERR_ATTEST_SECURITY_MEM_MALLOC                   302
#define ERR_ATTEST_SECURITY_MEM_MEMSET                   303
#define ERR_ATTEST_SECURITY_MEM_MEMCPY                   304
#define ERR_ATTEST_SECURITY_MEM_SPRINTF                  305
#define ERR_ATTEST_SECURITY_GEN_AESKEY                   306
#define ERR_ATTEST_SECURITY_DECRYPT                      307
#define ERR_ATTEST_SECURITY_ENCRYPT                      308
#define ERR_ATTEST_SECURITY_BASE64_DECODE                309
#define ERR_ATTEST_SECURITY_BASE64_ENCODE                310
#define ERR_ATTEST_SECURITY_GEN_UDID                     311
#define ERR_ATTEST_SECURITY_GEN_TOKEN_ID                 312
#define ERR_ATTEST_SECURITY_GEN_TOKEN_VALUE              313
#define ERR_ATTEST_SECURITY_READ_FROM_OS                 314
#define ERR_ATTEST_SECURITY_WRITE_TO_OS                  315
#define ERR_ATTEST_SECURITY_MD5                          316
#define ERR_ATTEST_SECURITY_GET_PSK                      317
#define ERR_ATTEST_SECURITY_HKDF                         318
#define ERR_ATTEST_SECURITY_GET_TOKEN_VALUE              319
#define ERR_ATTEST_SECURITY_GET_TOKEN                    320

#define ERR_NET_INVALID_ARG                            401
#define ERR_NET_MEM_MALLOC                             402
#define ERR_NET_MEM_MEMSET                             403
#define ERR_NET_MEM_MEMCPY                             404
#define ERR_NET_DRBG_SEED_FAIL                         405
#define ERR_NET_PARSE_CERT_FAIL                        406
#define ERR_NET_CONNECT_FAIL                           407
#define ERR_NET_SET_NON_BLOCK_FAIL                     408
#define ERR_NET_HANDSHAKE_FAIL                         409
#define ERR_NET_SET_SSL_CONFIG_FAIL                    410
#define ERR_NET_SETUP_FAIL                             411
#define ERR_NET_SET_HOSTNAME_FAIL                      412
#define ERR_NET_WRITE_FAIL                             413
#define ERR_NET_READ_FAIL                              414
#define ERR_NET_CERT_VERIFY_FAIL                       415

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif /* __cplusplus */

#endif


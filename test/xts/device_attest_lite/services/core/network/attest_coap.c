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

#include "stdlib.h"
#include "securec.h"
#include "attest_coap_def.h"
#include "attest_utils.h"
#include "attest_utils_log.h"
#include "attest_coap.h"

#define USHORT_MAX 0xFFFF

static int32_t CoapCreateHead(CoapPacket* pkt, uint8_t code, uint32_t transType, CoapRWBuffer* buf)
{
    ATTEST_LOG_DEBUG("[CoapCreateHead] Start");
    if (pkt == NULL || buf == NULL) {
        ATTEST_LOG_ERROR("[CoapCreateHead] Invalid parameter");
        return COAP_ERR_CODE_INVALID_ARGUMENT;
    }
    
    /* set transType */
    pkt->transType = transType;
    if (buf->size < HEADER_LEN) {
        ATTEST_LOG_ERROR("[CoapCreateHead] Header overruns the buffer");
        return COAP_ERR_CODE_PACKET_EXCEED_MAX_PDU;
    }
    pkt->hdr.code = code;

    /* LEN + TKL + CODE is 2 bytes */
    buf->len = HEADER_LEN;
    pkt->len = HEADER_LEN;

    /* rwBuffer 1 is the 8 bit of the code */
    buf->rwBuffer[1] = (char)pkt->hdr.code;
    ATTEST_LOG_DEBUG("[CoapCreateHead] End");
    return COAP_ERR_CODE_NONE;
}

static int32_t CoapCreateToken(uint8_t token[], uint8_t* tkl)
{
    if (token == NULL || tkl == NULL || (*tkl > MAX_TOK_LEN)) {
        ATTEST_LOG_ERROR("[CoapCreateToken] Invalid parameter");
        return COAP_ERR_CODE_INVALID_ARGUMENT;
    }
    if (*tkl == 0) {
        *tkl = (uint8_t)((GetRandomNum() % BITS_PER_BYTE) + 1); // create a random digit, range: 1~8
    }
    for (size_t i = 0; i < *tkl; i++) {
        token[i] = (uint8_t)(GetRandomNum() % (MAX_VALUE_ONE_BYTE + 1)); // create a random value, range: 0~255
    }
    return 0;
}

static int32_t CoapAddToken(CoapPacket* pkt, const CoapBuffer* token, CoapRWBuffer* buf)
{
    ATTEST_LOG_DEBUG("[CoapAddToken] Start");
    if (pkt == NULL || token == NULL || ((token->len != 0) && token->buffer == NULL) ||
        buf == NULL || buf->rwBuffer == NULL || (buf->len != HEADER_LEN)) {
        ATTEST_LOG_ERROR("[CoapAddToken] Invalid parameter");
        return COAP_ERR_CODE_INVALID_ARGUMENT;
    }

    if (token->len > MAX_TOK_LEN) {
        ATTEST_LOG_ERROR("[CoapAddToken] Length symbol exceed the limit");
        return COAP_ERR_CODE_INVALID_TOKEN_LEN;
    }

    if ((buf->len + token->len) > buf->size) {
        ATTEST_LOG_ERROR("[CoapAddToken] Symbol overruns the buffer");
        return COAP_ERR_CODE_PACKET_EXCEED_MAX_PDU;
    }

    pkt->tok.len = token->len;
    pkt->hdr.tkl = pkt->tok.len & 0x0F;
    pkt->tok.buffer = (const uint8_t*)&buf->rwBuffer[buf->len];
    if (token->len) {
        /* update header with tokenLen
        * Token length is the low 4 bit of the third Byte
        */
        buf->rwBuffer[0] = (char)((uint8_t)(buf->rwBuffer[0] & 0xF0) | pkt->hdr.tkl); /* rwBuffer 0 is the first Byte */
        if (memcpy_s(&buf->rwBuffer[buf->len], pkt->hdr.tkl, token->buffer, token->len) != 0) {
            return COAP_ERR_CODE_INVALID_ARGUMENT;
        }
    }
    buf->len += token->len;
    pkt->len = buf->len;
    ATTEST_LOG_DEBUG("[CoapAddToken] End");
    return COAP_ERR_CODE_NONE;
}

static void CoapGetOptionParam(const uint16_t value, uint8_t* param)
{
    if (param == NULL) {
        ATTEST_LOG_ERROR("[CoapGetOptionParam] Invalid parameter");
        return;
    }

    /* Option length
     * 4-bit unsigned integer. A value between 0 and 12 inclusive indicates the length of the message in bytes
     * starting with the first bit of the Options field. Three values are reserved for special constructs:
     *     13: An 8-bit unsigned integer (Extended Length) follows the initial byte and indicates the length
     *         of options/payload minus 13.
     *     14: A 16-bit unsigned integer (Extended Length) in networks byte order follows the initial byte and
     *         indicates the length of options/payload minus 269.
     */
    if (value < COAP_MESSAGE_OFFSET_ONE_BYTE) {
        *param = (uint8_t)(0xFF & value);
    } else {
        *param = (value < COAP_MESSAGE_DIFF_VALUE_TWO_BYTES) ? COAP_MESSAGE_OFFSET_ONE_BYTE :
                 COAP_MESSAGE_OFFSET_TWO_BYTES;
    }
}

int32_t CoapGetExtensionLen(uint8_t param, size_t *length)
{
    if (length == NULL) {
        return COAP_ERR_CODE_INVALID_ARGUMENT;
    }
    if (param == COAP_MESSAGE_OFFSET_ONE_BYTE) {
        *length = COAP_MESSAGE_LENGTH_ONE_BYTE;
    } else if (param == COAP_MESSAGE_OFFSET_TWO_BYTES) {
        *length = COAP_MESSAGE_LENGTH_TWO_BYTES;
    } else if (param == COAP_MESSAGE_OFFSET_FOUR_BYTES) {
        return COAP_ERR_CODE_EXTENDED_LENGTH_INVALID;
    }
    return COAP_ERR_CODE_NONE;
}

static int32_t CoapEncodeExtensionMsg(uint8_t param, size_t contentLen, uint32_t *index, CoapRWBuffer *buf)
{
    if (buf->rwBuffer == NULL) {
        ATTEST_LOG_ERROR("[CoapEncodeExtensionMsg] Invalid parameter");
        return COAP_ERR_CODE_INVALID_ARGUMENT;
    }
    if (param == COAP_MESSAGE_OFFSET_ONE_BYTE && contentLen >= COAP_MESSAGE_DIFF_VALUE_BYTE) {
        if ((buf->len + COAP_MESSAGE_LENGTH_ONE_BYTE) > buf->size) {
            ATTEST_LOG_ERROR("[CoapEncodeExtensionMsg] Extension msg overruns the buffer size");
            return COAP_ERR_CODE_PACKET_EXCEED_MAX_PDU;
        }
        buf->rwBuffer[(*index)++] = (char)(contentLen - COAP_MESSAGE_DIFF_VALUE_BYTE);
    } else if (param == COAP_MESSAGE_OFFSET_TWO_BYTES && contentLen >= COAP_MESSAGE_DIFF_VALUE_TWO_BYTES) {
        if ((buf->len + COAP_MESSAGE_LENGTH_TWO_BYTES) > buf->size) {
            ATTEST_LOG_ERROR("[CoapEncodeExtensionMsg] Extension msg  overruns the buffer size");
            return COAP_ERR_CODE_PACKET_EXCEED_MAX_PDU;
        }
        buf->rwBuffer[(*index)++] = (char)((contentLen - COAP_MESSAGE_DIFF_VALUE_TWO_BYTES) >> BITS_PER_BYTE);
        buf->rwBuffer[(*index)++] = (char)(0xFF & (contentLen - COAP_MESSAGE_DIFF_VALUE_TWO_BYTES));
    } else if (param == COAP_MESSAGE_OFFSET_FOUR_BYTES) {
        return COAP_ERR_CODE_EXTENDED_LENGTH_INVALID;
    }
    return COAP_ERR_CODE_NONE;
}

/* return total option length: (i.e., 1 + (extensions len) + (option value len)) */
static uint32_t CoapGetOptionLength(const CoapOption* opt, uint16_t runningDelta)
{
    if (opt == NULL) {
        ATTEST_LOG_ERROR("[CoapGetOptionLength] Invalid parameter");
        return COAP_ERR_CODE_INVALID_ARGUMENT;
    }
    uint32_t optionLen = 1;
    uint8_t delta = 0;
    uint8_t len = 0;

    CoapGetOptionParam((uint16_t)(opt->num - runningDelta), &delta);
    CoapGetOptionParam((uint16_t)opt->len, &len);

    if (delta == COAP_MESSAGE_OFFSET_ONE_BYTE) {
        optionLen += 1;
    } else if (delta == COAP_MESSAGE_OFFSET_TWO_BYTES) {
        optionLen += COAP_MESSAGE_LENGTH_TWO_BYTES;
    }
    if (len == COAP_MESSAGE_OFFSET_ONE_BYTE) {
        optionLen += 1;
    } else if (len == COAP_MESSAGE_OFFSET_TWO_BYTES) {
        optionLen += COAP_MESSAGE_LENGTH_TWO_BYTES;
    }
    return (uint32_t)(optionLen + opt->len);
}

static int32_t CheckOptionParameter(CoapPacket* pkt, const CoapOption* opt, CoapRWBuffer* buf)
{
    uint16_t runningDelta = 0;
    if (pkt == NULL || buf == NULL || opt == NULL) {
        ATTEST_LOG_ERROR("[CheckOptionParameter] Invalid parameter");
        return COAP_ERR_CODE_INVALID_ARGUMENT;
    }

    if (buf->rwBuffer == NULL || opt->optionBuffer == NULL) {
        ATTEST_LOG_ERROR("[CheckOptionParameter] Invalid parameter");
        return COAP_ERR_CODE_INVALID_ARGUMENT;
    }
    /* Coap header should have been created */
    if (buf->len < HEADER_LEN) {
        ATTEST_LOG_ERROR("[CheckOptionParameter] Invalid parameter");
        return COAP_ERR_CODE_INVALID_ARGUMENT;
    }
    if ((opt->len > USHORT_MAX) || (pkt->optsCnt > COAP_MAX_OPTION)) {
        ATTEST_LOG_ERROR("[CheckOptionParameter] Option length or number of options exceed the limit");
        return COAP_ERR_CODE_BAD_REQUEST;
    }
    /* option received is out-of-order */
    if (pkt->optsCnt) {
        if (pkt->opts[pkt->optsCnt - 1].num > opt->num) {
            ATTEST_LOG_ERROR("[CheckOptionParameter] Option out of order");
            return COAP_ERR_CODE_BAD_REQUEST;
        }
        runningDelta = pkt->opts[pkt->optsCnt - 1].num;
    }
    uint16_t optionLen = (uint16_t)CoapGetOptionLength(opt, runningDelta);
    if ((buf->len + optionLen) > buf->size) {
        ATTEST_LOG_ERROR("[CheckOptionParameter] Option overruns the buffer size");
        return COAP_ERR_CODE_PACKET_EXCEED_MAX_PDU;
    }
    return COAP_ERR_CODE_NONE;
}

static int32_t CoapAddOption(CoapPacket* pkt, const CoapOption* opt, CoapRWBuffer* buf)
{
    ATTEST_LOG_DEBUG("[CoapAddOption] Start");
    uint8_t delta;
    uint8_t len;
    int32_t ret = CheckOptionParameter(pkt, opt, buf);
    if (ret != 0) {
        return ret;
    }
    /* Add Delta & extensions */
    uint16_t prevOptType = (uint16_t)((pkt->optsCnt) ? pkt->opts[pkt->optsCnt - 1].num : 0);
    if (opt->num < prevOptType) {
        return COAP_ERR_CODE_INVALID_ARGUMENT;
    }
    uint16_t optdelta = (uint16_t)(opt->num - prevOptType);
    CoapGetOptionParam(optdelta, &delta);
    CoapGetOptionParam((uint16_t)opt->len, &len);

    if ((buf->len + 1) > buf->size) {
        ATTEST_LOG_ERROR("[CoapAddOption] Option overruns the buffer size");
        return COAP_ERR_CODE_PACKET_EXCEED_MAX_PDU;
    }
    
    buf->rwBuffer[buf->len++] = (char)(0xFF & ((delta << COAP_BITS_OPTION_DELTA) | len));

    if ((ret = CoapEncodeExtensionMsg(delta, optdelta, &buf->len, buf)) != 0) {
        return ret;
    }
    if ((ret = CoapEncodeExtensionMsg(len, opt->len, &buf->len, buf)) != 0) {
        return ret;
    }

    /* Add Option Value */
    if ((opt->len > 0) && ((buf->len + opt->len) < buf->size)) {
        if (memcpy_s(&buf->rwBuffer[buf->len], buf->size - buf->len, opt->optionBuffer, opt->len) != 0) {
            return COAP_ERR_CODE_INVALID_ARGUMENT;
        }
    }
    pkt->opts[pkt->optsCnt].optionBuffer = (const uint8_t*)&buf->rwBuffer[buf->len];
    pkt->opts[pkt->optsCnt].num = opt->num;
    pkt->opts[pkt->optsCnt].len = opt->len;
    buf->len += opt->len;
    pkt->len = buf->len;
    pkt->optsCnt++;
    ATTEST_LOG_DEBUG("[CoapAddOption] End");
    return COAP_ERR_CODE_NONE;
}

static int32_t CoapAddOptions(CoapPacket* pkt, const CoapPacketParam* param, CoapRWBuffer *buf)
{
    if (param->opts == NULL) {
        return COAP_ERR_CODE_INVALID_ARGUMENT;
    }
    int32_t ret = 0;
    if (param->optsCnt > COAP_MAX_OPTION) {
        ATTEST_LOG_ERROR("[CoapAddOptions] Options exceed the limit");
        return COAP_ERR_CODE_SERVER_ERROR;
    }
    for (size_t i = 0; i < param->optsCnt; i++) {
        if ((ret = CoapAddOption(pkt, &param->opts[i], buf)) != 0) {
            ATTEST_LOG_ERROR("[CoapAddOptions] Add coap option failed");
            break;
        } // need to check if content_type is NONE, sending payload is allowed ?
    }
    return ret;
}

static int32_t CoapAddData(CoapPacket* pkt, const CoapBuffer* payload, CoapRWBuffer* buf)
{
    ATTEST_LOG_DEBUG("[CoapAddData] Start");
    if ((pkt == NULL) || (payload == NULL) || (buf == NULL)) {
        ATTEST_LOG_ERROR("[CoapAddData] Invalid parameter");
        return COAP_ERR_CODE_INVALID_ARGUMENT;
    }

    if ((buf->rwBuffer == NULL) || ((payload->len != 0) && (payload->buffer == NULL))) {
        ATTEST_LOG_ERROR("[CoapAddData] Invalid parameter");
        return COAP_ERR_CODE_INVALID_ARGUMENT;
    }

    /* Coap header should have been created */
    if (buf->len < HEADER_LEN) {
        ATTEST_LOG_ERROR("[CoapAddData] Invalid coap head");
        return COAP_ERR_CODE_INVALID_ARGUMENT;
    }

    if ((payload->len > 0xFFFF) || ((buf->len + payload->len + 1) > buf->size)) {
        ATTEST_LOG_ERROR("[CoapAddData] Payload overruns the buffer");
        return COAP_ERR_CODE_PACKET_EXCEED_MAX_PDU;
    }
    
    pkt->payload.len = payload->len;
    if (payload->len) {
        pkt->payload.len = payload->len;
        buf->rwBuffer[(buf->len)++] = 0xFF; /* adding Marker */
        pkt->payload.buffer = (const uint8_t*)&buf->rwBuffer[buf->len];
        if (memcpy_s(&buf->rwBuffer[buf->len], MAX_MESSAGE_LEN, payload->buffer, payload->len) != 0) {
            ATTEST_LOG_ERROR("[CoapAddData] Coap payload failed");
            return COAP_ERR_CODE_INVALID_ARGUMENT;
        }
    }
    buf->len += payload->len;
    pkt->len = buf->len;
    ATTEST_LOG_DEBUG("[CoapAddData] End");
    return COAP_ERR_CODE_NONE;
}

static int32_t CoapCopyMessage(CoapPacket* pkt, CoapRWBuffer *buf, CoapRWBuffer *outBuf)
{
    ATTEST_LOG_DEBUG("[CoapCopyMessage] Start");
    if (pkt == NULL || buf == NULL || outBuf->rwBuffer == NULL) {
        ATTEST_LOG_ERROR("[CoapCopyMessage] Invalid parameter");
        return COAP_ERR_CODE_INVALID_ARGUMENT;
    }
    if (pkt->len < LENTKL_LEN) {
        return COAP_ERR_CODE_INVALID_ARGUMENT;
    }
    if (pkt->tok.len + HEADER_LEN > buf->len) {
        return COAP_ERR_CODE_INVALID_ARGUMENT;
    }
    uint8_t len = 0;
    uint32_t index = 0;
    size_t msgLen = 0;
    int32_t ret = 0;
    size_t contentLen = buf->len - pkt->tok.len - HEADER_LEN;
    CoapGetOptionParam(contentLen, &len);
    outBuf->rwBuffer[index++] = (char)((uint8_t)(buf->rwBuffer[0] & 0x0F) | ((len & 0x0F) << COAP_BITS_HEADER_LEN));

    if ((ret = CoapGetExtensionLen(len, &msgLen)) != 0) {
        return ret;
    }
    if ((ret = CoapEncodeExtensionMsg(len, contentLen, &index, outBuf)) != 0) {
        return ret;
    }

    ret = memcpy_s(outBuf->rwBuffer + index, pkt->len - LENTKL_LEN,
        buf->rwBuffer + LENTKL_LEN, pkt->len - LENTKL_LEN);
    if (ret != ATTEST_OK) {
        ATTEST_LOG_ERROR("[CoapCopyMessage] Invalid parameter");
        return COAP_ERR_CODE_INVALID_ARGUMENT;
    }
    pkt->len = buf->len + msgLen;
    pkt->hdr.len += len;
    outBuf->len = pkt->len;
    ATTEST_LOG_DEBUG("[CoapCopyMessage] End");
    return COAP_ERR_CODE_NONE;
}

static int32_t CoapEncode(CoapPacket* pkt, const CoapPacketParam* param, const CoapBuffer* token,
    const CoapBuffer* payload, CoapRWBuffer* outBuf)
{
    ATTEST_LOG_DEBUG("[CoapEncode] Start");
    if (pkt == NULL || param == NULL || payload == NULL || outBuf == NULL) {
        ATTEST_LOG_ERROR("[CoapEncode] Invalid parameter");
        return COAP_ERR_CODE_INVALID_ARGUMENT;
    }
    int32_t ret;
    CoapRWBuffer buf;
    (void)memset_s(&buf, sizeof(CoapRWBuffer), 0, sizeof(CoapRWBuffer));
    buf.rwBuffer = (char*)ATTEST_MEM_MALLOC(sizeof(char) * MAX_MESSAGE_LEN);
    if (buf.rwBuffer == NULL) {
        ATTEST_LOG_ERROR("[CoapEncode] Malloc memory failed");
        return ATTEST_ERR;
    }
    buf.size = MAX_MESSAGE_LEN;
    do {
        if ((ret = CoapCreateHead(pkt, param->code, param->transType, &buf)) != 0) {
            ATTEST_LOG_ERROR("[CoapEncode] Create coap header failed");
            break;
        }
        /* Empty Message Validation */
        if ((param->code == 0) && ((token != NULL) || (param->opts != NULL) || (payload != NULL))) {
            ATTEST_LOG_ERROR("[CoapEncode] Invalid empty message");
            ret = COAP_ERR_CODE_INVALID_EMPTY_MESSAGE;
            break;
        }
        if (token != NULL) {
            if ((ret = CoapAddToken(pkt, token, &buf)) != 0) {
                ATTEST_LOG_ERROR("[CoapEncode] Add coap token failed");
                break;
            }
        }
        if ((ret = CoapAddOptions(pkt, param, &buf)) != 0) {
            ATTEST_LOG_ERROR("[CoapEncode] Add options failed");
            break;
        }
        if ((ret = CoapAddData(pkt, payload, &buf)) != 0) {
            ATTEST_LOG_ERROR("[CoapEncode] Add coap data failed");
            break;
        }
        if ((ret = CoapCopyMessage(pkt, &buf, outBuf)) != 0) { // copy buf to outBuff
            ATTEST_LOG_ERROR("[CoapEncode] Copy message failed");
            break;
        }
    } while (0);
    ATTEST_MEM_FREE(buf.rwBuffer);
    if (ret != 0) {
        return ret;
    }
    ATTEST_LOG_DEBUG("[CoapEncode] End");
    return COAP_ERR_CODE_NONE;
}

int32_t CoapBuildMessage(CoapPacket* coapPacket, CoapPacketParam* coapPacketParam, CoapBuffer* payload,
                         char* buff, uint32_t* len)
{
    if (coapPacket == NULL || coapPacketParam == NULL || buff == NULL || len == NULL || payload == NULL) {
        ATTEST_LOG_ERROR("[CoapBuildMessage] Invalid parameter");
        return COAP_ERR_CODE_INVALID_ARGUMENT;
    }
    if (payload->buffer == NULL || payload->len >= *len) {
        ATTEST_LOG_ERROR("[CoapBuildMessage] Payload is too big");
        return COAP_ERR_CODE_INVALID_ARGUMENT;
    }
    CoapRWBuffer outputBuf;
    CoapBuffer inputPayload;
    CoapBuffer inputToken;
    uint8_t tkl = PKT_TOKEN_LEN;
    uint8_t token[PKT_TOKEN_LEN] = {0};

    (void)memset_s(&outputBuf, sizeof(CoapRWBuffer), 0, sizeof(CoapRWBuffer));
    (void)memset_s(&inputPayload, sizeof(CoapBuffer), 0, sizeof(CoapBuffer));
    (void)memset_s(&inputToken, sizeof(CoapBuffer), 0, sizeof(CoapBuffer));

    outputBuf.rwBuffer = buff;
    outputBuf.size = *len;
    inputPayload.buffer = payload->buffer;
    inputPayload.len = payload->len;

    if (payload->len >= *len) {
        ATTEST_LOG_ERROR("[CoapBuildMessage] Payload is too big");
        return ATTEST_ERR;
    }

    if (CoapCreateToken(token, &tkl) != 0) {
        ATTEST_LOG_ERROR("[CoapBuildMessage] Create token failed");
        return ATTEST_ERR;
    }

    inputToken.buffer = token;
    inputToken.len = tkl;

    int32_t ret;
    if ((ret = CoapEncode(coapPacket, coapPacketParam, &inputToken, &inputPayload, &outputBuf)) != 0) {
        ATTEST_LOG_ERROR("[CoapBuildMessage] Encode coap message failed");
        return ret;
    }

    *len = outputBuf.len;
    (void)memset_s(token, sizeof(token), 0, sizeof(token));
    ATTEST_LOG_DEBUG("[CoapBuildMessage] End");
    return ret;
}

static int32_t CoapParseOptionExtension(uint16_t* value, const uint8_t** p, uint8_t* hlen, size_t bufLen)
{
    if (value == NULL || *p == NULL || hlen == NULL) {
        ATTEST_LOG_ERROR("[CoapParseOptionExtension] Invalid parameter");
        return COAP_ERR_CODE_INVALID_ARGUMENT;
    }
    if (*value == COAP_MESSAGE_OFFSET_ONE_BYTE) { /* The delta is 13, the length is 1 byte */
        (*hlen)++;
        if (bufLen < *hlen) {
            ATTEST_LOG_ERROR("[CoapParseOptionExtension] Option extended delta or length overruns the buffer");
            return COAP_ERR_CODE_OPTION_TOO_SHORT_FOR_HEADER;
        }
        *value = (uint16_t)((*p)[1] + COAP_MESSAGE_OFFSET_ONE_BYTE);
        (*p)++;
        return COAP_ERR_CODE_NONE;
    }

    if (*value == COAP_MESSAGE_OFFSET_TWO_BYTES) { /* The delta is 14, the length is 2 bytes */
        (*hlen) += COAP_MESSAGE_LENGTH_TWO_BYTES;
        if (bufLen < *hlen) {
            ATTEST_LOG_ERROR("[CoapParseOptionExtension] Option extended delta or length overruns the buffer");
            return COAP_ERR_CODE_OPTION_TOO_SHORT_FOR_HEADER;
        }
        if (((uint32_t)((*p)[1] << BITS_PER_BYTE) | (*p)[COAP_OPTION_EXTENSION_LEN]) >
            (MAX_VALUE_TWO_BYTES - COAP_MESSAGE_DIFF_VALUE_TWO_BYTES)) {
            ATTEST_LOG_ERROR("[CoapParseOptionExtension] Option extend delta or length value is out of range");
            return COAP_ERR_CODE_BAD_REQUEST;
        }
        *value = (uint16_t)((((*p)[1] << BITS_PER_BYTE) | (*p)[COAP_OPTION_EXTENSION_LEN]) +
                 COAP_MESSAGE_DIFF_VALUE_TWO_BYTES);
        (*p) += COAP_MESSAGE_LENGTH_TWO_BYTES;
        return COAP_ERR_CODE_NONE;
    }
    
    if (*value == COAP_MESSAGE_OFFSET_FOUR_BYTES) {
        ATTEST_LOG_ERROR("[CoapParseOptionExtension] Option delta or length is invalid");
        return COAP_ERR_CODE_OPTION_DELTA_INVALID;
    }
    return COAP_ERR_CODE_NONE;
}

static int32_t CoapParseOption(CoapOption* option, uint16_t* runningDelta, const uint8_t** buf, size_t bufLen)
{
    if (option == NULL || runningDelta == NULL || *buf == NULL) {
        ATTEST_LOG_ERROR("[CoapParseOption] Invalid parameter");
        return COAP_ERR_CODE_INVALID_ARGUMENT;
    }
    uint8_t headLen = 1;
    uint16_t len;
    uint16_t delta;
    const uint8_t *p = *buf;

    if (bufLen < headLen) {
        ATTEST_LOG_ERROR("[CoapParseOption] Option header overruns the buffer");
        return COAP_ERR_CODE_OPTION_TOO_SHORT_FOR_HEADER;
    }
    delta = (p[0] & 0xF0) >> COAP_BITS_OPTION_DELTA;
    len = p[0] & 0x0F;
    int32_t ret;
    if ((ret = CoapParseOptionExtension(&delta, &p, &headLen, bufLen)) != 0) {
        ATTEST_LOG_ERROR("[CoapParseOption] Invalid option delta");
        return ret;
    }
    if ((ret = CoapParseOptionExtension(&len, &p, &headLen, bufLen)) != 0) {
        ATTEST_LOG_ERROR("[CoapParseOption] Invalid option length");
        return ret;
    }
    if ((p + 1 + len) > (*buf + bufLen)) {
        ATTEST_LOG_ERROR("[CoapParseOption] Opton too big than buffer");
        return COAP_ERR_CODE_OPTION_TOO_BIG;
    }

    option->num = (uint16_t)(delta + *runningDelta);
    option->optionBuffer = p + 1;
    option->len = len;
    // advance buf
    *buf = p + 1 + len;
    (*runningDelta) += delta;
    return COAP_ERR_CODE_NONE;
}

static int32_t CoapParseOptionAndPayload(CoapOption* options, uint8_t* numOptions, CoapBuffer* payload,
    const CoapHead* hdr, CoapBuffer *buffer)
{
    if (options == NULL || numOptions == NULL || payload == NULL || hdr == NULL || buffer == NULL) {
        ATTEST_LOG_ERROR("[CoapParseOptionAndPayload] Invalid parameter");
        return COAP_ERR_CODE_INVALID_ARGUMENT;
    }
    uint8_t optionIndex = 0;
    uint16_t delta = 0;
    const uint8_t* p = buffer->buffer + CODE_LEN + hdr->tkl;
    const uint8_t* end = buffer->buffer + buffer->len;

    if (p > end) {
        ATTEST_LOG_ERROR("[CoapParseOptionAndPayload] Option or payload overruns packet size");
        return COAP_ERR_CODE_OPTION_OVERRUNS_PACKET;
    }

    while ((p < end) && (*p != 0xFF) && (optionIndex < COAP_MAX_OPTION)) {
        int32_t ret = CoapParseOption(&options[optionIndex], &delta, &p, (size_t)(long)(end-p));
        if (ret != 0) {
            return ret;
        }
        optionIndex++;
    }
    
    if ((p < end) && (*p != 0xFF) && (optionIndex == COAP_MAX_OPTION)) {
        ATTEST_LOG_ERROR("[CoapParseOptionAndPayload] Option greater than maximum limit");
        return COAP_ERR_CODE_SERVER_ERROR;
    }
    *numOptions = optionIndex;
    if (*p == 0xFF) {
        if (p + 1 < end) {
            payload->buffer = p + 1;
            payload->len = (size_t)(long)(end - (p + 1));
        } else {
            ATTEST_LOG_ERROR("[CoapParseOptionAndPayload] Packet have payload maker but no payload");
            return COAP_ERR_CODE_INVALID_PACKET;
        }
    } else {
        payload->buffer = NULL;
        payload->len = 0;
    }

    return COAP_ERR_CODE_NONE;
}

int32_t CoapDecode(CoapPacket* pkt, const uint8_t* buf, size_t bufLen)
{
    ATTEST_LOG_DEBUG("[CoapDecode] Start");
    if (pkt == NULL || buf == NULL || bufLen > MAX_MESSAGE_LEN) {
        ATTEST_LOG_ERROR("[CoapDecode] Invalid parameter");
        return COAP_ERR_CODE_INVALID_ARGUMENT;
    }
    if (bufLen < HEADER_LEN) {
        ATTEST_LOG_ERROR("[CoapDecode] Buffer length is smaller than coap header length");
        return COAP_ERR_CODE_HEADER_TOO_SHORT;
    }
    pkt->hdr.code = buf[0]; /* The first Byte is code */

    if (pkt->hdr.tkl > MAX_TOK_LEN) {
        ATTEST_LOG_ERROR("[CoapDecode] Length of symbol exceed the limit");
        return COAP_ERR_CODE_INVALID_TOKEN_LEN;
    }
    if (bufLen > HEADER_LEN && pkt->hdr.code == 0) {
        return COAP_ERR_CODE_INVALID_EMPTY_MESSAGE;
    }

    if (pkt->hdr.tkl == 0) {
        pkt->tok.buffer = NULL;
        pkt->tok.len = 0;
    } else if ((size_t)(pkt->hdr.tkl + HEADER_LEN) > bufLen) {
        return COAP_ERR_CODE_TOKEN_TOO_SHORT;
    } else {
        pkt->tok.buffer = &buf[1];
        pkt->tok.len = pkt->hdr.tkl;
    }
    CoapBuffer buffer;
    (void)memset_s(&buffer, sizeof(CoapBuffer), 0, sizeof(CoapBuffer));
    buffer.buffer = buf;
    buffer.len = bufLen;
    
    int32_t ret = CoapParseOptionAndPayload(pkt->opts, &(pkt->optsCnt), &(pkt->payload), &pkt->hdr, &buffer);
    if (ret != 0) {
        ATTEST_LOG_ERROR("[CoapDecode] Parse option or payload failed");
        return ret;
    }
    ATTEST_LOG_DEBUG("[CoapDecode] End");
    return COAP_ERR_CODE_NONE;
}

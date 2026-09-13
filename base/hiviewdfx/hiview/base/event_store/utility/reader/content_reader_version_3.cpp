/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
 
#include "content_reader_version_3.h"

#include "base_def.h"
#include "content_reader_factory.h"
#include "base/raw_data_base_def.h"
#include "hiview_logger.h"
#include "securec.h"

namespace OHOS {
namespace HiviewDFX {
DEFINE_LOG_TAG("HiView-ContentReaderVersion3");
REGISTER_CONTENT_READER(EventStore::EVENT_DATA_FORMATE_VERSION::VERSION3, ContentReaderVersion3);
int ContentReaderVersion3::ReadDocDetails(std::ifstream& docStream, EventStore::DocHeader& header,
    uint64_t& docHeaderSize, HeadExtraInfo& headExtra)
{
    if (!docStream.is_open()) {
        return DOC_STORE_ERROR_IO;
    }
    docStream.seekg(0, std::ios::beg);
    docStream.read(reinterpret_cast<char*>(&header), sizeof(EventStore::DocHeader));
    if (!GetDataString(docStream, headExtra.sysVersion)) {
        HIVIEW_LOGE("system version invalid.");
        return DOC_STORE_ERROR_INVALID;
    }
    HIVIEW_LOGD("version read from db:%{public}s", headExtra.sysVersion.c_str());
    docHeaderSize = header.blockSize + sizeof(header.magicNum);
    return DOC_STORE_SUCCESS;
}

bool ContentReaderVersion3::IsValidMagicNum(const uint64_t magicNum)
{
    return magicNum == MAGIC_NUM_VERSION3;
}

int ContentReaderVersion3::GetContentHeader(uint8_t* content, EventStore::ContentHeader& header)
{
    if (content == nullptr) {
        return DOC_STORE_ERROR_NULL;
    }

    header = *(reinterpret_cast<EventStore::ContentHeader*>(content + HIVIEW_BLOCK_SIZE));
    return DOC_STORE_SUCCESS;
}

size_t ContentReaderVersion3::GetContentHeaderSize()
{
    return sizeof(EventStore::ContentHeader);
}
} // HiviewDFX
} // OHOS
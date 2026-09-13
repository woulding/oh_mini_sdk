# 二维码生成器

## 简介

二维码生成器为OpenHarmony系统提供二维码生成能力。二维码是一种经得起市场考验的被广泛使用的编码技术，它具有信息容量大、可靠性高、保密防伪性强的优点。二维码生成器遵循[**ISO/IEC 18004:2015标准**](https://www.iso.org/obp/ui/es/#iso:std:iso-iec:18004:ed-3:v1:en)实现，支持Version 1到Version 40的二维码生成，并提供了灵活的错误纠正等级选择。

-   **编码模式支持：** 二维码生成器支持数字模式（Numeric）、字母数字模式（Alphanumeric）和字节模式（Byte），能够满足不同场景下的数据编码需求。
-   **错误纠正能力：** 根据纠错等级的不同，可以在二维码25%到30%的码字被遮挡的情况下成功解码，保证了二维码在部分损坏时仍能被正常扫描。
-   **内存管理：** 提供自定义内存分配钩子，允许开发者注入自己的内存管理函数，便于在嵌入式设备中进行内存优化。
-   **形态支持：** 支持standard、mini、small三种形态。其中standard形态使用场景为QRCode控件，mini形态使用场景为UIQrcode控件，small形态暂无控件使用。

## 系统架构图

**图 1**  二维码生成器架构图

![](figures/zh-cn_qrcode_generator.png "二维码生成器架构图")

-   **对外接口层：** 提供二维码生成的内部API接口，包括图像编码、内存管理和返回给定坐标的颜色（浅色为false、深色为true）。

-   **数据编码：** 对输入字符码流信息进行解析编码，包括字符串解析、版本选择、数据分段、组装编码、RS纠错编码、掩码选择模块。


## 目录

```
/commonlibrary/qrcode_generator
├── interfaces/kits/qrcode_generator.h    # 二维码生成器对外接口
├── interfaces/innerkits/                 # 二维码生成器内部头文件
│       ├── qrcode_inner.h                # 内部数据结构定义
│       ├── qrcode_version.h              # 版本选择
│       ├── qrcode_stream.h               # 组装编码
│       ├── qrcode_rscode.h               # RS纠错编码
│       ├── qrcode_mask.h                 # 掩码选择
│       ├── qrcode_item.h                 # 数据分段
│       └── qrcode_list.h                 # 链表操作
├── frameworks/                           # 二维码核心实现代码
│       ├── qrcode_generator.cpp          # 二维码生成器主入口
│       ├── qrcode_version.cpp            # 版本选择
│       ├── qrcode_string.cpp             # 字符串解析
│       ├── qrcode_stream.cpp             # 组装编码
│       ├── qrcode_rscode.cpp             # RS纠错编码
│       ├── qrcode_mask.cpp               # 掩码选择
│       └── qrcode_item.cpp               # 数据分段
├── test/unittest/common/                 # 单元测试代码
│       ├── qrcode_generator_test.cpp
│       ├── qrcode_version_test.cpp
│       ├── qrcode_stream_test.cpp
│       ├── qrcode_item_test.cpp
│       ├── qrcode_mask_test.cpp
│       └── qrcode_rscode_test.cpp
└── patches/
    └── patches.json
```

## 约束

- 输入文本长度受版本和纠错等级限制，实际可用长度由运行时计算得出。例如：在H级别纠错下，输入字符码不得超过Version 40的最大数据容量（约1852字节），超出此长度将无法生成二维码。
- 输入字符码流后，二维码生成器会自动选择最小能包含数据的Version进行编码，Version为40时最大尺寸为177×177像素（px）。
- 仅支持正方形二维码输出，不支持其他形状（如矩形、圆形等）。
- 使用字节模式时，默认使用UTF-8编码。

## 编译构建

根据不同的目标平台，使用以下命令进行编译：

**编译32位ARM系统qrcode部件**

```bash
./build.sh --product-name {product_name} --ccache --build-target qrcode_generator
```

> **说明：**
> `{product_name}` 为当前支持的平台名称，例如 `rk3568`。

## 说明

二维码生成器提供公共接口，供系统组件或应用调用以生成二维码。

### 数据结构说明

#### QrcodeImage

`QrcodeImage` 是二维码生成函数的返回结构，定义如下：

```c
typedef struct {
    int32_t version;
    uint32_t width;
    uint8_t *data;
} QrcodeImage;
```

| 字段 | 类型 | 说明 |
|------|------|------|
| version | int32_t | 实际使用的二维码版本，范围1~40（根据输入数据自动选择） |
| width | uint32_t | 生成的二维码图像宽度，单位为像素（px） |
| data | uint8_t* | 图像像素数据缓冲区的指针 |

**注意事项：**
- `data` 缓冲区大小等于 `width * width` 字节
- 每个字节代表一个像素值（0表示白色，非零表示黑色）
- `data` 分配的内存必须通过调用 `QrcodeImageFree()` 释放

### 接口说明

<table><thead align="left"><tr id="row1"><th class="cellrowborder" valign="top" width="50.22%" id="mcps1.1.3.1.1"><p id="p1"><a name="p1"></a><a name="p1"></a>接口名</p>
</th>
<th class="cellrowborder" valign="top" width="49.78%" id="mcps1.1.3.1.2"><p id="p2"><a name="p2"></a><a name="p2"></a>说明</p>
</th>
</tr>
</thead>
<tbody><tr id="row2"><td class="cellrowborder" valign="top" width="50.22%" headers="mcps1.1.3.1.1 "><p id="p3"><a name="p3"></a><a name="p3"></a>QrcodeImage *QrcodeImageEncodeString(const char *text, QRCODE_ECC qrEcc)</p>
</td>
<td class="cellrowborder" valign="top" width="49.78%" headers="mcps1.1.3.1.2 "><p id="p4"><a name="p4"></a><a name="p4"></a>对字符串码流进行编码，输出二维码数据</p>
</td>
</tr>
<tr id="row3"><td class="cellrowborder" valign="top" width="50.22%" headers="mcps1.1.3.1.1 "><p id="p5"><a name="p5"></a><a name="p5"></a>bool QrcodeGetModule(const QrcodeImage *qrCode, int32_t xPos, int32_t yPos)</p>
</td>
<td class="cellrowborder" valign="top" width="49.78%" headers="mcps1.1.3.1.2 "><p id="p6"><a name="p6"></a><a name="p6"></a>返回给定坐标处模块（像素）的颜色，浅色为 false，深色为 true。左上角坐标为 (x=0, y=0)。如果给定坐标超出范围，则返回 false（浅色）</p>
</td>
</tr>
<tr id="row4"><td class="cellrowborder" valign="top" width="50.22%" headers="mcps1.1.3.1.1 "><p id="p7"><a name="p7"></a><a name="p7"></a>void QrcodeImageFree(QrcodeImage *qrImage)</p>
</td>
<td class="cellrowborder" valign="top" width="49.78%" headers="mcps1.1.3.1.2 "><p id="p8"><a name="p8"></a><a name="p8"></a>释放二维码数据内存</p>
</td>
</tr>
<tr id="row5"><td class="cellrowborder" valign="top" width="50.22%" headers="mcps1.1.3.1.1 "><p id="p9"><a name="p9"></a><a name="p9"></a>void QrcodeMemInitHooks(const QrcodeMemHooks *hooks)</p>
</td>
<td class="cellrowborder" valign="top" width="49.78%" headers="mcps1.1.3.1.2 "><p id="p10"><a name="p10"></a><a name="p10"></a>初始化自定义内存分配钩子</p>
</td>
</tr>
</tbody>
</table>

#### 纠错等级说明

<table><thead align="left"><tr id="row5555555555555"><th class="cellrowborder" valign="top" width="20%" id="mcps1.1.3.2.1"><p id="p1111111111112"><a name="p1111111111112"></a><a name="p1111111111112"></a>等级</p>
</th>
<th class="cellrowborder" valign="top" width="20%" id="mcps1.1.3.2.2"><p id="p2222222222223"><a name="p2222222222223"></a><a name="p2222222222223"></a>枚举值</p>
</th>
<th class="cellrowborder" valign="top" width="20%" id="mcps1.1.3.2.3"><p id="p3333333333334"><a name="p3333333333334"></a><a name="p3333333333334"></a>纠错能力</p>
</th>
<th class="cellrowborder" valign="top" width="40%" id="mcps1.1.3.2.4"><p id="p4444444444445"><a name="p4444444444445"></a><a name="p4444444444445"></a>适用场景</p>
</th>
</tr>
</thead>
<tbody><tr id="row6666666666666"><td class="cellrowborder" valign="top" width="20%" headers="mcps1.1.3.2.1 "><p id="p7777777777778"><a name="p7777777777778"></a><a name="p7777777777778"></a>M（中等）</p>
</td>
<td class="cellrowborder" valign="top" width="20%" headers="mcps1.1.3.2.2 "><p id="p8888888888889"><a name="p8888888888889"></a><a name="p8888888888889"></a>QRCODE_ECC_MEDIUM</p>
</td>
<td class="cellrowborder" valign="top" width="20%" headers="mcps1.1.3.2.3 "><p id="p9999999999999"><a name="p9999999999999"></a><a name="p9999999999999"></a>约15%</p>
</td>
<td class="cellrowborder" valign="top" width="40%" headers="mcps1.1.3.2.4 "><p id="p1010101010101"><a name="p1010101010101"></a><a name="p1010101010101"></a>通用场景，兼顾容量与纠错</p>
</td>
</tr>
<tr id="row7777777777777"><td class="cellrowborder" valign="top" width="20%" headers="mcps1.1.3.2.1 "><p id="p1111111111113"><a name="p1111111111113"></a><a name="p1111111111113"></a>H（高级）</p>
</td>
<td class="cellrowborder" valign="top" width="20%" headers="mcps1.1.3.2.2 "><p id="p2222222222224"><a name="p2222222222224"></a><a name="p2222222222224"></a>QRCODE_ECC_HIGH</p>
</td>
<td class="cellrowborder" valign="top" width="20%" headers="mcps1.1.3.2.3 "><p id="p3333333333335"><a name="p3333333333335"></a><a name="p3333333333335"></a>约30%</p>
</td>
<td class="cellrowborder" valign="top" width="40%" headers="mcps1.1.3.2.4 "><p id="p4444444444446"><a name="p4444444444446"></a><a name="p4444444444446"></a>高可靠性需求场景（工业、医疗等）</p>
</td>
</tr>
</tbody>
</table>

**说明：**
- 纠错等级越高，可恢复的损坏比例越大，但可用数据容量相应减少。
- 纠错算法采用 Reed-Solomon（RS）码实现。


### 使用说明

调用二维码生成器接口，将文本编码为二维码图像：

```
QrcodeImage *qrImage = QrcodeImageEncodeString("https://openharmony.cn", QRCODE_ECC_MEDIUM);
if (qrImage != NULL) {
    // 使用 qrImage->data 生成二维码图像
    // qrImage->width 为图像宽度
    // qrImage->version 为实际使用的二维码版本
    // qrImage数据使用完成后需要主动释放
    QrcodeImageFree(qrImage);
}
```

如需自定义内存分配：

```
QrcodeMemHooks hooks = {
    .mallocFunc = myMalloc,
    .freeFunc = myFree
};
QrcodeMemInitHooks(&hooks);
```

## 相关仓

- [third_party_bounds_checking_function](https://gitcode.com/openharmony/third_party_bounds_checking_function)
- [arkui_ui_lite](https://gitcode.com/openharmony/arkui_ui_lite)
- [arkui_ace_engine](https://gitcode.com/openharmony/arkui_ace_engine)
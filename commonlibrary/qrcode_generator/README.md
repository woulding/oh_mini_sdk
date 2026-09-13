# QR Code Generator

## Overview

The QR code generator provides the QR code generation capability for OpenHarmony. QR code is a widely used encoding technology that has proven its worth in the market. It features large information capacity, high reliability, and strong confidentiality and anti-counterfeiting capabilities. The QR code generator is implemented in compliance with the [ISO/IEC 18004:2015 criterion](https://www.iso.org/obp/ui/es/#iso:std:iso-iec:18004:ed-3:v1:en), and supports the generation of QR codes from version 1 to version 40. It also provides flexible error correction levels.

-   **Encoding mode**: The QR code generator supports the numeric, alphanumeric, and byte modes, enabling data encoding in different scenarios.
-   **Error correction**: Depending on the error correction level, the QR code can be successfully decoded even if 25% to 30% of the codewords are blocked. This ensures that the QR code can still be scanned even if it is partially damaged.
-   **Memory management**: The generator provides a custom memory allocation hook, allowing you to inject your own memory management functions to optimize memory usage on embedded devices.
-   **Form support**: The standard, mini, and small forms are supported. The **QRCode** component is used in the standard form, the **UIQrcode** component is used in the mini form, and no component is available in the small form.

## System Architecture

**Figure 1** Architecture of the QR code generator

![](figures/qrcode_generator.png "Architecture of the QR code generator")

-   **External API layer**: Provides internal APIs for generating QR codes, including image encoding and memory management and returns the color of the module (pixel) at the given coordinates.

-   **Data encoding**: Parses and encodes the input character code stream information, including string parsing, version selection, data segmentation, assembling and encoding, RS coding, and mask selection.


## Directory

```
/foundation/arkui/qrcode
├── interfaces/kits/qrcode_generator.h    # External API of the QR code generator
├── interfaces/innerkits/                 # Internal header file of the QR code generator
│       ├── qrcode_inner.h                # Internal data structure definition
│       ├── qrcode_version.h              # Version selection
│       ├── qrcode_stream.h               # Assembly coding
│       ├── qrcode_rscode.h               # RS coding
│       ├── qrcode_mask.h                 # Mask selection
│       ├── qrcode_item.h                 # Data segmentation
│       └── qrcode_list.h                 # Linked list operation
├── frameworks/                           # Core implementation code of the QR code
│       ├── qrcode_generator.cpp          # Main entry of the QR code generator
│       ├── qrcode_version.cpp            # Version selection
│       ├── qrcode_string.cpp             # String parsing
│       ├── qrcode_stream.cpp             # Assembly coding
│       ├── qrcode_rscode.cpp             # RS coding
│       ├── qrcode_mask.cpp               # Mask selection
│       └── qrcode_item.cpp               # Data segmentation
├── test/unittest/common/                 # Unit test code
│       ├── qrcode_generator_test.cpp
│       ├── qrcode_version_test.cpp
│       ├── qrcode_stream_test.cpp
│       ├── qrcode_item_test.cpp
│       ├── qrcode_mask_test.cpp
│       └── qrcode_rscode_test.cpp
└── patches/
    └── patches.json
```

## Constraints

- The length of the input text is restricted by the version and error correction level. The actual available length is calculated at runtime. For example, with H-level error correction, the input character code cannot exceed the maximum data capacity of version 40 (about 1852 bytes). If the length exceeds this limit, the QR code cannot be generated.
- After the character code stream is entered, the QR code generator automatically selects the minimum version that can contain the data for encoding. When the version is 40, the maximum dimensions are 177 × 177 pixels.
- Only square QR codes are supported. Other shapes (such as rectangle and circle) are not supported.
- When the byte mode is used, UTF-8 encoding is used by default.

## Compiling and Building

Run the following commands to perform compilation based on the target platform:

**Compile the QR code component for the 32-bit ARM system**

```bash
./build.sh --product-name {product_name} --ccache --build-target qrcode_generator
```

> **NOTE**
> **{product_name}** indicates the name of the supported platform, for example, **rk3568**. 

## Description

The QR code generator provides public APIs for system components or applications to generate QR codes.

### Data Structure Description

#### QrcodeImage

**QrcodeImage** is the return structure of the QR code generation function. The definition is as follows:

```c
typedef struct {
    int32_t version;
    uint32_t width;
    uint8_t *data;
} QrcodeImage;
```

| Field| Type| Description|
|------|------|------|
| version | int32_t | QR code version for actual use. The value ranges from 1 to 40. (The version is automatically selected based on the input data.)|
| width | uint32_t | Width of the generated QR code image, in pixels.|
| data | uint8_t* | Pointer to the data buffer area of image pixels.|

**NOTE**
- The size of the **data** buffer is equal to **width** × **width** bytes.
- Each byte represents a pixel value. The value **0** indicates white, and a non-zero value indicates black.
- The memory allocated to **data** must be released by calling **QrcodeImageFree()**.

### API Description

<table><thead align="left"><tr id="row1"><th class="cellrowborder" valign="top" width="50.22%" id="mcps1.1.3.1.1"><p id="p1"><a name="p1"></a><a name="p1"></a>Name</p>
</th>
<th class="cellrowborder" valign="top" width="49.78%" id="mcps1.1.3.1.2"><p id="p2"><a name="p2"></a><a name="p2"></a>Description</p>
</th>
</tr>
</thead>
<tbody><tr id="row2"><td class="cellrowborder" valign="top" width="50.22%" headers="mcps1.1.3.1.1 "><p id="p3"><a name="p3"></a><a name="p3"></a>QrcodeImage *QrcodeImageEncodeString(const char *text, QRCODE_ECC qrEcc)</p>
</td>
<td class="cellrowborder" valign="top" width="49.78%" headers="mcps1.1.3.1.2 "><p id="p4"><a name="p4"></a><a name="p4"></a>Encodes the string code stream and outputs the QR code data.</p>
</td>
</tr>
<tr id="row3"><td class="cellrowborder" valign="top" width="50.22%" headers="mcps1.1.3.1.1 "><p id="p5"><a name="p5"></a><a name="p5"></a>bool QrcodeGetModule(const QrcodeImage *qrCode, int32_t xPos, int32_t yPos)</p>
</td>
<td class="cellrowborder" valign="top" width="49.78%" headers="mcps1.1.3.1.2 "><p id="p6"><a name="p6"></a><a name="p6"></a>Returns the color of the module (pixel) at the given coordinates, which is false, for light or true for dark. The top left corner has the coordinates (x=0, y=0).If the given coordinates are out of bounds, then false (light) is returned.</p>
</td>
</tr>
<tr id="row4"><td class="cellrowborder" valign="top" width="50.22%" headers="mcps1.1.3.1.1 "><p id="p7"><a name="p7"></a><a name="p7"></a>void QrcodeImageFree(QrcodeImage *qrImage)</p>
</td>
<td class="cellrowborder" valign="top" width="49.78%" headers="mcps1.1.3.1.2 "><p id="p8"><a name="p8"></a><a name="p8"></a>Releases the memory of the QR code data.</p>
</td>
</tr>
<tr id="row5"><td class="cellrowborder" valign="top" width="50.22%" headers="mcps1.1.3.1.1 "><p id="p9"><a name="p9"></a><a name="p9"></a>void QrcodeMemInitHooks(const QrcodeMemHooks *hooks)</p>
</td>
<td class="cellrowborder" valign="top" width="49.78%" headers="mcps1.1.3.1.2 "><p id="p10"><a name="p10"></a><a name="p10"></a>Initializes the custom memory allocation hook.</p>
</td>
</tr>
</tbody>
</table>

#### Error Correction Level Description

<table><thead align="left"><tr id="row5555555555555"><th class="cellrowborder" valign="top" width="20%" id="mcps1.1.3.2.1"><p id="p1111111111112"><a name="p1111111111112"></a><a name="p1111111111112"></a>Level</p>
</th>
<th class="cellrowborder" valign="top" width="20%" id="mcps1.1.3.2.2"><p id="p2222222222223"><a name="p2222222222223"></a><a name="p2222222222223"></a>Value</p>
</th>
<th class="cellrowborder" valign="top" width="20%" id="mcps1.1.3.2.3"><p id="p3333333333334"><a name="p3333333333334"></a><a name="p3333333333334"></a>Correction Capability</p>
</th>
<th class="cellrowborder" valign="top" width="40%" id="mcps1.1.3.2.4"><p id="p4444444444445"><a name="p4444444444445"></a><a name="p4444444444445"></a>Use Scenario</p>
</th>
</tr>
</thead>
<tbody><tr id="row6666666666666"><td class="cellrowborder" valign="top" width="20%" headers="mcps1.1.3.2.1 "><p id="p7777777777778"><a name="p7777777777778"></a><a name="p7777777777778"></a>M (medium)</p>
</td>
<td class="cellrowborder" valign="top" width="20%" headers="mcps1.1.3.2.2 "><p id="p8888888888889"><a name="p8888888888889"></a><a name="p8888888888889"></a>QRCODE_ECC_MEDIUM</p>
</td>
<td class="cellrowborder" valign="top" width="20%" headers="mcps1.1.3.2.3 "><p id="p9999999999999"><a name="p9999999999999"></a><a name="p9999999999999"></a>About 15%</p>
</td>
<td class="cellrowborder" valign="top" width="40%" headers="mcps1.1.3.2.4 "><p id="p1010101010101"><a name="p1010101010101"></a><a name="p1010101010101"></a>General-purpose scenario, balancing capacity and error correction capability.</p>
</td>
</tr>
<tr id="row7777777777777"><td class="cellrowborder" valign="top" width="20%" headers="mcps1.1.3.2.1 "><p id="p1111111111113"><a name="p1111111111113"></a><a name="p1111111111113"></a>H (high)</p>
</td>
<td class="cellrowborder" valign="top" width="20%" headers="mcps1.1.3.2.2 "><p id="p2222222222224"><a name="p2222222222224"></a><a name="p2222222222224"></a>QRCODE_ECC_HIGH</p>
</td>
<td class="cellrowborder" valign="top" width="20%" headers="mcps1.1.3.2.3 "><p id="p3333333333335"><a name="p3333333333335"></a><a name="p3333333333335"></a>About 30%</p>
</td>
<td class="cellrowborder" valign="top" width="40%" headers="mcps1.1.3.2.4 "><p id="p4444444444446"><a name="p4444444444446"></a><a name="p4444444444446"></a>High-reliability scenarios (such industrial and healthcare).</p>
</td>
</tr>
</tbody>
</table>

**NOTE**
- A higher error correction level indicates a larger proportion of damage that can be recovered, but the available data capacity decreases accordingly.
- The error correction algorithm uses Reed-Solomon (RS) code.


### How to Use

Call the QR code generator API to encode the text into a QR code image.

```
QrcodeImage *qrImage = QrcodeImageEncodeString("https://openharmony.cn", QRCODE_ECC_MEDIUM);
if (qrImage != NULL) {
    // Use qrImage->data to generate a QR code image.
    // qrImage->width is the image width.
    // qrImage->version is the QR code version for actual use.
    // The qrImage data needs to be released after being used.
    QrcodeImageFree(qrImage);
}
```

To customize memory allocation:

```
QrcodeMemHooks hooks = {
    .mallocFunc = myMalloc,
    .freeFunc = myFree
};
QrcodeMemInitHooks(&hooks);
```

## Repositories Involved

- [third_party_bounds_checking_function](https://gitcode.com/openharmony/third_party_bounds_checking_function)
- [arkui_ui_lite](https://gitcode.com/openharmony/arkui_ui_lite)
- [arkui_ace_engine](https://gitcode.com/openharmony/arkui_ace_engine)

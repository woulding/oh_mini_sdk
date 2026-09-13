# Cast+ Stream module

## Introduction

Cast+ Stream module: The main function is to achieve the projection of media resources to the opposite device and support dual end playback control.
## Directory Structure

```
/foundation/CastEngine/castengine_cast_plus_stream  # Cast+ Stream模块业务代码
├── include                            # include file
├── src                                # source code
├── LICENSE                            # Certificate file
├── BUILD.gn                           # Compilation Entry
└── test                               # test code

```

## Compilation and Building

```
# Generate the libcast.z.so、libcast_engine_client.z.so、libcast_engine_service.z.so file in the out directory of the product folder through GN compilation.
hb build cast
```

### Usage

For details, see[Sample](https://gitee.com/openharmony/applications_app_samples/tree/master/code/BasicFeature/Media/AVSession)。

## Repositories Involved

[castengine_cast_framework](https://gitee.com/openharmony-sig/castengine_cast_framework)

[castengine_wifi_display](https://gitee.com/openharmony-sig/castengine_wifi_display)

[castengine_dlna](https://gitee.com/openharmony-sig/castengine_dlna)

hdc shell hilog -p off
hdc shell hilog -Q pidoff
hdc shell hilog -Q domainoff
hdc shell hilog -b D -D 0xD004601
hdc shell hilog -b D -D 0xD002B00
hdc shell hilog -b D -D 0xD00ff00
hdc shell hilog -b D -D 0xD002b2b
hdc shell hilog -b D -D 0xD003900
hdc shell hilog -b D -D 0xD0015c0
hdc shell hilog -b D -D 0x001b
hdc shell hilog -b X
hdc shell hilog -G 512M
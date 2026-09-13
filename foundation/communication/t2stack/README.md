# t2stack

## 简介
t2stack是面向智能终端场景的极简网络协议栈及其配套中间件的统称，主要提供文件、音视频流以及设备发现三大核心能力，且适配多种操作系统平台；同时，也属于软总线下面的关键传输、设备发现模块。

文件传输能力：提供文件传输基本能力，并在文件传输中提供多种优化，如大小文件协同、小文件打包等用途。

流传输能力：主要针对视频流、音频流传输场景，实现半可靠传输，自适应丢掉非关键帧，避免传输阻塞、带宽评估码率自适应、弱网检测动态缓存等三大竞争力方案，优化用户体验。

设备发现能力：主要提供局域网下设备之间发现能力，实现可靠单播、可扩展报文结构。

## 系统架构
<div align="left">
<img src=figures/arch.png width=75%/>
</div>

### 目录
t2stack主要代码目录结构如下：

```text
//t2stack
├── fillp                  # 流传输协议代码
│   ├── include            # Dstream对外接口代码
│   ├── src                # Dstream核心代码
├── nstackx_congestion     # 拥塞算法相关公共模块
│   ├── interface          # 对外接口
│   ├── core               # 核心代码
│   ├── platform           # 不同平台适配代码
├── nstackx_core           # 文件传输协议代码
│   ├── dfile              # DFile协议代码
│   |   ├── include        # DFile对外接口代码
│   |   ├── src            # DFile核心代码
│   ├── platform           # 不同平台适配代码
├── nstackx_ctrl           # ctrl组件
│   ├── interface          # 对外接口
│   ├── core               # 核心代码
│   ├── platform           # 不同平台适配代码
├── nstackx_util           # 公共模块代码
│   ├── interface          # 对外接口
│   ├── core               # 核心代码
│   ├── platform           # 不同平台适配代码
```


## 主要接口功能介绍

### 文件传输
#### 1.  建立连接
    Step 1: NSTACKX_DFileServer:创建文件传输服务端
    Step 2: NSTACKX_DFileClient:创建文件传输客户端，连接到服务端
#### 2.  关闭连接
    NSTACKX_DFileClose:关闭文件传输会话实例。
#### 3.  传输文件
    NSTACKX_DFileSendFiles:客户端发送文件
    NSTACKX_DFileSetStoragePath:接收端设置接收文件存储根路径
    NSTACKX_DFileSetRenameHook:接收端设置一个回调函数，对相同路径相同文件名的文件进行重命名，防止被覆盖
#### 4.  获取和设置支持的功能
    NSTACKX_DFileGetCapabilities:获取DFile支持的功能
    NSTACKX_DFileSetCapabilities:设置DFile需要开启的功能
#### 5.  交互流程

<div align="left">
<img src=figures/File_transfer_processes.png width=75%/>
</div>

### 流传输
#### 1.  初始化和销毁
    FtInit:使用前对Fillp进行初始化
    FtDestroy:使用完对Fillp进行销毁
#### 2.  建立连接
    FtSocket:创建socket
    FtBind:服务端将socket与地址绑定
    FtListen:服务端使socket进入监听
    FtAccept:服务端开始接收客户端的连接
    FtConnect:客户端调用此接口与服务端连接
#### 3.  发送和接收
    FtSendFrame:客户端调用此接口发送一个视频帧
    FtRecv:接收端调用此接口接收视频帧
#### 4.  关闭连接
    FtClose:调用此接口来关闭连接
#### 5.  交互流程

<div align="left">
<img src=figures/Stream_transfer_processes.png width=75%/>
</div>

## 更多、更详细的接口说明请参考接口说明文档
[t2stack接口说明文档](https://gitcode.com/openharmony-sig/communication_t2stack/blob/master/%E6%8E%A5%E5%8F%A3%E8%AF%B4%E6%98%8E%E6%96%87%E6%A1%A3.md)
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

import socket from '@ohos.bluetooth.socket';
import { BusinessError } from '@ohos.base';
import worker, { MessageEvents, ErrorEvent } from '@ohos.worker';
import { WorkerParam, WorkParam } from '.././workers/Worker';
import bluetooth from '@ohos.bluetooth.connection';
import abilityAccessCtrl, { Context, PermissionRequestResult } from '@ohos.abilityAccessCtrl';
import common from '@ohos.app.ability.common';

interface PairDevices {
  id: string;//配对设备的蓝牙mac地址
  name: string//配对设备的名字
}

@Component
export struct TitleBar {
  private title!: string;
  build() {
    Column() {
      Row() {
        Text(this.title)
          .fontSize(20)
          .layoutWeight(1)
          .margin({ left: 16 })
          .align(Alignment.Start)
        Blank()
      }
      .height(56)
      .width('100%')
    }
  }
}

@Extend(Column)
function backgroundStyle() {
  .width('100%')
  .padding(12)
  .borderRadius(16)
  .backgroundColor(Color.White)
  .justifyContent(FlexAlign.SpaceAround)
}


@Entry
@Component
struct Index {
  private sppOption:socket.SppOptions = { //spp监听配置参数
    uuid: '22001101-0000-1000-8000-77666f9b34fb',
    secure: false,
    type: 0,
  };
  private serverNumber: number = -1; //服务端Socket的id
  private clientNumber: number = -1; //客户端Socket的id
  @State len: number = 0; //服务端每次收到字长
  @State deltaDate: number = 0; //服务端每次收包时间
  @State packageNum: number = 0; //服务端收包个数
  @State velocity: number = 0;
  @State messageArr: Array<number> = []; //服务端收包字长数组
  @State deltaDateArr: Array<number> = []; //服务端收包时间数组
  @State packageNumArr: Array<number> = []; //服务端收包个数数组
  @State velocityArr: Array<number> = [];
  @State acceptNum: number = 0; //服务端收包次数
  @State serverButtonText: string = '测试Socket服务端'; //服务端按钮文本
  @State zeroLength: number = 0; //服务端接收的0的字长
  @State oneItem: number = 0; //数组中1的索引
  @State serverMac: string = '00:00:00:00:00:00';//服务端蓝牙mac地址
  @State pairDevices: Array<PairDevices> = [];
  @State devicesSelectOptions: Array<SelectOption> = [];
  @State serverColor: Color = Color.Blue;//服务端按钮颜色
  @State logButColor: Color = Color.White;
  @State workParam: WorkParam = {
    cliButtText: '测试Socket客户端',
    cliColor: Color.Blue,
    numArr: [],
    packArr: [],
    messArr: [],
    cliCnt: 0,
    cliLen: 0,
    cliBol: true
  }
  @State serBol: boolean = true; //是否禁用服务端按钮
  @State message: string = 'Hello World';
  @State listDirection: Axis = Axis.Vertical;
  @State space: number = 10;
  @State strokeWidth: number = 0;
  @State color: string = '#409EFF';
  @State barState: BarState = BarState.Auto;
  @State scrollBarWidth: number = 0;
  @State scrollBarColor: Color = Color.Blue;
  @State initIndex: number = AppStorage.get<number>('listSampleInitIndex') || 0;
  @State edgeEffect: EdgeEffect = EdgeEffect.Spring;
  @State isChainAnimation: boolean = false;
  @State multiSelectable: boolean = false;
  @State lanes: number = 1;
  @State alignListItem: ListItemAlign = ListItemAlign.Center;
  private controller: Scroller = new Scroller();
  @State numberArray: number[] = []; //服务端接收次序
  @State sendCnt: string = '100'; //传输次数
  @State packageSize: string = '1024'; //包长
  @State nameIndex: number = 1;
  @State cntIndex: number = 1;
  @State deviceIndex: number = 1;
  @State packageIndex: number = 1;
  @State recvSize: number = 0; //服务端接收总字长
  @State recvDuration: number = 0; //服务端总计时
  @State recvPackageNum: number = 0;
  @State debug: boolean = false;
  @State logCnt: number = 0;
  @State starttime: number = 0;
  @State endtime: number = 0;
  private data: Uint8Array = new Uint8Array();

  print(msg: string) {
    if (this.debug) {
      console.log(msg);
    }
  }

  getPairDevice(){
    let macs: Array<string> = bluetooth.getPairedDevices();//获取蓝牙mac地址列表
    this.print('getPairDevice macs: '+JSON.stringify(macs));
    for (let i = 0; i < macs.length; i++) {
      let name = bluetooth.getRemoteDeviceName(macs[i]);//获取对端蓝牙设备名称
      this.print('getPairDevice name: '+JSON.stringify(name));
      this.pairDevices.push({ id: macs[i], name: name });
    }
    this.print('getPairDevice pairDevices: '+JSON.stringify(this.pairDevices));
  }

  pairDevicesToSelectOptions(pairDevices: Array<PairDevices>): Array<SelectOption> {
    let result = new Array<SelectOption>();
    for(let i = 0; i < pairDevices.length; i++) {
      result[i] = { value: pairDevices[i].name };
    }
    return result;
  }

  aboutToAppear(){
    let abilityMgr: abilityAccessCtrl.AtManager = abilityAccessCtrl.createAtManager();
    let context: Context = getContext(this) as common.UIAbilityContext;
    abilityMgr.requestPermissionsFromUser(context, ['ohos.permission.ACCESS_BLUETOOTH'], (error: BusinessError, result: PermissionRequestResult) => {
        console.log('bluetooth requestPermissionsFromUser, err: ' + JSON.stringify(error) + '; result: ' + JSON.stringify(result));
    });
    this.getPairDevice();
    this.devicesSelectOptions = this.pairDevicesToSelectOptions(this.pairDevices);
  }

  @Styles
  listItemTextDynamicSize(){
    .height(this.listDirection === Axis.Horizontal ? '99%' : '20%')
    .width(this.listDirection === Axis.Vertical ? '99%' : '20%')
  }

  printMess() {
    this.print(`============第${this.acceptNum}次接收数据============`);
    this.print(`data[0] = ${this.data[0]}, data.length is ${this.data.length}`);
    this.print(`this.len is ${this.len}`);
    // this.print(`data = ${this.data}`);
  }

  startInit() {
    this.starttime = new Date().getTime();
    this.packageNum++;
    this.acceptNum++;
  }

  endCalculate() {
    this.endtime = new Date().getTime();
    this.deltaDate = this.endtime - this.starttime;
    this.velocity = this.len * 1000 / (this.deltaDate * 1024);
    this.printMess();
    this.print(`endtime is ${this.endtime}`);
    this.print(`this.deltaDate is ${this.deltaDate}`);
    this.numberArray.push(this.acceptNum);
    this.packageNumArr.push(this.packageNum);
    this.messageArr.push(this.len);
    this.deltaDateArr.push(this.deltaDate);
    this.velocityArr.push(this.velocity);
    this.recvDuration += this.deltaDate;//总计时
    this.recvSize += this.len;//总字长
    this.recvPackageNum += this.packageNum;
    this.starttime = 0;
    this.endtime = 0;
    this.len = 0;
    this.packageNum = 0;
  }

  checkHead(): boolean {
    if (this.data.includes(0) || this.data.includes(1)) {
      if (this.starttime == 0) {
        if (this.data.includes(0) && this.data.includes(1)) {
          this.startInit();
          this.len = this.data.length - this.data.indexOf(1);
          this.printMess();
          this.print(`starttime is ${this.starttime}`);
          return true;
        } else if (this.data[0] === 1) {
          this.startInit();
          this.len += this.data.length;
          this.printMess();
          this.print(`starttime is ${this.starttime}`);
          return true;
        } else {
          this.printMess();
          return true;
        }
      } else {
        return false;
      }
    } else {
      return false;
    }
  }

  checkTail(): boolean {
    if (this.data.includes(101)) {
      if (this.starttime !== 0) {
        if (this.data.includes(100)) {
          this.len += this.data.indexOf(101);
          this.packageNum++;
        }
        this.endCalculate();
        return true;
      } else {
        this.printMess();
        return true;
      }
    } else {
      return false;
    }
  }

  checkEnd(): boolean {
    if (this.data.includes(199)) {
      setTimeout(() => {
        this.print('delay 3s');
        try {
          socket.off('sppRead', this.clientNumber);
          this.print('取消订阅spp读请求事件成功！');
          try {
            socket.sppCloseServerSocket(this.serverNumber);
            this.print('关闭服务端监听Socket成功！');
            this.serverButtonText = '测试Socket服务端';
            this.serverColor = Color.Blue;
            this.serBol = true;
          } catch (err) {
            this.print('关闭服务端监听Socket失败，err: ' + JSON.stringify(err));
            this.serverButtonText = '关闭服务端监听Socket失败，请再试一次';
            this.serBol = true;
            this.serverColor = Color.Red;
          }
        } catch (err) {
          this.print('取消订阅spp读请求事件失败，err: ' + JSON.stringify(err));
          this.serverButtonText = '取消订阅spp读请求事件失败，请再试一次';
          this.serBol = true;
          this.serverColor = Color.Red;
          try {
            socket.sppCloseServerSocket(this.serverNumber);
            this.print('关闭服务端监听Socket成功！');
          } catch (err) {
            this.print('关闭服务端监听Socket失败，err: ' + JSON.stringify(err));
          }
        }
      }, 3000);
      return true;
    } else {
      return false;
    }
  }

  onRead=(dataBuffer: ArrayBuffer)=>{
    this.data = new Uint8Array(dataBuffer);
    if (this.checkHead()) {
      if (this.checkEnd()) {
        return;
      }
      return;
    }
    if (this.checkTail()) {
      return;
    }
    this.len += this.data.length;
    this.packageNum++;
    this.printMess();
  }

  build() {
    Flex({ direction: FlexDirection.Column, alignItems: ItemAlign.Center, justifyContent: FlexAlign.Start }) {
      TitleBar({ title: '蓝牙Socket测试' })
        .flexGrow(0)
        .onClick(() => {
          this.logCnt++;
          if (this.logCnt % 2 === 0) {
            this.debug = false;
          } else {
            this.debug = true;
          }
          if (this.debug) {
            this.logButColor = Color.Pink;
          } else {
            this.logButColor = Color.White;
          }
          this.print(`this.debug is ${this.debug}`);
          this.print(`this.logButColor is ${this.logButColor}`);
        })
        .backgroundColor(this.logButColor)

      // tab页签
      Column() {
        Tabs({ barPosition: BarPosition.Start }) {
          // 子页签：WaterFlow控制
          TabContent() {
            Column() {
              Row() {
                Text('服务端')
                Select(this.devicesSelectOptions)
                  .value('已配对的设备')
                  .backgroundColor(Color.White)
                  .borderRadius(19)
                  .constraintSize({ minWidth: 100 })
                  .selected(this.deviceIndex)
                  .onSelect((index) => {
                    this.nameIndex = index;
                    this.serverMac = this.pairDevices[this.nameIndex].id;
                  })
                  .width('70%')
                  .margin(10)
                  .borderRadius(2)
              }
              Row() {
                Text('次数')
                Select([{ value: '1'}, { value: '10' }, { value: '100' }, { value: '1000' }])
                  .value(this.sendCnt)
                  .backgroundColor(Color.White)
                  .borderRadius(19)
                  .constraintSize({ minWidth: 100 })
                  .selected(this.cntIndex)
                  .onSelect((index, value) => {
                    this.cntIndex = index;
                    this.sendCnt = value;
                  })
                  .width(50)
                  .margin(10)
                  .borderRadius(2)

                Text('长度')
                Select([{ value: '10' }, { value: '1024' }, { value: '4096' }])
                  .value(this.packageSize)
                  .backgroundColor(Color.White)
                  .borderRadius(19)
                  .constraintSize({ minWidth: 100 })
                  .selected(this.packageIndex)
                  .onSelect((index, value) => {
                    this.packageIndex = index;
                    this.packageSize = value;
                  })
                  .margin(10)
                  .borderRadius(2)
              }

              //客户端按钮
              Button(this.workParam.cliButtText)
                .height(50)
                .width('80%')
                .onClick(() => {
                  this.workParam.cliButtText = '数据发送中...';
                  this.workParam.cliColor = Color.Grey;
                  this.acceptNum = 0;
                  this.numberArray.length = 0;//服务端切至客户端清除收包信息列表
                  this.workParam.numArr.length = 0;
                  this.workParam.cliCnt = 0;
                  this.workParam.cliLen = 0;
                  this.workParam.cliBol = false;
                  // 主线程中创建Worker对象
                  const workerInstance = new worker.ThreadWorker('entry/ets/workers/Worker.ets');
                  let workerParam: WorkerParam = {
                    cnt: Number(this.sendCnt),
                    packageSize: Number(this.packageSize),
                    deviceId: this.serverMac,
                    debug: this.debug
                  }
                  let paramStr = JSON.stringify(workerParam);
                  // 主线程向worker线程传递信息
                  workerInstance.postMessage(paramStr);
                  // 主线程接收worker线程信息
                  workerInstance.onmessage = (e: MessageEvents): void => {
                    this.print('main thread onmessage');
                    // data：worker线程发送的信息
                    let data: WorkParam = JSON.parse(e.data)
                    this.workParam = data;
                  }
                  workerInstance.onerror = (err: ErrorEvent) => {
                    this.print('main error message ' + err.message);
                  }
                })
                .backgroundColor(this.workParam.cliColor)
                .enabled(this.workParam.cliBol)
                .stateEffect(true)
            }
            .height('100%')
          }.tabBar(new SubTabBarStyle($r('app.string.Socket_client')))

          // 子页签：WaterFlow属性
          TabContent() {
            Column() {
              //服务端按钮
              Button(`${this.serverButtonText}`)
                .height(50)
                .width('80%')
                .onClick(() => {
                  this.serverButtonText = '数据接收中...';
                  this.serverColor = Color.Grey;
                  this.serBol = false;//禁用按钮
                  this.workParam.cliCnt = 0;
                  this.workParam.numArr.length = 0;//客户端切至服务端清除发包信息列表
                  this.workParam.packArr.length = 0;
                  this.workParam.messArr.length = 0;
                  this.messageArr.length = 0;
                  this.numberArray.length = 0;
                  this.deltaDateArr.length = 0;
                  this.packageNumArr.length = 0;
                  this.velocityArr.length = 0;
                  this.messageArr.length = 0;
                  this.recvSize = 0;
                  this.recvDuration = 0;
                  this.recvPackageNum = 0;
                  this.acceptNum = 0;
                  let times = new Date().getTime();
                  console.info(`times : ===== ${times} =====`);
                  //创建服务端监听Socket
                  socket.sppListen('server', this.sppOption, (code: BusinessError, serverId: number) => {
                    if (code) {
                      this.print('服务端监听失败，code：' + JSON.stringify(code));
                      this.serverButtonText = '服务端监听失败，请再试一次';
                      this.serBol = true;
                      this.serverColor = Color.Red;
                      return;
                    } else {
                      this.serverNumber = serverId;
                      this.print(`服务端监听成功, serverNumber = ${this.serverNumber}`);
                      this.print('服务端等待连接');
                      try {
                        //与客户端连接
                        socket.sppAccept(this.serverNumber, (code: BusinessError, cliendId: number) => {
                          if (code) {
                            this.print('服务端等待连接失败，code: ' + JSON.stringify(code));
                            if ((code.code === -1) && (code.message === 'Inner error.')) {
                              this.serverButtonText = '蓝牙未打开，请再试一次';
                              this.serBol = true;
                              this.serverColor = Color.Red;
                            }
                            return;
                          } else {
                            this.clientNumber = cliendId;
                            this.print(`服务端等待连接成功, clientNumber = ${this.clientNumber}`);
                            try {
                              let dataRead = this.onRead;
                              //服务端接收数据
                              socket.on('sppRead', cliendId, dataRead);
                              this.print('订阅spp读请求事件成功！');
                            } catch (err) {
                              this.print('订阅spp读请求事件失败，err: ' + JSON.stringify(err));
                              this.serverButtonText = '订阅spp读请求事件失败，请再试一次';
                              this.serBol = true;
                              this.serverColor = Color.Red;
                            }
                          }
                        })
                      } catch (err) {
                        this.print('创建监听Socket服务端crash， err: ' + JSON.stringify(err));
                      }
                    }
                  })
                })
                .backgroundColor(this.serverColor)
                .enabled(this.serBol)
                .stateEffect(true)
            }
            .height('100%')
          }.tabBar(new SubTabBarStyle($r('app.string.Socket_server')))
        }
        .vertical(false)
        .scrollable(true)
        .barMode(BarMode.Fixed)
        .backgroundColor(Color.Pink)
        .onChange((index: number) => {
          console.info(index.toString())
        })
        .width('100%')
        .backgroundColor(0xF1F3F5)
      }
      .height('30%')
      .width('100%')

      // List
      Column() {
        //客户端发送信息列表
        List({ scroller: this.controller, initialIndex: this.initIndex, space: this.space }) {
          ForEach(this.workParam.numArr, (item: number, index: number) => {
            ListItem() {
              Column() {
                Text(`第${ this.workParam.numArr[item-1] }次，发包${ this.workParam.packArr[item-1] }个，长${
                this.workParam.messArr[item-1] }字节`)
                  .margin(5)
                  .width('90%')
                  .align(Alignment.Center)
                  .textAlign(TextAlign.Center)
              }
              .width('100%')
              .backgroundColor('#0d000000')
              .height(40)
            }
          })
        }

        //服务端接收信息列表
        List({ scroller: this.controller, initialIndex: this.initIndex, space: this.space }) {
          ForEach(this.numberArray, (item: number, index: number) => {
            ListItem() {
              Column() {
                Text(`第${this.numberArray[item-1]}次，收包${ this.packageNumArr[item-1] }个，长${this.messageArr[item-1]}字节`)
                  .margin(5)
                  .width('90%')
                  .align(Alignment.TopStart)
                  .textAlign(TextAlign.Start)
                Text(`用时${this.deltaDateArr[item-1]}毫秒，速度${ Math.round(this.velocityArr[item-1]) } KB/s`)
                  .margin(5)
                  .width('90%')
                  .align(Alignment.BottomEnd)
                  .textAlign(TextAlign.End)
              }
              .width('100%')
              .backgroundColor('#0d000000')
              .height(60)
            }
          })
        }
        .alignListItem(this.alignListItem)
        .height('100%')
        .width('100%')
        .listDirection(this.listDirection)
        .scrollBar(this.barState)
        .scrollBarColor(this.scrollBarColor)
        .scrollBarWidth(this.scrollBarWidth)
        .edgeEffect(this.edgeEffect)
        .multiSelectable(this.multiSelectable)
        .chainAnimation(this.isChainAnimation)
        .lanes(this.lanes)
        .divider(
          {
            strokeWidth: this.strokeWidth,
            color: this.color
          }
        )
      }
      .padding({ left: 12, right: 12 })
      .backgroundStyle()
      .height('40%')
      .width('100%')
      .flexGrow(0)

      Column() {
        if (this.acceptNum !== 0) {
          Text() {
            Span(`共测试次数: ${this.acceptNum}`)
          }

          Text(`共收到字节: ${this.recvSize}字节`)
            .textAlign(TextAlign.Start)
            .fontColor(Color.Gray)

          Text(`共收到包数: ${this.recvPackageNum}`)
            .textAlign(TextAlign.Start)
            .fontColor(Color.Gray)

          Text(`总计时: ${(this.recvDuration * 0.001).toFixed(6)}s`)
            .textAlign(TextAlign.Start)
            .fontColor(Color.Gray)

          Text(`平均速度：${Math.round(this.recvSize * 1000 / (this.recvDuration * 1024))}KB/s`)
            .textAlign(TextAlign.Start)
            .fontColor(Color.Gray)
        }
        if (this.workParam.cliCnt !== 0) {
          Text() {
            Span(`共测试次数: ${this.workParam.cliCnt}`)
          }

          Text(`共发送字节: ${this.workParam.cliLen}字节`)
            .textAlign(TextAlign.Start)
            .fontColor(Color.Gray)
        }
      }
      .height('16%')
      .width('100%')
      .padding({left:12})
      .alignItems(HorizontalAlign.Start)
      .justifyContent(FlexAlign.Center)
      .flexGrow(0)
    }
    .padding({ left: 12, right: 12 })
    .height('100%')
    .width('100%')
    .backgroundColor('$color:index_background')
  }
}
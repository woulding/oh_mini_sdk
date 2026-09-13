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
import worker, { ThreadWorkerGlobalScope, MessageEvents, ErrorEvent } from '@ohos.worker';

export interface WorkerParam {
  cnt: number; //发送次数
  packageSize: number; //包长
  deviceId: string;
  debug: boolean;
}


export interface WorkParam {
  cliButtText: string; //客户端按钮文本
  cliColor: Color; //客户端按钮颜色
  numArr: Array<number>; //发送数据次数
  packArr: Array<number>; //每次收包次数
  messArr: Array<number>; //每次发送的字节长
  cliCnt: number, //客户端总共发送次数
  cliLen: number, //客户端总共发送字节长度
  cliBol: boolean //是否禁用按钮
}

const sppOption:socket.SppOptions = {
  uuid: '22001101-0000-1000-8000-77666f9b34fb',
  secure: false,
  type: 0
};
let clientNumber: number = -1;
let packNum: number = 0; //发包数
let leng: number = 0; //每次发送字长
let workParam: WorkParam = {
  cliButtText: '数据发送中...',
  cliColor: Color.Grey,
  numArr: [],
  packArr: [],
  messArr: [],
  cliCnt: 0,
  cliLen: 0,
  cliBol: false
}
let logSym: boolean = false;
function print(msg: string) {
  if (logSym) {
    console.log(msg);
  }
}
const Sleep = (ms: number)=> {
  return new Promise<void> (resolve => setTimeout(resolve, ms))
}

// 创建worker线程中与主线程通信的对象
const workerPort: ThreadWorkerGlobalScope = worker.workerPort;

// worker线程接收主线程信息
workerPort.onmessage = (e: MessageEvents) => {
  // data：主线程发送的信息
  let data: string = e.data;
  print('worker.ets onmessage');
  let dataOjbect: WorkerParam = JSON.parse(data);
  logSym = dataOjbect.debug;
  try {
    //向服务端发起连接
    socket.sppConnect(dataOjbect.deviceId, sppOption, async (code: BusinessError, number: number) => {
      if (code) {
        print('发起连接失败，code: ' + JSON.stringify(code));
        if ((code.code === 2900003) && (code.message === 'BussinessError 2900003: Bluetooth disabled.')) {
          workParam.cliButtText = '蓝牙未打开，请再试一次';
          workParam.cliBol = true;
          workParam.cliColor = Color.Red;
          let paraStr = JSON.stringify(workParam);
          workerPort.postMessage(paraStr);
        }
        return;
      } else {
        print(`发起连接成功！bluetooth serverSocket Number: ${number}`);
        clientNumber = number;
        //向服务端发送数据
        let arrayBuffer = new ArrayBuffer(dataOjbect.packageSize);
        let data = new Uint8Array(arrayBuffer);
        //最后单独发送199表示发送完毕
        let arrayBuffer1 = new ArrayBuffer(32);
        let data1 = new Uint32Array(arrayBuffer1);
        data1[0] = 199;
        try {
          for (let k = 0; k < dataOjbect.cnt; k++) {
            workParam.cliCnt++;
            for (let j = 0; j < 102; j++) {
              for (let i = 0; i < dataOjbect.packageSize; i++) {
                data[i] = j;
                if ((i === dataOjbect.packageSize - 1) && (j > 0) && (j < 101)) {
                  leng += (data.length);
                }
              }
              if ((j > 0) && (j<101)) {
                packNum++;
              }
              if (j === 1) {
                workParam.numArr.push(k+1);
              }
              if (j === 100) {
                workParam.packArr.push(packNum);
                workParam.messArr.push(leng);
                workParam.cliLen +=leng;
              }
              if (j === 101) {
                packNum = 0;
                leng =0;
              }
              socket.sppWrite(clientNumber, arrayBuffer);
              print(`===========第${k+1}次发送数据============`);
              print(`第${j}次发送: data[0]为${data[0]}, data.length为${data.length}, data is ${data}`);
            }
            await Sleep(2000);
            print('wait 2s!')
            let paraStr = JSON.stringify(workParam);
            workerPort.postMessage(paraStr);
          }
          socket.sppWrite(clientNumber, arrayBuffer1);
          print(`最后发送${data1},发送完毕！`);
          setTimeout(() => {
            print('delay 5s');
            try {
              socket.sppCloseClientSocket(clientNumber);
              print('客户端Socket关闭成功！');
            } catch (err) {
              print('客户端Socket关闭失败，err: ' + JSON.stringify(err));
              if (err) {
                workParam.cliButtText = '客户端Socket关闭失败，请再试一次';
                workParam.cliBol = true;
                workParam.cliColor = Color.Red;
                let paraStr = JSON.stringify(workParam);
                workerPort.postMessage(paraStr);
              }
            }
            // worker线程向主线程发送信息
            workParam.cliButtText = '测试Socket客户端';
            workParam.cliColor = Color.Blue;
            workParam.cliBol = true;
            let paraStr = JSON.stringify(workParam);
            workerPort.postMessage(paraStr);
          }, 5000);
        } catch (err) {
          print('数据发送失败，err：' + JSON.stringify(err));
          workParam.cliButtText = '数据发送失败，请再试一次';
          workParam.cliBol = true;
          workParam.cliColor = Color.Red;
          let paraStr = JSON.stringify(workParam);
          workerPort.postMessage(paraStr);
        }
      }
    });
  } catch (err) {
    print('errCode: ' + (err as BusinessError).code + ', errMessage: ' + (err as BusinessError).message);
  }
}
// worker线程发生error的回调
workerPort.onerror = (err: ErrorEvent) => {
  print('worker.ets onerror ' + err.message);
}
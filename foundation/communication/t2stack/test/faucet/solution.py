# Copyright (c) 2026 Xiamen University. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Faucet: A Proactive Network-Aware and Retention-Guided Preloading Framework for Short Video Streaming

===============================================================================
算法核心思想:
===============================================================================
Faucet针对短视频流媒体中的两大核心挑战设计:
1. 网络动态性: 移动网络带宽波动剧烈，传统方法反应滞后导致卡顿
2. 用户不确定性: 用户随时可能划走，盲目预加载造成带宽浪费

===============================================================================
算法架构:
===============================================================================
1. 网络监控模块 (NetworkMonitor)
   - 实时跟踪带宽(b_t)、方差(v_t)、下载时间(d_t)
   - 计算趋势指标 τ_t = (b_short - b_long) / b_long, 预测网络变化方向
   - 基于当前网络状态动态调整预加载策略

2. 观看概率预测 (Retention-Guided)
   - 全局条件概率: R_i(j)/R_i(j_curr) 基于历史留存率
   - 个性化加权: 使用滑动窗口记录用户最近10个视频的观看行为
   - 视频相似度加权: 相似视频的行为更具参考价值

3. 播放紧迫性评分 (Urgency Scoring)
   - 计算到目标块的播放距离 Δ_{i,j} (考虑跨视频)
   - 紧迫性分数 U = 1/(Δ + 1)，距离越近越紧迫

4. 网络感知动态加权 (Network-Aware Weighting)
   - 综合分数 S = λ·U + (1-λ)·W
   - λ ∈ [0.3, 0.8] 由网络状态动态决定:
        * 好网络(高带宽+低方差): λ小 → 重概率(提升带宽效率)
        * 差网络(低带宽+高方差): λ大 → 重紧迫(防止卡顿)

5. 预加载深度自适应
   - 深度 D ∈ [1,5] 块，根据网络状态动态调整:
        * 好网络(b>4Mbps, 趋势上升): D=5 (多预加载)
        * 差网络(b<1.5Mbps, 趋势下降): D=1 (少预加载)

===============================================================================
核心参数:
===============================================================================
- alpha = 0.6        # 全局vs个性化权重
- window_size = 10    # SlidingWindow大小
- lambda_min/max = 0.3/0.8  # 网络权重范围
- base_depth = 2     # 基础预加载深度
- max/min_depth = 4/1 # 最大/最小深度
- chunk_duration = 1.0 # 默认块时长(秒)
""" 

from simulator.video_player import Player
import numpy as np
from collections import deque
from typing import List, Tuple, Dict, Optional
import math
import random
import traceback


class SlidingWindow:
    """滑动窗口，记录用户最近的观看历史"""
    def __init__(self, window_size: int = 10):
        self.window_size = window_size
        self.history = deque(maxlen=window_size)  # 每个元素为 (video_id, chunks_watched, retention_rate_at_exit)
        
    def add(self, video_id: int, chunks_watched: int, retention_at_exit: float = 0):
        """添加一次观看记录"""
        self.history.append((video_id, chunks_watched, retention_at_exit))
        
    def get_history(self) -> List[Tuple[int, int, float]]:
        """获取历史记录"""
        return list(self.history)
    
    def size(self) -> int:
        return len(self.history)


class NetworkMonitor:
    """网络监控模块"""
    def __init__(self, k: int = 10):
        self.k = k
        self.bandwidth_history = deque(maxlen=k)
        self.download_times = deque(maxlen=k)
        self.last_bandwidth = 1.0
        self.last_download_time = 0.1
        
    def update(self, bandwidth: float, download_time: float):
        """更新网络状态"""
        self.bandwidth_history.append(bandwidth)
        self.download_times.append(download_time)
        self.last_bandwidth = bandwidth
        self.last_download_time = download_time
        
    def get_network_state(self) -> Tuple[float, float, float]:
        """获取当前网络状态 [b_t, v_t, d_t]"""
        if len(self.bandwidth_history) == 0:
            return (1.0, 0.0, 0.1)
        
        # 使用最近一次带宽作为瞬时带宽
        b_t = self.last_bandwidth
        
        # 计算方差（至少需要2个样本）
        if len(self.bandwidth_history) >= 2:
            v_t = np.var(list(self.bandwidth_history))
        else:
            v_t = 0.0
            
        d_t = self.last_download_time
        
        return (b_t, v_t, d_t)
    
    def compute_trend(self) -> float:
        """计算趋势指标 τ_t"""
        if len(self.bandwidth_history) < 3:
            return 0.0
            
        short_window = min(3, len(self.bandwidth_history))
        long_window = min(10, len(self.bandwidth_history))
        
        b_short = np.mean(list(self.bandwidth_history)[-short_window:])
        b_long = np.mean(list(self.bandwidth_history)[-long_window:])
        
        if b_long < 0.01:
            return 0.0
        return (b_short - b_long) / b_long
    
    def get_bandwidth_stats(self) -> Tuple[float, float]:
        """获取短窗口和长窗口平均带宽"""
        if len(self.bandwidth_history) < 2:
            return (self.last_bandwidth, self.last_bandwidth)
        
        short_window = min(3, len(self.bandwidth_history))
        long_window = min(10, len(self.bandwidth_history))
        
        b_short = np.mean(list(self.bandwidth_history)[-short_window:])
        b_long = np.mean(list(self.bandwidth_history)[-long_window:])
        
        return (b_short, b_long)


class FaucetAlgorithm:
    """Faucet 预加载算法主类"""
    
    def __init__(self):
        # 核心参数
        self.alpha = 0.6  # 全局vs个性化权重 (调高一点，更依赖全局)
        self.window_size = 10  # 滑动窗口大小
        self.lookahead_seconds = 5.0  # 预取窗口（秒）
        self.chunk_duration = 1.0  # 默认块时长（秒）- 根据实际调整
        
        # 模块初始化
        self.sliding_window = SlidingWindow(self.window_size)
        self.network_monitor = NetworkMonitor(k=10)
        
        # 状态跟踪
        self.current_video_id = 0
        self.current_chunk_idx = 0
        self.playback_position = (0, 0)  # (video_id, chunk_idx)
        self.videos_info = {}  # video_id -> VideoInfo
        self.downloaded_counts = {}  # video_id -> 已下载块数
        
        # 网络权重参数
        self.lambda_min = 0.3
        self.lambda_max = 0.8
        
        # 预加载深度参数
        self.base_depth = 3
        self.max_depth = 5
        self.min_depth = 1
        
        # 码率等级
        self.VIDEO_BIT_RATE = [750, 1200, 1850]
        
        # 步数计数
        self.step_count = 0
        
    def video_similarity(self, video1_id: int, video2_id: int) -> float:
        """
        计算两个视频的相似度,这边可以再添加其他的像视频时长、类型等计算相似度
        """
        if video1_id == video2_id:
            return 1.0
        # ID相近的视频可能更相似
        return 1.0 / (abs(video1_id - video2_id) + 1)
    
    def _to_float(self, value):
        """将任意类型转换为浮点数"""
        try:
            if isinstance(value, (int, float)):
                return float(value)
            elif isinstance(value, str):
                return float(value.strip())
            else:
                return float(value)
        except:
            return 0.5  # 默认值
        
    def _get_safe_chunks_to_download(self, player, video_id, is_current=True, network_state=None, trend=0):
        """
        安全计算可以下载多少块（带总块数输出）
        可根据网络状态动态调整最大允许下载量
        """
        try:
            if player is None:
                print(f"[GetSafeChunks] Video {video_id}: Player is None")
                return 0
            
            # 获取视频总块数
            total_chunks = player.get_chunk_sum()
            
            # 已经下载了多少块
            downloaded = self.downloaded_counts.get(video_id, 0)

                # ===== 基础最大允许下载量 =====
            if is_current:
                # 当前视频：基础最多4块
                base_max = 8
            else:
                # 后续视频：基础最多2块
                base_max = 2
            
            # ===== 根据网络状态动态调整 =====
            boost = 0
            if network_state and trend is not None:
                b_t, v_t, d_t = network_state
                
                # 网络很好时增加
                if b_t > 4.0 and trend > 0.1:
                    boost = 1
                    print(f"[GetSafeChunks] 网络好+趋势上升，增加1块")
                elif b_t > 3.0 and trend > 0:
                    boost = 0  # 不增不减
                elif b_t < 1.5 or trend < -0.2:
                    boost = -1
                    print(f"[GetSafeChunks] 网络差或趋势下降，减少1块")

                
            
            # 计算最终最大允许下载量
            max_allowed = min(total_chunks, base_max + boost)
            max_allowed = max(1, max_allowed)  # 至少允许下载1块
            
            
            # ===== 输出详细信息 =====
            video_type = "当前播放" if is_current else "预加载"
            print(f"[GetSafeChunks] Video {video_id} ({video_type}): "
                f"总块数={total_chunks}, 已下载={downloaded}, "
                f"基础最大={base_max}, 网络调整={boost:+d}, "
                f"最终最大={max_allowed}")
            
            return max_allowed
            
        except Exception as e:
            default_val = 4 if is_current else 2
            print(f"[GetSafeChunks] 获取失败: {str(e)}, 使用默认值={default_val}")
            return default_val

    def compute_watch_probability(self, 
                                  video_id: int,
                                  chunk_idx: int,
                                  current_chunk_idx: int,
                                  retention_rates) -> float:
        """
        计算动态观看概率 W_{i,j}
        """
        # 确保retention_rates是列表并且所有元素都是浮点数
        if retention_rates is None:
            return 0.5
            
        # 将retention_rates转换为浮点数列表
        try:
            if isinstance(retention_rates, list):
                rates = [self._to_float(r) for r in retention_rates]
            else:
                # 如果是其他类型，尝试转换为列表
                rates = [self._to_float(retention_rates)]
        except:
            rates = [0.5] * (chunk_idx + 2)
        
        # 确保索引有效
        if chunk_idx >= len(rates):
            return 0.5
        if current_chunk_idx >= len(rates):
            current_chunk_idx = len(rates) - 1
            
        # 1. 全局条件概率
        R_j = rates[chunk_idx]
        R_curr = rates[current_chunk_idx] if current_chunk_idx < len(rates) else 0.5
        
        # 避免除零
        if R_curr < 1e-6:
            global_prob = R_j
        else:
            global_prob = R_j / R_curr
        global_prob = min(1.0, global_prob)  # 截断到[0,1]
        
        # 2. 个性化概率（基于滑动窗口的历史观看行为）
        history = self.sliding_window.get_history()
        if len(history) < 2:  # 历史数据不足时回退到全局
            return global_prob
        
        # 计算用户历史中看到类似深度的概率
        similar_history = []
        for (hist_video_id, hist_chunks, hist_retention) in history:
            # 计算相似度
            sim = self.video_similarity(hist_video_id, video_id)
            # 是否至少看到了chunk_idx
            reached = 1.0 if hist_chunks >= (chunk_idx + 1) else 0.0
            similar_history.append((sim, reached))
        total_sim = sum(sim for sim, _ in similar_history)
        if total_sim < 1e-6:
            return global_prob
            
        personal_prob = sum(sim * reached for sim, reached in similar_history) / total_sim
        result = self.alpha * global_prob + (1 - self.alpha) * personal_prob

        # with open('preload_tracking.txt', 'a', encoding='utf-8') as f:
        #     f.write(f"5\n")
        #     f.write(f"  len(history): {len(history)}\n")
        #     f.write(f"  video_id: {video_id}\n")
        #     f.write(f"  chunk_idx: {chunk_idx}\n")
        #     f.write(f"  global_prob: {global_prob}\n")
        #     f.write(f"  personal_prob: {personal_prob}\n")
        #     f.write(f"  W: {result}\n")

        return min(1.0, max(0.0, result))  # 确保在[0,1]范围内
    
    def compute_playback_distance(self, 
                                  target_video_id: int,
                                  target_chunk_idx: int,
                                  current_video_id: int,
                                  current_chunk_idx: int,
                                  video_durations: Dict[int, float]) -> float:
        """
        计算播放距离 Δ_{i,j}（秒）
        """
        # 确保所有ID都是整数
        target_video_id = int(target_video_id)
        current_video_id = int(current_video_id)
        
        # 如果目标在当前视频之前，返回大距离
        if target_video_id < current_video_id:
            return 1000.0
            
        distance = 0.0
        
        if target_video_id > current_video_id:
            # 当前视频剩余时长
            if current_video_id in video_durations:
                curr_duration = video_durations[current_video_id]
                played = (current_chunk_idx + 1) * self.chunk_duration
                remaining = max(0, curr_duration - played)
                distance += remaining
            
            # 中间完整视频
            for v in range(current_video_id + 1, target_video_id):
                if v in video_durations:
                    distance += video_durations[v]
            
            # 目标视频内到目标块的时长
            target_play_time = (target_chunk_idx + 1) * self.chunk_duration
            distance += target_play_time
        else:
            # 同一视频内
            for c in range(current_chunk_idx + 1, target_chunk_idx + 1):
                distance += self.chunk_duration
        
        return max(0.1, distance)  # 确保正数
    
    def get_urgency_score(self, distance: float) -> float:
        """计算紧迫性分数 U_{i,j}"""
        return 1.0 / (distance + 1.0)
    
    def get_network_weight(self, network_state: Tuple[float, float, float]) -> float:
        """
        获取网络动态权重 λ(N_t)
        """
        b_t, v_t, d_t = network_state
        
        # 归一化带宽（假设0-5 Mbps范围）
        norm_b = min(1.0, b_t / 5.0)
        
        # 归一化方差
        norm_v = min(1.0, v_t / 2.0)
        
        # 网络质量：带宽高、方差低 = 好网络
        network_quality = norm_b * (1.0 - norm_v * 0.5)
        
        # λ与网络质量负相关：好网络时λ小（重概率），差网络时λ大（重紧迫）
        lambda_t = self.lambda_max - (self.lambda_max - self.lambda_min) * network_quality
        lambda_t = max(self.lambda_min, min(self.lambda_max, lambda_t))
        
        return lambda_t
    
    def get_preloading_depth(self, 
                             network_state: Tuple[float, float, float],
                             trend: float,
                             buffer_ms: float) -> int:
        """
        获取预加载深度 D_t (块数)
        """
        b_t, v_t, d_t = network_state
        
        depth = self.base_depth
        
        # 根据网络调整
        if b_t > 4.0 and trend > 0.1:
            depth = self.max_depth  # 网络好且改善
        elif b_t < 1.5 or trend < -0.2:
            depth = self.min_depth  # 网络差或恶化
        elif b_t > 2.5:
            depth = self.base_depth
            
        return depth
    
    def get_bitrate(self,
                    network_state: Tuple[float, float, float],
                    buffer_ms: float,
                    is_preload: bool = False) -> int:
        """
        获取目标码率 Q_t
        返回码率等级索引 0,1,2
        """
        b_t, v_t, d_t = network_state
        
        if is_preload:
            # 预加载用中等码率
            return 1
        elif buffer_ms < 500 or b_t < 1.0:
            return 0  # 低码率
        elif buffer_ms > 3000 and b_t > 3.0:
            return 2  # 高码率
        elif buffer_ms > 1000:
            return 1  # 中等码率
        else:
            return 0  # 低码率
    
    def build_candidate_chunks(self, 
                           Players: List,
                           depth: int,
                           current_video_id: int,
                           current_chunk: int = 0,
                           current_buffer: float = 0,
                           network_state: Tuple = None,
                           trend: float = 0) -> List[Tuple[int, int]]:
        """
        构建候选块集合 - 使用网络状态动态调整
        返回 (video_id, chunk_idx) 列表
        """
        candidates = []
        current_video_id = int(current_video_id)
        
        print(f"\n[DEBUG] ===== 构建候选集 =====")
        print(f"[DEBUG] current_video_id={current_video_id}, depth={depth}, buffer={current_buffer}ms")
        
        for i, player in enumerate(Players):
            video_id = current_video_id + i
            video_id = int(video_id)
            
            try:
                total_chunks = player.get_chunk_sum()
                downloaded = self.downloaded_counts.get(video_id, 0)
                next_chunk = downloaded
                
                print(f"\n[DEBUG] 视频{video_id}: i={i}, total_chunks={total_chunks}, downloaded={downloaded}")
                
                # 获取还可以下载多少块
                is_current = (i == 0)

                max_allowed = self._get_safe_chunks_to_download(player, video_id, is_current)  # max_allowed:P_t_max
                
                print(f"[DEBUG] 视频{video_id}: next_chunk={next_chunk}, max_allowed={max_allowed}")
                
                # 添加到候选集
                for j in range(next_chunk, max_allowed):
                    candidates.append((video_id, j))
                    print(f"[DEBUG]   添加候选: 视频{video_id}块{j}")
                        
            except Exception as e:
                print(f"[DEBUG] 视频{video_id}处理出错: {e}")
                continue
        
        print(f"[DEBUG] 最终候选集: {[(v,c) for v,c in candidates]}")
        return candidates
    
    def update_after_playback(self, 
                              video_id: int,
                              chunks_watched: int,
                              bandwidth: float,
                              download_time: float,
                              retention_at_exit: float = 0):
        """
        播放后更新状态
        """
        # 更新滑动窗口
        self.sliding_window.add(video_id, chunks_watched, retention_at_exit)
        
        # 更新网络监控
        self.network_monitor.update(bandwidth, download_time)


# ========== 主算法类（适配你的接口） ==========

class Algorithm:
    def __init__(self):
        # 初始化Faucet算法实例
        self.faucet = FaucetAlgorithm()
        self.buffer_size = 0
        self.last_download_time = 0
        self.last_video_size = 0
        self.step_count = 0
        self.downloaded_counts = {}  # video_id -> 已下载块数
        self.VIDEO_BIT_RATE = [750, 1200, 1850]  # 保持与你的代码一致
        
        # 状态跟踪
        self.consecutive_sleeps = 0
        self.emergency_mode = False
        self.download_history = {}  # 添加download_history以兼容提示信息

        # 用作 D_t
        self.preload_depth = 0
        self.preload_curr = 0
        self.preload_chunk_list = []
        
    # Intial
    def Initialize(self):
        self.buffer_size = 0
        self.last_download_time = 0
        self.last_video_size = 0
        self.step_count = 0
        self.downloaded_counts = {}
        self.consecutive_sleeps = 0
        self.emergency_mode = False
        self.download_history = {}

        self.preload_depth = 0
        self.preload_curr = 0
        self.preload_chunk_list = []

        print("Faucet algorithm initialized")

    def run(self, delay, rebuf, video_size, end_of_video, play_video_id, Players, first_step=False):
        self.step_count += 1
        self.faucet.step_count = self.step_count
        
        self.faucet.sliding_window.add(play_video_id,Players[0].get_play_chunk())
        
        # ===== 第一步处理 =====
        if first_step:
            self.Initialize()
            self.download_history[play_video_id] = {
                'count': 0, 'preload_count': 0, 'play_count': 0, 'last_download': 0
            }
            print(f"[INIT] 初始化视频{play_video_id}下载历史，初始下载块数=0")
            return play_video_id, 0, 0.0
        
        # ===== 初始化返回值 =====
        download_video_id = play_video_id
        bit_rate = 0
        sleep_time = 0.0
        is_preload = False
        
        # ===== 安全检查 =====
        if len(Players) == 0:
            print(f"[Step {self.step_count}] 安全检查：无可用播放器，返回休眠50ms")
            return play_video_id, 0, 50.0
        
        current_player = Players[0]
        
        # ===== 1. 更新网络监控 =====
        if video_size > 0 and delay > 0:
            bandwidth_mbps = (video_size * 8 / 1e6) / (delay / 1000)
            self.faucet.network_monitor.update(bandwidth_mbps, delay)
            self.last_download_time = delay
            self.last_video_size = video_size
            print(f"[网络监控] 带宽={bandwidth_mbps:.2f}Mbps, 下载时间={delay}ms")
        
        # ===== 2. 获取当前状态 =====
        try:
            current_chunk = current_player.get_chunk_counter()
            total_chunks = current_player.get_chunk_sum()
            buffer_ms = current_player.get_buffer_size()
            has_chunks = current_chunk < total_chunks
            print(f"[当前状态] 视频{play_video_id}: chunk={current_chunk}/{total_chunks}, 缓冲区={buffer_ms}ms, 有块={has_chunks}")
        except Exception as e:
            current_chunk = 0
            total_chunks = 10
            buffer_ms = 2000
            has_chunks = True
            print(f"[当前状态] 获取失败: {str(e)}, 使用默认值")
        
        
        
        # ===== 4. 获取网络状态和趋势 =====
        network_state = self.faucet.network_monitor.get_network_state()
        trend = self.faucet.network_monitor.compute_trend()
        print(f"[网络状态] b_t={network_state[0]:.2f}Mbps, v_t={network_state[1]:.2f}, 趋势={trend:.3f}")
        with open('network_tracking.txt', 'a', encoding='utf-8') as f:
            f.write(f"[网络状态] b_t={network_state[0]:.2f}Mbps, v_t={network_state[1]:.2f}, 趋势={trend:.3f}\n")
        
        
        # ===== 7. 获取当前视频已下载块数 =====
        current_video_info = self.download_history.get(play_video_id, {
            'count': 0, 'preload_count': 0, 'play_count': 0, 'last_download': 0
        })
        current_downloaded = current_video_info['count']
        print(f"[下载状态] 当前视频已下载={current_downloaded}块")
        print(f"self.preload_depth={self.preload_depth},  self.preload_curr={self.preload_curr},  play_video_id={play_video_id}")

        # ===== 3. 紧急模式检查 =====
        if rebuf > 0:
            self.emergency_mode = True
            print(f"[紧急模式] 检测到卡顿(rebuf={rebuf}ms)，进入紧急模式")
        if buffer_ms < 500 and has_chunks:
            self.emergency_mode = True
            print(f"[紧急模式] 缓冲区过低({buffer_ms}ms<500ms)，进入紧急模式")

        # ===== 8. 决策：下载当前还是预加载 =====
        if has_chunks and self.emergency_mode:
            # 下载当前视频
            download_video_id = play_video_id
            is_preload = False
            
            # 更新下载历史
            self.download_history[play_video_id] = {
                'count': current_downloaded + 1,
                'preload_count': current_video_info['preload_count'],
                'play_count': current_video_info['play_count'] + 1,
                'last_download': self.step_count
            }
            self.downloaded_counts[play_video_id] = current_downloaded + 1
            self.faucet.downloaded_counts[play_video_id] = current_downloaded + 1
        
            print(f"[DEBUG] 更新下载计数: 视频{download_video_id} 原={current_downloaded} 新={current_downloaded+1}")
            
            self.consecutive_sleeps = 0
            self.emergency_mode = False
            print(f"[决策] 下载当前视频{download_video_id}，下载后块数={current_downloaded + 1}")

            # ===== 9. 选择码率 =====
            bit_rate = self.faucet.get_bitrate(network_state, buffer_ms, is_preload)
            # bit_rate = 0
            bitrate_kbps = self.VIDEO_BIT_RATE[bit_rate]
            reason = "预加载" if is_preload else "当前视频"
            print(f"[码率选择] bit_rate={bit_rate}({bitrate_kbps}kbps), 原因={reason}")
            return download_video_id, bit_rate, 0.0
        
        if self.preload_depth ==  0:

            self.preload_curr = 0
            self.preload_chunk_list.clear()
        
            # 尝试预加载

            # ===== 5. 获取预加载深度 =====
            depth = self.faucet.get_preloading_depth(network_state, trend, buffer_ms)
            self.preload_depth = depth
            print(f"[预加载深度] depth={depth}块")

            # ===== 6. 获取网络权重λ =====
            lambda_t = self.faucet.get_network_weight(network_state)
            print(f"[网络权重] λ={lambda_t:.2f} (范围[{self.faucet.lambda_min}, {self.faucet.lambda_max}])")
            with open('network_tracking.txt', 'a', encoding='utf-8') as f:
                f.write(f"[网络权重] λ={lambda_t:.2f} (范围[{self.faucet.lambda_min}, {self.faucet.lambda_max}])\n")

            print(f"[决策] 尝试预加载...")
            candidates = self.faucet.build_candidate_chunks(
                Players, 
                depth, 
                play_video_id,
                current_chunk=current_chunk,
                current_buffer=buffer_ms,
                network_state=network_state,
                trend=trend
            )
            print(f"[候选集] 共{len(candidates)}个候选块")
            
            if candidates:
                
                for (video_id, chunk_idx) in candidates:
                    if video_id == play_video_id and chunk_idx <= current_chunk:
                        continue
                    
                    player_idx = video_id - play_video_id
                    if 0 <= player_idx < len(Players):
                        player = Players[player_idx]
                        try:
                            user_time, retention_rates = player.get_user_model()
                            
                            # 计算观看概率
                            curr_chunk_for_prob = current_chunk if video_id == play_video_id else 0
                            W = self.faucet.compute_watch_probability(
                                video_id=video_id,
                                chunk_idx=chunk_idx,
                                current_chunk_idx=curr_chunk_for_prob,
                                retention_rates=retention_rates
                            )
                            
                            # 留存率概率决策
                            if retention_rates and chunk_idx < len(retention_rates):
                                watch_prob = float(retention_rates[chunk_idx])
                            else:
                                watch_prob = 0.5
                            vrandom = random.random()
                            print(f"[概率评估] 视频{video_id}块{chunk_idx}: 留存率={watch_prob:.2f}, 随机值={vrandom:.2f}")
                            
                            if vrandom > watch_prob:
                                print(f"  → 概率过滤跳过")
                                continue
                            

                            video_durations = {}
                            for i, p in enumerate(Players):
                                video_id_key = int(play_video_id + i)  # 确保键是整数
                                # 调用get_video_len()方法获取视频的长度
                                video_durations[video_id_key] = p.get_video_len()
                                
                            
                            distance = self.faucet.compute_playback_distance(
                                target_video_id=int(video_id),
                                target_chunk_idx=chunk_idx,
                                current_video_id=int(play_video_id),
                                current_chunk_idx=current_chunk,
                                video_durations=video_durations
                            )
                            U = self.faucet.get_urgency_score(distance)
                            
                            # 综合分数
                            S = lambda_t * U + (1 - lambda_t) * W
                            with open('preload_tracking.txt', 'a', encoding='utf-8') as f:
                                f.write(f"  U: {U}\n")
                                f.write(f"  lambda_t: {lambda_t}\n")
                                f.write(f"  S: {S}\n")
                                f.write("-" * 40 + "\n")
                            print(f"[评分] U={U:.2f}, W={W:.2f}, S={S:.2f}")

                            chunk = {
                                'video_id': video_id,
                                'chunk_id': chunk_idx,
                                'chunk_score': S
                            }
                            self.preload_chunk_list.append(chunk)
                                
                        except Exception as e:
                            print(f"[错误] 评估视频{video_id}失败: {str(e)}")
                            traceback.print_exc()  # 打印详细错误堆栈
                            continue

                self.preload_chunk_list.sort(key=lambda x: x['chunk_score'], reverse=True)

                with open('preload_tracking.txt', 'a', encoding='utf-8') as f:
                    f.write(f"  preload_depth: {self.preload_depth}\n")
                    f.write(f"  preload_chunk_list长度: {len(self.preload_chunk_list)}\n")
                    
                    if self.preload_chunk_list:
                        for i, chunk in enumerate(self.preload_chunk_list):
                            f.write(f"    [{i}] video={chunk['video_id']}, "
                                f"chunk={chunk['chunk_id']}, "
                                f"score={chunk['chunk_score']:.3f}\n")
                    
                    f.write("-" * 40 + "\n")
                
            else:
                # 无候选，休眠
                sleep_time = 50.0
                self.consecutive_sleeps += 1
                bit_rate = 0

                self.preload_depth = 0

                print(f"[决策] 无候选块，休眠{sleep_time}ms")
                return download_video_id, bit_rate, sleep_time
                
        if self.preload_depth >  0:
            download_video_id = play_video_id
            bit_rate = 0
            sleep_time = 0.0
            if self.preload_depth > self.preload_curr:
                deciside_loop = True
                while deciside_loop:
                    if self.preload_chunk_list and 0 <= self.preload_curr < len(self.preload_chunk_list):
                        download_video_id = self.preload_chunk_list[self.preload_curr]['video_id']
                        if download_video_id < play_video_id :
                            self.preload_curr = self.preload_curr + 1
                            continue
                        download_chunk_id = self.preload_chunk_list[self.preload_curr]['chunk_id']
                        if download_chunk_id < Players[download_video_id - play_video_id].get_chunk_counter():
                            self.preload_curr = self.preload_curr + 1
                            continue

                        is_preload = True
                        
                        # 更新下载历史
                        preload_info = self.download_history.get(download_video_id, {
                            'count': 0, 'preload_count': 0, 'play_count': 0, 'last_download': 0
                        })
                        self.download_history[download_video_id] = {
                            'count': preload_info['count'] + 1,
                            'preload_count': preload_info['preload_count'] + 1,
                            'play_count': preload_info['play_count'],
                            'last_download': self.step_count
                        }
                        self.downloaded_counts[download_video_id] = preload_info['count'] + 1
                        self.faucet.downloaded_counts[download_video_id] = preload_info['count'] + 1
                        
                        self.consecutive_sleeps = 0

                        c_chunk = self.preload_chunk_list[self.preload_curr]
                        print(f"[决策] 预加载视频{download_video_id}块{c_chunk['chunk_id']}, 分数={c_chunk['chunk_score']:.2f}")
                        self.preload_curr = self.preload_curr + 1
                        deciside_loop = False
                        break
                    else:
                        self.preload_depth = 0
                        return play_video_id,0,50.0
            else:
                self.preload_depth = 0
                self.preload_curr = 0

                # 无合适预加载，休眠
                sleep_time = 100.0 if buffer_ms > 2000 else 30.0
                self.consecutive_sleeps += 1
                bit_rate = 0
                print(f"[决策] 无合适预加载，休眠{sleep_time}ms")
                return download_video_id, bit_rate, sleep_time
            # ===== 9. 选择码率 =====
            bit_rate = self.faucet.get_bitrate(network_state, buffer_ms, is_preload)
            bitrate_kbps = self.VIDEO_BIT_RATE[bit_rate]
            reason = "预加载" if is_preload else "当前视频"
            print(f"[码率选择] bit_rate={bit_rate}({bitrate_kbps}kbps), 原因={reason}")
            
            # ===== 最终决策输出 =====
            action = "Sleep" if sleep_time > 0 else f"{'Preload' if is_preload else 'Download'} video {download_video_id}"
            print(f"[最终决策] {action}, 码率={bit_rate}({bitrate_kbps}kbps), 休眠={sleep_time:.1f}ms, 紧急模式={self.emergency_mode}")
            if  self.preload_curr==self.preload_depth :
                    self.preload_depth = 0
            return download_video_id, bit_rate, sleep_time
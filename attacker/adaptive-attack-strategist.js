'use strict';

/**
 * AdaptiveAttackStrategist
 * 此攻击者根据系统状态和防御措施动态调整攻击策略
 * 能够学习和适应系统的防御机制
 */
class AdaptiveAttackStrategist {
    constructor(transfer, registerAttackerTimeEvent, eventQ, nodeNum, byzantineNodeNum, getClockTime) {
        this.transfer = transfer;
        this.registerAttackerTimeEvent = registerAttackerTimeEvent;
        this.eventQ = eventQ;
        this.nodeNum = nodeNum;
        this.byzantineNodeNum = byzantineNodeNum;
        this.getClockTime = getClockTime;

        // 攻击策略状态
        this.strategies = {
            messageDelay: { active: true, effectiveness: 0.8, adjustRate: 0.07 },
            messageDropping: { active: true, effectiveness: 0.8, adjustRate: 0.07 },
            eventTampering: { active: true, effectiveness: 0.8, adjustRate: 0.07 },
            blockTampering: { active: true, effectiveness: 0.8, adjustRate: 0.07 },
            syncInterference: { active: true, effectiveness: 0.8, adjustRate: 0.07 }
        };

        // 系统状态监控
        this.systemState = {
            consensusProgress: 0,      // 共识进度指标
            detectionSigns: 0,         // 可能被检测到的迹象
            nodeActivity: {},          // 各节点活动状态
            roundProgression: {},      // 轮次推进情况
            lastDecisionTime: this.getClockTime(),  // 上次观察到决策的时间
            successfulAttacks: 0,      // 成功攻击计数
            failedAttacks: 0           // 失败攻击计数
        };

        // 初始化节点活动状态
        for (let i = 1; i <= this.nodeNum; i++) {
            this.systemState.nodeActivity[i] = {
                lastActive: 0,
                messageCount: 0,
                responseRate: 1.0
            };

            this.systemState.roundProgression[i] = {
                currentRound: 0,
                lastRoundChange: 0
            };
        }

        // 启动策略评估和调整
        this.registerAttackerTimeEvent(
            { name: 'evaluateStrategies' },
            5000 // 5秒后评估策略
        );

        console.log('Adaptive attack strategist initialized');
    }

    attack(packets) {
        // 更新系统状态基于观察的包
        this.updateSystemState(packets);

        return packets.map(packet => {
            let modifiedPacket = { ...packet };

            // 应用当前活跃的攻击策略
            if (this.strategies.messageDelay.active &&
                Math.random() < this.strategies.messageDelay.effectiveness) {
                modifiedPacket = this.applyMessageDelay(modifiedPacket);
            }

            if (this.strategies.messageDropping.active &&
                Math.random() < this.strategies.messageDropping.effectiveness) {
                // 如果返回null，表示丢弃消息
                const result = this.applyMessageDropping(modifiedPacket);
                if (result === null) return null;
                modifiedPacket = result;
            }

            if (modifiedPacket.content) {
                if (this.strategies.eventTampering.active &&
                    Math.random() < this.strategies.eventTampering.effectiveness &&
                    modifiedPacket.content.type === 'babble-event') {
                    modifiedPacket = this.applyEventTampering(modifiedPacket);
                }

                if (this.strategies.blockTampering.active &&
                    Math.random() < this.strategies.blockTampering.effectiveness &&
                    modifiedPacket.content.type === 'babble-block') {
                    modifiedPacket = this.applyBlockTampering(modifiedPacket);
                }

                if (this.strategies.syncInterference.active &&
                    Math.random() < this.strategies.syncInterference.effectiveness &&
                    (modifiedPacket.content.type === 'babble-sync-request' ||
                        modifiedPacket.content.type === 'babble-sync-response')) {
                    modifiedPacket = this.applySyncInterference(modifiedPacket);
                }
            }

            return modifiedPacket;
        }).filter(packet => packet !== null); // 过滤掉被丢弃的包
    }

    updateSystemState(packets) {
        const currentTime = this.getClockTime();

        for (const packet of packets) {
            // 更新节点活动状态
            const nodeId = parseInt(packet.src);
            if (nodeId && this.systemState.nodeActivity[nodeId]) {
                this.systemState.nodeActivity[nodeId].lastActive = currentTime;
                this.systemState.nodeActivity[nodeId].messageCount++;
            }

            // 分析消息内容，更新系统状态
            if (packet.content) {
                // 检测到关于视图变更的消息，可能表示防御机制激活
                if (packet.content.type === 'view-change' ||
                    packet.content.type === 'new-view') {
                    this.systemState.detectionSigns += 0.2;
                }

                // 检测轮次进展
                if (packet.content.type === 'babble-event' &&
                    packet.content.event &&
                    packet.content.event.round !== undefined) {
                    const srcId = parseInt(packet.src);
                    if (srcId && this.systemState.roundProgression[srcId]) {
                        const currentRound = packet.content.event.round;
                        const prevRound = this.systemState.roundProgression[srcId].currentRound;

                        if (currentRound > prevRound) {
                            this.systemState.roundProgression[srcId].currentRound = currentRound;
                            this.systemState.roundProgression[srcId].lastRoundChange = currentTime;

                            // 轮次推进可能表示共识进展
                            this.systemState.consensusProgress += 0.1;
                        }
                    }
                }

                // 检测决策块
                if (packet.content.type === 'babble-block' &&
                    packet.content.block &&
                    packet.content.block.final === true) {
                    this.systemState.lastDecisionTime = currentTime;
                    this.systemState.consensusProgress += 0.3;
                }
            }
        }

        // 随着时间推移，逐渐减少检测迹象
        if (this.systemState.detectionSigns > 0) {
            this.systemState.detectionSigns -= 0.01;
            if (this.systemState.detectionSigns < 0) this.systemState.detectionSigns = 0;
        }

        // 随着时间推移，逐渐减少共识进度指标
        if (this.systemState.consensusProgress > 0) {
            this.systemState.consensusProgress -= 0.03;
            if (this.systemState.consensusProgress < 0) this.systemState.consensusProgress = 0;
        }
    }

    applyMessageDelay(packet) {
        // 如果共识进度高，增加延迟
        const delayMultiplier = 1 + this.systemState.consensusProgress;

        // 基础延迟时间
        const baseDelay = Math.random() * 0.5; // 0-0.5秒的基础延迟

        // 应用延迟
        packet.delay = (packet.delay || 0) + baseDelay * delayMultiplier;

        return packet;
    }

    applyMessageDropping(packet) {
        // 根据目标节点的活跃度决定是否丢弃
        const dstId = parseInt(packet.dst);

        // 如果目标是广播或者未知节点，低概率丢弃
        if (packet.dst === 'broadcast' || !dstId || !this.systemState.nodeActivity[dstId]) {
            if (Math.random() < 0.05) return null; // 5%概率丢弃
            return packet;
        }

        // 目标节点最近不活跃，更高概率丢弃
        const timeSinceActive = this.getClockTime() - this.systemState.nodeActivity[dstId].lastActive;
        if (timeSinceActive > 5 && Math.random() < 0.3) {
            return null; // 30%概率丢弃
        }

        // 根据消息类型决定丢弃
        if (packet.content && packet.content.type) {
            // 对同步请求和响应的丢弃概率更高
            if ((packet.content.type === 'babble-sync-request' ||
                packet.content.type === 'babble-sync-response') &&
                Math.random() < 0.2) {
                return null; // 20%概率丢弃
            }

            // 对普通事件消息，根据节点活跃度丢弃
            if (packet.content.type === 'babble-event' && Math.random() < 0.1) {
                return null; // 10%概率丢弃
            }
        }

        return packet;
    }

    applyEventTampering(packet) {
        const event = packet.content.event;
        if (!event) return packet;

        // 检查是否是关键事件
        const isKeyEvent = event.isWitness === true ||
            (event.round !== undefined && event.round > 0);

        // 关键事件有更高篡改概率
        if (isKeyEvent || Math.random() < 0.4) {
            // 根据系统状态选择篡改策略
            if (this.systemState.detectionSigns > 0.5) {
                // 如果检测到强防御，使用更微妙的篡改
                if (event.timestamp !== undefined) {
                    // 微调时间戳
                    event.timestamp += (Math.random() * 0.2 - 0.1);
                }
            } else {
                // 使用更激进的篡改
                const strategy = Math.random();

                if (strategy < 0.3 && event.selfParent) {
                    // 破坏事件链
                    event.selfParent = null;
                }
                else if (strategy < 0.6) {
                    // 篡改交易
                    if (!event.transactions) event.transactions = [];
                    event.transactions.push(`ADAPT_INJECT_${Math.random().toString(36).substring(2, 8)}`);
                }
                else if (event.round !== undefined) {
                    // 篡改轮次
                    event.round = Math.max(0, event.round + Math.floor(Math.random() * 3) - 1);
                }
            }

            // 更新哈希以使篡改看起来有效
            if (event.hash) {
                event.hash = `adaptive_${Math.random().toString(36).substring(2, 15)}`;
            }

            // 记录攻击尝试
            this.systemState.successfulAttacks++;
        } else {
            this.systemState.failedAttacks++;
        }

        return packet;
    }

    applyBlockTampering(packet) {
        const block = packet.content.block;
        if (!block) return packet;

        // 根据系统状态决定篡改策略
        if (this.systemState.detectionSigns > 0.6) {
            // 高检测风险，只做轻微修改
            if (block.timestamp !== undefined) {
                block.timestamp += (Math.random() * 0.5 - 0.25);
            }
        } else {
            // 低检测风险，做更明显的篡改
            if (block.transactions && block.transactions.length > 0) {
                const txIndex = Math.floor(Math.random() * block.transactions.length);
                block.transactions[txIndex] = `ADAPTIVE_TX_${Math.random().toString(36).substring(2, 8)}`;
            }

            // 修改事件引用
            if (block.events && block.events.length > 0 && Math.random() < 0.3) {
                const eventIndex = Math.floor(Math.random() * block.events.length);
                block.events[eventIndex] = `fake_event_${Math.random().toString(36).substring(2, 10)}`;
            }
        }

        // 更新区块哈希
        if (block.hash) {
            block.hash = `adaptive_block_${Math.random().toString(36).substring(2, 12)}`;
        }

        this.systemState.successfulAttacks++;
        return packet;
    }

    applySyncInterference(packet) {
        if (packet.content.type === 'babble-sync-request') {
            // 干扰同步请求
            if (packet.content.knownEvents && Math.random() < 0.4) {
                // 随机修改已知事件引用
                for (const nodeID in packet.content.knownEvents) {
                    if (Math.random() < 0.3) {
                        packet.content.knownEvents[nodeID] = `fake_ref_${Math.random().toString(36).substring(2, 10)}`;
                    }
                }
            }
        }
        else if (packet.content.type === 'babble-sync-response') {
            // 干扰同步响应
            if (packet.content.events && packet.content.events.length > 0) {
                // 根据系统状态调整干扰强度
                const interferenceRate = this.systemState.detectionSigns > 0.5 ? 0.2 : 0.4;

                if (Math.random() < interferenceRate) {
                    // 随机删除一些事件
                    const removeCount = Math.floor(packet.content.events.length * 0.2);
                    for (let i = 0; i < removeCount; i++) {
                        if (packet.content.events.length > 1) { // 至少保留一个事件
                            const idx = Math.floor(Math.random() * packet.content.events.length);
                            packet.content.events.splice(idx, 1);
                        }
                    }
                }

                // 随机篡改部分事件
                for (let i = 0; i < packet.content.events.length; i++) {
                    if (Math.random() < interferenceRate) {
                        const event = packet.content.events[i];

                        // 轻微篡改
                        if (event.timestamp !== undefined) {
                            event.timestamp += (Math.random() * 0.5 - 0.25);
                        }

                        // 更新哈希
                        if (event.hash) {
                            event.hash = `adapt_sync_${Math.random().toString(36).substring(2, 10)}`;
                        }
                    }
                }
            }
        }

        this.systemState.successfulAttacks++;
        return packet;
    }

    onTimeEvent(event) {
        if (event.functionMeta.name === 'evaluateStrategies') {
            this.evaluateAndAdjustStrategies();

            // 再次注册评估事件
            this.registerAttackerTimeEvent(
                { name: 'evaluateStrategies' },
                8000 // 8秒后再次评估
            );
        }
    }

    evaluateAndAdjustStrategies() {
        const currentTime = this.getClockTime();

        // 计算当前策略有效性
        const effectivenessMetrics = {
            consensusDelay: currentTime - this.systemState.lastDecisionTime, // 共识延迟
            attackSuccessRate: this.systemState.successfulAttacks /
                (this.systemState.successfulAttacks + this.systemState.failedAttacks + 0.1),
            detectionLevel: this.systemState.detectionSigns // 被检测级别
        };

        console.log(`Evaluating strategies: consensusDelay=${effectivenessMetrics.consensusDelay.toFixed(2)}, successRate=${effectivenessMetrics.attackSuccessRate.toFixed(2)}, detection=${effectivenessMetrics.detectionLevel.toFixed(2)}`);

        // 根据不同指标调整策略
        this.adjustStrategy('messageDelay',
            effectivenessMetrics.consensusDelay > 5, // 如果共识延迟大，说明有效
            effectivenessMetrics.detectionLevel < 0.4); // 如果检测低，安全

        this.adjustStrategy('messageDropping',
            effectivenessMetrics.consensusDelay > 3,
            effectivenessMetrics.detectionLevel < 0.5);

        this.adjustStrategy('eventTampering',
            effectivenessMetrics.attackSuccessRate > 0.6,
            effectivenessMetrics.detectionLevel < 0.7);

        this.adjustStrategy('blockTampering',
            effectivenessMetrics.consensusDelay > 4,
            effectivenessMetrics.detectionLevel < 0.6);

        this.adjustStrategy('syncInterference',
            effectivenessMetrics.consensusDelay > 2,
            effectivenessMetrics.detectionLevel < 0.4);

        // 重置计数器
        this.systemState.successfulAttacks = 0;
        this.systemState.failedAttacks = 0;
    }

    adjustStrategy(strategyName, isEffective, isSafe) {
        const strategy = this.strategies[strategyName];
        if (!strategy) return;

        // 根据有效性和安全性调整策略
        if (isEffective && isSafe) {
            // 策略有效且安全，增加使用率
            strategy.effectiveness += strategy.adjustRate;
            strategy.active = true;
        }
        else if (!isEffective && isSafe) {
            // 策略无效但安全，小幅度减少使用率
            strategy.effectiveness -= strategy.adjustRate / 2;
        }
        else if (isEffective && !isSafe) {
            // 策略有效但不安全，稍微减少使用率
            strategy.effectiveness -= strategy.adjustRate;
        }
        else {
            // 策略无效且不安全，大幅减少使用率
            strategy.effectiveness -= strategy.adjustRate * 2;
        }

        // 限制范围
        strategy.effectiveness = Math.min(0.9, Math.max(0.1, strategy.effectiveness));

        // 如果效率太低，暂时停用该策略
        if (strategy.effectiveness < 0.2) {
            strategy.active = false;
            // 增加调整率，以便快速恢复
            strategy.adjustRate = Math.min(0.15, strategy.adjustRate * 1.5);
        } else {
            strategy.active = true;
            // 正常调整率
            strategy.adjustRate = Math.max(0.05, strategy.adjustRate * 0.9);
        }

        console.log(`Adjusted ${strategyName}: active=${strategy.active}, effectiveness=${strategy.effectiveness.toFixed(2)}, adjustRate=${strategy.adjustRate.toFixed(2)}`);
    }

    updateParam() {
        return false; // 不更新参数
    }
}

module.exports = AdaptiveAttackStrategist;
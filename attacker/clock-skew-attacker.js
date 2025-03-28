'use strict';

/**
 * EnhancedClockSkewAttacker
 * 增强型时钟偏移攻击器 - 针对多种共识协议的时间相关机制进行攻击
 */
class ClockSkewAttacker {
    constructor(transfer, registerAttackerTimeEvent, eventQ, nodeNum, byzantineNodeNum, getClockTime) {
        this.transfer = transfer;
        this.registerAttackerTimeEvent = registerAttackerTimeEvent;
        this.eventQ = eventQ;
        this.nodeNum = nodeNum;
        this.byzantineNodeNum = byzantineNodeNum;
        this.getClockTime = getClockTime;

        // 基础攻击参数 - 大幅提高默认值
        this.timestampManipulationRate = 0.1;  // 基础时间戳篡改概率提高到50%
        this.maxTimeSkew = 5;                 // 最大时间偏移提高到15秒
        this.targetCriticalEvents = false;      // 默认针对关键事件
        this.extremeTimeSkewProbability = 0.1; // 极端时间篡改概率

        // 协议特定攻击参数
        this.protocolParams = {
            // 不同协议的攻击参数
            babble: {
                enabled: true,       // 最适合此攻击
                attackRate: 0.7,     // 高概率攻击
                timeSkewFactor: 1.5  // 更大的时间偏移
            },
            pbft: {
                enabled: true,       // 低效但仍可能有用
                attackRate: 0.4,     // 中等概率
                timeSkewFactor: 0.8  // 较小偏移，更关注超时
            },
            hotstuff: {
                enabled: true,       // 中等效果
                attackRate: 0.6,     // 中高概率
                timeSkewFactor: 1.2  // 较大偏移
            },
            libra: {
                enabled: true,       // 中等效果
                attackRate: 0.1,     // 中高概率
                timeSkewFactor: 0.2  // 较大偏移
            },
            algorand: {
                enabled: true,       // 中低效果
                attackRate: 0.5,     // 中等概率
                timeSkewFactor: 1.0  // 标准偏移
            },
            asyncBA: {
                enabled: false,      // 几乎无效
                attackRate: 0.3,     // 低概率
                timeSkewFactor: 0.5  // 小偏移
            }
        };

        // 超时攻击的延迟范围
        this.timeoutDelayRange = {
            min: 0.1,  // 最小延迟系数
            max: 2.0   // 最大延迟系数
        };

        // 记录观察到的时间戳范围和协议类型
        this.observedTimestamps = {
            min: Infinity,
            max: -Infinity,
            avg: 0,
            count: 0
        };

        this.detectedProtocols = new Set();

        // 使用更激进的初始策略
        this.useExtremeSkews = true;
        this.attackTimeouts = true;

        // 开始周期性变更攻击策略
        this.registerAttackerTimeEvent(
            { name: 'escalateAttack' },
            10000 // 10秒后升级攻击
        );

        // console.log("EnhancedClockSkewAttacker 已初始化，攻击率：" + this.timestampManipulationRate);
    }

    attack(packets) {
        this.updateObservedTimestamps(packets);
        this.detectProtocols(packets);

        return packets.map(packet => {
            if (!packet.content) return packet;

            // 检测协议类型
            const protocol = this.identifyProtocol(packet);
            if (!protocol || !this.protocolParams[protocol].enabled) {
                return packet; // 不攻击禁用的协议
            }

            const attackRate = this.protocolParams[protocol].attackRate;
            const timeSkewFactor = this.protocolParams[protocol].timeSkewFactor;

            // 决定是否攻击此消息
            if (Math.random() >= attackRate) {
                return packet; // 跳过此消息
            }

            // 应用协议特定攻击
            switch (protocol) {
                case 'babble':
                    this.attackBabbleMessage(packet, timeSkewFactor);
                    break;
                case 'pbft':
                    this.attackPBFTMessage(packet, timeSkewFactor);
                    break;
                case 'hotstuff':
                    this.attackHotStuffMessage(packet, timeSkewFactor);
                    break;
                case 'libra':
                    this.attackLibraMessage(packet, timeSkewFactor);
                    break;
                case 'algorand':
                    this.attackAlgorandMessage(packet, timeSkewFactor);
                    break;
                case 'asyncBA':
                    this.attackAsyncBAMessage(packet, timeSkewFactor);
                    break;
            }

            return packet;
        });
    }

    // 识别消息所属协议
    identifyProtocol(packet) {
        const content = packet.content;
        if (!content || !content.type) return null;

        const msgType = content.type.toLowerCase();

        if (msgType.includes('babble') || msgType.includes('ssb')) {
            return 'babble';
        } else if (msgType.includes('pbft')) {
            return 'pbft';
        } else if (msgType.includes('hotstuff') || msgType.includes('viewchange')) {
            return 'hotstuff';
        } else if (msgType.includes('libra')) {
            return 'libra';
        } else if (msgType.includes('algorand') ||
            (msgType.includes('proposal') && !msgType.includes('hotstuff'))) {
            return 'algorand';
        } else if (msgType.includes('async') || msgType.includes('ba-')) {
            return 'asyncBA';
        }

        return null;
    }

    // 检测协议
    detectProtocols(packets) {
        for (const packet of packets) {
            if (!packet.content || !packet.content.type) continue;

            const protocol = this.identifyProtocol(packet);
            if (protocol) {
                this.detectedProtocols.add(protocol);
            }
        }
    }

    // 更新观察到的时间戳信息
    updateObservedTimestamps(packets) {
        for (const packet of packets) {
            if (!packet.content) continue;

            let timestamp = this.extractTimestamp(packet);

            if (timestamp !== null && timestamp !== undefined) {
                this.observedTimestamps.min = Math.min(this.observedTimestamps.min, timestamp);
                this.observedTimestamps.max = Math.max(this.observedTimestamps.max, timestamp);
                this.observedTimestamps.avg = (this.observedTimestamps.avg * this.observedTimestamps.count + timestamp) /
                    (this.observedTimestamps.count + 1);
                this.observedTimestamps.count++;
            }
        }
    }

    // 从消息中提取时间戳
    extractTimestamp(packet) {
        const content = packet.content;
        if (!content) return null;

        // 各种协议的时间戳位置
        if (content.type === 'babble-event' && content.event) {
            return content.event.timestamp;
        } else if (content.type === 'babble-block' && content.block) {
            return content.block.timestamp;
        } else if (content.type === 'ssb-message' && content.message) {
            return content.message.timestamp;
        } else if (content.timestamp) {
            return content.timestamp;
        } else if (content.time) {
            return content.time;
        }

        return null;
    }

    // 生成时间偏移值
    generateTimeSkew(baseSkew, isCritical = false) {
        let timeSkew;

        // 极端偏移处理
        if (this.useExtremeSkews && Math.random() < this.extremeTimeSkewProbability) {
            // 制造极端偏移，远超其他节点的时间戳
            const extremeFactor = Math.random() < 0.5 ? 5 : -3;
            timeSkew = this.maxTimeSkew * extremeFactor;
        } else {
            // 一般偏移
            if (Math.random() < 0.7) {
                // 更倾向于未来偏移
                timeSkew = Math.random() * this.maxTimeSkew * baseSkew;
            } else {
                // 较少的过去偏移
                timeSkew = -Math.random() * this.maxTimeSkew * baseSkew * 0.7;
            }

            // 关键事件额外偏移
            if (isCritical) {
                timeSkew *= 1.5;
            }
        }

        return timeSkew;
    }

    // 攻击Babble消息
    attackBabbleMessage(packet, timeSkewFactor) {
        const content = packet.content;
        const msgType = content.type;

        if (msgType === 'babble-event') {
            this.attackBabbleEvent(content, timeSkewFactor);
        } else if (msgType === 'babble-block') {
            this.attackBabbleBlock(content, timeSkewFactor);
        } else if (msgType === 'ssb-message') {
            this.attackSSBMessage(content, timeSkewFactor);
        } else if (msgType.includes('sync')) {
            // 攻击同步消息
            if (content.events && Array.isArray(content.events)) {
                // 同步响应中的事件
                content.events.forEach(event => {
                    if (event.timestamp !== undefined) {
                        const isCritical = event.isWitness === true;
                        const timeSkew = this.generateTimeSkew(timeSkewFactor, isCritical);
                        event.timestamp += timeSkew;

                        // 同时可能修改轮次
                        if (event.round !== undefined && Math.random() < 0.6) {
                            event.round += (timeSkew > 0 ? 1 : -1);
                            if (event.round < 0) event.round = 0;
                        }
                    }
                });
            }
        }
    }

    // 攻击Babble事件
    attackBabbleEvent(content, timeSkewFactor) {
        const event = content.event;
        if (!event || event.timestamp === undefined) return;

        // 判断是否是关键事件
        const isCritical = this.targetCriticalEvents &&
            ((event.isWitness === true) ||
                (event.round !== undefined && event.round > 0));

        const timeSkew = this.generateTimeSkew(timeSkewFactor, isCritical);
        event.timestamp += timeSkew;

        // 修改轮次
        if (event.round !== undefined && Math.random() < 0.7) {
            const roundSkew = timeSkew > 0 ?
                Math.ceil(Math.random() * 2) : // 未来：增加1-2轮
                -Math.ceil(Math.random());     // 过去：减少0-1轮

            event.round = Math.max(0, event.round + roundSkew);
        }

        // 修改是否为见证事件
        if (event.isWitness !== undefined && Math.random() < 0.5) {
            event.isWitness = !event.isWitness; // 翻转见证状态
        }
    }

    // 攻击Babble区块
    attackBabbleBlock(content, timeSkewFactor) {
        const block = content.block;
        if (!block || block.timestamp === undefined) return;

        const timeSkew = this.generateTimeSkew(timeSkewFactor, true);
        block.timestamp += timeSkew;

        // 修改区块轮次
        if (block.round !== undefined && Math.random() < 0.6) {
            block.round += Math.ceil(Math.random() * 2) * (timeSkew > 0 ? 1 : -1);
            if (block.round < 0) block.round = 0;
        }

        // 修改哈希值
        if (block.hash && Math.random() < 0.8) {
            block.hash = `tampered_${Math.random().toString(36).substring(2, 15)}`;
        }
    }

    // 攻击SSB消息
    attackSSBMessage(content, timeSkewFactor) {
        const message = content.message;
        if (!message || message.timestamp === undefined) return;

        const timeSkew = this.generateTimeSkew(timeSkewFactor);
        message.timestamp += timeSkew;

        // 可能修改序列号
        if (message.sequence !== undefined && Math.random() < 0.5) {
            // 序列号偏移
            message.sequence += Math.ceil(Math.random() * 3) - 1; // -1, 0, 1, 2
            if (message.sequence < 1) message.sequence = 1;
        }
    }

    // 攻击PBFT消息
    attackPBFTMessage(packet, timeSkewFactor) {
        const content = packet.content;

        // PBFT主要依赖视图号和序列号，时间攻击重点是干扰超时机制
        if (Math.random() < 0.7 && this.attackTimeouts) {
            // 给消息增加延迟，使其错过超时窗口
            const delay = this.timeoutDelayRange.min +
                Math.random() * (this.timeoutDelayRange.max - this.timeoutDelayRange.min);
            packet.delay = (packet.delay || 0) + delay;
        }

        // 修改视图号，干扰视图同步
        if (content.view !== undefined && Math.random() < 0.6) {
            // 随机增减视图号，对于减少概率更低
            const viewDelta = Math.random() < 0.8 ?
                Math.ceil(Math.random() * 2) : // 80%概率增加
                -1;                           // 20%概率减少
            content.view += viewDelta;
            if (content.view < 0) content.view = 0;
        }

        // 修改时间戳（如果存在）
        if (content.timestamp !== undefined) {
            content.timestamp += this.generateTimeSkew(timeSkewFactor);
        }
    }

    // 攻击HotStuff消息
    attackHotStuffMessage(packet, timeSkewFactor) {
        const content = packet.content;

        // 修改视图号
        if (content.view !== undefined && Math.random() < 0.7) {
            const viewDelta = Math.ceil(Math.random() * 3) - 1; // -1, 0, 1, 2
            content.view += viewDelta;
            if (content.view < 0) content.view = 0;
        }

        // 攻击石英证书
        if (content.qc && Math.random() < 0.6) {
            if (content.qc.view !== undefined) {
                content.qc.view += Math.ceil(Math.random() * 2) - 1;
                if (content.qc.view < 0) content.qc.view = 0;
            }

            if (content.qc.timestamp !== undefined) {
                content.qc.timestamp += this.generateTimeSkew(timeSkewFactor);
            }
        }

        // 修改视图变更超时
        if (this.attackTimeouts && Math.random() < 0.8) {
            if (content.type && content.type.includes('new-view')) {
                // 给视图变更消息增加延迟
                const delay = this.timeoutDelayRange.min +
                    Math.random() * (this.timeoutDelayRange.max - this.timeoutDelayRange.min);
                packet.delay = (packet.delay || 0) + delay * 2; // 给视图变更加倍延迟
            }
        }

        // 修改时间戳
        if (content.timestamp !== undefined) {
            content.timestamp += this.generateTimeSkew(timeSkewFactor);
        }
    }

    // 攻击Libra消息
    attackLibraMessage(packet, timeSkewFactor) {
        // Libra与HotStuff类似
        this.attackHotStuffMessage(packet, timeSkewFactor);

        const content = packet.content;

        // 额外攻击Libra特有字段
        if (content.round !== undefined && Math.random() < 0.6) {
            content.round += Math.ceil(Math.random() * 2) - 1;
            if (content.round < 0) content.round = 0;
        }

        // 操作epoch（如果存在）
        if (content.epoch !== undefined && Math.random() < 0.4) {
            // 主要是增加epoch
            content.epoch += Math.random() < 0.8 ? 1 : 0;
        }
    }

    // 攻击Algorand消息
    attackAlgorandMessage(packet, timeSkewFactor) {
        const content = packet.content;

        // 主要攻击轮次
        if (content.round !== undefined && Math.random() < 0.7) {
            const roundDelta = Math.random() < 0.7 ?
                Math.ceil(Math.random() * 2) : // 70%概率增加
                -Math.ceil(Math.random());     // 30%概率减少
            content.round += roundDelta;
            if (content.round < 0) content.round = 0;
        }

        // 攻击步骤（Step）
        if (content.step !== undefined && Math.random() < 0.6) {
            content.step += Math.ceil(Math.random() * 2) - 1;
            if (content.step < 0) content.step = 0;
        }

        // 修改时间戳
        if (content.timestamp !== undefined) {
            content.timestamp += this.generateTimeSkew(timeSkewFactor);
        }

        // 对于轮次消息，增加延迟
        if (this.attackTimeouts && content.type &&
            (content.type.includes('proposal') || content.type.includes('vote'))) {
            const delay = this.timeoutDelayRange.min +
                Math.random() * (this.timeoutDelayRange.max - this.timeoutDelayRange.min);
            packet.delay = (packet.delay || 0) + delay;
        }
    }

    // 攻击AsyncBA消息
    attackAsyncBAMessage(packet, timeSkewFactor) {
        const content = packet.content;

        // 对于异步BA，主要攻击超时机制
        if (this.attackTimeouts && Math.random() < 0.8) {
            const delay = this.timeoutDelayRange.min +
                Math.random() * (this.timeoutDelayRange.max - this.timeoutDelayRange.min);
            packet.delay = (packet.delay || 0) + delay;
        }

        // 如果有时间戳，也进行修改
        if (content.timestamp !== undefined) {
            content.timestamp += this.generateTimeSkew(timeSkewFactor * 0.5); // 减少强度
        }

        // 攻击轮次信息（如果有）
        if (content.round !== undefined && Math.random() < 0.5) {
            content.round += Math.ceil(Math.random() * 2) - 1;
            if (content.round < 0) content.round = 0;
        }
    }

    // 处理时间事件，升级攻击强度
    onTimeEvent(event) {
        if (event.functionMeta.name === 'escalateAttack') {
            // 递增攻击强度
            this.maxTimeSkew = Math.min(30, this.maxTimeSkew + 5);  // 增加到最大30秒
            this.extremeTimeSkewProbability = Math.min(0.5, this.extremeTimeSkewProbability + 0.1);

            // 更新攻击策略
            this.attackTimeouts = true;  // 确保超时攻击开启

            // 提高所有协议的攻击率
            for (const protocol in this.protocolParams) {
                if (this.protocolParams[protocol].enabled) {
                    this.protocolParams[protocol].attackRate =
                        Math.min(0.9, this.protocolParams[protocol].attackRate + 0.1);

                    this.protocolParams[protocol].timeSkewFactor =
                        Math.min(2.0, this.protocolParams[protocol].timeSkewFactor + 0.2);
                }
            }

            // console.log(`升级攻击: maxTimeSkew=${this.maxTimeSkew}, extremeProb=${this.extremeTimeSkewProbability}`);
            // console.log(`检测到的协议: ${Array.from(this.detectedProtocols).join(', ')}`);

            // 再次注册，持续升级攻击
            this.registerAttackerTimeEvent(
                { name: 'escalateAttack' },
                15000 // 15秒后再次升级
            );
        }
    }

    // 更新参数
    updateParam() {
        return false; // 不需要额外更新参数
    }
}

module.exports = ClockSkewAttacker;
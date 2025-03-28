'use strict';

/**
 * MessageSequenceManipulator
 * 此攻击者专注于破坏消息的顺序性，通过修改序列号、重放旧消息、
 * 乱序发送等方式，干扰依赖消息顺序的共识算法
 */
class MessageSequenceManipulator {
    constructor(transfer, registerAttackerTimeEvent, eventQ, nodeNum, byzantineNodeNum, getClockTime) {
        this.transfer = transfer;
        this.registerAttackerTimeEvent = registerAttackerTimeEvent;
        this.eventQ = eventQ;
        this.nodeNum = nodeNum;
        this.byzantineNodeNum = byzantineNodeNum;
        this.getClockTime = getClockTime;

        // 攻击参数
        this.seqNumManipulationRate = 0.8;    // 序列号篡改概率
        this.messageReplayRate = 0.8;         // 消息重放概率
        this.messageReorderingRate = 0.65;    // 消息乱序概率

        // 消息历史记录与缓存
        this.messageHistory = {};      // 存储历史消息以便重放
        this.messageBuffer = [];       // 缓存消息以实现乱序发送
        this.maxHistorySize = 50;     // 历史消息最大数量
        this.bufferFlushThreshold = 2; // 缓冲区刷新阈值
        this.lastFlushTime = this.getClockTime();

        // 拜占庭节点的身份（随机选择）
        this.byzantineIdSet = new Set();
        for (let i = 0; i < byzantineNodeNum; i++) {
            this.byzantineIdSet.add((this.nodeNum - i).toString());
        }

        // 启动定期刷新缓冲区
        this.registerAttackerTimeEvent(
            { name: 'flushMessageBuffer' },
            5000 // 5秒后刷新缓冲区
        );

        // console.log('Message sequence manipulator initialized');
    }

    attack(packets) {
        const processedPackets = [];

        for (const packet of packets) {
            // 更新消息历史记录
            this.updateMessageHistory(packet);

            // 决定如何处理当前消息
            const action = this.decideAction(packet);

            switch (action) {
                case 'manipulate_seq':
                    processedPackets.push(this.manipulateSequenceNumber(packet));
                    break;

                case 'replay':
                    // 重放历史消息并处理当前消息
                    const replayedPackets = this.replayHistoricalMessages(packet);
                    processedPackets.push(...replayedPackets);
                    break;

                case 'buffer':
                    // 缓存当前消息以便乱序发送
                    this.bufferMessage(packet);
                    break;

                case 'pass':
                default:
                    // 不做修改，直接转发
                    processedPackets.push(packet);
                    break;
            }
        }

        // 如果缓冲区达到阈值或超过时间限制，刷新缓冲区
        if (this.messageBuffer.length >= this.bufferFlushThreshold ||
            (this.getClockTime() - this.lastFlushTime) > 10) {
            processedPackets.push(...this.flushBuffer());
        }

        return processedPackets;
    }

    updateMessageHistory(packet) {
        // 只存储有类型和内容的消息
        if (!packet.content || !packet.content.type) return;

        const msgType = packet.content.type;
        const src = packet.src;
        const dst = packet.dst;

        // 为每个源节点和消息类型维护历史记录
        if (!this.messageHistory[src]) {
            this.messageHistory[src] = {};
        }

        if (!this.messageHistory[src][msgType]) {
            this.messageHistory[src][msgType] = [];
        }

        // 添加消息到历史记录
        this.messageHistory[src][msgType].push({
            packet: { ...packet }, // 深拷贝以避免引用问题
            timestamp: this.getClockTime()
        });

        // 限制历史记录大小
        while (this.messageHistory[src][msgType].length > this.maxHistorySize) {
            this.messageHistory[src][msgType].shift();
        }
    }

    decideAction(packet) {
        // 对于拜占庭节点发送的消息，直接通过
        if (this.byzantineIdSet.has(packet.src)) {
            return 'pass';
        }

        // 对于没有内容的消息，直接通过
        if (!packet.content || !packet.content.type) {
            return 'pass';
        }

        // 对于关键消息类型，使用不同的攻击策略
        const msgType = packet.content.type;

        if (this.isSequenceRelevantMessage(packet)) {
            // 对包含序列号的消息，尝试篡改序列号
            if (Math.random() < this.seqNumManipulationRate) {
                return 'manipulate_seq';
            }
        }

        // 对事件消息，尝试重放历史消息
        if ((msgType === 'babble-event' || msgType === 'ssb-message') &&
            Math.random() < this.messageReplayRate) {
            return 'replay';
        }

        // 对其他消息类型，尝试乱序发送
        if (Math.random() < this.messageReorderingRate) {
            return 'buffer';
        }

        return 'pass';
    }

    isSequenceRelevantMessage(packet) {
        if (!packet.content) return false;

        const msgType = packet.content.type;

        // 判断消息是否包含序列号或与顺序相关
        return (
            // 明确包含序列号的消息
            (packet.content.seq !== undefined) ||
            // SSB消息包含序列号
            (msgType === 'ssb-message' && packet.content.message &&
                packet.content.message.sequence !== undefined) ||
            // 区块有索引
            (msgType === 'babble-block' && packet.content.block &&
                packet.content.block.index !== undefined) ||
            // 事件有轮次信息
            (msgType === 'babble-event' && packet.content.event &&
                packet.content.event.round !== undefined)
        );
    }

    manipulateSequenceNumber(packet) {
        const modifiedPacket = { ...packet };

        // 根据消息类型选择合适的篡改方式
        if (modifiedPacket.content.seq !== undefined) {
            // 直接篡改packet层的序列号
            this.modifySequenceValue(modifiedPacket, 'content.seq');
        }

        if (modifiedPacket.content.type === 'ssb-message' &&
            modifiedPacket.content.message &&
            modifiedPacket.content.message.sequence !== undefined) {
            // 篡改SSB消息序列号
            this.modifySequenceValue(modifiedPacket, 'content.message.sequence');
        }

        if (modifiedPacket.content.type === 'babble-block' &&
            modifiedPacket.content.block &&
            modifiedPacket.content.block.index !== undefined) {
            // 篡改区块索引
            this.modifySequenceValue(modifiedPacket, 'content.block.index');

            // 如果区块有hash，需要更新以保持看起来合法
            if (modifiedPacket.content.block.hash) {
                modifiedPacket.content.block.hash = `seq_modified_${Math.random().toString(36).substring(2, 15)}`;
            }
        }

        if (modifiedPacket.content.type === 'babble-event' &&
            modifiedPacket.content.event &&
            modifiedPacket.content.event.round !== undefined) {
            // 篡改事件轮次
            this.modifySequenceValue(modifiedPacket, 'content.event.round');

            // 更新事件哈希
            if (modifiedPacket.content.event.hash) {
                modifiedPacket.content.event.hash = `seq_modified_${Math.random().toString(36).substring(2, 15)}`;
            }
        }

        return modifiedPacket;
    }

    modifySequenceValue(packet, path) {
        // 拆分路径
        const parts = path.split('.');
        let target = packet;

        // 遍历到倒数第二层
        for (let i = 0; i < parts.length - 1; i++) {
            if (!target[parts[i]]) return;
            target = target[parts[i]];
        }

        // 获取最后一个属性名
        const lastProp = parts[parts.length - 1];

        // 修改序列号
        if (typeof target[lastProp] === 'number') {
            // 选择篡改策略
            const strategy = Math.random();

            if (strategy < 0.4) {
                // 大幅度增加序列号
                target[lastProp] += Math.floor(Math.random() * 10) + 5;
            } else if (strategy < 0.7) {
                // 小幅度减少序列号
                target[lastProp] = Math.max(0, target[lastProp] - (Math.floor(Math.random() * 3) + 1));
            } else {
                // 随机调整
                const adjustment = Math.floor(Math.random() * 7) - 3; // -3到3的随机调整
                target[lastProp] = Math.max(0, target[lastProp] + adjustment);
            }
        }
    }

    replayHistoricalMessages(currentPacket) {
        const packets = [];

        // 首先处理当前消息
        packets.push(currentPacket);

        // 寻找可以重放的历史消息
        const src = currentPacket.src;
        const dst = currentPacket.dst;
        const msgType = currentPacket.content.type;

        // 找出所有可能的历史消息来源
        const potentialSources = Object.keys(this.messageHistory);

        // 随机选择1-3个历史消息重放
        const replayCount = Math.floor(Math.random() * 3) + 1;
        let replayed = 0;

        for (const historySrc of potentialSources) {
            // 不重放拜占庭节点发的消息
            if (this.byzantineIdSet.has(historySrc)) continue;

            // 获取这个源的历史消息
            const srcHistory = this.messageHistory[historySrc];
            if (!srcHistory) continue;

            // 随机选择一个消息类型
            const messageTypes = Object.keys(srcHistory);
            if (messageTypes.length === 0) continue;

            for (let attempt = 0; attempt < 3 && replayed < replayCount; attempt++) {
                // 随机选择一个消息类型
                const randomType = messageTypes[Math.floor(Math.random() * messageTypes.length)];
                const typeHistory = srcHistory[randomType];

                if (typeHistory && typeHistory.length > 0) {
                    // 从历史记录中随机选择一个消息
                    const historyIndex = Math.floor(Math.random() * typeHistory.length);
                    const historyItem = typeHistory[historyIndex];

                    // 创建重放包，将原目标修改为当前消息的目标
                    const replayPacket = { ...historyItem.packet };
                    replayPacket.dst = currentPacket.dst;

                    // 标记为重放消息（可选，用于调试）
                    // replayPacket.replayed = true;

                    // 如果是带序列号的消息，重新修改序列号
                    if (this.isSequenceRelevantMessage(replayPacket)) {
                        replayPacket = this.manipulateSequenceNumber(replayPacket);
                    }

                    packets.push(replayPacket);
                    replayed++;
                }
            }

            if (replayed >= replayCount) break;
        }

        return packets;
    }

    bufferMessage(packet) {
        // 将消息添加到缓冲区
        this.messageBuffer.push({
            packet: packet,
            timestamp: this.getClockTime()
        });
    }

    flushBuffer() {
        if (this.messageBuffer.length === 0) return [];

        // 随机打乱缓冲区顺序
        this.messageBuffer.sort(() => Math.random() - 0.5);

        // 提取所有缓冲的消息
        const packets = this.messageBuffer.map(item => item.packet);

        // 清空缓冲区并更新上次刷新时间
        this.messageBuffer = [];
        this.lastFlushTime = this.getClockTime();

        return packets;
    }

    onTimeEvent(event) {
        if (event.functionMeta.name === 'flushMessageBuffer') {
            // 定期刷新消息缓冲区
            if (this.messageBuffer.length > 0) {
                this.transfer(this.flushBuffer());
            }

            // 再次注册刷新事件
            this.registerAttackerTimeEvent(
                { name: 'flushMessageBuffer' },
                Math.floor(Math.random() * 5000) + 3000 // 3-8秒后刷新
            );

            // 周期性调整攻击参数
            this.adjustAttackParameters();
        }
    }

    adjustAttackParameters() {
        // 轻微随机调整攻击参数，使攻击更加不可预测
        const adjustmentFactor = 0.05;

        this.seqNumManipulationRate += (Math.random() * 2 - 1) * adjustmentFactor;
        this.messageReplayRate += (Math.random() * 2 - 1) * adjustmentFactor;
        this.messageReorderingRate += (Math.random() * 2 - 1) * adjustmentFactor;

        // 限制在合理范围内
        this.seqNumManipulationRate = Math.min(0.7, Math.max(0.2, this.seqNumManipulationRate));
        this.messageReplayRate = Math.min(0.5, Math.max(0.1, this.messageReplayRate));
        this.messageReorderingRate = Math.min(0.6, Math.max(0.2, this.messageReorderingRate));

        // console.log(`Adjusted attack parameters: seq=${this.seqNumManipulationRate.toFixed(2)}, replay=${this.messageReplayRate.toFixed(2)}, reorder=${this.messageReorderingRate.toFixed(2)}`);
    }

    updateParam() {
        return false; // 不更新参数
    }
}

module.exports = MessageSequenceManipulator;
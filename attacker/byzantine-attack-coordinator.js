'use strict';

/**
 * ByzantineAttackCoordinator
 * 此攻击者整合多种拜占庭攻击策略，能够动态切换和组合不同攻击模式
 * 可以根据系统状态和时间调整攻击强度和类型
 */
class ByzantineAttackCoordinator {
    constructor(transfer, registerAttackerTimeEvent, eventQ, nodeNum, byzantineNodeNum, getClockTime) {
        this.transfer = transfer;
        this.registerAttackerTimeEvent = registerAttackerTimeEvent;
        this.eventQ = eventQ;
        this.nodeNum = nodeNum;
        this.byzantineNodeNum = byzantineNodeNum;
        this.getClockTime = getClockTime;

        // 攻击阶段和模式
        this.currentPhase = 0;       // 当前攻击阶段
        this.phaseStartTime = this.getClockTime(); // 阶段开始时间
        this.phaseDuration = 2;     // 每个阶段持续时间（秒）
        this.attackModes = [
            'normal',        // 正常行为（休眠期）
            'data_forgery',  // 数据篡改
            'sync_disrupt',  // 同步干扰
            'partition',     // 网络分区
            'equivocation',  // 等价攻击（向不同节点发送不同消息）
            'timing',        // 时序攻击（时间戳篡改）
            'comprehensive'  // 综合攻击
        ];
        this.currentMode = 'comprehensive';
        this.attackIntensity = 0.1;  // 攻击强度（0-1）

        // 观测和学习系统状态
        this.systemState = {
            round: 0,               // 当前观察到的最高轮次
            blocks: 0,              // 观察到的区块数
            activeNodes: new Set(), // 活跃节点集合
            eventCount: 0,          // 观察到的事件总数
            lastDecisionTime: 0     // 上次观察到决策的时间
        };

        // 拜占庭节点集
        this.byzantineNodes = new Set();
        for (let i = 1; i <= byzantineNodeNum; i++) {
            this.byzantineNodes.add((this.nodeNum - i + 1).toString());
        }

        // 注册阶段切换事件
        this.registerAttackerTimeEvent(
            { name: 'phaseChange' },
            this.phaseDuration * 1000
        );

        // 注册系统观察事件
        this.registerAttackerTimeEvent(
            { name: 'observeSystem' },
            5000 // 5秒后观察系统
        );

        console.log('Byzantine attack coordinator initialized in normal mode');
    }

    attack(packets) {
        // 更新系统状态
        this.updateSystemState(packets);

        // 应用当前活跃的攻击模式
        switch (this.currentMode) {
            case 'normal':
                return this.normalBehavior(packets);

            case 'data_forgery':
                return this.dataForgeryAttack(packets);

            case 'sync_disrupt':
                return this.syncDisruptionAttack(packets);

            case 'partition':
                return this.partitionAttack(packets);

            case 'equivocation':
                return this.equivocationAttack(packets);

            case 'timing':
                return this.timingAttack(packets);

            case 'comprehensive':
                return this.comprehensiveAttack(packets);

            default:
                return packets;
        }
    }

    updateSystemState(packets) {
        const currentTime = this.getClockTime();

        // 更新活跃节点
        for (const packet of packets) {
            if (packet.src) {
                this.systemState.activeNodes.add(packet.src);
            }

            // 分析消息内容
            if (packet.content) {
                // 更新轮次信息
                if (packet.content.type === 'babble-event' &&
                    packet.content.event &&
                    packet.content.event.round !== undefined) {
                    this.systemState.round = Math.max(
                        this.systemState.round,
                        packet.content.event.round
                    );
                    this.systemState.eventCount++;
                }

                // 更新区块信息
                if (packet.content.type === 'babble-block') {
                    this.systemState.blocks++;

                    // 更新决策时间
                    if (packet.content.block && packet.content.block.final === true) {
                        this.systemState.lastDecisionTime = currentTime;
                    }
                }
            }
        }
    }

    // 正常行为 
    normalBehavior(packets) {
        // 极低概率做一些微小修改，大部分包保持不变
        return packets.map(packet => {
            if (Math.random() < 0.02 && packet.content) { // 仅2%的概率
                // 极轻微的修改
                if (packet.content.type === 'babble-event' &&
                    packet.content.event &&
                    packet.content.event.timestamp !== undefined) {
                    packet.content.event.timestamp += (Math.random() * 0.1 - 0.05);
                }
            }
            return packet;
        });
    }

    // 数据篡改攻击
    dataForgeryAttack(packets) {
        return packets.map(packet => {
            // 不修改拜占庭节点发送的消息
            if (this.byzantineNodes.has(packet.src)) return packet;

            // 根据攻击强度决定是否篡改
            if (Math.random() < this.attackIntensity && packet.content) {
                const msgType = packet.content.type;

                if (msgType === 'babble-event') {
                    return this.forgeEventData(packet);
                }
                else if (msgType === 'babble-block') {
                    return this.forgeBlockData(packet);
                }
                else if (msgType === 'ssb-message') {
                    return this.forgeSSBData(packet);
                }
            }

            return packet;
        });
    }

    forgeEventData(packet) {
        const event = packet.content.event;
        if (!event) return packet;

        // 篡改事件数据
        const strategy = Math.random();

        if (strategy < 0.3) {
            // 篡改事件父引用
            if (event.selfParent) {
                event.selfParent = `forged_${Math.random().toString(36).substring(2, 10)}`;
            }
        }
        else if (strategy < 0.6) {
            // 注入虚假交易
            if (!event.transactions) event.transactions = [];
            event.transactions.push(`FORGED_TX_${Math.random().toString(36).substring(2, 8)}`);
        }
        else {
            // 篡改事件轮次
            if (event.round !== undefined) {
                event.round = Math.max(0, event.round + Math.floor(Math.random() * 3) - 1);
            }
        }

        // 更新哈希
        if (event.hash) {
            event.hash = `forged_${Math.random().toString(36).substring(2, 15)}`;
        }

        return packet;
    }

    forgeBlockData(packet) {
        const block = packet.content.block;
        if (!block) return packet;

        // 篡改区块数据
        if (block.transactions && block.transactions.length > 0) {
            // 替换部分交易
            const replaceCount = Math.min(3, Math.floor(block.transactions.length * 0.3));
            for (let i = 0; i < replaceCount; i++) {
                const idx = Math.floor(Math.random() * block.transactions.length);
                block.transactions[idx] = `FORGED_BLOCK_TX_${Math.random().toString(36).substring(2, 8)}`;
            }
        }

        // 更新区块哈希
        if (block.hash) {
            block.hash = `forged_block_${Math.random().toString(36).substring(2, 15)}`;
        }

        return packet;
    }

    forgeSSBData(packet) {
        const message = packet.content.message;
        if (!message) return packet;

        // 篡改SSB消息
        if (message.content) {
            // 如果内容是对象
            if (typeof message.content === 'object') {
                message.content.forged = true;
                message.content.timestamp = this.getClockTime();
            }
            // 如果内容是字符串
            else if (typeof message.content === 'string') {
                message.content = `FORGED: ${message.content}`;
            }
        }

        // 篡改序列号
        if (message.sequence !== undefined) {
            message.sequence += Math.floor(Math.random() * 3) - 1;
            if (message.sequence < 1) message.sequence = 1;
        }

        return packet;
    }

    // 同步干扰攻击
    syncDisruptionAttack(packets) {
        return packets.map(packet => {
            // 不修改拜占庭节点发送的消息
            if (this.byzantineNodes.has(packet.src)) return packet;

            // 只关注同步请求和响应
            if (packet.content &&
                (packet.content.type === 'babble-sync-request' ||
                    packet.content.type === 'babble-sync-response')) {

                // 根据攻击强度决定是否干扰
                if (Math.random() < this.attackIntensity) {
                    return this.disruptSyncMessage(packet);
                }
            }

            return packet;
        });
    }

    disruptSyncMessage(packet) {
        if (packet.content.type === 'babble-sync-request') {
            // 干扰同步请求
            if (packet.content.knownEvents) {
                const knownEvents = packet.content.knownEvents;

                // 随机修改已知事件引用
                for (const nodeID in knownEvents) {
                    if (Math.random() < 0.4) {
                        // 随机清空或修改
                        if (Math.random() < 0.5) {
                            knownEvents[nodeID] = null;
                        } else {
                            knownEvents[nodeID] = `disrupted_${Math.random().toString(36).substring(2, 10)}`;
                        }
                    }
                }
            }
        }
        else if (packet.content.type === 'babble-sync-response') {
            // 干扰同步响应
            if (packet.content.events && packet.content.events.length > 0) {
                const events = packet.content.events;

                // 策略1: 删除一些事件
                if (events.length > 2 && Math.random() < 0.4) {
                    const removeCount = Math.floor(events.length * 0.3);
                    for (let i = 0; i < removeCount; i++) {
                        const idx = Math.floor(Math.random() * events.length);
                        events.splice(idx, 1);
                    }
                }

                // 策略2: 篡改部分事件
                for (let i = 0; i < events.length; i++) {
                    if (Math.random() < 0.3) {
                        const event = events[i];

                        // 轻微篡改
                        if (event.timestamp !== undefined) {
                            event.timestamp += (Math.random() * 0.5 - 0.25);
                        }

                        // 损坏事件链
                        if (Math.random() < 0.3 && event.selfParent) {
                            event.selfParent = null;
                        }

                        // 更新哈希
                        if (event.hash) {
                            event.hash = `disrupted_${Math.random().toString(36).substring(2, 15)}`;
                        }
                    }
                }
            }
        }

        return packet;
    }

    // 网络分区攻击
    partitionAttack(packets) {
        // 根据节点ID创建两个分区
        return packets.filter(packet => {
            // 不修改拜占庭节点发送的消息
            if (this.byzantineNodes.has(packet.src)) return true;

            // 如果是广播消息，低概率丢弃
            if (packet.dst === 'broadcast') {
                return Math.random() > this.attackIntensity * 0.3;
            }

            const srcId = parseInt(packet.src);
            const dstId = parseInt(packet.dst);

            // 如果无法解析ID，保留消息
            if (isNaN(srcId) || isNaN(dstId)) return true;

            // 基于节点ID奇偶性划分分区
            const srcGroup = srcId % 2;
            const dstGroup = dstId % 2;

            // 如果跨分区通信，根据攻击强度决定是否丢弃
            if (srcGroup !== dstGroup) {
                return Math.random() > this.attackIntensity;
            }

            return true;
        });
    }

    // 等价攻击（向不同节点发送不同内容）
    equivocationAttack(packets) {
        const modifiedPackets = [];

        for (const packet of packets) {
            // 不修改拜占庭节点发送的消息
            if (this.byzantineNodes.has(packet.src)) {
                modifiedPackets.push(packet);
                continue;
            }

            // 只对消息类型为babble-event或babble-block的消息进行等价攻击
            if (packet.content &&
                (packet.content.type === 'babble-event' ||
                    packet.content.type === 'babble-block')) {

                // 只对点对点消息进行等价攻击
                if (packet.dst !== 'broadcast' && Math.random() < this.attackIntensity) {
                    // 添加原始包
                    modifiedPackets.push(packet);

                    // 为其他节点创建不同版本的消息
                    this.createEquivocatingMessages(packet, modifiedPackets);

                    continue;
                }
            }

            modifiedPackets.push(packet);
        }

        return modifiedPackets;
    }

    createEquivocatingMessages(originalPacket, packetsArray) {
        // 为除原目标外的其他节点创建不同的消息版本
        const originalDst = originalPacket.dst;

        // 随机选择1-3个其他节点进行等价攻击
        const targetCount = Math.floor(Math.random() * 3) + 1;
        let targetsSelected = 0;

        // 遍历所有可能的目标节点
        for (let i = 1; i <= this.nodeNum - this.byzantineNodeNum; i++) {
            const nodeId = i.toString();

            // 跳过原目标和拜占庭节点
            if (nodeId === originalDst || this.byzantineNodes.has(nodeId)) continue;

            // 随机决定是否选择这个节点
            if (Math.random() < 0.3 && targetsSelected < targetCount) {
                // 创建一个修改过的消息拷贝
                const equivPacket = this.createDifferentMessageVersion(originalPacket, nodeId);
                packetsArray.push(equivPacket);
                targetsSelected++;
            }

            // 已达到目标数量
            if (targetsSelected >= targetCount) break;
        }
    }

    createDifferentMessageVersion(originalPacket, newDst) {
        // 创建一个深拷贝
        const newPacket = JSON.parse(JSON.stringify(originalPacket));

        // 修改目标
        newPacket.dst = newDst;

        if (newPacket.content.type === 'babble-event') {
            const event = newPacket.content.event;
            if (event) {
                // 为不同节点创建矛盾的事件版本

                // 修改交易内容
                if (event.transactions) {
                    if (event.transactions.length > 0) {
                        // 修改或添加交易
                        event.transactions.push(`EQUIV_${newDst}_${Math.random().toString(36).substring(2, 8)}`);
                    } else {
                        event.transactions = [`EQUIV_${newDst}_${Math.random().toString(36).substring(2, 8)}`];
                    }
                }

                // 修改事件轮次
                if (event.round !== undefined) {
                    // 稍微增加或减少轮次
                    event.round = Math.max(0, event.round + (Math.floor(Math.random() * 3) - 1));
                }

                // 更新哈希
                if (event.hash) {
                    event.hash = `equiv_${newDst}_${Math.random().toString(36).substring(2, 15)}`;
                }
            }
        }
        else if (newPacket.content.type === 'babble-block') {
            const block = newPacket.content.block;
            if (block) {
                // 为不同节点创建矛盾的区块版本

                // 修改交易列表
                if (block.transactions && block.transactions.length > 0) {
                    // 替换一部分交易
                    const replaceIdx = Math.floor(Math.random() * block.transactions.length);
                    block.transactions[replaceIdx] = `EQUIV_BLOCK_${newDst}_${Math.random().toString(36).substring(2, 8)}`;
                }

                // 更新哈希
                if (block.hash) {
                    block.hash = `equiv_block_${newDst}_${Math.random().toString(36).substring(2, 15)}`;
                }
            }
        }

        return newPacket;
    }

    // 时序攻击（时间戳篡改）
    timingAttack(packets) {
        return packets.map(packet => {
            // 不修改拜占庭节点发送的消息
            if (this.byzantineNodes.has(packet.src)) return packet;

            // 根据攻击强度决定是否进行时序攻击
            if (Math.random() < this.attackIntensity && packet.content) {
                const msgType = packet.content.type;

                // 修改事件时间戳
                if (msgType === 'babble-event' && packet.content.event &&
                    packet.content.event.timestamp !== undefined) {
                    packet.content.event.timestamp += this.generateTimeOffset();
                }

                // 修改区块时间戳
                if (msgType === 'babble-block' && packet.content.block &&
                    packet.content.block.timestamp !== undefined) {
                    packet.content.block.timestamp += this.generateTimeOffset();

                    // 更新区块哈希
                    if (packet.content.block.hash) {
                        packet.content.block.hash = `time_block_${Math.random().toString(36).substring(2, 15)}`;
                    }
                }

                // 修改SSB消息时间戳
                if (msgType === 'ssb-message' && packet.content.message &&
                    packet.content.message.timestamp !== undefined) {
                    packet.content.message.timestamp += this.generateTimeOffset();
                }
            }

            return packet;
        });
    }

    generateTimeOffset() {
        // 生成时间偏移
        const offsetStrategy = Math.random();

        if (offsetStrategy < 0.4) {
            // 未来时间戳 (正偏移)
            return Math.random() * 3;
        } else if (offsetStrategy < 0.8) {
            // 过去时间戳 (负偏移)
            return -Math.random() * 3;
        } else {
            // 极端偏移
            return (Math.random() * 10 - 5);
        }
    }

    // 综合攻击
    comprehensiveAttack(packets) {
        // 对每个包应用多种攻击策略的组合
        let processedPackets = [...packets];

        // 1. 首先应用分区攻击（可能会过滤一些包）
        if (Math.random() < 0.3) {
            processedPackets = this.partitionAttack(processedPackets);
        }

        // 2. 对剩余的包应用数据篡改
        processedPackets = processedPackets.map(packet => {
            // 不修改拜占庭节点发送的消息
            if (this.byzantineNodes.has(packet.src)) return packet;

            const attackStrategy = Math.random();

            if (attackStrategy < 0.3 && packet.content) {
                // 数据篡改
                if (packet.content.type === 'babble-event') {
                    return this.forgeEventData(packet);
                } else if (packet.content.type === 'babble-block') {
                    return this.forgeBlockData(packet);
                } else if (packet.content.type === 'ssb-message') {
                    return this.forgeSSBData(packet);
                }
            }
            else if (attackStrategy < 0.5 && packet.content) {
                // 时序攻击
                if (packet.content.type === 'babble-event' ||
                    packet.content.type === 'babble-block' ||
                    packet.content.type === 'ssb-message') {
                    return this.timingAttack([packet])[0];
                }
            }
            else if (attackStrategy < 0.7 && packet.content &&
                (packet.content.type === 'babble-sync-request' ||
                    packet.content.type === 'babble-sync-response')) {
                // 同步干扰
                return this.disruptSyncMessage(packet);
            }

            return packet;
        });

        // 3. 应用等价攻击（可能添加新的包）
        if (Math.random() < 0.3) {
            // 复制一份以防止在迭代中修改
            const packetsToProcess = [...processedPackets];
            processedPackets = [];

            for (const packet of packetsToProcess) {
                // 不修改拜占庭节点发送的消息
                if (this.byzantineNodes.has(packet.src)) {
                    processedPackets.push(packet);
                    continue;
                }

                // 随机选择消息进行等价攻击
                if (packet.content &&
                    (packet.content.type === 'babble-event' ||
                        packet.content.type === 'babble-block') &&
                    packet.dst !== 'broadcast' &&
                    Math.random() < 0.2) {

                    processedPackets.push(packet);
                    this.createEquivocatingMessages(packet, processedPackets);
                } else {
                    processedPackets.push(packet);
                }
            }
        }

        return processedPackets;
    }

    onTimeEvent(event) {
        if (event.functionMeta.name === 'phaseChange') {
            this.advancePhase();

            // 注册下一次阶段切换
            this.registerAttackerTimeEvent(
                { name: 'phaseChange' },
                this.phaseDuration * 1000
            );
        }
        else if (event.functionMeta.name === 'observeSystem') {
            this.adjustAttackParameters();

            // 注册下一次系统观察
            this.registerAttackerTimeEvent(
                { name: 'observeSystem' },
                8000 // 8秒后观察
            );
        }
    }

    advancePhase() {
        const currentTime = this.getClockTime();
        this.currentPhase = (this.currentPhase + 1) % this.attackModes.length;
        this.currentMode = this.attackModes[this.currentPhase];
        this.phaseStartTime = currentTime;

        // 随机调整阶段持续时间
        this.phaseDuration = 15 + Math.floor(Math.random() * 10); // 15-25秒

        console.log(`Advanced to attack phase ${this.currentPhase}: ${this.currentMode}, intensity: ${this.attackIntensity.toFixed(2)}, duration: ${this.phaseDuration}s`);
    }

    adjustAttackParameters() {
        const currentTime = this.getClockTime();

        // 计算系统活跃度指标
        const activeNodeCount = this.systemState.activeNodes.size;
        const consensusProgress = this.systemState.round;
        const timeSinceLastDecision = currentTime - this.systemState.lastDecisionTime;

        // 节点活跃度指标 (0-1)
        const nodeActivityFactor = Math.min(1.0, activeNodeCount / (this.nodeNum - this.byzantineNodeNum));

        // 共识延迟指标 (0-1)
        let consensusDelayFactor = 0;
        if (this.systemState.lastDecisionTime > 0) {
            consensusDelayFactor = Math.min(1.0, timeSinceLastDecision / 30);
        }

        // 根据系统状态调整攻击强度
        if (consensusDelayFactor > 0.7) {
            // 共识被严重延迟，减少攻击强度以避免完全阻止进展
            this.attackIntensity = Math.max(0.1, this.attackIntensity - 0.1);
        }
        else if (nodeActivityFactor < 0.5) {
            // 很多节点不活跃，减少攻击强度
            this.attackIntensity = Math.max(0.1, this.attackIntensity - 0.05);
        }
        else {
            // 默认情况，随机小幅调整攻击强度
            this.attackIntensity += (Math.random() * 0.2 - 0.1);
            this.attackIntensity = Math.min(0.8, Math.max(0.1, this.attackIntensity));
        }

        // 清理不再活跃的节点
        const currentActiveNodes = new Set();
        for (const nodeId of this.systemState.activeNodes) {
            // 仅保留最近有活动的节点
            currentActiveNodes.add(nodeId);
        }
        this.systemState.activeNodes = currentActiveNodes;

        console.log(`System state: round=${this.systemState.round}, blocks=${this.systemState.blocks}, activeNodes=${this.systemState.activeNodes.size}, attackIntensity=${this.attackIntensity.toFixed(2)}`);
    }

    updateParam() {
        return false; // 不更新参数
    }
}

module.exports = ByzantineAttackCoordinator;
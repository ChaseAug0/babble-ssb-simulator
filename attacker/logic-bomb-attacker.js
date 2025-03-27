'use strict';

/**
 * LogicBombAttacker
 * 此攻击者长期表现正常，然后在特定条件（如时间、轮次或特定事件）触发后
 * 突然发动大规模攻击，造成系统瞬间崩溃或严重中断
 */
class LogicBombAttacker {
    constructor(transfer, registerAttackerTimeEvent, eventQ, nodeNum, byzantineNodeNum, getClockTime) {
        this.transfer = transfer;
        this.registerAttackerTimeEvent = registerAttackerTimeEvent;
        this.eventQ = eventQ;
        this.nodeNum = nodeNum;
        this.byzantineNodeNum = byzantineNodeNum;
        this.getClockTime = getClockTime;

        // 攻击状态
        this.bombActivated = true;       // 炸弹是否已激活
        this.dormantPeriod = false;        // 是否处于休眠期
        this.suspiciousActivityRate = 0.05; // 休眠期间的可疑活动率（低以避免检测）

        // 触发条件
        this.triggerConditions = {
            targetTime: this.getClockTime() + 2,  // 30秒后触发时间炸弹
            targetRound: 2,                       // 轮次达到10时触发
            targetBlockCount: 2,                   // 区块数达到5时触发
            specificEventDetected: false,          // 特定事件触发（如视图变更）
            nodeFailuresRequired: 1                // 观察到至少1个节点失效时触发
        };

        // 攻击后的冷却期
        this.attackCooldown = 1; // 15秒冷却期
        this.lastAttackTime = 0;

        // 计数器和监控
        this.highestObservedRound = 0;
        this.observedBlockCount = 0;
        this.nodeFailures = new Set();

        // 注册初始触发器检查
        this.registerAttackerTimeEvent(
            { name: 'checkTriggerConditions' },
            5000 // 5秒后检查触发条件
        );

        console.log(`Logic bomb attacker initialized. Target time: ${new Date(this.triggerConditions.targetTime * 1000).toISOString()}`);
    }

    attack(packets) {
        // 更新系统状态
        this.updateSystemState(packets);

        // 检查是否满足触发条件
        this.checkConditions();

        // 如果在冷却期，减少活动性
        const currentTime = this.getClockTime();
        if (this.bombActivated && (currentTime - this.lastAttackTime) < this.attackCooldown) {
            return packets; // 冷却期内不攻击
        }

        // 攻击状态下的包处理
        if (this.bombActivated) {
            // 返回大规模攻击后的包
            return this.executeMassiveAttack(packets);
        } else {
            // 休眠期的正常或近似正常行为
            return this.dormantBehavior(packets);
        }
    }

    updateSystemState(packets) {
        for (const packet of packets) {
            if (!packet.content) continue;

            // 跟踪轮次进展
            if (packet.content.type === 'babble-event' &&
                packet.content.event &&
                packet.content.event.round !== undefined) {
                this.highestObservedRound = Math.max(
                    this.highestObservedRound,
                    packet.content.event.round
                );
            }

            // 跟踪区块数量
            if (packet.content.type === 'babble-block') {
                this.observedBlockCount++;
            }

            // 检测特定事件（如视图变更）
            if (packet.content.type === 'view-change' ||
                packet.content.type === 'new-view') {
                this.triggerConditions.specificEventDetected = true;
            }

            // 检测节点失效
            this.detectNodeFailures(packets);
        }
    }

    detectNodeFailures(packets) {
        // 简单的节点失效检测：收集当前活跃的节点
        const activeNodes = new Set();
        for (const packet of packets) {
            if (packet.src) {
                activeNodes.add(packet.src);
            }
        }

        // 如果一段时间内未观察到某些节点的活动，认为它们可能失效
        // 此处简化实现，实际上需要更复杂的检测机制
        for (let i = 1; i <= this.nodeNum - this.byzantineNodeNum; i++) {
            const nodeId = `${i}`;
            if (!activeNodes.has(nodeId) && Math.random() < 0.1) { // 10%随机概率
                this.nodeFailures.add(nodeId);
            }
        }
    }

    checkConditions() {
        const currentTime = this.getClockTime();

        // 避免重复触发
        if (this.bombActivated && (currentTime - this.lastAttackTime) < this.attackCooldown) {
            return;
        }

        // 检查各种触发条件
        if (
            currentTime >= this.triggerConditions.targetTime || // 时间触发
            this.highestObservedRound >= this.triggerConditions.targetRound || // 轮次触发
            this.observedBlockCount >= this.triggerConditions.targetBlockCount || // 区块数触发
            this.triggerConditions.specificEventDetected || // 特定事件触发
            this.nodeFailures.size >= this.triggerConditions.nodeFailuresRequired // 节点失效触发
        ) {
            if (!this.bombActivated) {
                console.log(`Logic bomb triggered at ${currentTime}!`);
                console.log(`Trigger conditions: time=${currentTime >= this.triggerConditions.targetTime}, round=${this.highestObservedRound >= this.triggerConditions.targetRound}, blocks=${this.observedBlockCount >= this.triggerConditions.targetBlockCount}, specificEvent=${this.triggerConditions.specificEventDetected}, nodeFailures=${this.nodeFailures.size >= this.triggerConditions.nodeFailuresRequired}`);
            }

            this.bombActivated = true;
            this.dormantPeriod = false;
            this.lastAttackTime = currentTime;

            // 更新下一个目标时间（用于周期性攻击）
            this.triggerConditions.targetTime = currentTime + this.attackCooldown + 10;
        }
    }

    dormantBehavior(packets) {
        // 休眠期间表现几乎正常，仅有极低频率的可疑行为
        return packets.map(packet => {
            // 极小概率进行微小篡改，以避免被检测
            if (Math.random() < this.suspiciousActivityRate && packet.content) {
                if (packet.content.type === 'babble-event' && packet.content.event) {
                    // 非常轻微的篡改
                    if (packet.content.event.timestamp !== undefined) {
                        packet.content.event.timestamp += (Math.random() * 0.1 - 0.05); // 非常小的时间戳调整
                    }
                }
            }
            return packet;
        });
    }

    executeMassiveAttack(packets) {
        console.log(`Executing massive attack at ${this.getClockTime()}`);

        // 激活后进行大规模攻击
        const attackedPackets = [];

        for (const packet of packets) {
            // 大概率直接丢弃消息
            if (Math.random() < 0.5) {
                continue; // 丢弃50%的消息
            }

            let modifiedPacket = { ...packet };

            // 处理不同类型的消息
            if (modifiedPacket.content) {
                // 攻击事件消息
                if (modifiedPacket.content.type === 'babble-event') {
                    modifiedPacket = this.bombEventMessage(modifiedPacket);
                }
                // 攻击区块消息
                else if (modifiedPacket.content.type === 'babble-block') {
                    modifiedPacket = this.bombBlockMessage(modifiedPacket);
                }
                // 攻击同步消息
                else if (modifiedPacket.content.type === 'babble-sync-request' ||
                    modifiedPacket.content.type === 'babble-sync-response') {
                    modifiedPacket = this.bombSyncMessage(modifiedPacket);
                }
            }

            // 额外延迟
            if (Math.random() < 0.7) {
                modifiedPacket.delay = (modifiedPacket.delay || 0) + Math.random() * 3; // 高达3秒的额外延迟
            }

            attackedPackets.push(modifiedPacket);
        }

        // 注入大量虚假事件(至少每个目标节点 1 条消息)
        this.injectFakeMessages(attackedPackets);

        return attackedPackets;
    }

    bombEventMessage(packet) {
        const event = packet.content.event;
        if (!event) return packet;

        // 大规模篡改事件

        // 1. 破坏事件链
        if (Math.random() < 0.9) {
            event.selfParent = null;
        }

        // 2. 注入恶意交易
        event.transactions = Array(Math.floor(Math.random() * 10) + 5)
            .fill(0)
            .map(() => `BOMB_TX_${Math.random().toString(36).substring(2, 10)}`);

        // 3. 修改轮次信息
        if (event.round !== undefined) {
            // 强制事件成为极高轮次
            event.round = this.highestObservedRound + Math.floor(Math.random() * 20) + 10;
        }

        // 4. 标记为见证事件
        event.isWitness = true;

        // 5. 更新哈希
        if (event.hash) {
            event.hash = `bomb_${Math.random().toString(36).substring(2, 15)}`;
        }

        return packet;
    }

    bombBlockMessage(packet) {
        const block = packet.content.block;
        if (!block) return packet;

        // 大规模篡改区块

        // 1. 修改区块索引
        if (block.index !== undefined) {
            block.index = Math.floor(Math.random() * 1000) + 50; // 非常高的区块索引
        }

        // 2. 修改轮次
        if (block.round !== undefined) {
            block.round = Math.floor(Math.random() * 100) + 3; // 非常高的轮次
        }

        // 3. 大量虚假交易
        block.transactions = Array(Math.floor(Math.random() * 50) + 20)
            .fill(0)
            .map(() => `BOMB_BLOCK_TX_${Math.random().toString(36).substring(2, 12)}`);

        // 4. 伪造事件引用
        if (block.events) {
            block.events = Array(Math.floor(Math.random() * 10) + 5)
                .fill(0)
                .map(() => `fake_event_${Math.random().toString(36).substring(2, 15)}`);
        }

        // 5. 修改区块哈希
        if (block.hash) {
            block.hash = `bomb_block_${Math.random().toString(36).substring(2, 15)}`;
        }

        return packet;
    }

    bombSyncMessage(packet) {
        // 同步消息攻击
        if (packet.content.type === 'babble-sync-request') {
            // 清空已知事件记录，迫使节点发送所有事件
            packet.content.knownEvents = {};
        }
        else if (packet.content.type === 'babble-sync-response') {
            // 注入大量虚假事件
            if (!packet.content.events) packet.content.events = [];

            const fakeEventCount = Math.floor(Math.random() * 20) + 10; // 10-30个虚假事件
            for (let i = 0; i < fakeEventCount; i++) {
                packet.content.events.push(this.createFakeEvent());
            }
        }

        return packet;
    }

    injectFakeMessages(packets) {
        // 为每个非拜占庭节点注入虚假消息
        for (let i = 1; i <= this.nodeNum - this.byzantineNodeNum; i++) {
            const targetNodeId = `${i}`;
            const sampleSrcNodes = [];

            // 随机选择多个源节点
            for (let j = 1; j <= Math.min(5, this.nodeNum - this.byzantineNodeNum); j++) {
                if (j != i) { // 不选自己
                    sampleSrcNodes.push(`${j}`);
                }
            }

            // 为每个源节点创建1-3条攻击消息
            for (const srcNodeId of sampleSrcNodes) {
                const messageCount = Math.floor(Math.random() * 3) + 1;

                for (let k = 0; k < messageCount; k++) {
                    // 随机选择注入的消息类型
                    const msgType = Math.random();

                    if (msgType < 0.4) {
                        // 注入虚假事件
                        packets.push({
                            src: srcNodeId,
                            dst: targetNodeId,
                            content: {
                                type: 'babble-event',
                                event: this.createFakeEvent()
                            }
                        });
                    }
                    else if (msgType < 0.7) {
                        // 注入虚假区块
                        packets.push({
                            src: srcNodeId,
                            dst: targetNodeId,
                            content: {
                                type: 'babble-block',
                                block: this.createFakeBlock()
                            }
                        });
                    }
                    else {
                        // 注入虚假同步响应
                        packets.push({
                            src: srcNodeId,
                            dst: targetNodeId,
                            content: {
                                type: 'babble-sync-response',
                                events: Array(Math.floor(Math.random() * 10) + 5)
                                    .fill(0)
                                    .map(() => this.createFakeEvent())
                            }
                        });
                    }
                }
            }
        }
    }

    createFakeEvent() {
        return {
            creatorID: `${Math.floor(Math.random() * this.nodeNum) + 1}`,
            selfParent: `fake_parent_${Math.random().toString(36).substring(2, 10)}`,
            otherParent: Math.random() < 0.5 ? `fake_other_${Math.random().toString(36).substring(2, 10)}` : null,
            timestamp: this.getClockTime() + (Math.random() * 10 - 5),
            transactions: Array(Math.floor(Math.random() * 5) + 1)
                .fill(0)
                .map(() => `BOMB_TX_${Math.random().toString(36).substring(2, 8)}`),
            round: Math.floor(Math.random() * 50) + this.highestObservedRound,
            isWitness: Math.random() < 0.7,
            hash: `fake_hash_${Math.random().toString(36).substring(2, 15)}`,
            signature: `fake_sig_${Math.random().toString(36).substring(2, 15)}`
        };
    }

    createFakeBlock() {
        return {
            index: Math.floor(Math.random() * 1000) + 100,
            round: Math.floor(Math.random() * 100) + this.highestObservedRound,
            events: Array(Math.floor(Math.random() * 10) + 3)
                .fill(0)
                .map(() => `fake_event_${Math.random().toString(36).substring(2, 12)}`),
            transactions: Array(Math.floor(Math.random() * 20) + 5)
                .fill(0)
                .map(() => `BOMB_BLOCK_TX_${Math.random().toString(36).substring(2, 10)}`),
            timestamp: this.getClockTime(),
            hash: `fake_block_${Math.random().toString(36).substring(2, 15)}`,
            signature: `fake_block_sig_${Math.random().toString(36).substring(2, 15)}`
        };
    }

    onTimeEvent(event) {
        if (event.functionMeta.name === 'checkTriggerConditions') {
            // 检查是否满足触发条件
            this.checkConditions();

            // 再次注册检查事件
            this.registerAttackerTimeEvent(
                { name: 'checkTriggerConditions' },
                3000 // 3秒后再次检查
            );

            // 如果当前处于炸弹激活状态，但是已经超过冷却期
            const currentTime = this.getClockTime();
            if (this.bombActivated && (currentTime - this.lastAttackTime) >= this.attackCooldown) {
                // 重置为休眠状态
                this.bombActivated = false;
                this.dormantPeriod = true;

                // 更新触发条件，为下一次攻击做准备
                this.triggerConditions.targetTime = currentTime + 30 + Math.random() * 20;
                this.triggerConditions.targetRound = this.highestObservedRound + 10;
                this.triggerConditions.targetBlockCount = this.observedBlockCount + 5;
                this.triggerConditions.specificEventDetected = false;
                this.nodeFailures.clear();

                console.log(`Logic bomb deactivated at ${currentTime}. Next target time: ${new Date(this.triggerConditions.targetTime * 1000).toISOString()}`);
            }
        }
    }

    updateParam() {
        return false; // 不更新参数
    }
}

module.exports = LogicBombAttacker;
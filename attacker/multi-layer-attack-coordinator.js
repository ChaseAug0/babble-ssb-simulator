'use strict';

/**
 * MultiLayerAttackCoordinator
 * 此攻击者在多个协议层次上同时进行协同攻击
 * 包括网络层、传输层、应用层和共识层
 */
class MultiLayerAttackCoordinator {
    constructor(transfer, registerAttackerTimeEvent, eventQ, nodeNum, byzantineNodeNum, getClockTime) {
        this.transfer = transfer;
        this.registerAttackerTimeEvent = registerAttackerTimeEvent;
        this.eventQ = eventQ;
        this.nodeNum = nodeNum;
        this.byzantineNodeNum = byzantineNodeNum;
        this.getClockTime = getClockTime;

        // 初始攻击模式
        this.currentPhase = 0;

        // 不同层次的攻击强度（0-1之间）
        this.attackStrength = {
            network: 0.1,    // 网络层攻击强度
            transport: 0.1,  // 传输层攻击强度
            application: 0.1, // 应用层攻击强度
            consensus: 0.1    // 共识层攻击强度
        };

        // 被攻击节点分组
        this.targetGroups = this.initializeTargetGroups();

        // 启动攻击周期
        this.registerAttackerTimeEvent(
            { name: 'phaseChange' },
            8000 // 8秒后切换攻击阶段
        );

        console.log('Multi-layer attack coordinator initialized');
    }

    initializeTargetGroups() {
        // 将非拜占庭节点分成不同组，用于针对性攻击
        const correctNodeCount = this.nodeNum - this.byzantineNodeNum;
        const groups = {
            networkTargets: new Set(),    // 网络层攻击目标
            transportTargets: new Set(),  // 传输层攻击目标
            applicationTargets: new Set(), // 应用层攻击目标
            consensusTargets: new Set()    // 共识层攻击目标
        };

        // 为每组分配一些节点（可能有重叠）
        for (let i = 1; i <= correctNodeCount; i++) {
            const nodeId = i.toString();

            // 随机分配到不同组
            if (Math.random() < 0.4) groups.networkTargets.add(nodeId);
            if (Math.random() < 0.4) groups.transportTargets.add(nodeId);
            if (Math.random() < 0.4) groups.applicationTargets.add(nodeId);
            if (Math.random() < 0.4) groups.consensusTargets.add(nodeId);
        }

        return groups;
    }

    attack(packets) {
        const processedPackets = [];

        for (const packet of packets) {
            let modifiedPacket = this.applyMultiLayerAttack(packet);

            // 如果包没有被完全丢弃（返回null），则添加到处理后的包列表
            if (modifiedPacket !== null) {
                processedPackets.push(modifiedPacket);
            }
        }

        return processedPackets;
    }

    applyMultiLayerAttack(packet) {
        const src = packet.src;
        const dst = packet.dst;

        // 1. 网络层攻击 - 丢包、延迟
        if (this.isNetworkLayerTarget(src, dst) && Math.random() < this.attackStrength.network) {
            // 丢包攻击
            if (Math.random() < 0.3) {
                return null; // 完全丢弃包
            }

            // 延迟攻击 - 通过修改延迟时间实现
            if (Math.random() < 0.4) {
                packet.delay = (packet.delay || 0) + Math.random() * 2; // 增加最多2秒延迟
            }
        }

        // 如果包被丢弃，提前返回
        if (packet === null) return null;

        // 2. 传输层攻击 - 包序列、分片
        if (this.isTransportLayerTarget(src, dst) &&
            packet.content && Math.random() < this.attackStrength.transport) {
            // 修改消息序列号（如果存在）
            if (packet.content.seq !== undefined) {
                if (Math.random() < 0.5) {
                    packet.content.seq += Math.floor(Math.random() * 10) - 5; // 上下偏移
                }
            }
        }

        // 3. 应用层攻击 - 数据内容篡改
        if (this.isApplicationLayerTarget(src, dst) &&
            packet.content && Math.random() < this.attackStrength.application) {

            // 根据消息类型选择合适的攻击
            if (packet.content.type === 'babble-event') {
                this.attackEventData(packet);
            }
            else if (packet.content.type === 'ssb-message') {
                this.attackSSBData(packet);
            }
        }

        // 4. 共识层攻击 - 轮次、区块、签名
        if (this.isConsensusLayerTarget(src, dst) &&
            packet.content && Math.random() < this.attackStrength.consensus) {

            if (packet.content.type === 'babble-block') {
                this.attackBlockData(packet);
            }
            else if (packet.content.type === 'babble-block-signature') {
                this.attackSignatureData(packet);
            }
            else if (packet.content.type === 'babble-sync-response') {
                this.attackSyncData(packet);
            }
        }

        return packet;
    }

    // 网络层攻击目标判断
    isNetworkLayerTarget(src, dst) {
        return this.targetGroups.networkTargets.has(src) ||
            this.targetGroups.networkTargets.has(dst);
    }

    // 传输层攻击目标判断
    isTransportLayerTarget(src, dst) {
        return this.targetGroups.transportTargets.has(src) ||
            this.targetGroups.transportTargets.has(dst);
    }

    // 应用层攻击目标判断
    isApplicationLayerTarget(src, dst) {
        return this.targetGroups.applicationTargets.has(src) ||
            this.targetGroups.applicationTargets.has(dst);
    }

    // 共识层攻击目标判断
    isConsensusLayerTarget(src, dst) {
        return this.targetGroups.consensusTargets.has(src) ||
            this.targetGroups.consensusTargets.has(dst);
    }

    // 攻击事件数据
    attackEventData(packet) {
        const event = packet.content.event;
        if (!event) return;

        // 篡改事件数据
        if (Math.random() < 0.4) {
            // 选择一个攻击策略
            const strategy = Math.random();

            if (strategy < 0.3) {
                // 篡改事件父引用
                event.selfParent = null;
            }
            else if (strategy < 0.6) {
                // 篡改事件交易
                if (event.transactions && event.transactions.length > 0) {
                    event.transactions[0] = `CORRUPT_${Math.random().toString(36).substring(2, 8)}`;
                }
            }
            else {
                // 篡改事件回合
                if (event.round !== undefined) {
                    event.round = Math.max(0, event.round + Math.floor(Math.random() * 3) - 1);
                }
            }

            // 更新哈希以使篡改看起来有效
            if (event.hash) {
                event.hash = `multi_corrupt_${Math.random().toString(36).substring(2, 15)}`;
            }
        }
    }

    // 攻击SSB数据
    attackSSBData(packet) {
        const message = packet.content.message;
        if (!message) return;

        // 篡改SSB消息
        if (Math.random() < 0.4) {
            // 修改序列号
            if (message.sequence !== undefined) {
                message.sequence += Math.floor(Math.random() * 3) - 1;
                if (message.sequence < 1) message.sequence = 1;
            }

            // 修改内容
            if (message.content) {
                if (typeof message.content === 'object') {
                    message.content.corrupted = true;
                    message.content.timestamp = this.getClockTime();
                }
            }
        }
    }

    // 攻击区块数据
    attackBlockData(packet) {
        const block = packet.content.block;
        if (!block) return;

        if (Math.random() < 0.5) {
            // 篡改区块交易
            if (block.transactions && block.transactions.length > 0) {
                const txIndex = Math.floor(Math.random() * block.transactions.length);
                block.transactions[txIndex] = `FAKE_TX_${Math.random().toString(36).substring(2, 8)}`;
            }

            // 修改区块哈希
            if (block.hash) {
                block.hash = `fake_block_${Math.random().toString(36).substring(2, 15)}`;
            }
        }
    }

    // 攻击签名数据
    attackSignatureData(packet) {
        if (Math.random() < 0.4) {
            // 篡改签名
            packet.content.signature = `invalid_sig_${Math.random().toString(36).substring(2, 15)}`;
        }
    }

    // 攻击同步数据
    attackSyncData(packet) {
        const response = packet.content;

        if (response.events && response.events.length > 0 && Math.random() < 0.4) {
            // 随机删除一些事件
            const removeCount = Math.floor(response.events.length * 0.2);
            for (let i = 0; i < removeCount; i++) {
                const idx = Math.floor(Math.random() * response.events.length);
                response.events.splice(idx, 1);
            }
        }
    }

    onTimeEvent(event) {
        if (event.functionMeta.name === 'phaseChange') {
            this.currentPhase = (this.currentPhase + 1) % 4;

            // 根据当前阶段调整攻击强度
            switch (this.currentPhase) {
                case 0: // 网络层重点攻击
                    this.attackStrength = {
                        network: 0.7,
                        transport: 0.2,
                        application: 0.1,
                        consensus: 0.1
                    };
                    break;

                case 1: // 传输层重点攻击
                    this.attackStrength = {
                        network: 0.2,
                        transport: 0.7,
                        application: 0.2,
                        consensus: 0.1
                    };
                    break;

                case 2: // 应用层重点攻击
                    this.attackStrength = {
                        network: 0.1,
                        transport: 0.2,
                        application: 0.7,
                        consensus: 0.2
                    };
                    break;

                case 3: // 共识层重点攻击
                    this.attackStrength = {
                        network: 0.1,
                        transport: 0.1,
                        application: 0.2,
                        consensus: 0.7
                    };
                    break;
            }

            console.log(`Switched to attack phase ${this.currentPhase}: network=${this.attackStrength.network}, transport=${this.attackStrength.transport}, application=${this.attackStrength.application}, consensus=${this.attackStrength.consensus}`);

            // 再次注册阶段转换事件
            this.registerAttackerTimeEvent(
                { name: 'phaseChange' },
                12000 // 12秒后切换
            );
        }
    }

    updateParam() {
        return false; // 不更新参数
    }
}

module.exports = MultiLayerAttackCoordinator;
'use strict';

/**
 * ManInTheMiddleAttacker
 * 此攻击者在节点之间充当中间人，拦截、修改、伪造消息
 * 可以选择性地改变消息内容或篡改发送者身份
 */
class ManInTheMiddleAttacker {
    constructor(transfer, registerAttackerTimeEvent, eventQ, nodeNum, byzantineNodeNum, getClockTime) {
        this.transfer = transfer;
        this.registerAttackerTimeEvent = registerAttackerTimeEvent;
        this.eventQ = eventQ;
        this.nodeNum = nodeNum;
        this.byzantineNodeNum = byzantineNodeNum;
        this.getClockTime = getClockTime;

        // 攻击参数
        this.modificationRate = 0.1;      // 消息修改概率
        this.identitySpoofingRate = 0.1;  // 身份欺骗概率
        this.routingManipulationRate = 0.1; // 路由操纵概率

        // 节点关系图 - 记录哪些节点通信频繁
        this.nodeRelationships = this.initNodeRelationships();

        // 记录已观察到的节点签名和身份信息
        this.observedSignatures = {}; // nodeID -> 签名样本
        this.observedIdentities = {}; // nodeID -> 身份相关信息

        // 定期更新节点关系图
        this.registerAttackerTimeEvent(
            { name: 'updateRelationships' },
            10000 // 10秒后更新
        );

        console.log('Man-in-the-middle attacker initialized');
    }

    initNodeRelationships() {
        const relationships = {};

        // 初始化节点关系矩阵
        for (let i = 1; i <= this.nodeNum; i++) {
            relationships[i] = {
                communicationFrequency: {}, // 与其他节点的通信频率
                trustLevel: {},             // 对其他节点的信任度（基于观察）
                lastSeen: this.getClockTime() // 上次活动时间
            };

            // 初始化与其他节点的关系数据
            for (let j = 1; j <= this.nodeNum; j++) {
                if (i !== j) {
                    relationships[i].communicationFrequency[j] = 0;
                    relationships[i].trustLevel[j] = 0.5; // 初始中等信任度
                }
            }
        }

        return relationships;
    }

    attack(packets) {
        // 更新节点关系数据
        this.updateNodeRelationships(packets);

        return packets.map(packet => {
            // 学习节点特征
            this.learnNodeSignatures(packet);

            // 决定是否进行中间人攻击
            if (this.shouldIntercept(packet)) {
                return this.interceptAndModify(packet);
            }

            return packet;
        });
    }

    updateNodeRelationships(packets) {
        // 基于消息流更新节点之间的关系数据
        for (const packet of packets) {
            const src = parseInt(packet.src);
            const dst = parseInt(packet.dst);

            // 跳过非数字ID或广播消息
            if (isNaN(src) || isNaN(dst) || dst === 0 || packet.dst === 'broadcast') continue;

            // 更新节点活动时间
            if (this.nodeRelationships[src]) {
                this.nodeRelationships[src].lastSeen = this.getClockTime();
            }

            // 更新通信频率
            if (this.nodeRelationships[src] && this.nodeRelationships[src].communicationFrequency[dst] !== undefined) {
                this.nodeRelationships[src].communicationFrequency[dst] += 1;
            }

            // 根据消息内容分析信任关系
            if (packet.content) {
                // 例如，同步消息或区块消息表示更高信任度
                if (packet.content.type === 'babble-sync-request' ||
                    packet.content.type === 'babble-sync-response' ||
                    packet.content.type === 'babble-block') {

                    if (this.nodeRelationships[src] && this.nodeRelationships[src].trustLevel[dst] !== undefined) {
                        // 略微增加信任度
                        this.nodeRelationships[src].trustLevel[dst] = Math.min(
                            1.0,
                            this.nodeRelationships[src].trustLevel[dst] + 0.01
                        );
                    }
                }
            }
        }
    }

    learnNodeSignatures(packet) {
        // 学习节点的签名模式用于后续伪造
        const src = packet.src;
        if (!src) return;

        // 初始化节点签名记录
        if (!this.observedSignatures[src]) {
            this.observedSignatures[src] = [];
            this.observedIdentities[src] = {
                knownEvents: {},
                publicKey: null,
                signingPattern: null
            };
        }

        // 收集签名样本
        if (packet.content) {
            if (packet.content.type === 'babble-event' && packet.content.event) {
                const event = packet.content.event;

                // 记录签名格式
                if (event.signature) {
                    this.observedSignatures[src].push(event.signature);

                    // 限制记录数量
                    if (this.observedSignatures[src].length > 10) {
                        this.observedSignatures[src].shift();
                    }

                    // 分析签名模式
                    if (this.observedSignatures[src].length >= 3) {
                        this.observedIdentities[src].signingPattern = this.analyzeSigningPattern(this.observedSignatures[src]);
                    }
                }

                // 记录事件引用模式
                if (event.selfParent) {
                    this.observedIdentities[src].knownEvents[src] = event.hash;
                }
            }

            if (packet.content.type === 'babble-block-signature') {
                // 记录区块签名
                if (packet.content.signature) {
                    this.observedSignatures[src].push(packet.content.signature);
                }
            }

            // 收集同步请求中的已知事件信息
            if (packet.content.type === 'babble-sync-request' && packet.content.knownEvents) {
                Object.assign(this.observedIdentities[src].knownEvents, packet.content.knownEvents);
            }
        }
    }

    analyzeSigningPattern(signatures) {
        // 简单分析签名的模式（前缀、长度等）
        if (!signatures || signatures.length === 0) return null;

        // 提取前缀（如果存在）
        let prefix = '';
        for (const sig of signatures) {
            if (typeof sig === 'string') {
                const parts = sig.split('_');
                if (parts.length > 1) {
                    prefix = parts[0] + '_' + parts[1] + '_';
                    break;
                }
            }
        }

        // 计算平均长度
        let totalLength = 0;
        let validCount = 0;

        for (const sig of signatures) {
            if (typeof sig === 'string') {
                totalLength += sig.length;
                validCount++;
            }
        }

        const avgLength = validCount > 0 ? totalLength / validCount : 0;

        return {
            prefix: prefix,
            averageLength: avgLength,
            sample: signatures[signatures.length - 1]
        };
    }

    shouldIntercept(packet) {
        // 确定是否应该截获并修改此消息
        const src = parseInt(packet.src);
        const dst = parseInt(packet.dst);

        // 不截获拜占庭节点发送的消息
        if (src > this.nodeNum - this.byzantineNodeNum) return false;

        // 不截获广播消息（除非低概率）
        if (packet.dst === 'broadcast' && Math.random() > 0.1) return false;

        // 检查消息类型 - 针对关键消息类型进行截获
        if (packet.content) {
            const msgType = packet.content.type;

            // 高价值目标：区块、共识相关消息
            if (msgType === 'babble-block' ||
                msgType === 'babble-block-signature' ||
                msgType === 'view-change') {
                return Math.random() < this.modificationRate * 1.5; // 高概率截获
            }

            // 事件和同步消息
            if (msgType === 'babble-event' ||
                msgType === 'babble-sync-response') {
                return Math.random() < this.modificationRate;
            }
        }

        // 基于节点关系决定是否截获
        if (!isNaN(src) && !isNaN(dst) &&
            this.nodeRelationships[src] &&
            this.nodeRelationships[dst]) {

            // 频繁通信的节点对更容易被截获
            const commFrequency = this.nodeRelationships[src].communicationFrequency[dst] || 0;
            if (commFrequency > 10) {
                return Math.random() < this.modificationRate * 1.2;
            }

            // 高信任关系的节点对
            const trustLevel = this.nodeRelationships[src].trustLevel[dst] || 0.5;
            if (trustLevel > 0.7) {
                return Math.random() < this.modificationRate * 1.3;
            }
        }

        // 默认截获率
        return Math.random() < this.modificationRate * 0.7;
    }

    interceptAndModify(packet) {
        const modifiedPacket = { ...packet };
        const attackType = Math.random();

        // 选择攻击类型
        if (attackType < this.identitySpoofingRate && packet.content) {
            // 身份欺骗攻击 - 伪造发送者
            return this.spoofSenderIdentity(modifiedPacket);
        }
        else if (attackType < this.identitySpoofingRate + this.routingManipulationRate) {
            // 路由操纵 - 改变消息目的地
            return this.manipulateRouting(modifiedPacket);
        }
        else {
            // 内容修改 - 篡改消息内容
            return this.modifyMessageContent(modifiedPacket);
        }
    }

    spoofSenderIdentity(packet) {
        // 伪造发送者身份
        const originalSrc = packet.src;

        // 找一个受信任的节点身份来伪造
        const trustworthyNodes = [];
        for (let i = 1; i <= this.nodeNum - this.byzantineNodeNum; i++) {
            const nodeId = i.toString();
            if (nodeId !== originalSrc && this.observedSignatures[nodeId] &&
                this.observedSignatures[nodeId].length > 0) {
                trustworthyNodes.push(nodeId);
            }
        }

        // 如果没有可用的信任节点，则不修改
        if (trustworthyNodes.length === 0) {
            return packet;
        }

        // 随机选择一个节点身份
        const spoofedNodeId = trustworthyNodes[Math.floor(Math.random() * trustworthyNodes.length)];
        packet.src = spoofedNodeId;

        // 如果有签名信息，尝试伪造
        if (packet.content) {
            if (packet.content.type === 'babble-event' && packet.content.event) {
                const event = packet.content.event;

                // 修改创建者ID
                event.creatorID = spoofedNodeId;

                // 尝试伪造签名
                if (this.observedIdentities[spoofedNodeId] &&
                    this.observedIdentities[spoofedNodeId].signingPattern) {

                    const pattern = this.observedIdentities[spoofedNodeId].signingPattern;
                    if (pattern.prefix && typeof pattern.sample === 'string') {
                        event.signature = pattern.prefix + Math.random().toString(36).substring(2, 15);
                    }
                }

                // 更新自引用
                if (this.observedIdentities[spoofedNodeId] &&
                    this.observedIdentities[spoofedNodeId].knownEvents[spoofedNodeId]) {
                    event.selfParent = this.observedIdentities[spoofedNodeId].knownEvents[spoofedNodeId];
                } else {
                    event.selfParent = null;
                }

                // 更新事件哈希
                if (event.hash) {
                    event.hash = `spoofed_${Math.random().toString(36).substring(2, 15)}`;
                }
            }

            if (packet.content.type === 'babble-block-signature') {
                // 伪造区块签名
                packet.content.nodeID = spoofedNodeId;

                // 尝试伪造签名
                if (this.observedSignatures[spoofedNodeId] &&
                    this.observedSignatures[spoofedNodeId].length > 0) {

                    const sampleSig = this.observedSignatures[spoofedNodeId][this.observedSignatures[spoofedNodeId].length - 1];
                    if (typeof sampleSig === 'string') {
                        const parts = sampleSig.split('_');
                        if (parts.length > 1) {
                            packet.content.signature = `${parts[0]}_${parts[1]}_${Math.random().toString(36).substring(2, 12)}`;
                        } else {
                            packet.content.signature = `spoofed_sig_${Math.random().toString(36).substring(2, 12)}`;
                        }
                    }
                }
            }
        }

        return packet;
    }

    manipulateRouting(packet) {
        const originalDst = packet.dst;

        // 广播消息变为点对点
        if (originalDst === 'broadcast') {
            // 挑选一个节点作为目标
            const targetId = Math.floor(Math.random() * (this.nodeNum - this.byzantineNodeNum)) + 1;
            packet.dst = targetId.toString();
            return packet;
        }

        // 点对点消息重定向到其他节点或变为广播
        if (originalDst !== 'broadcast') {
            if (Math.random() < 0.3) {
                // 变为广播
                packet.dst = 'broadcast';
            } else {
                // 重定向到其他节点
                let newDst;
                do {
                    newDst = Math.floor(Math.random() * (this.nodeNum - this.byzantineNodeNum)) + 1;
                } while (newDst.toString() === originalDst);

                packet.dst = newDst.toString();
            }
        }

        return packet;
    }

    modifyMessageContent(packet) {
        if (!packet.content || !packet.content.type) return packet;

        const msgType = packet.content.type;

        switch (msgType) {
            case 'babble-event':
                return this.modifyEventMessage(packet);

            case 'babble-block':
                return this.modifyBlockMessage(packet);

            case 'babble-sync-response':
                return this.modifySyncMessage(packet);

            case 'babble-block-signature':
                return this.modifySignatureMessage(packet);

            default:
                return packet;
        }
    }

    modifyEventMessage(packet) {
        const event = packet.content.event;
        if (!event) return packet;

        // 选择修改策略
        const strategy = Math.random();

        if (strategy < 0.3) {
            // 修改事件的父引用
            if (event.selfParent || event.otherParent) {
                if (Math.random() < 0.5 && event.selfParent) {
                    event.selfParent = `mitm_fake_${Math.random().toString(36).substring(2, 10)}`;
                }

                if (Math.random() < 0.5 && event.otherParent) {
                    event.otherParent = `mitm_fake_${Math.random().toString(36).substring(2, 10)}`;
                }
            }
        }
        else if (strategy < 0.6) {
            // 修改事件的交易内容
            if (event.transactions) {
                if (event.transactions.length > 0) {
                    // 替换部分交易
                    for (let i = 0; i < event.transactions.length; i++) {
                        if (Math.random() < 0.5) {
                            event.transactions[i] = `MITM_TX_${Math.random().toString(36).substring(2, 8)}`;
                        }
                    }
                } else {
                    // 添加虚假交易
                    event.transactions = [`MITM_TX_${Math.random().toString(36).substring(2, 8)}`];
                }
            }
        }
        else {
            // 修改事件的轮次或见证状态
            if (event.round !== undefined) {
                event.round = Math.max(0, event.round + Math.floor(Math.random() * 3) - 1);
            }

            if (event.isWitness !== undefined) {
                event.isWitness = !event.isWitness;
            }
        }

        // 更新事件哈希以使修改看起来有效
        if (event.hash) {
            event.hash = `mitm_${Math.random().toString(36).substring(2, 15)}`;
        }

        return packet;
    }

    modifyBlockMessage(packet) {
        const block = packet.content.block;
        if (!block) return packet;

        // 修改区块内容
        if (block.transactions && block.transactions.length > 0) {
            // 替换一些交易
            const txCount = Math.min(3, Math.floor(block.transactions.length * 0.3));
            for (let i = 0; i < txCount; i++) {
                const idx = Math.floor(Math.random() * block.transactions.length);
                block.transactions[idx] = `MITM_BLOCK_TX_${Math.random().toString(36).substring(2, 8)}`;
            }
        }

        // 修改区块的事件引用
        if (block.events && block.events.length > 0) {
            // 替换部分事件引用
            const eventCount = Math.min(2, Math.floor(block.events.length * 0.2));
            for (let i = 0; i < eventCount; i++) {
                const idx = Math.floor(Math.random() * block.events.length);
                block.events[idx] = `mitm_event_${Math.random().toString(36).substring(2, 10)}`;
            }
        }

        // 修改区块哈希
        if (block.hash) {
            block.hash = `mitm_block_${Math.random().toString(36).substring(2, 15)}`;
        }

        return packet;
    }

    modifySyncMessage(packet) {
        // 修改同步响应消息
        if (packet.content.events && packet.content.events.length > 0) {
            const events = packet.content.events;

            // 随机选择1-3个事件进行修改
            const modifyCount = Math.min(3, Math.ceil(events.length * 0.2));

            for (let i = 0; i < modifyCount; i++) {
                const eventIdx = Math.floor(Math.random() * events.length);
                const event = events[eventIdx];

                if (event) {
                    // 应用与事件消息相同的修改逻辑
                    const tempPacket = {
                        content: {
                            type: 'babble-event',
                            event: event
                        }
                    };

                    const modifiedPacket = this.modifyEventMessage(tempPacket);
                    events[eventIdx] = modifiedPacket.content.event;
                }
            }
        }

        return packet;
    }

    modifySignatureMessage(packet) {
        // 篡改签名消息
        if (packet.content.signature) {
            packet.content.signature = `mitm_sig_${Math.random().toString(36).substring(2, 12)}`;
        }

        // 有时更改引用的区块哈希
        if (packet.content.blockHash && Math.random() < 0.3) {
            packet.content.blockHash = `mitm_block_${Math.random().toString(36).substring(2, 12)}`;
        }

        return packet;
    }

    onTimeEvent(event) {
        if (event.functionMeta.name === 'updateRelationships') {
            // 清理和更新节点关系数据
            this.cleanupNodeData();

            // 调整攻击参数
            this.adjustAttackParameters();

            // 再次注册更新事件
            this.registerAttackerTimeEvent(
                { name: 'updateRelationships' },
                15000 // 15秒后更新
            );
        }
    }

    cleanupNodeData() {
        const currentTime = this.getClockTime();

        // 清理长时间不活跃节点的数据
        for (let nodeId in this.nodeRelationships) {
            const lastSeen = this.nodeRelationships[nodeId].lastSeen;
            if (currentTime - lastSeen > 60) { // 超过60秒不活跃
                // 重置通信频率
                for (let targetId in this.nodeRelationships[nodeId].communicationFrequency) {
                    this.nodeRelationships[nodeId].communicationFrequency[targetId] *= 0.5;
                }
            }
        }
    }

    adjustAttackParameters() {
        // 动态调整攻击参数
        const adjustmentFactor = 0.05;

        // 随机调整攻击概率
        this.modificationRate += (Math.random() * 2 - 1) * adjustmentFactor;
        this.identitySpoofingRate += (Math.random() * 2 - 1) * adjustmentFactor;
        this.routingManipulationRate += (Math.random() * 2 - 1) * adjustmentFactor;

        // 限制在合理范围内
        this.modificationRate = Math.min(0.6, Math.max(0.2, this.modificationRate));
        this.identitySpoofingRate = Math.min(0.5, Math.max(0.1, this.identitySpoofingRate));
        this.routingManipulationRate = Math.min(0.5, Math.max(0.1, this.routingManipulationRate));

        console.log(`Adjusted MITM parameters: mod=${this.modificationRate.toFixed(2)}, spoof=${this.identitySpoofingRate.toFixed(2)}, route=${this.routingManipulationRate.toFixed(2)}`);
    }

    updateParam() {
        return false; // 不更新参数
    }
}

module.exports = ManInTheMiddleAttacker;
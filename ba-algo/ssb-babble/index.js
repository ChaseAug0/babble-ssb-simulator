'use strict';

const Node = require('../node');
const uuid = require('uuid/v4');
const config = require('../../config');

// 消息类型定义
const MSG_TYPES = {
    // Babble 事件类型
    EVENT: 'babble-event',
    SYNC_REQUEST: 'babble-sync-request',
    SYNC_RESPONSE: 'babble-sync-response',

    // 区块和共识消息
    BLOCK: 'babble-block',
    BLOCK_SIGNATURE: 'babble-block-signature',

    // SSB 消息类型
    SSB_MESSAGE: 'ssb-message',
    SSB_SYNC_REQUEST: 'ssb-sync-request',
    SSB_SYNC_RESPONSE: 'ssb-sync-response'
};

// 辅助函数 - 扩展向量
function extendVector(v, index) {
    if (v[index] === undefined) {
        v[index] = [];
    }
    return v[index];
}

// 辅助函数 - 计算哈希
function calculateHash(data) {
    // 简单实现，实际应使用加密哈希
    return 'hash_' + Math.random().toString(36).substring(2, 15);
}

class SSBBabbleNode extends Node {
    constructor(nodeID, nodeNum, network, registerTimeEvent, customConfig) {
        super(nodeID, nodeNum, network, registerTimeEvent);
        this.config = customConfig || config;

        // 拜占庭容错参数
        this.f = Math.floor((this.nodeNum - 1) / 3); // 最大容错数

        // SSB 相关结构
        this.ssbMessages = {}; // 作者 -> 消息数组
        this.ssbFeed = {};     // 作者 -> 最新序列号

        // Babble 哈希图相关结构
        this.events = {};           // 事件哈希 -> 事件对象
        this.head = null;           // 本节点最新事件哈希
        this.witnesses = {};        // 轮次 -> 见证事件数组
        this.pendingEvents = [];    // 待处理事件数组
        this.knownEvents = {};      // 节点ID -> 已知事件哈希

        // 共识和区块相关
        this.round = 0;                // 当前轮次
        this.blocks = [];              // 已创建区块数组
        this.pendingTransactions = []; // 待处理交易
        this.consensusEvents = new Set(); // 已达成共识的事件
        this.blockSignatures = {};     // 区块哈希 -> 签名数组

        // 时间和同步
        this.syncInterval = 1000;    // 同步间隔(毫秒)
        this.lastSyncTime = {};      // 节点ID -> 上次同步时间
        this.heartbeatTimeout = this.config.lambda || 3; // 心跳超时(秒)
        this.isDecided = false;      // 是否达成共识
        this.isSuspended = false;    // 是否暂停共识
        this.undeterminedEvents = 0; // 未确定事件数量

        // 初始化节点
        this.initialize();
    }

    /*
     * 初始化和启动函数
     */

    initialize() {
        // 初始化与其他节点的连接
        for (let i = 1; i <= this.nodeNum; i++) {
            const peerID = i.toString();
            if (peerID !== this.nodeID) {
                this.knownEvents[peerID] = null;
                this.lastSyncTime[peerID] = 0;
            }
        }

        // 为自己创建初始事件
        this.createAndStoreEvent();

        // 开始同步循环
        this.registerTimeEvent({
            name: 'sync',
            params: {}
        }, this.syncInterval);

        // 开始心跳
        this.registerTimeEvent({
            name: 'heartbeat',
            params: {}
        }, this.heartbeatTimeout * 1000);
    }

    /*
     * SSB 相关方法
     */

    // 创建新的 SSB 消息
    createSSBMessage(content) {
        if (!this.ssbFeed[this.nodeID]) {
            this.ssbFeed[this.nodeID] = 0;
        }

        const sequence = this.ssbFeed[this.nodeID] + 1;
        const previous = sequence > 1 ?
            this.ssbMessages[this.nodeID][sequence - 2].hash : null;

        const message = {
            author: this.nodeID,
            sequence: sequence,
            previous: previous,
            timestamp: this.clock,
            content: content,
            hash: this._getSSBMessageHash(this.nodeID, sequence, previous, content)
        };

        // 签名消息
        message.signature = this._signSSBMessage(message);

        // 保存消息
        if (!this.ssbMessages[this.nodeID]) {
            this.ssbMessages[this.nodeID] = [];
        }
        this.ssbMessages[this.nodeID].push(message);
        this.ssbFeed[this.nodeID] = sequence;

        return message;
    }

    // 验证 SSB 消息
    validateSSBMessage(message) {
        // 检查消息是否有效
        if (!message || !message.author || !message.sequence) {
            return false;
        }

        // 检查序列号
        const author = message.author;
        const expectedSeq = (this.ssbFeed[author] || 0) + 1;

        if (message.sequence !== expectedSeq) {
            return false;
        }

        // 检查前置消息引用
        if (message.sequence > 1) {
            if (!this.ssbMessages[author] || !this.ssbMessages[author][message.sequence - 2]) {
                return false;
            }

            const previousMessage = this.ssbMessages[author][message.sequence - 2];
            if (message.previous !== previousMessage.hash) {
                return false;
            }
        }

        // 检查签名
        return this._verifySSBMessageSignature(message);
    }

    // 添加 SSB 消息到存储
    addSSBMessage(message) {
        if (!this.validateSSBMessage(message)) {
            return false;
        }

        const author = message.author;

        if (!this.ssbMessages[author]) {
            this.ssbMessages[author] = [];
        }

        this.ssbMessages[author].push(message);
        this.ssbFeed[author] = message.sequence;

        // 广播消息
        this.broadcastSSBMessage(message);

        return true;
    }

    // 广播 SSB 消息
    broadcastSSBMessage(message) {
        const ssbMsg = {
            type: MSG_TYPES.SSB_MESSAGE,
            message: message
        };

        this.send(this.nodeID, 'broadcast', ssbMsg);
    }

    // 处理接收到的 SSB 消息
    handleSSBMessage(msg) {
        const message = msg.message;
        this.addSSBMessage(message);

        // 将消息添加到待处理交易
        this.pendingTransactions.push(message.hash);
    }

    // 处理 SSB 同步请求
    handleSSBSyncRequest(msg, src) {
        const author = msg.author || this.nodeID;
        const fromSeq = msg.fromSequence || 0;

        // 获取请求的消息
        const messages = [];
        if (this.ssbMessages[author]) {
            for (const message of this.ssbMessages[author]) {
                if (message.sequence > fromSeq) {
                    messages.push(message);
                }
            }
        }

        // 发送响应
        const response = {
            type: MSG_TYPES.SSB_SYNC_RESPONSE,
            author: author,
            messages: messages
        };

        this.send(this.nodeID, src, response);
    }

    // 处理 SSB 同步响应
    handleSSBSyncResponse(msg) {
        for (const message of msg.messages) {
            this.addSSBMessage(message);
        }
    }

    // 请求 SSB 消息同步
    requestSSBSync(peer, author, fromSequence) {
        const request = {
            type: MSG_TYPES.SSB_SYNC_REQUEST,
            author: author,
            fromSequence: fromSequence
        };

        this.send(this.nodeID, peer, request);
    }

    /*
     * Babble 哈希图相关方法
     */

    // 创建新的事件
    createEvent(selfParent, otherParent, transactions) {
        const event = {
            creatorID: this.nodeID,
            selfParent: selfParent,
            otherParent: otherParent,
            timestamp: this.clock,
            transactions: transactions || [],
            signature: null,
            round: -1,
            consensus: false,
            isWitness: false
        };

        // 计算事件哈希
        event.hash = this._calculateEventHash(event);

        // 签名事件
        event.signature = this._signEvent(event);

        return event;
    }

    // 创建并存储新事件
    createAndStoreEvent(otherParent, transactions) {
        const event = this.createEvent(this.head, otherParent, transactions);
        this.storeEvent(event);
        return event;
    }

    // 存储事件
    storeEvent(event) {
        // 存储事件
        this.events[event.hash] = event;

        // 更新头指针
        if (event.creatorID === this.nodeID) {
            this.head = event.hash;
            this.knownEvents[this.nodeID] = event.hash;
        }

        // 更新已知事件
        if (!this.knownEvents[event.creatorID] ||
            this.events[this.knownEvents[event.creatorID]].timestamp < event.timestamp) {
            this.knownEvents[event.creatorID] = event.hash;
        }

        // 处理新事件
        this.processNewEvent(event);
    }

    // 处理新事件
    processNewEvent(event) {
        // 添加到待处理列表
        this.pendingEvents.push(event.hash);

        // 运行共识算法
        this.runConsensus();
    }

    // 广播事件
    broadcastEvent(event) {
        const eventMsg = {
            type: MSG_TYPES.EVENT,
            event: event
        };

        this.send(this.nodeID, 'broadcast', eventMsg);
    }

    // 同步事件
    syncEvents(peer) {
        const knownEvents = {};
        for (const nodeID in this.knownEvents) {
            if (this.knownEvents[nodeID]) {
                knownEvents[nodeID] = this.knownEvents[nodeID];
            }
        }

        const syncRequest = {
            type: MSG_TYPES.SYNC_REQUEST,
            knownEvents: knownEvents
        };

        this.send(this.nodeID, peer, syncRequest);
        this.lastSyncTime[peer] = this.clock;
    }

    // 处理同步请求
    handleSyncRequest(msg, src) {
        const theirKnownEvents = msg.knownEvents || {};
        const eventsToSend = [];

        // 查找对方不知道的事件
        for (const eventHash in this.events) {
            const event = this.events[eventHash];
            const nodeID = event.creatorID;

            if (!theirKnownEvents[nodeID] ||
                !this.events[theirKnownEvents[nodeID]] ||
                this.events[theirKnownEvents[nodeID]].timestamp < event.timestamp) {
                eventsToSend.push(event);
            }
        }

        // 发送响应
        const syncResponse = {
            type: MSG_TYPES.SYNC_RESPONSE,
            events: eventsToSend
        };

        this.send(this.nodeID, src, syncResponse);
    }

    // 处理同步响应
    handleSyncResponse(msg) {
        const events = msg.events || [];
        let newEvents = false;

        for (const event of events) {
            if (!this.events[event.hash]) {
                this.storeEvent(event);
                newEvents = true;
            }
        }

        if (newEvents) {
            // 有新事件，运行共识
            this.runConsensus();
        }
    }

    /*
     * 共识算法实现
     */

    // 运行共识算法
    runConsensus() {
        if (this.isSuspended) {
            return;
        }

        // 1. 分配轮次
        this.divideRounds();

        // 2. 确定见证节点
        this.decideFame();

        // 3. 查找共识顺序
        const newConsensusEvents = this.findConsensusOrder();

        // 4. 处理新达成共识的事件
        if (newConsensusEvents.length > 0) {
            this.processConsensusEvents(newConsensusEvents);
        }

        // 检查是否应该暂停
        this.checkSuspendCondition();
    }

    // 分配轮次
    divideRounds() {
        // 遍历所有待处理事件
        for (const eventHash of this.pendingEvents) {
            const event = this.events[eventHash];

            if (event.round < 0) {
                // 确定父事件的最高轮次
                let parentRound = -1;

                if (event.selfParent && this.events[event.selfParent]) {
                    parentRound = Math.max(parentRound, this.events[event.selfParent].round);
                }

                if (event.otherParent && this.events[event.otherParent]) {
                    parentRound = Math.max(parentRound, this.events[event.otherParent].round);
                }

                // 当前事件的轮次为父事件的最高轮次+1
                event.round = parentRound + 1;

                // 更新最高轮次
                this.round = Math.max(this.round, event.round);

                // 检查是否为见证事件
                event.isWitness = this.isWitness(event);

                // 将见证事件添加到见证列表
                if (event.isWitness) {
                    if (!this.witnesses[event.round]) {
                        this.witnesses[event.round] = [];
                    }
                    this.witnesses[event.round].push(eventHash);
                }
            }
        }

        // 清空待处理列表
        this.pendingEvents = [];
    }

    // 检查事件是否为见证事件
    isWitness(event) {
        if (event.round <= 0) {
            return true;  // 第0轮所有事件都是见证事件
        }

        // 检查是否是自己创建的第一个事件
        if (event.selfParent) {
            const parentEvent = this.events[event.selfParent];
            return parentEvent.round < event.round;
        }

        return true;  // 没有自引用，所以是创建者的第一个事件
    }

    // 决定见证事件的"著名性"
    decideFame() {
        // 简化实现：假设所有见证事件都是著名的
        // 实际上应该实现 Babble 的虚拟投票算法
    }

    // 找出新达成共识的事件
    findConsensusOrder() {
        const newConsensus = [];

        // 遍历所有事件
        for (const eventHash in this.events) {
            const event = this.events[eventHash];

            // 如果事件已达成共识，则跳过
            if (this.consensusEvents.has(eventHash)) {
                continue;
            }

            // 简化条件：轮次比当前轮次小2的事件被认为达成共识
            if (event.round <= this.round - 2) {
                event.consensus = true;
                this.consensusEvents.add(eventHash);
                newConsensus.push(eventHash);
            } else {
                this.undeterminedEvents++;
            }
        }

        return newConsensus;
    }

    // 处理新达成共识的事件
    processConsensusEvents(consensusEvents) {
        if (consensusEvents.length === 0) return;

        // 按轮次分组事件
        const eventsByRound = {};

        for (const eventHash of consensusEvents) {
            const event = this.events[eventHash];
            if (!eventsByRound[event.round]) {
                eventsByRound[event.round] = [];
            }
            eventsByRound[event.round].push(event);
        }

        // 为每个轮次创建区块
        for (const round in eventsByRound) {
            const events = eventsByRound[round];
            const transactions = this.collectTransactions(events);

            const block = {
                index: this.blocks.length,
                round: parseInt(round),
                events: events.map(e => e.hash),
                transactions: transactions,
                timestamp: this.clock,
                signature: null
            };

            // 计算区块哈希
            block.hash = this._calculateBlockHash(block);

            // 签名区块
            block.signature = this._signBlock(block);

            // 添加区块
            this.blocks.push(block);

            // 初始化区块签名集合
            this.blockSignatures[block.hash] = [
                { nodeID: this.nodeID, signature: block.signature }
            ];

            // 广播区块
            this.broadcastBlock(block);

            // 检查是否已经达成决策
            if (this.blocks.length > 3) {
                this.isDecided = true;
            }
        }
    }

    // 从事件中收集交易
    collectTransactions(events) {
        const transactions = [];
        const seenTxs = new Set();

        for (const event of events) {
            for (const tx of event.transactions) {
                if (!seenTxs.has(tx)) {
                    transactions.push(tx);
                    seenTxs.add(tx);
                }
            }
        }

        return transactions;
    }

    // 广播区块
    broadcastBlock(block) {
        const blockMsg = {
            type: MSG_TYPES.BLOCK,
            block: block
        };

        this.send(this.nodeID, 'broadcast', blockMsg);
    }

    // 处理接收到的区块
    handleBlock(msg) {
        const block = msg.block;

        // 验证区块
        if (!this._verifyBlock(block)) {
            return;
        }

        // 如果是新区块，保存并签名
        if (!this.blocks.some(b => b.hash === block.hash)) {
            this.blocks.push(block);

            // 签名区块
            const signature = this._signBlock(block);

            // 发送签名
            const signatureMsg = {
                type: MSG_TYPES.BLOCK_SIGNATURE,
                blockHash: block.hash,
                signature: signature,
                nodeID: this.nodeID
            };

            this.send(this.nodeID, 'broadcast', signatureMsg);

            // 检查是否已经达成决策
            if (this.blocks.length > 3) {
                this.isDecided = true;
            }
        }
    }

    // 处理区块签名
    handleBlockSignature(msg) {
        const { blockHash, signature, nodeID } = msg;

        // 初始化签名集合
        if (!this.blockSignatures[blockHash]) {
            this.blockSignatures[blockHash] = [];
        }

        // 添加签名
        if (!this.blockSignatures[blockHash].some(s => s.nodeID === nodeID)) {
            this.blockSignatures[blockHash].push({ nodeID, signature });
        }

        // 检查签名是否足够
        if (this.blockSignatures[blockHash].length >= 2 * this.f + 1) {
            // 区块获得足够多的签名，可以认为是最终确定的
            const block = this.blocks.find(b => b.hash === blockHash);
            if (block) {
                block.final = true;
            }
        }
    }

    // 检查是否应该暂停
    checkSuspendCondition() {
        const suspendLimit = this.config.suspendLimit || 100;
        if (this.undeterminedEvents > suspendLimit * this.nodeNum) {
            this.isSuspended = true;
            this.logger.warning(['Node suspended due to too many undetermined events']);
        }
    }

    /*
     * BFT-Simulator 接口实现
     */

    // 处理消息事件
    onMsgEvent(msgEvent) {
        super.onMsgEvent(msgEvent);
        const msg = msgEvent.packet.content;
        const src = msgEvent.packet.src;

        this.logger.info(['recv', this.logger.round(msgEvent.triggeredTime), JSON.stringify(msg)]);

        // 处理不同类型的消息
        switch (msg.type) {
            case MSG_TYPES.EVENT:
                this.storeEvent(msg.event);
                break;

            case MSG_TYPES.SYNC_REQUEST:
                this.handleSyncRequest(msg, src);
                break;

            case MSG_TYPES.SYNC_RESPONSE:
                this.handleSyncResponse(msg);
                break;

            case MSG_TYPES.SSB_MESSAGE:
                this.handleSSBMessage(msg);
                break;

            case MSG_TYPES.SSB_SYNC_REQUEST:
                this.handleSSBSyncRequest(msg, src);
                break;

            case MSG_TYPES.SSB_SYNC_RESPONSE:
                this.handleSSBSyncResponse(msg);
                break;

            case MSG_TYPES.BLOCK:
                this.handleBlock(msg);
                break;

            case MSG_TYPES.BLOCK_SIGNATURE:
                this.handleBlockSignature(msg);
                break;

            default:
                this.logger.warning(['Unknown message type:', msg.type]);
        }
    }

    // 处理时间事件
    onTimeEvent(timeEvent) {
        super.onTimeEvent(timeEvent);
        const functionMeta = timeEvent.functionMeta;

        // 处理不同类型的时间事件
        switch (functionMeta.name) {
            case 'sync':
                // 执行同步
                this.doSync();
                // 注册下一次同步
                this.registerTimeEvent({
                    name: 'sync',
                    params: {}
                }, this.syncInterval);
                break;

            case 'heartbeat':
                // 执行心跳
                this.doHeartbeat();
                // 注册下一次心跳
                this.registerTimeEvent({
                    name: 'heartbeat',
                    params: {}
                }, this.heartbeatTimeout * 1000);
                break;

            default:
                this.logger.warning(['Unknown time event:', functionMeta.name]);
        }
    }

    // 执行同步
    doSync() {
        if (this.isSuspended) {
            return;
        }

        // 随机选择一个对等点进行同步
        const peers = Object.keys(this.knownEvents).filter(id => id !== this.nodeID);

        if (peers.length > 0) {
            const peer = peers[Math.floor(Math.random() * peers.length)];
            this.syncEvents(peer);

            // 同步 SSB 消息
            if (this.ssbFeed[peer] !== undefined) {
                this.requestSSBSync(peer, peer, this.ssbFeed[peer] || 0);
            }
        }

        // 创建新事件，如果有待处理交易
        if (this.pendingTransactions.length > 0) {
            const txs = this.pendingTransactions.splice(0, 10); // 最多处理10个交易
            this.createAndStoreEvent(null, txs);
        }
    }

    // 执行心跳
    doHeartbeat() {
        if (this.isSuspended) {
            return;
        }

        // 如果没有待处理交易，创建一个空事件
        if (this.pendingTransactions.length === 0) {
            this.createAndStoreEvent();
        }

        // 运行共识算法
        this.runConsensus();
    }

    /*
     * 辅助方法 (内部使用)
     */

    // 计算事件哈希
    _calculateEventHash(event) {
        // 简化实现，实际应使用加密哈希
        const data = `${event.creatorID}|${event.selfParent}|${event.otherParent}|${event.timestamp}|${JSON.stringify(event.transactions)}`;
        return calculateHash(data);
    }

    // 签名事件
    _signEvent(event) {
        // 简化实现，实际应使用私钥签名
        return `signature_${this.nodeID}_${event.hash}`;
    }

    // 验证事件签名
    _verifyEventSignature(event) {
        // 简化实现，实际应使用公钥验证
        return event.signature === `signature_${event.creatorID}_${event.hash}`;
    }

    // 计算区块哈希
    _calculateBlockHash(block) {
        // 简化实现，实际应使用加密哈希
        const data = `${block.index}|${block.round}|${JSON.stringify(block.events)}|${JSON.stringify(block.transactions)}|${block.timestamp}`;
        return calculateHash(data);
    }

    // 签名区块
    _signBlock(block) {
        // 简化实现，实际应使用私钥签名
        return `block_signature_${this.nodeID}_${block.hash}`;
    }

    // 验证区块
    _verifyBlock(block) {
        // 验证基本字段
        if (!block || !block.hash || !block.events || !block.transactions) {
            return false;
        }

        // 验证事件列表
        for (const eventHash of block.events) {
            if (!this.events[eventHash]) {
                return false;
            }
        }

        // 验证签名
        if (block.signature) {
            // 简化实现，实际应使用公钥验证
            return block.signature.startsWith(`block_signature_`);
        }

        return true;
    }

    // 获取 SSB 消息哈希
    _getSSBMessageHash(author, sequence, previous, content) {
        // 简化实现，实际应使用加密哈希
        const data = `${author}|${sequence}|${previous}|${JSON.stringify(content)}`;
        return calculateHash(data);
    }

    // 签名 SSB 消息
    _signSSBMessage(message) {
        // 简化实现，实际应使用私钥签名
        return `ssb_signature_${this.nodeID}_${message.hash}`;
    }

    // 验证 SSB 消息签名
    _verifySSBMessageSignature(message) {
        // 简化实现，实际应使用公钥验证
        return message.signature === `ssb_signature_${message.author}_${message.hash}`;
    }
}

// Byzantine 节点的基础类
class ByzantineBabbleNode extends SSBBabbleNode {
    constructor(nodeID, nodeNum, network, registerTimeEvent, customConfig) {
        super(nodeID, nodeNum, network, registerTimeEvent, customConfig);
        this.isByzantine = true;
        this.byzantineType = "generic";
    }

    // 重写消息处理方法来实现拜占庭行为
    onMsgEvent(msgEvent) {
        // 随机丢弃消息
        if (Math.random() < 0.3) {
            return;
        }

        super.onMsgEvent(msgEvent);
    }

    // 创建可能包含恶意行为的事件
    createEvent(selfParent, otherParent, transactions) {
        // 恶意行为选择
        const byzantineChoice = Math.random();

        if (byzantineChoice < 0.3) {
            // 创建无效事件 (使用不存在的父事件)
            return super.createEvent("invalid_parent", otherParent, transactions);
        } else if (byzantineChoice < 0.6) {
            // 不引用其他节点 (不帮助达成共识)
            return super.createEvent(selfParent, null, transactions);
        }

        // 正常行为
        return super.createEvent(selfParent, otherParent, transactions);
    }
}

// 分叉攻击节点
class ForkingNode extends ByzantineBabbleNode {
    constructor(nodeID, nodeNum, network, registerTimeEvent, customConfig) {
        super(nodeID, nodeNum, network, registerTimeEvent, customConfig);
        this.byzantineType = "forking";
        this.forkEvents = {};
    }

    // 创建分叉事件
    createAndStoreEvent(otherParent, transactions) {
        // 创建多个使用相同自引用的事件 (分叉)
        const event1 = this.createEvent(this.head, otherParent, transactions);
        this.storeEvent(event1);

        // 对不同节点发送不同的事件
        this.forkEvents[event1.hash] = {};

        for (let i = 1; i <= this.nodeNum; i++) {
            const peerID = i.toString();
            if (peerID !== this.nodeID) {
                // 创建一个不同的事件，但使用相同的自引用
                const forkEvent = this.createEvent(this.head, otherParent, ["FORK_" + peerID]);
                this.forkEvents[event1.hash][peerID] = forkEvent;
            }
        }

        return event1;
    }

    // 发送针对特定节点的分叉事件
    broadcastEvent(event) {
        // 如果有对应的分叉事件，分别发送给不同节点
        if (this.forkEvents[event.hash]) {
            for (const peerID in this.forkEvents[event.hash]) {
                const forkEvent = this.forkEvents[event.hash][peerID];
                const eventMsg = {
                    type: MSG_TYPES.EVENT,
                    event: forkEvent
                };

                this.send(this.nodeID, peerID, eventMsg);
            }
        } else {
            // 没有分叉事件，正常广播
            super.broadcastEvent(event);
        }
    }
}

// 等价攻击节点
class EquivocatingNode extends ByzantineBabbleNode {
    constructor(nodeID, nodeNum, network, registerTimeEvent, customConfig) {
        super(nodeID, nodeNum, network, registerTimeEvent, customConfig);
        this.byzantineType = "equivocating";
        this.syncResponses = {};
    }

    // 为不同节点提供不同的同步响应
    handleSyncRequest(msg, src) {
        // 随机决定是否进行等价攻击
        if (Math.random() < 0.5) {
            // 创建一个特定于此接收者的同步响应
            const eventsToSend = [];

            // 选择一部分事件发送，忽略另一部分
            for (const eventHash in this.events) {
                if (Math.random() < 0.7) {  // 70%的概率包含事件
                    eventsToSend.push(this.events[eventHash]);
                }
            }

            // 保存这个响应用于将来比较
            this.syncResponses[src] = eventsToSend.map(e => e.hash);

            // 发送响应
            const syncResponse = {
                type: MSG_TYPES.SYNC_RESPONSE,
                events: eventsToSend
            };

            this.send(this.nodeID, src, syncResponse);
        } else {
            // 正常行为
            super.handleSyncRequest(msg, src);
        }
    }
}

// 延迟节点
class DelayingNode extends ByzantineBabbleNode {
    constructor(nodeID, nodeNum, network, registerTimeEvent, customConfig) {
        super(nodeID, nodeNum, network, registerTimeEvent, customConfig);
        this.byzantineType = "delaying";
        this.delayedMessages = [];
    }

    // 延迟消息处理
    onMsgEvent(msgEvent) {
        // 随机延迟消息
        if (Math.random() < 0.6) {
            const delay = 2 + Math.random() * 3;  // 2-5秒延迟
            this.registerTimeEvent(
                { name: 'delayedMsg', params: { msg: msgEvent } },
                delay * 1000
            );
            return;
        }

        // 正常处理消息
        super.onMsgEvent(msgEvent);
    }

    // 处理延迟消息
    onTimeEvent(timeEvent) {
        const functionMeta = timeEvent.functionMeta;

        if (functionMeta.name === 'delayedMsg') {
            super.onMsgEvent(functionMeta.params.msg);
        } else {
            super.onTimeEvent(timeEvent);
        }
    }
}

// 根据类型创建拜占庭节点
function createByzantineNode(type, nodeID, nodeNum, network, registerTimeEvent, customConfig) {
    switch (type) {
        case 'forking':
            return new ForkingNode(nodeID, nodeNum, network, registerTimeEvent, customConfig);
        case 'equivocating':
            return new EquivocatingNode(nodeID, nodeNum, network, registerTimeEvent, customConfig);
        case 'delaying':
            return new DelayingNode(nodeID, nodeNum, network, registerTimeEvent, customConfig);
        default:
            return new ByzantineBabbleNode(nodeID, nodeNum, network, registerTimeEvent, customConfig);
    }
}

// 导出主节点类和函数
module.exports = SSBBabbleNode;
module.exports.createByzantineNode = createByzantineNode;
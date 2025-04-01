'use strict';

/**
 * EnhancedByzantineAttackCoordinator
 * 增强版拜占庭攻击协调器，支持针对多种共识协议的特定攻击
 * 包括 LibP2P-Babble, Algorand, HotStuff-NS, LibraBFT, PBFT
 */
class ByzantineAttackCoordinator {
    constructor(transfer, registerAttackerTimeEvent, eventQ, nodeNum, byzantineNodeNum, getClockTime) {
        this.transfer = transfer;
        this.registerAttackerTimeEvent = registerAttackerTimeEvent;
        this.eventQ = eventQ;
        this.nodeNum = nodeNum;
        this.byzantineNodeNum = byzantineNodeNum;
        this.getClockTime = getClockTime;

        // 协议检测
        this.detectedProtocol = null;
        this.protocolTypes = [
            'libp2p-babble',    // 基于Hashgraph的共识
            'ssb-babble',    // 基于Hashgraph的共识
            'algorand',         // 基于VRF和BA*的共识
            'hotstuff-ns',      // 链式BFT共识
            'librabft',         // 基于HotStuff的共识
            'pbft'              // 实用拜占庭容错
        ];
        this.protocolDetectionCount = {};
        this.protocolTypes.forEach(p => this.protocolDetectionCount[p] = 0);

        // 攻击阶段和模式
        this.currentPhase = 0;
        this.phaseStartTime = this.getClockTime();
        this.phaseDuration = 2;
        this.attackModes = [
            'normal',           // 正常行为（休眠期）
            'data_forgery',     // 数据篡改
            'sync_disrupt',     // 同步干扰
            'partition',        // 网络分区
            'equivocation',     // 等价攻击
            'timing',           // 时序攻击
            'protocol_specific',// 协议特定攻击
            'comprehensive'     // 综合攻击
        ];
        this.currentMode = 'comprehensive';
        this.attackIntensity = 0.6;

        // 协议特定状态跟踪
        this.protocolState = {
            babble: {
                round: 0,
                events: {},
                blocks: [],
                witnessed: new Set(),
                ssbFeeds: {},         // Track author -> sequence mappings
                ssbMessages: {},      // Track message hashes
                ssbForks: new Set()   // Track detected feed forks
            },
            algorand: {
                round: 0,
                step: 0,
                proposals: {},
                votes: {}
            },
            hotstuff: {
                view: 0,
                highQC: null,
                leaders: new Set()
            },
            libra: {
                round: 0,
                view: 0,
                timeout: false
            },
            pbft: {
                view: 0,
                sequence: 0,
                prepares: {},
                commits: {}
            }
        };

        // 系统状态
        this.systemState = {
            round: 0,
            blocks: 0,
            activeNodes: new Set(),
            eventCount: 0,
            lastDecisionTime: 0
        };

        // 拜占庭节点集
        this.byzantineNodes = new Set();
        for (let i = 1; i <= byzantineNodeNum; i++) {
            this.byzantineNodes.add((this.nodeNum - i + 1).toString());
        }

        // 注册周期性事件
        this.registerAttackerTimeEvent(
            { name: 'phaseChange' },
            this.phaseDuration * 1000
        );

        this.registerAttackerTimeEvent(
            { name: 'observeSystem' },
            5000
        );

        // console.log('增强版拜占庭攻击协调器已初始化，支持多协议攻击');
    }

    attack(packets) {
        // 检测协议类型
        this.detectProtocol(packets);

        // 更新系统和协议状态
        this.updateSystemState(packets);
        this.updateProtocolState(packets);

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

            case 'protocol_specific':
                return this.protocolSpecificAttack(packets);

            case 'comprehensive':
                return this.comprehensiveAttack(packets);

            default:
                return packets;
        }
    }

    /**
     * 协议检测 
     */
    detectProtocol(packets) {
        if (this.detectedProtocol) return; // 已经检测到协议

        for (const packet of packets) {
            if (!packet.content || !packet.content.type) continue;

            const msgType = packet.content.type.toLowerCase();

            if (msgType.includes('babble') ||
                msgType === 'babble-event' ||
                msgType === 'babble-sync-request' ||
                msgType === 'babble-sync-response' ||
                msgType === 'babble-block' ||
                msgType === 'babble-block-signature' ||
                msgType === 'ssb-message' ||
                msgType === 'ssb-sync-request' ||
                msgType === 'ssb-sync-response') {
                this.protocolDetectionCount['libp2p-babble'] += 2; // 增加权重
            }
            // LibP2P-Babble 检测
            if (msgType.includes('babble') || msgType === 'babble-event' ||
                msgType === 'babble-sync-request' || msgType === 'babble-block') {
                this.protocolDetectionCount['libp2p-babble']++;
            }
            // ssb-babble 检测
            else if (msgType === 'ssb-message' ||
                msgType === 'ssb-sync-request' ||
                msgType === 'ssb-sync-response') {
                this.protocolDetectionCount['libp2p-babble']++;
            }
            // Algorand 检测
            else if (msgType === 'propose' || msgType === 'soft' ||
                msgType === 'cert' || msgType === 'next' ||
                msgType === 'certificate') {
                this.protocolDetectionCount['algorand']++;
            }

            // HotStuff-NS 检测
            else if (msgType === 'hot-stuff-vote' || msgType === 'hot-stuff-proposal' ||
                msgType.includes('hot-stuff-') ||
                packet.content.view !== undefined && packet.content.QC !== undefined) {
                this.protocolDetectionCount['hotstuff-ns']++;
            }

            // LibraBFT 检测
            else if (msgType === 'hot-stuff-update' || msgType === 'hot-stuff-next-view' ||
                (msgType.includes('hot-stuff') && packet.content.primary !== undefined)) {
                this.protocolDetectionCount['librabft']++;
            }

            // PBFT 检测
            else if (msgType === 'pre-prepare' || msgType === 'prepare' ||
                msgType === 'commit' || msgType === 'view-change' ||
                msgType === 'new-view') {
                this.protocolDetectionCount['pbft']++;
            }
        }

        // 确定检测到的主要协议
        let maxCount = 0;
        let detectedProtocol = null;

        for (const protocol in this.protocolDetectionCount) {
            if (this.protocolDetectionCount[protocol] > maxCount) {
                maxCount = this.protocolDetectionCount[protocol];
                detectedProtocol = protocol;
            }
        }

        // 当检测计数达到一定阈值时确认协议
        if (maxCount >= 2) {
            this.detectedProtocol = detectedProtocol;
            console.log(`检测到共识协议: ${this.detectedProtocol}`);
        }
    }

    /**
     * 系统状态更新
     */
    updateSystemState(packets) {
        const currentTime = this.getClockTime();

        // 更新活跃节点
        for (const packet of packets) {
            if (packet.src) {
                this.systemState.activeNodes.add(packet.src);
            }

            if (!packet.content) continue;

            // 更新轮次/区块计数
            if (packet.content.round !== undefined) {
                this.systemState.round = Math.max(this.systemState.round, packet.content.round);
            }

            if (packet.content.type &&
                (packet.content.type.includes('block') ||
                    packet.content.type.includes('decide'))) {
                this.systemState.blocks++;
                this.systemState.lastDecisionTime = currentTime;
            }

            // 事件计数
            this.systemState.eventCount++;
        }
    }

    /**
     * 协议特定状态更新
     */
    updateProtocolState(packets) {
        for (const packet of packets) {
            if (!packet.content) continue;

            const content = packet.content;
            const msgType = content.type?.toLowerCase();

            // LibP2P-Babble状态更新
            if (msgType === 'babble-event') {
                if (content.event) {
                    const event = content.event;
                    this.protocolState.babble.events[event.hash] = event;

                    // 更强健的轮次追踪
                    if (event.round !== undefined) {
                        const roundValue = parseInt(event.round);
                        if (!isNaN(roundValue) && roundValue > this.protocolState.babble.round) {
                            console.log(`更新Babble轮次: ${roundValue}`);
                            this.protocolState.babble.round = roundValue;
                            this.systemState.round = Math.max(this.systemState.round, roundValue);
                        }
                    }

                    if (event.isWitness) {
                        this.protocolState.babble.witnessed.add(event.hash);
                    }
                }
            }
            else if (msgType === 'babble-block') {
                if (content.block) {
                    this.protocolState.babble.blocks.push(content.block);

                    // 从块中也尝试获取轮次信息
                    if (content.block.round !== undefined) {
                        const blockRound = parseInt(content.block.round);
                        if (!isNaN(blockRound) && blockRound > this.protocolState.babble.round) {
                            console.log(`从区块更新Babble轮次: ${blockRound}`);
                            this.protocolState.babble.round = blockRound;
                            this.systemState.round = Math.max(this.systemState.round, blockRound);
                        }
                    }

                    // 区块索引也可能指示进度
                    if (content.block.index !== undefined) {
                        const blockIndex = parseInt(content.block.index);
                        if (!isNaN(blockIndex) && blockIndex > this.systemState.blocks) {
                            this.systemState.blocks = blockIndex;
                            this.systemState.lastDecisionTime = this.getClockTime();
                        }
                    }
                }
            }
            else if (msgType === 'ssb-message') {
                if (content.message) {
                    const message = content.message;
                    const author = message.author;

                    // Track feed state
                    if (!this.protocolState.babble.ssbFeeds[author]) {
                        this.protocolState.babble.ssbFeeds[author] = [];
                    }

                    // Track sequence numbers for fork detection
                    const sequence = message.sequence;
                    const existing = this.protocolState.babble.ssbFeeds[author].find(
                        m => m.sequence === sequence
                    );

                    if (existing && existing.hash !== message.hash) {
                        // Detected a potential fork!
                        this.protocolState.babble.ssbForks.add(`${author}-${sequence}`);
                    }

                    this.protocolState.babble.ssbFeeds[author].push({
                        sequence: message.sequence,
                        hash: message.hash
                    });

                    // Track message
                    this.protocolState.babble.ssbMessages[message.hash] = message;
                }
            }

            // Algorand状态更新
            else if (msgType === 'propose' || msgType === 'soft' ||
                msgType === 'cert' || msgType === 'next') {
                if (content.p !== undefined) {
                    this.protocolState.algorand.round = Math.max(
                        this.protocolState.algorand.round, content.p);
                }

                if (content.step !== undefined) {
                    this.protocolState.algorand.step = Math.max(
                        this.protocolState.algorand.step, content.step);
                }

                if (msgType === 'propose' && content.v !== undefined) {
                    const key = `${content.p}-${content.randomness || ''}`;
                    this.protocolState.algorand.proposals[key] = content.v;
                }

                if ((msgType === 'soft' || msgType === 'cert' || msgType === 'next') &&
                    content.v !== undefined) {
                    const key = `${content.p}-${msgType}`;
                    if (!this.protocolState.algorand.votes[key]) {
                        this.protocolState.algorand.votes[key] = new Set();
                    }
                    this.protocolState.algorand.votes[key].add(content.v);
                }
            }

            // HotStuff-NS状态更新
            else if (msgType === 'hot-stuff-proposal' || msgType === 'hot-stuff-vote') {
                if (content.view !== undefined) {
                    this.protocolState.hotstuff.view = Math.max(
                        this.protocolState.hotstuff.view, content.view);
                }

                if (msgType === 'hot-stuff-proposal' && content.src) {
                    this.protocolState.hotstuff.leaders.add(content.src);
                }

                if (content.QC) {
                    this.protocolState.hotstuff.highQC = content.QC;
                }
            }

            // LibraBFT状态更新
            else if (msgType === 'hot-stuff-update' || msgType === 'hot-stuff-next-view') {
                if (content.view !== undefined) {
                    this.protocolState.libra.view = Math.max(
                        this.protocolState.libra.view, content.view);
                }

                if (content.round !== undefined) {
                    this.protocolState.libra.round = Math.max(
                        this.protocolState.libra.round, content.round);
                }

                if (msgType === 'hot-stuff-next-view') {
                    this.protocolState.libra.timeout = true;
                }
            }

            // PBFT状态更新
            else if (msgType === 'pre-prepare' || msgType === 'prepare' ||
                msgType === 'commit' || msgType === 'view-change') {
                if (content.v !== undefined) {
                    this.protocolState.pbft.view = Math.max(
                        this.protocolState.pbft.view, content.v);
                }

                if (content.n !== undefined) {
                    this.protocolState.pbft.sequence = Math.max(
                        this.protocolState.pbft.sequence, content.n);
                }

                if (msgType === 'prepare') {
                    const key = `${content.v}-${content.n}`;
                    if (!this.protocolState.pbft.prepares[key]) {
                        this.protocolState.pbft.prepares[key] = new Set();
                    }
                    this.protocolState.pbft.prepares[key].add(content.d);
                }

                if (msgType === 'commit') {
                    const key = `${content.v}-${content.n}`;
                    if (!this.protocolState.pbft.commits[key]) {
                        this.protocolState.pbft.commits[key] = new Set();
                    }
                    this.protocolState.pbft.commits[key].add(content.d);
                }
            }
        }
    }

    /**
     * 协议特定攻击 - 根据检测到的协议类型选择适当的攻击
     */
    protocolSpecificAttack(packets) {
        switch (this.detectedProtocol) {
            case 'libp2p-babble':
                return this.babbleSpecificAttack(packets);
            case 'algorand':
                return this.algorandSpecificAttack(packets);
            case 'hotstuff-ns':
                return this.hotstuffSpecificAttack(packets);
            case 'librabft':
                return this.libraSpecificAttack(packets);
            case 'pbft':
                return this.pbftSpecificAttack(packets);
            // Add to the babbleSpecificAttack method to handle SSB messages:
            case 'ssb-message':
                // Attack SSB message
                return this.attackSSBMessage(packet);

            case 'ssb-sync-request':
                // Attack SSB sync request
                return this.attackSSBSyncRequest(packet);

            case 'ssb-sync-response':
                // Attack SSB sync response
                return this.attackSSBSyncResponse(packet);

            default:
                // 如果无法确定协议，使用通用攻击
                return this.dataForgeryAttack(packets);
        }
    }

    /**
     * LibP2P-Babble特定攻击
     * 针对Hashgraph的攻击，重点是破坏事件见证系统和哈希引用
     */
    babbleSpecificAttack(packets) {
        return packets.map(packet => {
            // 不修改拜占庭节点发送的消息
            if (this.byzantineNodes.has(packet.src)) return packet;

            // 增加攻击概率，从attackIntensity直接提高到attackIntensity * 1.5
            if (Math.random() >= this.attackIntensity * 1.5) return packet;

            if (!packet.content) return packet;

            const msgType = packet.content.type;

            if (msgType === 'babble-event') {
                // 攻击事件
                const event = packet.content.event;
                if (!event) return packet;

                const strategy = Math.random();

                if (strategy < 0.4) {  // 增加概率
                    // 策略1: 破坏事件祖先关系 - 更激进的策略
                    if (event.selfParent) {
                        const randomHash = `fake_${Math.random().toString(36).substring(2, 10)}`;
                        event.selfParent = randomHash;
                        console.log(`攻击事件: 篡改selfParent为${randomHash}`);
                    }
                    if (event.otherParent) {
                        event.otherParent = null; // 完全删除其他父引用
                        console.log(`攻击事件: 删除otherParent`);
                    }
                }
                else if (strategy < 0.7) {  // 增加概率
                    // 策略2: 篡改轮次和见证状态 - 更激进改变轮次
                    if (event.round !== undefined) {
                        // 更大幅度修改轮次 - 使其向前跳跃或后退
                        const oldRound = event.round;
                        event.round = Math.max(0, event.round + (Math.floor(Math.random() * 10) - 3));
                        console.log(`攻击事件: 轮次从${oldRound}改为${event.round}`);
                    }
                    // 翻转见证标志
                    event.isWitness = !event.isWitness;
                }
                else {
                    // 策略3: 注入矛盾交易 - 更具破坏性
                    if (!event.transactions) event.transactions = [];
                    // 清空原有交易并添加冲突交易
                    const originalTxCount = event.transactions.length;
                    event.transactions = [`CONFLICT_${this.getClockTime()}_${Math.random().toString(36).substring(2, 8)}`];
                    console.log(`攻击事件: 替换${originalTxCount}个交易为冲突交易`);
                }

                // 更新哈希和签名以保持一致性
                event.hash = `tampered_${this.getClockTime()}_${Math.random().toString(36).substring(2, 15)}`;
                event.signature = `forged_sig_${event.hash}`;

                if (event.creatorID) {
                    // 确保签名格式与libp2p-babble的期望一致
                    event.signature = `signature_${event.creatorID}_${event.hash}`;
                }
            }
            else if (msgType === 'babble-sync-request') {
                // 篡改同步请求中的已知事件
                if (packet.content.knownEvents) {
                    const knownEvents = packet.content.knownEvents;
                    let modifiedCount = 0;

                    // 随机删除或修改更多已知事件引用
                    for (const nodeID in knownEvents) {
                        if (Math.random() < 0.7) {  // 增加概率
                            // 随机伪造哈希值
                            knownEvents[nodeID] = `fake_hash_${Math.random().toString(36).substring(2, 10)}`;
                            modifiedCount++;
                        }
                    }

                    if (modifiedCount > 0) {
                        console.log(`攻击同步请求: 修改了${modifiedCount}个已知事件哈希`);
                    }
                }
            }
            else if (msgType === 'babble-sync-response') {
                // 篡改同步响应中的事件
                if (packet.content.events && packet.content.events.length > 0) {
                    const events = packet.content.events;

                    // 策略1: 在同步响应中插入伪造的事件
                    if (Math.random() < 0.5) {  // 增加概率
                        // 创建虚假事件
                        const fakeEvent = {
                            creatorID: (Math.floor(Math.random() * this.nodeNum) + 1).toString(),
                            selfParent: `fake_parent_${Math.random().toString(36).substring(2, 10)}`,
                            otherParent: `fake_parent_${Math.random().toString(36).substring(2, 10)}`,
                            timestamp: this.getClockTime() - Math.random() * 10000,
                            transactions: [`FAKE_TX_${Math.random().toString(36).substring(2, 8)}`],
                            round: Math.max(0, this.protocolState.babble.round + Math.floor(Math.random() * 5) - 1),
                            consensus: false,
                            isWitness: true,
                            hash: `fake_event_${Math.random().toString(36).substring(2, 15)}`
                        };

                        // 添加签名 - 与libp2p-babble格式一致
                        fakeEvent.signature = `signature_${fakeEvent.creatorID}_${fakeEvent.hash}`;

                        // 插入虚假事件到事件列表中
                        const insertPosition = Math.floor(Math.random() * (events.length + 1));
                        events.splice(insertPosition, 0, fakeEvent);
                        console.log(`攻击同步响应: 插入伪造事件在位置${insertPosition}`);
                    }

                    // 策略2: 篡改现有事件
                    let modifiedCount = 0;
                    for (let i = 0; i < events.length; i++) {
                        if (Math.random() < 0.3) {
                            const event = events[i];
                            // 简单篡改
                            if (event.round !== undefined) {
                                event.round = Math.max(0, event.round + Math.floor(Math.random() * 3) - 1);
                            }
                            if (event.hash) {
                                event.hash = `tampered_sync_${Math.random().toString(36).substring(2, 15)}`;
                                if (event.signature && event.creatorID) {
                                    event.signature = `signature_${event.creatorID}_${event.hash}`;
                                }
                            }
                            modifiedCount++;
                        }
                    }

                    if (modifiedCount > 0) {
                        console.log(`攻击同步响应: 修改了${modifiedCount}个现有事件`);
                    }
                }
            }
            else if (msgType === 'babble-block') {
                // 篡改区块
                const block = packet.content.block;
                if (!block) return packet;

                // 修改区块中的事件引用 - 更激进
                if (block.events && block.events.length > 0) {
                    let modifiedCount = 0;
                    // 随机替换更多事件引用
                    for (let i = 0; i < block.events.length; i++) {
                        if (Math.random() < 0.5) {  // 增加概率
                            block.events[i] = `fake_event_${Math.random().toString(36).substring(2, 15)}`;
                            modifiedCount++;
                        }
                    }

                    if (modifiedCount > 0) {
                        console.log(`攻击区块: 篡改了${modifiedCount}个事件引用`);
                    }
                }

                // 篡改区块交易 - 更激进
                if (block.transactions && block.transactions.length > 0) {
                    // 随机删除、修改或添加交易
                    const action = Math.floor(Math.random() * 3);

                    if (action === 0 && block.transactions.length > 1) {
                        // 删除一半以上的交易
                        const removeCount = Math.ceil(block.transactions.length * 0.5);
                        block.transactions.splice(0, removeCount);
                        console.log(`攻击区块: 删除了${removeCount}个交易`);
                    }
                    else if (action === 1) {
                        // 修改多个交易
                        let modifiedCount = 0;
                        for (let i = 0; i < block.transactions.length; i++) {
                            if (Math.random() < 0.5) {
                                block.transactions[i] = `TAMPERED_TX_${Math.random().toString(36).substring(2, 8)}`;
                                modifiedCount++;
                            }
                        }
                        console.log(`攻击区块: 修改了${modifiedCount}个交易`);
                    }
                    else {
                        // 添加多个虚假交易
                        const addCount = Math.floor(Math.random() * 5) + 1;
                        for (let i = 0; i < addCount; i++) {
                            block.transactions.push(`INJECTED_TX_${Math.random().toString(36).substring(2, 8)}`);
                        }
                        console.log(`攻击区块: 添加了${addCount}个虚假交易`);
                    }
                }

                // 篡改区块轮次
                if (block.round !== undefined) {
                    const oldRound = block.round;
                    // 尝试设置错误的轮次
                    block.round = Math.max(0, block.round + Math.floor(Math.random() * 5) - 2);
                    console.log(`攻击区块: 轮次从${oldRound}改为${block.round}`);
                }

                // 更新区块哈希和签名
                block.hash = `tampered_block_${Math.random().toString(36).substring(2, 15)}`;
                block.signature = `block_signature_${this.nodeID}_${block.hash}`;
            }
            else if (msgType === 'babble-block-signature') {
                // 攻击区块签名
                if (Math.random() < 0.7) {
                    // 篡改签名或者引用的区块哈希
                    if (Math.random() < 0.5 && packet.content.signature) {
                        const originalSig = packet.content.signature;
                        packet.content.signature = `fake_signature_${Math.random().toString(36).substring(2, 15)}`;
                        console.log(`攻击区块签名: ${originalSig} -> ${packet.content.signature}`);
                    } else if (packet.content.blockHash) {
                        const originalHash = packet.content.blockHash;
                        packet.content.blockHash = `fake_block_hash_${Math.random().toString(36).substring(2, 15)}`;
                        console.log(`攻击区块哈希引用: ${originalHash} -> ${packet.content.blockHash}`);
                    }
                }
            }

            return packet;
        });
    }

    /**
     * Algorand特定攻击
     * 针对Algorand的BA*协议和委员会选择机制
     */
    algorandSpecificAttack(packets) {
        return packets.map(packet => {
            // 不修改拜占庭节点发送的消息
            if (this.byzantineNodes.has(packet.src)) return packet;

            // 根据攻击强度决定是否攻击
            if (Math.random() >= this.attackIntensity) return packet;

            if (!packet.content) return packet;

            const msgType = packet.content.type;

            if (msgType === 'propose') {
                // 攻击提案消息
                // 修改提案值和随机数
                if (packet.content.v !== undefined) {
                    // 改变提案值
                    const newValue = uuid();
                    packet.content.v = newValue;
                }

                if (packet.content.randomness !== undefined) {
                    // 修改随机数(用于委员会选择)
                    packet.content.randomness = Math.floor(Math.random() * 1000000000);
                }
            }
            else if (msgType === 'soft') {
                // 攻击软投票
                if (packet.content.v !== undefined) {
                    // 随机改为BOT值或任意值
                    packet.content.v = Math.random() < 0.5 ?
                        'BOT' : `soft_fake_${Math.random().toString(36).substring(2, 8)}`;
                }
            }
            else if (msgType === 'cert') {
                // 攻击认证投票
                if (packet.content.v !== undefined) {
                    // 注入伪造的认证值
                    packet.content.v = `cert_fake_${Math.random().toString(36).substring(2, 8)}`;
                }
            }
            else if (msgType === 'next') {
                // 攻击下一轮投票
                if (packet.content.v !== undefined) {
                    // 随机在BOT和伪造值之间选择
                    packet.content.v = Math.random() < 0.5 ?
                        'BOT' : `next_fake_${Math.random().toString(36).substring(2, 8)}`;
                }
            }
            else if (msgType === 'certificate') {
                // 攻击最终证书
                if (packet.content.proof && Array.isArray(packet.content.proof)) {
                    // 修改证书中的投票证明
                    for (let i = 0; i < packet.content.proof.length; i++) {
                        if (Math.random() < 0.3 && packet.content.proof[i].sender) {
                            // 修改投票发送者
                            const randomNode = Math.floor(Math.random() * this.nodeNum) + 1;
                            packet.content.proof[i].sender = randomNode.toString();
                        }

                        if (Math.random() < 0.3 && packet.content.proof[i].v !== undefined) {
                            // 修改投票值
                            packet.content.proof[i].v = `forged_${Math.random().toString(36).substring(2, 8)}`;
                        }
                    }
                }

                // 可能直接修改证书的值
                if (packet.content.v !== undefined) {
                    packet.content.v = `forged_cert_${Math.random().toString(36).substring(2, 8)}`;
                }
            }

            return packet;
        });
    }

    /**
     * HotStuff特定攻击
     * 针对HotStuff的链式三阶段协议和视图更改机制
     */
    hotstuffSpecificAttack(packets) {
        return packets.map(packet => {
            // 不修改拜占庭节点发送的消息
            if (this.byzantineNodes.has(packet.src)) return packet;

            // 根据攻击强度决定是否攻击
            if (Math.random() >= this.attackIntensity) return packet;

            if (!packet.content) return packet;

            const msgType = packet.content.type;

            if (msgType === 'hot-stuff-proposal') {
                // 攻击提案消息

                // 策略1: 篡改视图号
                if (packet.content.view !== undefined) {
                    const viewDelta = Math.floor(Math.random() * 3) - 1; // -1, 0, 或 1
                    packet.content.view += viewDelta;
                    if (packet.content.view < 0) packet.content.view = 0;
                }

                // 策略2: 篡改高度
                if (packet.content.height !== undefined) {
                    const heightDelta = Math.floor(Math.random() * 3) - 1; // -1, 0, 或 1
                    packet.content.height += heightDelta;
                    if (packet.content.height < 0) packet.content.height = 0;
                }

                // 策略3: 篡改石英证书(QC)
                if (packet.content.QC) {
                    // 修改QC中的高度或视图
                    if (packet.content.QC.height !== undefined) {
                        const qcHeightDelta = Math.floor(Math.random() * 3) - 1;
                        packet.content.QC.height += qcHeightDelta;
                        if (packet.content.QC.height < 0) packet.content.QC.height = 0;
                    }

                    if (packet.content.QC.view !== undefined) {
                        const qcViewDelta = Math.floor(Math.random() * 3) - 1;
                        packet.content.QC.view += qcViewDelta;
                        if (packet.content.QC.view < 0) packet.content.QC.view = 0;
                    }

                    // 修改QC中的签名者
                    if (packet.content.QC.signers && Array.isArray(packet.content.QC.signers)) {
                        // 随机添加或删除签名者
                        if (Math.random() < 0.5 && packet.content.QC.signers.length > 1) {
                            // 删除一个签名者
                            const removeIdx = Math.floor(Math.random() * packet.content.QC.signers.length);
                            packet.content.QC.signers.splice(removeIdx, 1);
                        } else {
                            // 添加一个随机签名者
                            const randomNode = Math.floor(Math.random() * this.nodeNum) + 1;
                            packet.content.QC.signers.push(randomNode.toString());
                        }
                    }
                }

                // 策略4: 篡改请求/区块哈希
                if (packet.content.request) {
                    packet.content.request = `fake_req_${Math.random().toString(36).substring(2, 15)}`;
                }

                // 策略5: 修改父引用
                if (packet.content.parent) {
                    packet.content.parent = `fake_parent_${Math.random().toString(36).substring(2, 15)}`;
                }
            }
            else if (msgType === 'hot-stuff-vote') {
                // 攻击投票消息

                // 策略1: 篡改视图号
                if (packet.content.view !== undefined) {
                    const viewDelta = Math.floor(Math.random() * 3) - 1;
                    packet.content.view += viewDelta;
                    if (packet.content.view < 0) packet.content.view = 0;
                }

                // 策略2: 篡改请求/区块哈希
                if (packet.content.request) {
                    packet.content.request = `fake_vote_req_${Math.random().toString(36).substring(2, 15)}`;
                }

                // 策略3: 篡改QC
                if (packet.content.QC) {
                    if (packet.content.QC.request) {
                        packet.content.QC.request = `fake_qc_req_${Math.random().toString(36).substring(2, 15)}`;
                    }
                }
            }
            else if (msgType === 'hot-stuff-next-view-interrupt') {
                // 对view change中断攻击
                // 直接延迟这个消息，使timeout触发
                packet.delay = (packet.delay || 0) + Math.random() * 5;
            }

            return packet;
        });
    }

    /**
     * LibraBFT特定攻击
     * 针对LibraBFT的pacemaker机制和视图同步
     */
    libraSpecificAttack(packets) {
        return packets.map(packet => {
            // 不修改拜占庭节点发送的消息
            if (this.byzantineNodes.has(packet.src)) return packet;

            // 根据攻击强度决定是否攻击
            if (Math.random() >= this.attackIntensity) return packet;

            if (!packet.content) return packet;

            const msgType = packet.content.type;

            if (msgType === 'hot-stuff-update') {
                // 攻击更新消息

                // 策略1: 篡改视图号
                if (packet.content.view !== undefined) {
                    // 修改视图号会干扰pacemaker
                    const viewDelta = Math.floor(Math.random() * 3) - 1;
                    packet.content.view += viewDelta;
                    if (packet.content.view < 0) packet.content.view = 0;
                }

                // 策略2: 篡改当前主节点
                if (packet.content.primary) {
                    // 指向错误的主节点
                    const fakePrimary = Math.floor(Math.random() * this.nodeNum) + 1;
                    packet.content.primary = fakePrimary.toString();
                }

                // 策略3: 篡改QC
                if (packet.content.QC) {
                    if (packet.content.QC.view !== undefined) {
                        packet.content.QC.view = Math.max(0, packet.content.QC.view +
                            (Math.floor(Math.random() * 3) - 1));
                    }

                    if (packet.content.QC.request) {
                        packet.content.QC.request = `fake_qc_req_${Math.random().toString(36).substring(2, 15)}`;
                    }
                }

                // 策略4: 篡改请求/区块引用
                if (packet.content.request) {
                    packet.content.request = `fake_update_req_${Math.random().toString(36).substring(2, 15)}`;
                }

                // 策略5: 篡改父引用
                if (packet.content.parent) {
                    packet.content.parent = `fake_parent_${Math.random().toString(36).substring(2, 15)}`;
                }
            }
            else if (msgType === 'hot-stuff-next-view') {
                // 攻击视图切换消息

                // 策略1: 篡改视图号
                if (packet.content.view !== undefined) {
                    // 增加视图号会导致不必要的视图同步
                    packet.content.view += Math.floor(Math.random() * 3) + 1; // 增加1-3
                }

                // 策略2: 篡改主节点
                if (packet.content.primary) {
                    const fakePrimary = Math.floor(Math.random() * this.nodeNum) + 1;
                    packet.content.primary = fakePrimary.toString();
                }

                // 策略3: 篡改QC
                if (packet.content.QC) {
                    if (packet.content.QC.view !== undefined) {
                        // 修改QC视图，干扰主节点选择
                        packet.content.QC.view = Math.max(0, this.protocolState.libra.view -
                            (Math.floor(Math.random() * 3) + 1));
                    }
                }

                // 策略4: 修改源节点
                if (packet.content.sourceReplica) {
                    const fakeSource = Math.floor(Math.random() * this.nodeNum) + 1;
                    packet.content.sourceReplica = fakeSource.toString();
                }
            }

            return packet;
        });
    }
    attackSSBMessage(packet) {
        if (!packet.content || !packet.content.message) return packet;

        const message = packet.content.message;

        // Don't modify if not meeting attack threshold
        if (Math.random() >= this.attackIntensity) return packet;

        const strategy = Math.random();

        if (strategy < 0.3) {
            // Strategy 1: Break feed chain by corrupting previous reference
            if (message.previous) {
                message.previous = `fake_prev_${Math.random().toString(36).substring(2, 15)}`;
            }
        }
        else if (strategy < 0.6) {
            // Strategy 2: Create sequence number forks/gaps
            if (message.sequence !== undefined) {
                // Either duplicate a sequence or create a gap
                if (Math.random() < 0.5) {
                    // Duplicate (fork) - set to an earlier sequence
                    message.sequence = Math.max(1, message.sequence - Math.floor(Math.random() * 3));
                } else {
                    // Gap - increase sequence by more than 1
                    message.sequence += Math.floor(Math.random() * 3) + 1;
                }
            }
        }
        else {
            // Strategy 3: Inject malicious content
            if (message.content) {
                message.content = {
                    type: "MALICIOUS_SSB_CONTENT",
                    payload: `attack_${Math.random().toString(36).substring(2, 8)}`,
                    timestamp: this.getClockTime()
                };
            }
        }

        // Update hash and signature to maintain consistency
        message.hash = `tampered_ssb_${Math.random().toString(36).substring(2, 15)}`;
        message.signature = `forged_ssb_sig_${message.hash}`;

        return packet;
    }
    /**
 * Attack SSB sync request
 */
    attackSSBSyncRequest(packet) {
        if (!packet.content) return packet;

        // Don't modify if not meeting attack threshold
        if (Math.random() >= this.attackIntensity) return packet;

        // Strategy 1: Change the author being requested
        if (packet.content.author) {
            const randomNodeId = Math.floor(Math.random() * this.nodeNum) + 1;
            packet.content.author = randomNodeId.toString();
        }

        // Strategy 2: Manipulate fromSequence to request wrong range
        if (packet.content.fromSequence !== undefined) {
            // Either request from beginning (overwhelming) or skip messages
            if (Math.random() < 0.5) {
                packet.content.fromSequence = 0; // Request from beginning
            } else {
                // Skip some messages
                packet.content.fromSequence += Math.floor(Math.random() * 10) + 5;
            }
        }

        return packet;
    }

    /**
     * Attack SSB sync response
     */
    attackSSBSyncResponse(packet) {
        if (!packet.content || !packet.content.messages || !Array.isArray(packet.content.messages))
            return packet;

        // Don't modify if not meeting attack threshold
        if (Math.random() >= this.attackIntensity) return packet;

        const messages = packet.content.messages;

        // Strategy 1: Inject contradicting sequence numbers
        if (messages.length > 0) {
            for (let i = 0; i < messages.length; i++) {
                if (Math.random() < 0.3) {
                    // Create sequence inconsistencies
                    if (i > 0) {
                        // Set equal or lower sequence than previous message
                        messages[i].sequence = messages[i - 1].sequence;
                    }

                    // Corrupt previous reference
                    if (messages[i].previous) {
                        messages[i].previous = `fake_sync_prev_${Math.random().toString(36).substring(2, 15)}`;
                    }

                    // Update hash to avoid easy detection
                    messages[i].hash = `tampered_sync_${Math.random().toString(36).substring(2, 15)}`;
                    messages[i].signature = `forged_sync_sig_${messages[i].hash}`;
                }
            }
        }

        // Strategy 2: Remove some messages randomly to create gaps
        if (messages.length > 2 && Math.random() < 0.4) {
            const removeIdx = Math.floor(Math.random() * (messages.length - 1)) + 1;
            messages.splice(removeIdx, 1);
        }

        // Strategy 3: Sometimes add duplicate messages with different content
        if (Math.random() < 0.3 && messages.length > 0) {
            const originalMsg = messages[0];
            const duplicateMsg = JSON.parse(JSON.stringify(originalMsg));

            // Modify duplicate but keep same sequence/author
            duplicateMsg.content = {
                type: "FORKED_CONTENT",
                payload: `fork_attack_${Math.random().toString(36).substring(2, 8)}`,
                timestamp: this.getClockTime()
            };
            duplicateMsg.hash = `fork_${Math.random().toString(36).substring(2, 15)}`;
            duplicateMsg.signature = `forged_fork_sig_${duplicateMsg.hash}`;

            // Insert the duplicate message
            const insertIdx = Math.min(messages.length, 2);
            messages.splice(insertIdx, 0, duplicateMsg);
        }

        return packet;
    }
    /**
     * PBFT特定攻击
     * 针对PBFT的三阶段共识(pre-prepare, prepare, commit)和视图变更
     */
    pbftSpecificAttack(packets) {
        return packets.map(packet => {
            // 不修改拜占庭节点发送的消息
            if (this.byzantineNodes.has(packet.src)) return packet;

            // 根据攻击强度决定是否攻击
            if (Math.random() >= this.attackIntensity) return packet;

            if (!packet.content) return packet;

            const msgType = packet.content.type;

            if (msgType === 'pre-prepare') {
                // 攻击预准备消息

                // 策略1: 篡改视图号
                if (packet.content.v !== undefined) {
                    // 修改视图号使消息被拒绝
                    const viewDelta = Math.floor(Math.random() * 3) - 1;
                    packet.content.v += viewDelta;
                    if (packet.content.v < 0) packet.content.v = 0;
                }

                // 策略2: 篡改序列号
                if (packet.content.n !== undefined) {
                    // 修改序列号使消息与其他pre-prepare冲突
                    packet.content.n += Math.floor(Math.random() * 3) - 1;
                    if (packet.content.n < 0) packet.content.n = 0;
                }

                // 策略3: 篡改摘要
                if (packet.content.d) {
                    // 修改摘要使消息与区块不匹配
                    packet.content.d = `fake_digest_${Math.random().toString(36).substring(2, 15)}`;
                }
            }
            else if (msgType === 'prepare') {
                // 攻击准备消息

                // 篡改视图、序列号或摘要
                if (packet.content.v !== undefined) {
                    packet.content.v = Math.max(0, packet.content.v + (Math.floor(Math.random() * 3) - 1));
                }

                if (packet.content.n !== undefined) {
                    packet.content.n = Math.max(0, packet.content.n + (Math.floor(Math.random() * 3) - 1));
                }

                if (packet.content.d) {
                    // 修改摘要使prepare与pre-prepare不匹配
                    packet.content.d = `fake_prepare_${Math.random().toString(36).substring(2, 15)}`;
                }

                // 篡改节点ID
                if (packet.content.i) {
                    const fakeNode = Math.floor(Math.random() * this.nodeNum) + 1;
                    packet.content.i = fakeNode.toString();
                }
            }
            else if (msgType === 'commit') {
                // 攻击提交消息

                // 篡改视图、序列号或摘要
                if (packet.content.v !== undefined) {
                    packet.content.v = Math.max(0, packet.content.v + (Math.floor(Math.random() * 3) - 1));
                }

                if (packet.content.n !== undefined) {
                    packet.content.n = Math.max(0, packet.content.n + (Math.floor(Math.random() * 3) - 1));
                }

                if (packet.content.d) {
                    // 修改摘要使commit与prepare不匹配
                    packet.content.d = `fake_commit_${Math.random().toString(36).substring(2, 15)}`;
                }

                // 篡改节点ID
                if (packet.content.i) {
                    const fakeNode = Math.floor(Math.random() * this.nodeNum) + 1;
                    packet.content.i = fakeNode.toString();
                }
            }
            else if (msgType === 'view-change') {
                // 攻击视图变更消息

                // 策略1: 篡改目标视图号
                if (packet.content.v !== undefined) {
                    // 增加视图号会导致更多的视图变更和更多的不稳定
                    packet.content.v += Math.floor(Math.random() * 3) + 1; // 增加1-3
                }

                // 策略2: 篡改稳定检查点序列号
                if (packet.content.n !== undefined) {
                    packet.content.n = Math.max(0, packet.content.n + (Math.floor(Math.random() * 3) - 1));
                }

                // 策略3: 篡改检查点证明
                if (packet.content.C && Array.isArray(packet.content.C)) {
                    for (let i = 0; i < packet.content.C.length; i++) {
                        if (packet.content.C[i].d) {
                            packet.content.C[i].d = `fake_checkpoint_${Math.random().toString(36).substring(2, 10)}`;
                        }
                    }
                }

                // 策略4: 篡改准备消息集合
                if (packet.content.P && Array.isArray(packet.content.P)) {
                    for (let i = 0; i < packet.content.P.length; i++) {
                        if (packet.content.P[i]['pre-prepare'] && packet.content.P[i]['pre-prepare'].d) {
                            packet.content.P[i]['pre-prepare'].d = `fake_pp_${Math.random().toString(36).substring(2, 10)}`;
                        }
                    }
                }
            }
            else if (msgType === 'new-view') {
                // 攻击新视图消息

                // 策略1: 篡改视图号
                if (packet.content.v !== undefined) {
                    packet.content.v = Math.max(0, packet.content.v + (Math.floor(Math.random() * 3) - 1));
                }

                // 策略2: 篡改视图变更证明
                if (packet.content.V && Array.isArray(packet.content.V)) {
                    // 随机删除一个视图变更证明
                    if (packet.content.V.length > 1) {
                        const removeIdx = Math.floor(Math.random() * packet.content.V.length);
                        packet.content.V.splice(removeIdx, 1);
                    }
                }

                // 策略3: 篡改新序列号集合
                if (packet.content.O && Array.isArray(packet.content.O)) {
                    for (let i = 0; i < packet.content.O.length; i++) {
                        if (packet.content.O[i].d) {
                            packet.content.O[i].d = `fake_newview_${Math.random().toString(36).substring(2, 10)}`;
                        }
                    }
                }

                // 策略4: 篡改节点ID
                if (packet.content.i) {
                    const fakeNode = Math.floor(Math.random() * this.nodeNum) + 1;
                    packet.content.i = fakeNode.toString();
                }
            }
            else if (msgType === 'checkpoint') {
                // 攻击检查点消息

                // 篡改序列号
                if (packet.content.n !== undefined) {
                    packet.content.n = Math.max(0, packet.content.n + (Math.floor(Math.random() * 3) - 1));
                }

                // 篡改摘要
                if (packet.content.d) {
                    packet.content.d = `fake_checkpoint_${Math.random().toString(36).substring(2, 15)}`;
                }
            }

            return packet;
        });
    }

    /**
     * 综合攻击 - 结合多种攻击策略
     */
    comprehensiveAttack(packets) {
        // 先应用基础攻击
        let processedPackets = [...packets];

        // 1. 应用分区攻击 (20%概率)
        if (Math.random() < 0.2) {
            processedPackets = this.partitionAttack(processedPackets);
        }

        // 2. 对协议特定消息应用针对性攻击 (30%概率) 
        if (Math.random() < 0.3 && this.detectedProtocol) {
            processedPackets = this.protocolSpecificAttack(processedPackets);
        }

        // 3. 应用数据篡改或时序攻击
        processedPackets = processedPackets.map(packet => {
            // 不修改拜占庭节点发送的消息
            if (this.byzantineNodes.has(packet.src)) return packet;

            // 选择攻击类型
            const attackChoice = Math.random();

            if (attackChoice < 0.3 * this.attackIntensity) {
                // 数据篡改
                if (packet.content && packet.content.type) {
                    if (packet.content.type.includes('babble-event') ||
                        packet.content.type.includes('block')) {
                        packet = this.dataForgeryAttack([packet])[0];
                    }
                }
            }
            else if (attackChoice < 0.5 * this.attackIntensity) {
                // 时序攻击
                if (packet.content) {
                    packet = this.timingAttack([packet])[0];
                }
            }
            else if (attackChoice < 0.7 * this.attackIntensity) {
                // 同步干扰
                if (packet.content && packet.content.type &&
                    packet.content.type.includes('sync')) {
                    packet = this.syncDisruptionAttack([packet])[0];
                }
            }

            return packet;
        });

        // 4. 应用等价攻击 (20%概率)
        if (Math.random() < 0.2) {
            processedPackets = this.equivocationAttack(processedPackets);
        }

        return processedPackets;
    }

    /**
     * 正常行为 
     */
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

    /**
     * 数据篡改攻击
     */
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
                else if (msgType.includes('hot-stuff')) {
                    return this.forgeHotStuffData(packet);
                }
                else if (msgType === 'pre-prepare' || msgType === 'prepare' ||
                    msgType === 'commit' || msgType === 'view-change') {
                    return this.forgePBFTData(packet);
                }
                else if (msgType === 'propose' || msgType === 'soft' ||
                    msgType === 'cert' || msgType === 'next') {
                    return this.forgeAlgorandData(packet);
                }
            }

            return packet;
        });
    }

    // 篡改Babble事件数据
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

    // 篡改Babble区块数据
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

    // 篡改HotStuff消息
    forgeHotStuffData(packet) {
        const content = packet.content;

        // 篡改视图或高度
        if (content.view !== undefined) {
            content.view = Math.max(0, content.view + Math.floor(Math.random() * 3) - 1);
        }

        if (content.height !== undefined) {
            content.height = Math.max(0, content.height + Math.floor(Math.random() * 3) - 1);
        }

        // 篡改请求ID
        if (content.request) {
            content.request = `forged_req_${Math.random().toString(36).substring(2, 10)}`;
        }

        // 篡改QC
        if (content.QC) {
            if (content.QC.request) {
                content.QC.request = `forged_qc_${Math.random().toString(36).substring(2, 10)}`;
            }

            if (content.QC.view !== undefined) {
                content.QC.view = Math.max(0, content.QC.view + Math.floor(Math.random() * 3) - 1);
            }
        }

        return packet;
    }

    // 篡改PBFT消息
    forgePBFTData(packet) {
        const content = packet.content;

        // 篡改视图或序列号
        if (content.v !== undefined) {
            content.v = Math.max(0, content.v + Math.floor(Math.random() * 3) - 1);
        }

        if (content.n !== undefined) {
            content.n = Math.max(0, content.n + Math.floor(Math.random() * 3) - 1);
        }

        // 篡改摘要
        if (content.d) {
            content.d = `forged_digest_${Math.random().toString(36).substring(2, 10)}`;
        }

        return packet;
    }

    // 篡改Algorand消息
    forgeAlgorandData(packet) {
        const content = packet.content;

        // 篡改周期或步骤
        if (content.p !== undefined) {
            content.p = Math.max(0, content.p + Math.floor(Math.random() * 3) - 1);
        }

        if (content.step !== undefined) {
            content.step = Math.max(0, content.step + Math.floor(Math.random() * 3) - 1);
        }

        // 篡改值或随机数
        if (content.v !== undefined) {
            // 50%概率使用BOT，50%概率使用随机值
            content.v = Math.random() < 0.5 ?
                "BOT" : `forged_value_${Math.random().toString(36).substring(2, 8)}`;
        }

        if (content.randomness !== undefined) {
            content.randomness = Math.floor(Math.random() * 1000000000);
        }

        return packet;
    }

    /**
     * 同步干扰攻击
     */
    syncDisruptionAttack(packets) {
        return packets.map(packet => {
            // 不修改拜占庭节点发送的消息
            if (this.byzantineNodes.has(packet.src)) return packet;

            // 只关注同步请求和响应
            if (packet.content &&
                (packet.content.type === 'babble-sync-request' ||
                    packet.content.type === 'babble-sync-response' ||
                    packet.content.type.includes('sync'))) {

                // 根据攻击强度决定是否干扰
                if (Math.random() < this.attackIntensity) {
                    return this.disruptSyncMessage(packet);
                }
            }

            return packet;
        });
    }

    disruptSyncMessage(packet) {
        if (packet.content.type.includes('request')) {
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
        else if (packet.content.type.includes('response')) {
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

    /**
     * 网络分区攻击
     */
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

    /**
     * 等价攻击（向不同节点发送不同内容）
     */
    equivocationAttack(packets) {
        const modifiedPackets = [];

        for (const packet of packets) {
            // 不修改拜占庭节点发送的消息
            if (this.byzantineNodes.has(packet.src)) {
                modifiedPackets.push(packet);
                continue;
            }

            // 只对关键消息类型进行等价攻击
            if (packet.content &&
                (packet.content.type === 'babble-event' ||
                    packet.content.type === 'babble-block' ||
                    packet.content.type === 'hot-stuff-proposal' ||
                    packet.content.type === 'hot-stuff-vote' ||
                    packet.content.type === 'pre-prepare' ||
                    packet.content.type === 'prepare' ||
                    packet.content.type === 'commit' ||
                    packet.content.type === 'propose' ||
                    packet.content.type === 'soft' ||
                    packet.content.type === 'cert')) {

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

        const msgType = newPacket.content.type;

        // 根据消息类型应用不同的修改
        if (msgType === 'babble-event') {
            this.equivocateBabbleEvent(newPacket, newDst);
        }
        else if (msgType === 'babble-block') {
            this.equivocateBabbleBlock(newPacket, newDst);
        }
        else if (msgType === 'hot-stuff-proposal' || msgType === 'hot-stuff-vote') {
            this.equivocateHotStuffMessage(newPacket, newDst);
        }
        else if (msgType === 'pre-prepare' || msgType === 'prepare' || msgType === 'commit') {
            this.equivocatePBFTMessage(newPacket, newDst);
        }
        else if (msgType === 'propose' || msgType === 'soft' || msgType === 'cert' || msgType === 'next') {
            this.equivocateAlgorandMessage(newPacket, newDst);
        }

        return newPacket;
    }

    // 为不同节点创建不同版本的Babble事件
    equivocateBabbleEvent(packet, newDst) {
        const event = packet.content.event;
        if (!event) return;

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
    equivocateSSBMessage(packet, newDst) {
        const message = packet.content.message;
        if (!message) return;

        // Create equivocating SSB message with same sequence but different content
        // This creates a "feed fork" - a critical attack against append-only logs
        if (message.sequence !== undefined) {
            // Keep the same sequence number and previous reference
            // But change the content - classic equivocation attack
            if (message.content) {
                message.content = {
                    type: message.content.type || "equivocated",
                    text: `EQUIVOCATION_FOR_${newDst}_${Math.random().toString(36).substring(2, 8)}`,
                    timestamp: message.timestamp
                };
            }

            // Update hash and signature
            message.hash = `equiv_ssb_${newDst}_${Math.random().toString(36).substring(2, 15)}`;
            message.signature = `forged_equiv_sig_${message.hash}`;
        }
    }
    // 为不同节点创建不同版本的Babble区块
    equivocateBabbleBlock(packet, newDst) {
        const block = packet.content.block;
        if (!block) return;

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

    // 为不同节点创建不同版本的HotStuff消息
    equivocateHotStuffMessage(packet, newDst) {
        const content = packet.content;

        // 修改请求ID
        if (content.request) {
            content.request = `equiv_req_${newDst}_${Math.random().toString(36).substring(2, 10)}`;
        }

        // 修改QC
        if (content.QC && content.QC.request) {
            content.QC.request = `equiv_qc_${newDst}_${Math.random().toString(36).substring(2, 10)}`;
        }

        // 修改视图号
        if (content.view !== undefined) {
            // 小幅修改视图号
            content.view = Math.max(0, content.view + (Math.floor(Math.random() * 3) - 1));
        }
    }

    // 为不同节点创建不同版本的PBFT消息
    equivocatePBFTMessage(packet, newDst) {
        const content = packet.content;

        // 修改摘要值
        if (content.d) {
            content.d = `equiv_digest_${newDst}_${Math.random().toString(36).substring(2, 10)}`;
        }

        // 轻微修改序列号
        if (content.n !== undefined) {
            // 小幅修改序列号
            content.n = Math.max(0, content.n + (Math.floor(Math.random() * 3) - 1));
        }
    }

    // 为不同节点创建不同版本的Algorand消息
    equivocateAlgorandMessage(packet, newDst) {
        const content = packet.content;

        // 修改值
        if (content.v !== undefined) {
            // 根据消息类型和概率选择不同的值
            if (content.type === 'soft' || content.type === 'next') {
                content.v = Math.random() < 0.5 ?
                    "BOT" : `equiv_${newDst}_${Math.random().toString(36).substring(2, 8)}`;
            } else {
                content.v = `equiv_${newDst}_${Math.random().toString(36).substring(2, 8)}`;
            }
        }

        // 修改随机数 (仅适用于propose消息)
        if (content.randomness !== undefined) {
            content.randomness = Math.floor(Math.random() * 1000000000);
        }
    }

    /**
     * 时序攻击（时间戳篡改）
     */
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

                // 给消息添加延迟（模拟网络时序干扰）
                if (Math.random() < this.attackIntensity * 0.5) {
                    const delay = Math.random() * 2; // 添加0-2秒的额外延迟
                    packet.delay = (packet.delay || 0) + delay;
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

    /**
     * 阶段管理与参数调整
     */
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

        console.log(`进入攻击阶段${this.currentPhase}: ${this.currentMode}, 强度: ${this.attackIntensity.toFixed(2)}, 持续: ${this.phaseDuration}秒`);
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

        // 根据系统状态调整攻击强度 - 修改后的策略
        if (consensusDelayFactor > 0.8) {
            // 共识被极度延迟，适度减少攻击强度，但保持在较高水平
            this.attackIntensity = Math.max(0.4, this.attackIntensity - 0.1);
        }
        else if (nodeActivityFactor < 0.3) {
            // 很多节点不活跃，稍微减少攻击强度，但保持有效
            this.attackIntensity = Math.max(0.4, this.attackIntensity - 0.05);
        }
        else if (consensusProgress === 0 && this.getClockTime() > 20) {
            // 如果长时间没有进展，临时减轻攻击让系统有机会前进
            this.attackIntensity = Math.max(0.3, this.attackIntensity - 0.2);
            console.log("检测到系统无进展，临时减轻攻击强度");
        }
        else {
            // 默认情况，逐渐增加攻击强度
            this.attackIntensity += 0.05;
            this.attackIntensity = Math.min(0.8, Math.max(0.4, this.attackIntensity));
        }

        // 每隔一段时间尝试更激进的攻击
        if (this.getClockTime() % 30 < 10) {
            this.attackIntensity = Math.min(0.9, this.attackIntensity + 0.1);
        }

        // 清理不再活跃的节点
        const currentActiveNodes = new Set();
        for (const nodeId of this.systemState.activeNodes) {
            // 仅保留最近有活动的节点
            currentActiveNodes.add(nodeId);
        }
        this.systemState.activeNodes = currentActiveNodes;

        console.log(`系统状态: 协议=${this.detectedProtocol}, 轮次=${this.systemState.round}, 活跃节点=${this.systemState.activeNodes.size}, 攻击强度=${this.attackIntensity.toFixed(2)}`);
    }

    updateParam() {
        return false; // 不更新参数
    }
}

// 生成随机ID工具函数
function uuid() {
    return Math.random().toString(36).substring(2, 15) +
        Math.random().toString(36).substring(2, 15);
}

module.exports = ByzantineAttackCoordinator;
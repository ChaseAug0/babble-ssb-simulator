'use strict';

/**
 * AdaptiveAttacker
 * 高级自适应攻击器，能够监控系统状态并在关键时刻发起针对性攻击
 * 适用于多种BFT共识协议
 */
class AdaptiveAttacker {
    constructor(transfer, registerAttackerTimeEvent, eventQ, nodeNum, byzantineNodeNum, getClockTime) {
        this.transfer = transfer;
        this.registerAttackerTimeEvent = registerAttackerTimeEvent;
        this.eventQ = eventQ;
        this.nodeNum = nodeNum;
        this.byzantineNodeNum = byzantineNodeNum;
        this.getClockTime = getClockTime;

        // 协议检测与攻击配置
        this.detectedProtocol = null;
        this.protocolStates = {
            pbft: {
                detected: false,
                phase: 'unknown',   // pre-prepare, prepare, commit
                view: 0,
                sequence: 0,
                leaders: new Set(),
                prepareCount: {},   // 记录prepare消息计数
                commitCount: {},    // 记录commit消息计数
                viewChangeCount: 0  // 视图切换计数
            },
            hotstuff: {
                detected: false,
                phase: 'unknown',   // new-view, prepare, pre-commit, commit, decide
                view: 0,
                leaders: new Set(),
                qcRounds: {},       // 石英证书轮次 
                highQC: 0           // 最高QC轮次
            },
            algorand: {
                detected: false,
                round: 0,
                step: 0,            // Algorand BA*阶段
                proposalValues: {}, // 提案值
                voteCount: {}       // 投票计数
            },
            babble: {
                detected: false,
                round: 0,
                witnessEvents: new Set(), // 见证事件
                lastBlockIndex: -1,
                pendingBlockEvents: []    // 待处理区块事件
            },
            libra: {
                detected: false,
                round: 0,
                epoch: 0,
                leaders: new Set(),
                proposalCount: 0
            },
            asyncBA: {
                detected: false,
                round: 0,
                binaryValues: {}    // 轮次->值的映射
            }
        };

        // 攻击模式
        this.attackModes = {
            honest: { active: true, weight: 0.3 },          // 诚实行为，隐藏攻击意图
            delayLeader: { active: true, weight: 0.7 },     // 延迟领导者消息
            conflictingVotes: { active: true, weight: 0.8 }, // 发送冲突投票
            dropSync: { active: true, weight: 0.6 },        // 丢弃同步消息
            tamperEvents: { active: true, weight: 0.7 },    // 篡改事件
            splitBrain: { active: true, weight: 0.9 }       // 网络分区攻击
        };

        // 保持攻击模式一段时间
        this.currentAttackMode = 'honest';
        this.attackModeStartTime = this.getClockTime();
        this.attackModeDuration = 15; // 10秒

        // 跟踪关键消息
        this.messageHistory = {};
        this.maxHistorySize = 1000;
        this.historyCount = 0;

        // 信任建立阶段
        this.trustBuildingPhase = true;
        this.trustBuildingDuration = 15; // 10秒
        this.trustBuildingStartTime = this.getClockTime();

        // 攻击日志
        this.attackLog = [];
        this.maxLogSize = 100;

        // 启动状态监控和攻击模式切换
        this.registerAttackerTimeEvent(
            { name: 'monitorSystemState' },
            2000 // 2秒后开始监控
        );

        this.registerAttackerTimeEvent(
            { name: 'switchAttackMode' },
            this.attackModeDuration * 1000 // 切换攻击模式
        );

        // console.log('Smart adaptive attacker initialized');
    }

    attack(packets) {
        // 检测协议类型和系统状态
        this.detectProtocolAndState(packets);

        // 信任建立阶段: 一开始表现诚实
        if (this.trustBuildingPhase &&
            this.getClockTime() - this.trustBuildingStartTime < this.trustBuildingDuration) {
            // console.log("Trust building phase, behaving honestly...");
            return packets; // 不修改任何消息
        }

        // 当前活跃的攻击模式
        if (this.currentAttackMode === 'honest') {
            return packets; // 诚实模式，不篡改
        }

        // 处理消息并应用当前攻击模式
        let modifiedPackets = [...packets];

        // 应用当前攻击策略
        switch (this.currentAttackMode) {
            case 'delayLeader':
                modifiedPackets = this.applyLeaderDelay(modifiedPackets);
                break;
            case 'conflictingVotes':
                modifiedPackets = this.applyConflictingVotes(modifiedPackets);
                break;
            case 'dropSync':
                modifiedPackets = this.applyDropSync(modifiedPackets);
                break;
            case 'tamperEvents':
                modifiedPackets = this.applyTamperEvents(modifiedPackets);
                break;
            case 'splitBrain':
                modifiedPackets = this.applySplitBrain(modifiedPackets);
                break;
        }

        return modifiedPackets;
    }

    /**
     * 检测协议类型和系统状态
     */
    detectProtocolAndState(packets) {
        for (const packet of packets) {
            if (!packet.content || !packet.content.type) continue;

            const msgType = packet.content.type.toLowerCase();
            this.addToMessageHistory(msgType, packet);

            // PBFT协议检测
            if (msgType.includes('pbft') ||
                msgType === 'pre-prepare' ||
                msgType === 'prepare' ||
                msgType === 'commit') {

                this.protocolStates.pbft.detected = true;
                this.updatePBFTState(packet);
            }

            // HotStuff协议检测
            else if (msgType.includes('hotstuff') ||
                msgType === 'new-view' ||
                msgType.includes('qc')) {

                this.protocolStates.hotstuff.detected = true;
                this.updateHotStuffState(packet);
            }

            // Algorand协议检测
            else if (msgType.includes('algorand') ||
                msgType === 'proposal' ||
                msgType === 'vote') {

                this.protocolStates.algorand.detected = true;
                this.updateAlgorandState(packet);
            }

            // Babble协议检测
            else if (msgType.includes('babble') || msgType.includes('ssb')) {
                this.protocolStates.babble.detected = true;
                this.updateBabbleState(packet);
            }

            // LibraBFT协议检测
            else if (msgType.includes('libra')) {
                this.protocolStates.libra.detected = true;
                this.updateLibraState(packet);
            }

            // Async-BA协议检测
            else if (msgType.includes('async') || msgType.includes('ba-')) {
                this.protocolStates.asyncBA.detected = true;
                this.updateAsyncBAState(packet);
            }
        }

        // 确定主要检测到的协议
        if (!this.detectedProtocol) {
            for (const protocol in this.protocolStates) {
                if (this.protocolStates[protocol].detected) {
                    this.detectedProtocol = protocol;
                    //console.log(`Detected protocol: ${protocol}`);
                    break;
                }
            }
        }
    }

    /**
     * 将消息添加到历史记录
     */
    addToMessageHistory(type, packet) {
        if (this.historyCount >= this.maxHistorySize) {
            return; // 历史记录已满
        }

        if (!this.messageHistory[type]) {
            this.messageHistory[type] = [];
        }

        this.messageHistory[type].push({
            time: this.getClockTime(),
            src: packet.src,
            dst: packet.dst,
            content: packet.content
        });

        this.historyCount++;
    }

    /**
     * 记录攻击行为
     */
    logAttack(attackType, details) {
        if (this.attackLog.length >= this.maxLogSize) {
            this.attackLog.shift(); // 移除最旧的记录
        }

        this.attackLog.push({
            time: this.getClockTime(),
            type: attackType,
            details: details
        });
    }

    /**
     * PBFT状态更新
     */
    updatePBFTState(packet) {
        const content = packet.content;
        const msgType = content.type.toLowerCase();
        const state = this.protocolStates.pbft;

        if (content.view !== undefined) {
            state.view = Math.max(state.view, content.view);
        }

        if (content.sequence !== undefined) {
            state.sequence = Math.max(state.sequence, content.sequence);
        }

        // 记录领导者
        if (msgType === 'pre-prepare') {
            state.leaders.add(packet.src);
            state.phase = 'pre-prepare';
        }

        // 跟踪准备阶段消息
        if (msgType === 'prepare') {
            state.phase = 'prepare';
            const key = `${content.view}-${content.sequence}`;

            if (!state.prepareCount[key]) {
                state.prepareCount[key] = new Set();
            }

            state.prepareCount[key].add(packet.src);

            // 检测准备阶段即将完成
            if (state.prepareCount[key].size >= Math.floor((this.nodeNum - this.byzantineNodeNum) * 2 / 3)) {
                // 准备阶段接近完成 - 关键时刻
                this.considerAttackModeSwitch('conflictingVotes', 0.8);
            }
        }

        // 跟踪提交阶段消息
        if (msgType === 'commit') {
            state.phase = 'commit';
            const key = `${content.view}-${content.sequence}`;

            if (!state.commitCount[key]) {
                state.commitCount[key] = new Set();
            }

            state.commitCount[key].add(packet.src);
        }

        // 检测视图变更
        if (msgType === 'view-change') {
            state.viewChangeCount++;

            // 视图变更是关键时刻
            this.considerAttackModeSwitch('delayLeader', 0.9);
        }
    }

    /**
     * HotStuff状态更新
     */
    updateHotStuffState(packet) {
        const content = packet.content;
        const msgType = content.type.toLowerCase();
        const state = this.protocolStates.hotstuff;

        if (content.view !== undefined) {
            state.view = Math.max(state.view, content.view);
        }

        // 记录领导者
        if (msgType.includes('new-view') || msgType.includes('prepare')) {
            state.leaders.add(packet.src);
        }

        // 跟踪石英证书
        if (content.qc) {
            state.phase = 'qc-aggregation';

            if (content.qc.view !== undefined) {
                const qcView = content.qc.view;
                if (!state.qcRounds[qcView]) {
                    state.qcRounds[qcView] = 0;
                }
                state.qcRounds[qcView]++;

                state.highQC = Math.max(state.highQC, qcView);

                // QC形成阶段是关键时刻
                if (state.qcRounds[qcView] >= Math.floor(this.nodeNum / 2)) {
                    this.considerAttackModeSwitch('conflictingVotes', 0.7);
                }
            }
        }

        // 跟踪阶段
        if (msgType.includes('prepare')) {
            state.phase = 'prepare';
        } else if (msgType.includes('pre-commit')) {
            state.phase = 'pre-commit';
        } else if (msgType.includes('commit')) {
            state.phase = 'commit';
        } else if (msgType.includes('decide')) {
            state.phase = 'decide';
            // 决策阶段是关键时刻
            this.considerAttackModeSwitch('splitBrain', 0.8);
        }
    }

    /**
     * Algorand状态更新
     */
    updateAlgorandState(packet) {
        const content = packet.content;
        const msgType = content.type.toLowerCase();
        const state = this.protocolStates.algorand;

        if (content.round !== undefined) {
            state.round = Math.max(state.round, content.round);
        }

        if (content.step !== undefined) {
            state.step = Math.max(state.step, content.step);
        }

        // 跟踪提案
        if (msgType === 'proposal' && content.value !== undefined) {
            const key = `${content.round}-${content.step}`;
            if (!state.proposalValues[key]) {
                state.proposalValues[key] = new Set();
            }
            state.proposalValues[key].add(JSON.stringify(content.value));

            // 提案阶段是关键时刻
            if (state.proposalValues[key].size === 1) {
                this.considerAttackModeSwitch('conflictingVotes', 0.7);
            }
        }

        // 跟踪投票
        if (msgType === 'vote') {
            const key = `${content.round}-${content.step}`;
            if (!state.voteCount[key]) {
                state.voteCount[key] = {};
            }

            const voteValue = JSON.stringify(content.value);
            if (!state.voteCount[key][voteValue]) {
                state.voteCount[key][voteValue] = new Set();
            }

            state.voteCount[key][voteValue].add(packet.src);

            // 检测投票是否接近阈值
            let maxVotes = 0;
            for (const value in state.voteCount[key]) {
                maxVotes = Math.max(maxVotes, state.voteCount[key][value].size);
            }

            // 投票接近阈值是关键时刻
            if (maxVotes >= Math.floor(this.nodeNum * 0.6)) {
                this.considerAttackModeSwitch('conflictingVotes', 0.8);
            }
        }
    }

    /**
     * Babble状态更新
     */
    updateBabbleState(packet) {
        const content = packet.content;
        const msgType = content.type.toLowerCase();
        const state = this.protocolStates.babble;

        // 跟踪事件和轮次
        if (msgType === 'babble-event' && content.event) {
            const event = content.event;

            if (event.round !== undefined) {
                state.round = Math.max(state.round, event.round);
            }

            // 记录见证事件
            if (event.isWitness) {
                state.witnessEvents.add(event.hash || JSON.stringify(event));

                // 见证事件是关键时刻
                this.considerAttackModeSwitch('tamperEvents', 0.8);
            }
        }

        // 跟踪区块
        if (msgType === 'babble-block' && content.block) {
            const block = content.block;

            if (block.index !== undefined) {
                state.lastBlockIndex = Math.max(state.lastBlockIndex, block.index);
            }

            // 记录区块中的事件
            if (block.events && Array.isArray(block.events)) {
                state.pendingBlockEvents = [...block.events];

                // 区块形成是关键时刻
                this.considerAttackModeSwitch('tamperEvents', 0.7);
            }
        }

        // 跟踪同步消息
        if (msgType.includes('sync')) {
            // 同步阶段是关键时刻
            this.considerAttackModeSwitch('dropSync', 0.8);
        }
    }

    /**
     * LibraBFT状态更新
     */
    updateLibraState(packet) {
        const content = packet.content;
        const state = this.protocolStates.libra;

        if (content.round !== undefined) {
            state.round = Math.max(state.round, content.round);
        }

        if (content.epoch !== undefined) {
            state.epoch = Math.max(state.epoch, content.epoch);
        }

        // 记录领导者
        if (content.author) {
            state.leaders.add(content.author);
        }

        // 跟踪提案
        if (content.type && content.type.includes('proposal')) {
            state.proposalCount++;

            // 提案阶段是关键时刻
            this.considerAttackModeSwitch('delayLeader', 0.7);
        }

        // 跟踪投票聚合
        if (content.type && content.type.includes('vote')) {
            // 投票聚合是关键时刻
            this.considerAttackModeSwitch('conflictingVotes', 0.8);
        }
    }

    /**
     * Async-BA状态更新
     */
    updateAsyncBAState(packet) {
        const content = packet.content;
        const state = this.protocolStates.asyncBA;

        if (content.round !== undefined) {
            state.round = Math.max(state.round, content.round);
        }

        // 跟踪二进制值
        if (content.value !== undefined) {
            if (!state.binaryValues[state.round]) {
                state.binaryValues[state.round] = new Set();
            }

            state.binaryValues[state.round].add(JSON.stringify(content.value));

            // 检测是否有多个值
            if (state.binaryValues[state.round].size > 1) {
                // 出现分歧是关键时刻
                this.considerAttackModeSwitch('conflictingVotes', 0.6);
            }
        }
    }

    /**
     * 考虑切换攻击模式
     */
    considerAttackModeSwitch(suggestedMode, probability) {
        // 如果信任建立阶段未结束，不要主动切换攻击模式
        if (this.trustBuildingPhase &&
            this.getClockTime() - this.trustBuildingStartTime < this.trustBuildingDuration) {
            return;
        }

        // 如果当前模式正在进行且未到切换时间，保持当前模式
        if (this.currentAttackMode !== 'honest' &&
            this.getClockTime() - this.attackModeStartTime < this.attackModeDuration) {
            return;
        }

        // 根据概率决定是否切换
        if (Math.random() < probability && this.attackModes[suggestedMode].active) {
            this.switchToAttackMode(suggestedMode);
        }
    }

    /**
     * 切换到指定攻击模式
     */
    switchToAttackMode(mode) {
        if (this.currentAttackMode === mode) {
            return; // 已经是此模式
        }

        this.currentAttackMode = mode;
        this.attackModeStartTime = this.getClockTime();

        //console.log(`Switched to attack mode: ${mode} at time ${this.attackModeStartTime}`);
        this.logAttack('mode-switch', { mode: mode });
    }

    /**
     * 领导者消息延迟攻击
     */
    applyLeaderDelay(packets) {
        const leaders = new Set();

        // 根据协议确定领导者
        if (this.detectedProtocol === 'pbft') {
            leaders = this.protocolStates.pbft.leaders;
        } else if (this.detectedProtocol === 'hotstuff') {
            leaders = this.protocolStates.hotstuff.leaders;
        } else if (this.detectedProtocol === 'libra') {
            leaders = this.protocolStates.libra.leaders;
        }

        return packets.map(packet => {
            // 如果是领导者发送的消息，增加延迟
            if (leaders.has(packet.src)) {
                const delayFactor = 1.5 + Math.random() * 2; // 1.5-3.5倍延迟
                packet.delay = (packet.delay || 0) * delayFactor;

                this.logAttack('leader-delay', {
                    src: packet.src,
                    factor: delayFactor.toFixed(2)
                });
            }
            return packet;
        });
    }

    /**
     * 冲突投票攻击
     */
    applyConflictingVotes(packets) {
        // 寻找投票类消息
        const votePackets = packets.filter(p =>
            p.content &&
            (p.content.type === 'prepare' ||
                p.content.type === 'commit' ||
                p.content.type === 'vote')
        );

        if (votePackets.length === 0) {
            return packets; // 没有投票消息
        }

        // 选择一个投票消息作为模板
        const templatePacket = votePackets[Math.floor(Math.random() * votePackets.length)];

        // 创建冲突投票
        if (templatePacket.content) {
            // 复制消息并修改值
            const conflictPacket = JSON.parse(JSON.stringify(templatePacket));

            // 根据协议类型修改冲突值
            if (this.detectedProtocol === 'pbft') {
                if (conflictPacket.content.digest) {
                    conflictPacket.content.digest = `conflict_${Math.random()}`;
                }
            } else if (this.detectedProtocol === 'algorand' || this.detectedProtocol === 'asyncBA') {
                if (conflictPacket.content.value !== undefined) {
                    // 翻转布尔值或修改值
                    if (typeof conflictPacket.content.value === 'boolean') {
                        conflictPacket.content.value = !conflictPacket.content.value;
                    } else if (typeof conflictPacket.content.value === 'number') {
                        conflictPacket.content.value = (conflictPacket.content.value + 1) % 2;
                    } else {
                        conflictPacket.content.value = `conflict_${Math.random()}`;
                    }
                }
            } else {
                // 通用冲突方法
                conflictPacket.content.conflicted = true;
                if (conflictPacket.content.hash) {
                    conflictPacket.content.hash = `conflict_${Math.random()}`;
                }
            }

            // 将冲突消息添加到返回列表
            packets.push(conflictPacket);

            this.logAttack('conflict-vote', {
                original: templatePacket.content,
                conflict: conflictPacket.content
            });
        }

        return packets;
    }

    /**
     * 同步消息丢弃攻击
     */
    applyDropSync(packets) {
        // 针对同步类消息
        return packets.filter(packet => {
            if (packet.content && packet.content.type &&
                (packet.content.type.includes('sync') ||
                    packet.content.type === 'babble-sync-request' ||
                    packet.content.type === 'babble-sync-response')) {

                // 70%概率丢弃同步消息
                if (Math.random() < 0.7) {
                    this.logAttack('drop-sync', { type: packet.content.type });
                    return false;
                }
            }
            return true;
        });
    }

    /**
     * 事件篡改攻击
     */
    applyTamperEvents(packets) {
        return packets.map(packet => {
            if (!packet.content) return packet;

            if (packet.content.type === 'babble-event' && packet.content.event) {
                // 篡改Babble事件
                const event = packet.content.event;

                // 50%概率篡改
                if (Math.random() < 0.5) {
                    // 随机选择篡改方式
                    const tamperType = Math.floor(Math.random() * 3);

                    if (tamperType === 0 && event.selfParent) {
                        // 破坏事件链
                        event.selfParent = null;
                        this.logAttack('tamper-event', { type: 'break-chain' });
                    }
                    else if (tamperType === 1) {
                        // 注入虚假交易
                        if (!event.transactions) event.transactions = [];
                        event.transactions.push(`MALICIOUS_${Math.random()}`);
                        this.logAttack('tamper-event', { type: 'inject-tx' });
                    }
                    else if (tamperType === 2 && event.round !== undefined) {
                        // 修改轮次
                        event.round = Math.max(0, event.round + Math.floor(Math.random() * 3) - 1);
                        this.logAttack('tamper-event', { type: 'change-round' });
                    }

                    // 更新哈希
                    if (event.hash) {
                        event.hash = `tampered_${Math.random().toString(36).substring(2, 15)}`;
                    }
                }
            }
            else if (packet.content.type === 'babble-block' && packet.content.block) {
                // 篡改区块
                const block = packet.content.block;

                // 40%概率篡改区块
                if (Math.random() < 0.4) {
                    // 篡改区块的事件引用
                    if (block.events && block.events.length > 0) {
                        const eventIndex = Math.floor(Math.random() * block.events.length);
                        block.events[eventIndex] = `fake_event_${Math.random()}`;
                        this.logAttack('tamper-block', { type: 'event-ref' });
                    }

                    // 更新哈希
                    if (block.hash) {
                        block.hash = `tampered_block_${Math.random().toString(36).substring(2, 15)}`;
                    }
                }
            }

            return packet;
        });
    }

    /**
     * 网络分区攻击
     */
    applySplitBrain(packets) {
        // 将网络分成两半，只允许同组节点通信
        return packets.filter(packet => {
            const srcId = parseInt(packet.src);
            const dstId = parseInt(packet.dst);

            // 如果是广播消息
            if (packet.dst === 'broadcast') {
                // 只发送给同组
                const newContent = { ...packet.content };
                packet.content = newContent;

                // 记录攻击
                this.logAttack('split-brain', { type: 'filter-broadcast' });
                return true;
            }

            // 如果源和目标都有效，检查是否在同一组
            if (srcId && dstId) {
                const srcGroup = srcId % 2;
                const dstGroup = dstId % 2;

                // 跨组消息被丢弃
                if (srcGroup !== dstGroup) {
                    this.logAttack('split-brain', {
                        src: srcId,
                        dst: dstId,
                        srcGroup: srcGroup,
                        dstGroup: dstGroup
                    });
                    return false;
                }
            }

            return true;
        });
    }

    /**
     * 处理定时事件
     */
    onTimeEvent(event) {
        if (event.functionMeta.name === 'monitorSystemState') {
            this.monitorSystemState();

            // 再次注册监控
            this.registerAttackerTimeEvent(
                { name: 'monitorSystemState' },
                3000 // 3秒后再次监控
            );
        }
        else if (event.functionMeta.name === 'switchAttackMode') {
            this.randomAttackModeSwitch();

            // 再次注册切换
            this.registerAttackerTimeEvent(
                { name: 'switchAttackMode' },
                this.attackModeDuration * 1000 // N秒后再次切换
            );
        }
    }

    /**
     * 监控系统状态
     */
    monitorSystemState() {
        const currentTime = this.getClockTime();

        // 信任建立阶段结束检查
        if (this.trustBuildingPhase &&
            currentTime - this.trustBuildingStartTime >= this.trustBuildingDuration) {
            this.trustBuildingPhase = false;
            // console.log("Trust building phase ended, starting attacks");

            // 结束信任建立阶段后，随机选择攻击模式
            this.randomAttackModeSwitch();
        }
    }

    /**
     * 随机切换攻击模式
     */
    randomAttackModeSwitch() {
        // 如果信任建立阶段未结束，保持诚实
        if (this.trustBuildingPhase) {
            this.switchToAttackMode('honest');
            return;
        }

        // 计算总权重
        let totalWeight = 0;
        const availableModes = [];

        for (const mode in this.attackModes) {
            if (this.attackModes[mode].active) {
                totalWeight += this.attackModes[mode].weight;
                availableModes.push(mode);
            }
        }

        // 随机选择一个攻击模式
        let randomValue = Math.random() * totalWeight;
        let cumulativeWeight = 0;

        for (const mode of availableModes) {
            cumulativeWeight += this.attackModes[mode].weight;

            if (randomValue <= cumulativeWeight) {
                this.switchToAttackMode(mode);
                break;
            }
        }
    }

    updateParam() {
        return false; // 不更新参数
    }
}

module.exports = AdaptiveAttacker;
'use strict';

/**
 * EquivocationAttacker (改进版)
 * 
 * 此攻击者实现"多重发送"攻击 - 对同一轮次或同一笔交易向不同节点发送互相冲突的消息
 * 适用于PBFT、Algorand、HotStuff、LibraBFT、AsyncBA、SSB-Babble等共识协议
 */
class EquivocationAttacker {
    constructor(transfer, registerAttackerTimeEvent, eventQ, nodeNum, byzantineNodeNum, getClockTime) {
        this.transfer = transfer;
        this.registerAttackerTimeEvent = registerAttackerTimeEvent;
        this.eventQ = eventQ;
        this.nodeNum = nodeNum;
        this.byzantineNodeNum = byzantineNodeNum;
        this.getClockTime = getClockTime;

        // 攻击参数 - 可以通过config文件调整
        this.equivocationRate = 0.1;        // 应用多重发送攻击的消息比率
        this.modificationIntensity = 0.1;   // 修改强度 (0-1)

        // 攻击统计
        this.attackedMessages = 0;
        this.equivocatedPackets = 0;
        this.lastLogTime = this.getClockTime();

        // 检测到的协议类型
        this.detectedProtocol = null;

        // 协议配置 - 识别不同协议的关键消息类型和字段
        this.protocolConfigs = {
            pbft: {
                messageTypes: ['pre-prepare', 'prepare', 'commit', 'view-change'],
                roundField: 'v',                // 视图字段
                sequenceField: 'n',             // 序列号字段
                modifyFields: ['d']             // 可篡改的字段 (摘要)
            },
            algorand: {
                messageTypes: ['propose', 'soft', 'cert', 'next'],
                roundField: 'p',                // 周期字段
                sequenceField: 'step',          // 步骤字段
                modifyFields: ['v']             // 可篡改的字段 (值)
            },
            hotstuff: {
                messageTypes: ['hot-stuff-proposal', 'hot-stuff-vote'],
                roundField: 'view',             // 视图字段
                sequenceField: 'height',        // 高度字段
                modifyFields: ['request', 'QC'] // 可篡改的字段
            },
            librabft: {
                messageTypes: ['hot-stuff-update', 'hot-stuff-next-view'],
                roundField: 'view',             // 视图字段 
                sequenceField: 'n',             // 序列号字段
                modifyFields: ['request', 'QC'] // 可篡改的字段
            },
            asyncba: {
                messageTypes: ['init', 'echo', 'ready'],
                roundField: 'k',                // 函数不直接可见，而是在v.k中
                sequenceField: null,            // AsyncBA不使用传统序列号
                modifyFields: ['v.value', 'v.ID'] // 可篡改的字段
            },
            ssbbabble: {
                messageTypes: ['babble-event', 'babble-sync-response', 'babble-block'],
                roundField: 'round',            // 在event子对象中
                sequenceField: null,            // 使用不同机制
                modifyFields: ['event.hash', 'event.selfParent', 'event.transactions'] // 可篡改的字段
            }
        };

        // 注册周期性状态报告
        this.registerAttackerTimeEvent({ name: 'statusReport' }, 5000);

        // console.log(`Equivocation attacker initialized with rate=${this.equivocationRate}, intensity=${this.modificationIntensity}`);
    }

    attack(packets) {
        // 检测协议类型
        this.detectProtocol(packets);

        // 如果超过5秒没有进行攻击，记录状态
        const currentTime = this.getClockTime();
        if (currentTime - this.lastLogTime > 5000) {
            this.lastLogTime = currentTime;
            // console.log(`Attack status: attacked=${this.attackedMessages}, equivocated=${this.equivocatedPackets}, protocol=${this.detectedProtocol || 'unknown'}, rate=${this.equivocationRate}`);
        }

        // 创建一个新的数组来保存处理后的包
        const processedPackets = [];

        // 处理每个包
        for (const packet of packets) {
            // 1. 如果包含内容且是目标消息类型，考虑进行攻击
            if (packet.content && packet.content.type && this.isTargetMessageType(packet.content.type)) {
                // 确定是否应该攻击这个消息
                if (Math.random() < this.equivocationRate) {
                    // 增加计数
                    this.attackedMessages++;

                    // 对于广播消息，创建多个冲突版本发送到不同节点
                    if (packet.dst === 'broadcast') {
                        const equivocationPackets = this.createEquivocationPackets(packet);
                        processedPackets.push(...equivocationPackets);
                        this.equivocatedPackets += equivocationPackets.length;

                        // 输出详细日志
                        console.log(`Equivocated broadcast message: type=${packet.content.type}, created ${equivocationPackets.length} variants`);
                    }
                    // 对于点对点消息，有时也创建冲突版本
                    else if (Math.random() < this.modificationIntensity) {
                        // 篡改消息并发送
                        const modifiedPacket = this.createConflictingVersion(packet, this.detectedProtocol, Math.floor(Math.random() * 10));
                        processedPackets.push(modifiedPacket);

                        // 有时发送额外的冲突版本到其他节点
                        if (Math.random() < 0.3) {
                            const extraTargets = this.selectRandomTargets(2, packet.dst);
                            for (const target of extraTargets) {
                                const extraPacket = this.createConflictingVersion(packet, this.detectedProtocol, Math.floor(Math.random() * 10));
                                extraPacket.dst = target;
                                processedPackets.push(extraPacket);
                                this.equivocatedPackets++;
                            }
                        }
                    } else {
                        // 保持原样
                        processedPackets.push(packet);
                    }
                } else {
                    // 保持原样
                    processedPackets.push(packet);
                }
            } else {
                // 保持原样
                processedPackets.push(packet);
            }
        }

        return processedPackets;
    }

    isTargetMessageType(type) {
        // 检查是否是任何协议的目标消息类型
        for (const config of Object.values(this.protocolConfigs)) {
            if (config.messageTypes.includes(type)) {
                return true;
            }
        }
        return false;
    }

    selectRandomTargets(count, exclude) {
        // 选择随机目标节点，排除指定节点
        const targets = [];
        const correctNodeCount = this.nodeNum - this.byzantineNodeNum;

        // 试着选择指定数量的目标
        for (let attempt = 0; attempt < count * 2 && targets.length < count; attempt++) {
            const targetId = Math.floor(Math.random() * correctNodeCount) + 1;
            const targetIdStr = targetId.toString();

            // 确保不选择排除的节点和已选过的节点
            if (targetIdStr !== exclude && !targets.includes(targetIdStr)) {
                targets.push(targetIdStr);
            }
        }

        return targets;
    }

    detectProtocol(packets) {
        // 已经检测到协议，不再重复检测
        if (this.detectedProtocol) return;

        for (const packet of packets) {
            if (!packet.content || !packet.content.type) continue;

            const msgType = packet.content.type;

            // 检查各协议的消息类型
            for (const [protocol, config] of Object.entries(this.protocolConfigs)) {
                if (config.messageTypes.includes(msgType)) {
                    this.detectedProtocol = protocol;
                    console.log(`Detected protocol: ${protocol}`);
                    return;
                }
            }
        }
    }

    createEquivocationPackets(packet) {
        // 创建多个互相冲突的消息版本发送给不同节点
        const packets = [];
        const protocol = this.detectedProtocol || this.guessProtocol(packet);

        if (!protocol) {
            // 如果无法确定协议，直接做最基本的冲突修改
            return this.createGenericEquivocationPackets(packet);
        }

        // 计算可能的目标节点数量 (非拜占庭节点)
        const correctNodeCount = this.nodeNum - this.byzantineNodeNum;

        // 确定要创建的冲突版本数量 (通常2-4个版本就足够制造混乱)
        // 版本数的选择受到modificationIntensity影响
        const versionCount = Math.min(
            correctNodeCount,
            Math.max(2, Math.floor(4 * this.modificationIntensity))
        );

        // 跟踪生成的不同消息版本
        const messageVersions = [];

        // 为每个目标节点创建一个版本
        for (let i = 1; i <= correctNodeCount; i++) {
            const targetNodeId = i.toString();

            // 选择一个版本索引
            const versionIndex = i % versionCount;

            // 如果这个版本还没创建过，创建它
            if (!messageVersions[versionIndex]) {
                messageVersions[versionIndex] = this.createConflictingVersion(
                    packet,
                    protocol,
                    versionIndex
                );
            }

            // 创建针对该节点的消息副本
            const nodeSpecificPacket = JSON.parse(JSON.stringify(messageVersions[versionIndex]));

            // 修改目标为点对点而非广播
            nodeSpecificPacket.dst = targetNodeId;

            packets.push(nodeSpecificPacket);
        }

        return packets;
    }

    createGenericEquivocationPackets(packet) {
        // 当无法确定协议时使用的基础多重发送
        const packets = [];
        const correctNodeCount = this.nodeNum - this.byzantineNodeNum;

        // 只创建2个不同版本
        const version1 = JSON.parse(JSON.stringify(packet));
        const version2 = JSON.parse(JSON.stringify(packet));

        // 对第2个版本做一些通用修改
        if (version2.content) {
            // 尝试修改一些常见字段
            for (const field of ['request', 'd', 'v', 'value', 'hash']) {
                if (version2.content[field]) {
                    version2.content[field] = `equiv_${field}_${Math.random().toString(36).substring(2, 10)}`;
                    break; // 修改一个字段就够了
                }
            }
        }

        // 将广播消息发送给不同的节点
        for (let i = 1; i <= correctNodeCount; i++) {
            const targetNodeId = i.toString();

            // 选择版本
            const versionToUse = i % 2 === 0 ? version1 : version2;

            // 创建针对该节点的消息副本
            const nodeSpecificPacket = JSON.parse(JSON.stringify(versionToUse));

            // 修改目标为点对点而非广播
            nodeSpecificPacket.dst = targetNodeId;

            packets.push(nodeSpecificPacket);
        }

        return packets;
    }

    guessProtocol(packet) {
        // 如果还没有检测到协议，尝试根据消息内容猜测
        const msgType = packet.content.type;

        for (const [protocol, config] of Object.entries(this.protocolConfigs)) {
            if (config.messageTypes.includes(msgType)) {
                return protocol;
            }
        }

        return null;
    }

    createConflictingVersion(packet, protocol, versionIndex) {
        // 创建一个与原始消息相互冲突的版本
        const modifiedPacket = JSON.parse(JSON.stringify(packet)); // 深拷贝确保不修改原包

        // 如果没有指定协议，使用通用冲突创建
        if (!protocol) {
            this.createGenericConflict(modifiedPacket.content, versionIndex);
            return modifiedPacket;
        }

        // 根据协议类型创建冲突
        switch (protocol) {
            case 'pbft':
                this.createPBFTConflict(modifiedPacket.content, versionIndex);
                break;

            case 'algorand':
                this.createAlgorandConflict(modifiedPacket.content, versionIndex);
                break;

            case 'hotstuff':
            case 'librabft':
                this.createHotStuffConflict(modifiedPacket.content, versionIndex);
                break;

            case 'asyncba':
                this.createAsyncBAConflict(modifiedPacket.content, versionIndex);
                break;

            case 'ssbbabble':
                this.createSSBBabbleConflict(modifiedPacket.content, versionIndex);
                break;

            default:
                // 通用冲突创建
                this.createGenericConflict(modifiedPacket.content, versionIndex);
        }

        return modifiedPacket;
    }

    createPBFTConflict(content, versionIndex) {
        // 为PBFT创建冲突版本
        const msgType = content.type;

        switch (msgType) {
            case 'pre-prepare':
            case 'prepare':
            case 'commit':
                // 修改摘要值 (d) - 这会导致不同节点对同一序列号有不同的请求
                content.d = `equivocated_${versionIndex}_${Math.random().toString(36).substring(2, 10)}`;
                break;

            case 'view-change':
                // 修改检查点证明或准备集合
                if (content.C && content.C.length > 0) {
                    // 修改检查点证明
                    for (let i = 0; i < content.C.length; i++) {
                        if (content.C[i].d) {
                            content.C[i].d = `equiv_ckpt_${versionIndex}_${Math.random().toString(36).substring(2, 8)}`;
                        }
                    }
                }

                if (content.P && content.P.length > 0) {
                    // 修改准备集合
                    for (let i = 0; i < content.P.length; i++) {
                        if (content.P[i]['pre-prepare'] && content.P[i]['pre-prepare'].d) {
                            content.P[i]['pre-prepare'].d = `equiv_pp_${versionIndex}_${Math.random().toString(36).substring(2, 8)}`;
                        }
                    }
                }
                break;

            case 'new-view':
                // 修改新视图消息
                if (content.O && content.O.length > 0) {
                    for (let i = 0; i < content.O.length; i++) {
                        if (content.O[i].d) {
                            content.O[i].d = `equiv_newview_${versionIndex}_${Math.random().toString(36).substring(2, 8)}`;
                        }
                    }
                }
                break;
        }
    }

    createAlgorandConflict(content, versionIndex) {
        // 为Algorand创建冲突版本
        const msgType = content.type;

        switch (msgType) {
            case 'propose':
                // 修改提案值和随机数
                content.v = `equiv_prop_${versionIndex}_${Math.random().toString(36).substring(2, 10)}`;
                if (content.randomness !== undefined) {
                    content.randomness = Math.floor(Math.random() * 1000000000 + 1);
                }
                break;

            case 'soft':
                // 修改软投票值
                content.v = (versionIndex % 2 === 0) ?
                    `equiv_soft_${versionIndex}_${Math.random().toString(36).substring(2, 10)}` : 'BOT';
                break;

            case 'cert':
                // 修改认证投票值
                content.v = `equiv_cert_${versionIndex}_${Math.random().toString(36).substring(2, 10)}`;
                break;

            case 'next':
                // 修改下一轮投票值
                content.v = (versionIndex % 2 === 0) ?
                    `equiv_next_${versionIndex}_${Math.random().toString(36).substring(2, 10)}` : 'BOT';
                break;
        }
    }

    createHotStuffConflict(content, versionIndex) {
        // 为HotStuff/LibraBFT创建冲突版本
        const msgType = content.type;

        if (msgType === 'hot-stuff-proposal' || msgType === 'hot-stuff-update') {
            // 修改提案请求
            content.request = `equiv_req_${versionIndex}_${Math.random().toString(36).substring(2, 10)}`;

            // 修改父块引用
            if (content.parent) {
                content.parent = `equiv_parent_${versionIndex}_${Math.random().toString(36).substring(2, 10)}`;
            }

            // 修改QC
            if (content.QC) {
                if (content.QC.request) {
                    content.QC.request = `equiv_qc_${versionIndex}_${Math.random().toString(36).substring(2, 10)}`;
                }
            }
        }
        else if (msgType === 'hot-stuff-vote') {
            // 修改投票请求
            content.request = `equiv_req_${versionIndex}_${Math.random().toString(36).substring(2, 10)}`;

            // 修改QC引用
            if (content.QC && content.QC.request) {
                content.QC.request = `equiv_qc_${versionIndex}_${Math.random().toString(36).substring(2, 10)}`;
            }
        }
        else if (msgType === 'hot-stuff-next-view') {
            // 修改QC
            if (content.QC) {
                if (content.QC.request) {
                    content.QC.request = `equiv_qc_${versionIndex}_${Math.random().toString(36).substring(2, 10)}`;
                }
            }
        }
    }

    createAsyncBAConflict(content, versionIndex) {
        // 为AsyncBA创建冲突版本
        if (!content.v) return;

        // 1. 修改值ID - 这会破坏消息关联
        if (content.v.ID) {
            content.v.ID = `equiv_id_${versionIndex}_${Math.random().toString(36).substring(2, 15)}`;
        }

        // 2. 修改值内容 - 这会破坏共识
        if (content.v.value !== undefined) {
            // 如果是二值共识(0/1)，则按版本索引决定值
            if (typeof content.v.value === 'number' &&
                (content.v.value === 0 || content.v.value === 1)) {
                content.v.value = versionIndex % 2;
            }
            // 否则替换为随机字符串
            else if (typeof content.v.value === 'string') {
                content.v.value = `equiv_val_${versionIndex}_${Math.random().toString(36).substring(2, 10)}`;
            }
        }
    }

    createSSBBabbleConflict(content, versionIndex) {
        // 为SSB-Babble创建冲突版本
        const msgType = content.type;

        if (msgType === 'babble-event') {
            if (content.event) {
                // 修改事件哈希
                if (content.event.hash) {
                    content.event.hash = `equiv_hash_${versionIndex}_${Math.random().toString(36).substring(2, 15)}`;
                }

                // 修改父引用
                if (content.event.selfParent) {
                    content.event.selfParent = `equiv_parent_${versionIndex}_${Math.random().toString(36).substring(2, 15)}`;
                }

                // 添加/修改交易
                if (content.event.transactions !== undefined) {
                    if (Array.isArray(content.event.transactions)) {
                        // 添加版本特定的交易
                        content.event.transactions.push(`EQUIV_TX_${versionIndex}_${Math.random().toString(36).substring(2, 8)}`);
                    } else {
                        content.event.transactions = [`EQUIV_TX_${versionIndex}_${Math.random().toString(36).substring(2, 8)}`];
                    }
                }
            }
        }
        else if (msgType === 'babble-block') {
            if (content.block) {
                // 修改区块哈希
                if (content.block.hash) {
                    content.block.hash = `equiv_block_${versionIndex}_${Math.random().toString(36).substring(2, 15)}`;
                }

                // 修改交易内容
                if (content.block.transactions && content.block.transactions.length > 0) {
                    const txIndex = Math.floor(Math.random() * content.block.transactions.length);
                    content.block.transactions[txIndex] = `EQUIV_BLOCK_TX_${versionIndex}_${Math.random().toString(36).substring(2, 8)}`;
                }

                // 修改事件引用
                if (content.block.events && content.block.events.length > 0) {
                    const eventIndex = Math.floor(Math.random() * content.block.events.length);
                    content.block.events[eventIndex] = `equiv_event_ref_${versionIndex}_${Math.random().toString(36).substring(2, 15)}`;
                }
            }
        }
        else if (msgType === 'babble-sync-response') {
            // 修改同步响应中的事件
            if (content.events && content.events.length > 0) {
                for (let i = 0; i < content.events.length; i++) {
                    if (Math.random() < 0.3 && content.events[i].hash) {
                        content.events[i].hash = `equiv_sync_${versionIndex}_${Math.random().toString(36).substring(2, 15)}`;
                    }
                }
            }
        }
    }

    createGenericConflict(content, versionIndex) {
        // 通用冲突创建方法 - 尝试修改各种可能的字段

        // 常见字段名列表
        const potentialFields = [
            'request', 'd', 'v', 'value', 'hash', 'parent', 'transactions'
        ];

        // 尝试修改这些字段
        let fieldModified = false;
        for (const field of potentialFields) {
            if (content[field] !== undefined) {
                if (typeof content[field] === 'string') {
                    content[field] = `equiv_${field}_${versionIndex}_${Math.random().toString(36).substring(2, 10)}`;
                    fieldModified = true;
                    break; // 只修改一个字段
                }
            }
        }

        // 如果没有找到可修改的直接字段，检查嵌套对象
        if (!fieldModified) {
            for (const key in content) {
                if (content[key] && typeof content[key] === 'object' && !Array.isArray(content[key])) {
                    this.createGenericConflict(content[key], versionIndex);
                    break; // 只修改一个嵌套对象
                }
            }
        }
    }

    onTimeEvent(event) {
        if (event.functionMeta.name === 'statusReport') {
            console.log(`Equivocation report: attacked=${this.attackedMessages}, equivocated=${this.equivocatedPackets}, protocol=${this.detectedProtocol || 'unknown'}, rate=${this.equivocationRate}, modIntensity=${this.modificationIntensity}`);

            // 重新注册状态报告
            this.registerAttackerTimeEvent({ name: 'statusReport' }, 5000);
        }
    }

    updateParam() {
        // 如果从config文件读取了新的参数，在这里更新
        console.log(`Updated parameters: rate=${this.equivocationRate}, intensity=${this.modificationIntensity}`);
        return false;
    }
}

module.exports = EquivocationAttacker;
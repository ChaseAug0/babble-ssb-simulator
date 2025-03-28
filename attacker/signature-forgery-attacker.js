'use strict';

/**
 * SignatureForgeryAttacker
 * 此攻击者专注于伪造签名、篡改投票证明和伪造身份
 * 适用于使用签名验证、投票聚合或证书的协议
 * (如HotStuff的QC, PBFT的视图变更证明, Algorand的VRF)
 */
class SignatureForgeryAttacker {
    constructor(transfer, registerAttackerTimeEvent, eventQ, nodeNum, byzantineNodeNum, getClockTime) {
        this.transfer = transfer;
        this.registerAttackerTimeEvent = registerAttackerTimeEvent;
        this.eventQ = eventQ;
        this.nodeNum = nodeNum;
        this.byzantineNodeNum = byzantineNodeNum;
        this.getClockTime = getClockTime;

        // 攻击参数
        this.signatureForgeryRate = 0.7;      // 基础签名伪造概率
        this.certificateTamperRate = 0.7;     // 证书篡改概率
        this.identityForgeryRate = 0.7;       // 身份伪造概率
        this.rotateSignatureScheme = true;    // 是否定期轮换伪造策略

        // 攻击统计
        this.forgedSignatures = 0;            // 伪造签名次数
        this.tamperedCertificates = 0;        // 篡改证书次数
        this.forgedIdentities = 0;            // 伪造身份次数

        // 协议检测和配置
        this.detectedProtocol = null;          // 检测到的协议
        this.protocolSignatureFields = {
            pbft: {
                messageTypes: ['pre-prepare', 'prepare', 'commit', 'view-change', 'new-view'],
                signatureFields: ['i', 'signature'],
                certificateFields: ['C', 'P', 'proof']
            },
            hotstuff: {
                messageTypes: ['hot-stuff-proposal', 'hot-stuff-vote', 'hot-stuff-next-view'],
                signatureFields: ['sourceReplica', 'signature'],
                certificateFields: ['QC', 'signers']
            },
            librabft: {
                messageTypes: ['hot-stuff-update', 'hot-stuff-next-view'],
                signatureFields: ['sourceReplica', 'signature'],
                certificateFields: ['QC', 'signers']
            },
            algorand: {
                messageTypes: ['propose', 'soft', 'cert', 'next'],
                signatureFields: ['sender', 'signature', 'randomness'],
                certificateFields: ['proof']
            },
            asyncba: {
                messageTypes: ['init', 'echo', 'ready'],
                signatureFields: ['sender', 'signature'],
                certificateFields: []
            },
            ssbbabble: {
                messageTypes: ['babble-event', 'babble-block', 'babble-block-signature'],
                signatureFields: ['signature', 'sourceReplica'],
                certificateFields: ['proof', 'signers']
            }
        };

        // 观察到的签名样本
        this.observedSignatures = {};         // 节点ID -> 签名样本数组
        this.observedCertificates = {};       // 协议 -> 证书样本数组

        // 当前活跃的签名伪造策略
        this.currentForgeryStrategy = 0;

        // 启动策略轮换
        if (this.rotateSignatureScheme) {
            this.registerAttackerTimeEvent(
                { name: 'rotateStrategy' },
                10000 // 10秒后轮换策略
            );
        }

        // 启动状态报告
        this.registerAttackerTimeEvent(
            { name: 'statusReport' },
            5000  // 5秒后报告状态
        );

        //console.log('Signature forgery attacker initialized');
    }

    attack(packets) {
        // 检测协议类型
        this.detectProtocol(packets);

        // 学习签名模式
        this.learnSignaturePatterns(packets);

        // 处理包并应用攻击
        return packets.map(packet => {
            // 不修改拜占庭节点发送的消息
            if (this.isByzantineNode(packet.src)) return packet;

            // 如果没有内容，直接返回
            if (!packet.content || !packet.content.type) return packet;

            // 检查消息类型是否适合伪造签名
            if (!this.isSignatureRelevantMessage(packet.content.type)) return packet;

            // 决定是否攻击这个消息
            const shouldAttack = Math.random() < this.getAttackProbability(packet);
            if (!shouldAttack) return packet;

            // 根据消息类型选择攻击策略
            return this.applySignatureAttack(packet);
        });
    }

    isByzantineNode(nodeId) {
        // 检查节点是否是拜占庭节点
        const nodeIdInt = parseInt(nodeId);
        return nodeIdInt > (this.nodeNum - this.byzantineNodeNum);
    }

    detectProtocol(packets) {
        // 已经检测到协议，不再重复检测
        if (this.detectedProtocol) return;

        for (const packet of packets) {
            if (!packet.content || !packet.content.type) continue;

            const msgType = packet.content.type;

            // 检查各协议的消息类型
            for (const [protocol, config] of Object.entries(this.protocolSignatureFields)) {
                if (config.messageTypes.includes(msgType)) {
                    this.detectedProtocol = protocol;
                    //(`Detected protocol: ${protocol}`);
                    return;
                }
            }
        }
    }

    isSignatureRelevantMessage(msgType) {
        for (const config of Object.values(this.protocolSignatureFields)) {
            if (config.messageTypes.includes(msgType)) {
                return true;
            }
        }
        return false;
    }

    getAttackProbability(packet) {
        // 根据消息类型和协议调整攻击概率
        const msgType = packet.content.type;

        // 投票/证书/签名消息有更高攻击概率
        if (msgType.includes('vote') ||
            msgType.includes('cert') ||
            msgType.includes('signature') ||
            msgType === 'commit' ||
            msgType === 'prepare') {
            return this.signatureForgeryRate * 1.2;
        }

        // 视图变更/同步消息有中等攻击概率
        if (msgType.includes('view-change') ||
            msgType.includes('new-view') ||
            msgType.includes('next-view') ||
            msgType === 'next') {
            return this.signatureForgeryRate;
        }

        // 其他消息有较低攻击概率
        return this.signatureForgeryRate * 0.8;
    }

    learnSignaturePatterns(packets) {
        // 学习节点的签名模式用于后续伪造
        for (const packet of packets) {
            if (!packet.content) continue;

            const src = packet.src;
            if (!src) continue;

            // 1. 学习基本签名
            this.learnBasicSignature(src, packet.content);

            // 2. 学习证书/聚合签名
            this.learnCertificates(packet.content);
        }
    }

    learnBasicSignature(nodeId, content) {
        // 初始化节点签名存储
        if (!this.observedSignatures[nodeId]) {
            this.observedSignatures[nodeId] = [];
        }

        // 查找签名字段
        for (const protocol in this.protocolSignatureFields) {
            const signatureFields = this.protocolSignatureFields[protocol].signatureFields;

            for (const field of signatureFields) {
                // 修复: 正确使用括号分组逻辑表达式
                if (content[field] && typeof content[field] === 'string' &&
                    (content[field].includes('signature') || content[field].includes('sig_'))) {
                    // 找到了签名，添加到样本中
                    if (this.observedSignatures[nodeId].length < 5) { // 限制样本数量
                        this.observedSignatures[nodeId].push(content[field]);
                    }
                    return;
                }
            }

            // 检查嵌套字段，比如event.signature
            for (const key in content) {
                if (content[key] && typeof content[key] === 'object') {
                    for (const field of signatureFields) {
                        // 修复: 正确使用括号分组逻辑表达式
                        if (content[key][field] && typeof content[key][field] === 'string' &&
                            (content[key][field].includes('signature') || content[key][field].includes('sig_'))) {
                            // 找到了签名，添加到样本中
                            if (this.observedSignatures[nodeId].length < 5) {
                                this.observedSignatures[nodeId].push(content[key][field]);
                            }
                            return;
                        }
                    }
                }
            }
        }
    }

    learnCertificates(content) {
        if (!this.detectedProtocol) return;

        // 初始化协议证书存储
        if (!this.observedCertificates[this.detectedProtocol]) {
            this.observedCertificates[this.detectedProtocol] = [];
        }

        const certificateFields = this.protocolSignatureFields[this.detectedProtocol].certificateFields;

        // 检查主证书字段
        for (const field of certificateFields) {
            if (content[field]) {
                // 找到了证书，添加到样本中
                if (this.observedCertificates[this.detectedProtocol].length < 3) {
                    this.observedCertificates[this.detectedProtocol].push(content[field]);
                }
                return;
            }
        }

        // 检查嵌套字段
        for (const key in content) {
            if (content[key] && typeof content[key] === 'object') {
                for (const field of certificateFields) {
                    if (content[key][field]) {
                        // 找到了证书，添加到样本中
                        if (this.observedCertificates[this.detectedProtocol].length < 3) {
                            this.observedCertificates[this.detectedProtocol].push(content[key][field]);
                        }
                        return;
                    }
                }
            }
        }
    }

    applySignatureAttack(packet) {
        // 创建包的深拷贝
        const modifiedPacket = JSON.parse(JSON.stringify(packet));

        // 选择攻击类型
        const attackType = Math.random();

        if (attackType < this.identityForgeryRate && this.canForgeIdentity(modifiedPacket)) {
            // 身份伪造攻击
            this.forgeIdentity(modifiedPacket);
            this.forgedIdentities++;
        }
        else if (attackType < this.identityForgeryRate + this.certificateTamperRate &&
            this.canTamperCertificate(modifiedPacket)) {
            // 证书篡改攻击
            this.tamperCertificate(modifiedPacket);
            this.tamperedCertificates++;
        }
        else {
            // 签名伪造攻击
            this.forgeSignature(modifiedPacket);
            this.forgedSignatures++;
        }

        return modifiedPacket;
    }

    canForgeIdentity(packet) {
        // 检查是否可以伪造身份
        return packet.src !== undefined;
    }

    canTamperCertificate(packet) {
        // 检查是否有可篡改的证书
        if (!this.detectedProtocol) return false;

        const content = packet.content;
        const certificateFields = this.protocolSignatureFields[this.detectedProtocol].certificateFields;

        // 检查主证书字段
        for (const field of certificateFields) {
            if (content[field]) return true;
        }

        // 检查嵌套字段
        for (const key in content) {
            if (content[key] && typeof content[key] === 'object') {
                for (const field of certificateFields) {
                    if (content[key][field]) return true;
                }
            }
        }

        return false;
    }

    forgeIdentity(packet) {
        // 伪造发送者身份
        const originalSrc = packet.src;

        // 在非拜占庭节点中选择一个不同的节点ID
        let forgeSrc;
        do {
            forgeSrc = Math.floor(Math.random() * (this.nodeNum - this.byzantineNodeNum)) + 1;
        } while (forgeSrc.toString() === originalSrc);

        packet.src = forgeSrc.toString();

        // 根据协议调整相应的身份字段
        if (this.detectedProtocol && packet.content) {
            const signatureFields = this.protocolSignatureFields[this.detectedProtocol].signatureFields;

            // 替换内容中的发送者ID字段
            for (const field of signatureFields) {
                if (field === 'sourceReplica' || field === 'sender' || field === 'i') {
                    if (packet.content[field]) {
                        packet.content[field] = forgeSrc.toString();
                    }
                }
            }

            // 替换嵌套对象中的发送者ID
            for (const key in packet.content) {
                if (packet.content[key] && typeof packet.content[key] === 'object') {
                    for (const field of signatureFields) {
                        if ((field === 'sourceReplica' || field === 'sender' || field === 'i') &&
                            packet.content[key][field]) {
                            packet.content[key][field] = forgeSrc.toString();
                        }
                    }
                }
            }
        }

        // 还需要伪造对应的签名
        this.forgeSignature(packet);

        //console.log(`Forged identity from ${originalSrc} to ${forgeSrc}`);
    }

    tamperCertificate(packet) {
        if (!this.detectedProtocol) return;

        const content = packet.content;
        const certificateFields = this.protocolSignatureFields[this.detectedProtocol].certificateFields;

        // 根据协议特定的证书结构进行篡改
        switch (this.detectedProtocol) {
            case 'pbft':
                this.tamperPBFTCertificate(content, certificateFields);
                break;

            case 'hotstuff':
            case 'librabft':
                this.tamperHotStuffCertificate(content, certificateFields);
                break;

            case 'algorand':
                this.tamperAlgorandCertificate(content, certificateFields);
                break;

            case 'ssbbabble':
                this.tamperBabbleCertificate(content, certificateFields);
                break;

            default:
                this.tamperGenericCertificate(content, certificateFields);
        }

        //console.log(`Tampered certificate in message type: ${content.type}`);
    }

    tamperPBFTCertificate(content, certificateFields) {
        // PBFT特定的证书篡改

        // 1. 视图变更证明篡改
        if (content.type === 'view-change') {
            // 修改检查点证明
            if (content.C && content.C.length > 0) {
                for (let i = 0; i < content.C.length; i++) {
                    if (content.C[i].i && content.C[i].d) {
                        // 篡改节点ID和摘要
                        content.C[i].i = this.getRandomNodeId(content.C[i].i);
                        content.C[i].d = `forged_ckpt_${Math.random().toString(36).substring(2, 10)}`;
                    }
                }
            }

            // 修改准备消息集合
            if (content.P && content.P.length > 0) {
                for (let i = 0; i < content.P.length; i++) {
                    if (content.P[i]['pre-prepare']) {
                        // 篡改pre-prepare消息
                        content.P[i]['pre-prepare'].d = `forged_pp_${Math.random().toString(36).substring(2, 10)}`;
                    }

                    if (content.P[i].prepare && Array.isArray(content.P[i].prepare)) {
                        // 篡改prepare消息
                        for (let j = 0; j < content.P[i].prepare.length; j++) {
                            if (content.P[i].prepare[j].i) {
                                content.P[i].prepare[j].i = this.getRandomNodeId(content.P[i].prepare[j].i);
                            }
                        }
                    }
                }
            }
        }

        // 2. 新视图证明篡改
        else if (content.type === 'new-view') {
            // 修改视图变更消息集合
            if (content.V && Array.isArray(content.V)) {
                for (let i = 0; i < content.V.length; i++) {
                    if (content.V[i].i) {
                        content.V[i].i = this.getRandomNodeId(content.V[i].i);
                    }
                }
            }

            // 修改操作集合
            if (content.O && Array.isArray(content.O)) {
                for (let i = 0; i < content.O.length; i++) {
                    if (content.O[i].d) {
                        content.O[i].d = `forged_op_${Math.random().toString(36).substring(2, 10)}`;
                    }
                }
            }
        }

        // 3. 决定证明篡改
        else if (content.type === 'decide' && content.proof && Array.isArray(content.proof)) {
            for (let i = 0; i < content.proof.length; i++) {
                if (content.proof[i].i) {
                    // 篡改证明中的节点ID
                    content.proof[i].i = this.getRandomNodeId(content.proof[i].i);
                }

                // 有时篡改摘要
                if (Math.random() < 0.3 && content.proof[i].d) {
                    content.proof[i].d = `forged_decide_${Math.random().toString(36).substring(2, 10)}`;
                }
            }
        }
    }

    tamperHotStuffCertificate(content, certificateFields) {
        // HotStuff/LibraBFT特定的证书篡改

        // 篡改QC
        if (content.QC) {
            // 篡改请求引用
            if (content.QC.request) {
                content.QC.request = `forged_qc_${Math.random().toString(36).substring(2, 10)}`;
            }

            // 篡改签名者列表
            if (content.QC.signers && Array.isArray(content.QC.signers)) {
                // 添加不存在的节点ID
                if (content.QC.signers.length > 0 && Math.random() < 0.5) {
                    const fakeSigners = [];
                    const existingSigners = new Set(content.QC.signers);

                    // 添加一些伪造的签名者
                    for (let i = 1; i <= Math.min(3, this.nodeNum); i++) {
                        const randomId = this.getRandomNodeId();
                        if (!existingSigners.has(randomId)) {
                            fakeSigners.push(randomId);
                            existingSigners.add(randomId);
                        }
                    }

                    // 合并伪造签名者
                    content.QC.signers = [...content.QC.signers, ...fakeSigners];
                }

                // 有时移除一些签名者
                else if (content.QC.signers.length > 1) {
                    const removeCount = Math.floor(content.QC.signers.length * 0.3);
                    for (let i = 0; i < removeCount; i++) {
                        if (content.QC.signers.length > 1) {
                            const removeIndex = Math.floor(Math.random() * content.QC.signers.length);
                            content.QC.signers.splice(removeIndex, 1);
                        }
                    }
                }
            }

            // 篡改视图号或高度
            if (content.QC.view !== undefined) {
                content.QC.view = Math.max(0, content.QC.view + Math.floor(Math.random() * 5) - 2);
            }

            if (content.QC.height !== undefined) {
                content.QC.height = Math.max(0, content.QC.height + Math.floor(Math.random() * 5) - 2);
            }
        }
    }

    tamperAlgorandCertificate(content, certificateFields) {
        // Algorand特定的证书篡改

        // 篡改投票值
        if (content.type === 'soft' || content.type === 'cert' || content.type === 'next') {
            if (content.v !== undefined) {
                if (typeof content.v === 'string') {
                    content.v = `forged_${content.type}_${Math.random().toString(36).substring(2, 10)}`;
                } else if (content.v === 0 || content.v === 1) {
                    // 二值共识翻转
                    content.v = 1 - content.v;
                }
            }
        }

        // 篡改随机数 (VRF相关)
        if (content.randomness !== undefined) {
            content.randomness = Math.floor(Math.random() * 1000000000 + 1);
        }
    }

    tamperBabbleCertificate(content, certificateFields) {
        // SSB-Babble特定的证书篡改

        // 篡改区块签名消息
        if (content.type === 'babble-block-signature') {
            // 篡改区块哈希
            if (content.blockHash) {
                content.blockHash = `forged_blockhash_${Math.random().toString(36).substring(2, 15)}`;
            }

            // 篡改签名
            if (content.signature) {
                content.signature = `forged_sig_${Math.random().toString(36).substring(2, 15)}`;
            }
        }

        // 篡改决策证明
        if (content.proof && Array.isArray(content.proof)) {
            for (let i = 0; i < content.proof.length; i++) {
                if (content.proof[i].sourceReplica) {
                    content.proof[i].sourceReplica = this.getRandomNodeId(content.proof[i].sourceReplica);
                }

                if (content.proof[i].signature) {
                    content.proof[i].signature = `forged_proof_${Math.random().toString(36).substring(2, 15)}`;
                }
            }
        }
    }

    tamperGenericCertificate(content, certificateFields) {
        // 通用证书篡改

        // 尝试篡改各种证书字段
        for (const field of certificateFields) {
            if (content[field]) {
                if (Array.isArray(content[field])) {
                    // 针对数组类型的证书
                    this.tamperArrayCertificate(content[field]);
                } else if (typeof content[field] === 'object') {
                    // 针对对象类型的证书
                    this.tamperObjectCertificate(content[field]);
                }
            }
        }

        // 检查嵌套对象中的证书字段
        for (const key in content) {
            if (content[key] && typeof content[key] === 'object') {
                for (const field of certificateFields) {
                    if (content[key][field]) {
                        if (Array.isArray(content[key][field])) {
                            this.tamperArrayCertificate(content[key][field]);
                        } else if (typeof content[key][field] === 'object') {
                            this.tamperObjectCertificate(content[key][field]);
                        }
                    }
                }
            }
        }
    }

    tamperArrayCertificate(certArray) {
        // 篡改数组类型的证书
        if (!Array.isArray(certArray) || certArray.length === 0) return;

        // 随机添加或删除数组元素
        if (Math.random() < 0.5 && certArray.length > 1) {
            // 删除一些元素
            const removeCount = Math.floor(certArray.length * 0.3);
            for (let i = 0; i < removeCount; i++) {
                if (certArray.length > 1) {
                    const removeIndex = Math.floor(Math.random() * certArray.length);
                    certArray.splice(removeIndex, 1);
                }
            }
        } else {
            // 添加伪造元素
            const sampleItem = certArray[0];
            if (typeof sampleItem === 'object') {
                // 复制并修改第一个元素
                const forgedItem = JSON.parse(JSON.stringify(sampleItem));
                // 尝试修改一些常见字段
                for (const field of ['signature', 'id', 'hash', 'i', 'sourceReplica', 'sender']) {
                    if (forgedItem[field]) {
                        if (field === 'i' || field === 'sourceReplica' || field === 'sender') {
                            forgedItem[field] = this.getRandomNodeId(forgedItem[field]);
                        } else {
                            forgedItem[field] = `forged_${field}_${Math.random().toString(36).substring(2, 10)}`;
                        }
                    }
                }
                certArray.push(forgedItem);
            } else if (typeof sampleItem === 'string') {
                // 添加伪造字符串
                certArray.push(`forged_cert_${Math.random().toString(36).substring(2, 10)}`);
            }
        }
    }

    tamperObjectCertificate(certObject) {
        // 篡改对象类型的证书
        if (!certObject || typeof certObject !== 'object') return;

        // 修改对象的一些字段
        for (const field in certObject) {
            // 找到可能的签名或ID字段
            if (field === 'signature' || field.includes('sig')) {
                certObject[field] = `forged_${field}_${Math.random().toString(36).substring(2, 10)}`;
            }
            else if (field === 'id' || field === 'hash' || field.includes('hash')) {
                certObject[field] = `forged_${field}_${Math.random().toString(36).substring(2, 10)}`;
            }
            else if (field === 'i' || field === 'sourceReplica' || field === 'sender') {
                certObject[field] = this.getRandomNodeId(certObject[field]);
            }
            // 递归处理嵌套对象
            else if (typeof certObject[field] === 'object') {
                this.tamperObjectCertificate(certObject[field]);
            }
        }
    }

    forgeSignature(packet) {
        // 根据当前策略伪造签名
        switch (this.currentForgeryStrategy) {
            case 0:
                // 完全随机签名
                this.forgeRandomSignature(packet);
                break;
            case 1:
                // 基于观察到的签名模式伪造
                this.forgePatternBasedSignature(packet);
                break;
            case 2:
                // 使用其他节点的签名
                this.forgeBorrowedSignature(packet);
                break;
            default:
                this.forgeRandomSignature(packet);
        }
    }

    forgeRandomSignature(packet) {
        // 完全随机的签名伪造
        if (!this.detectedProtocol) return;

        const content = packet.content;
        const signatureFields = this.protocolSignatureFields[this.detectedProtocol].signatureFields;

        // 篡改主签名字段
        for (const field of signatureFields) {
            if (field === 'signature' && content[field]) {
                content[field] = `random_sig_${Math.random().toString(36).substring(2, 15)}`;
            }
        }

        // 篡改嵌套对象中的签名
        for (const key in content) {
            if (content[key] && typeof content[key] === 'object') {
                for (const field of signatureFields) {
                    if (field === 'signature' && content[key][field]) {
                        content[key][field] = `random_sig_${Math.random().toString(36).substring(2, 15)}`;
                    }
                }

                // 递归检查更深层次
                if (typeof content[key] === 'object' && !Array.isArray(content[key])) {
                    this.forgeRandomSignatureRecursive(content[key]);
                }
            }
        }
    }

    forgeRandomSignatureRecursive(obj) {
        // 递归查找并篡改签名字段
        if (!obj || typeof obj !== 'object') return;

        for (const key in obj) {
            if (key === 'signature' || key.includes('sig')) {
                obj[key] = `random_sig_${Math.random().toString(36).substring(2, 15)}`;
            } else if (typeof obj[key] === 'object') {
                this.forgeRandomSignatureRecursive(obj[key]);
            }
        }
    }

    forgePatternBasedSignature(packet) {
        // 基于观察到的签名模式伪造
        const src = packet.src;

        // 如果没有观察到该节点的签名，使用随机签名
        if (!this.observedSignatures[src] || this.observedSignatures[src].length === 0) {
            this.forgeRandomSignature(packet);
            return;
        }

        if (!this.detectedProtocol) return;

        const content = packet.content;
        const signatureFields = this.protocolSignatureFields[this.detectedProtocol].signatureFields;

        // 选择一个观察到的签名样本
        const sampleSig = this.observedSignatures[src][
            Math.floor(Math.random() * this.observedSignatures[src].length)
        ];

        // 提取签名模式
        let sigPrefix = '';
        const parts = sampleSig.split('_');
        if (parts.length > 1) {
            sigPrefix = parts.slice(0, 2).join('_') + '_';
        }

        // 创建类似的伪造签名
        const forgedSig = `${sigPrefix}forged_${Math.random().toString(36).substring(2, 12)}`;

        // 篡改主签名字段
        for (const field of signatureFields) {
            if (field === 'signature' && content[field]) {
                content[field] = forgedSig;
            }
        }

        // 篡改嵌套对象中的签名
        for (const key in content) {
            if (content[key] && typeof content[key] === 'object') {
                for (const field of signatureFields) {
                    if (field === 'signature' && content[key][field]) {
                        content[key][field] = forgedSig;
                    }
                }
            }
        }
    }

    forgeBorrowedSignature(packet) {
        // 使用其他节点的签名
        const src = packet.src;

        // 查找其他节点的签名样本
        const otherSigs = {};
        for (const nodeId in this.observedSignatures) {
            if (nodeId !== src && this.observedSignatures[nodeId].length > 0) {
                otherSigs[nodeId] = this.observedSignatures[nodeId];
            }
        }

        // 如果没有其他节点的签名，使用随机签名
        if (Object.keys(otherSigs).length === 0) {
            this.forgeRandomSignature(packet);
            return;
        }

        if (!this.detectedProtocol) return;

        const content = packet.content;
        const signatureFields = this.protocolSignatureFields[this.detectedProtocol].signatureFields;

        // 随机选择一个其他节点
        const otherNodeIds = Object.keys(otherSigs);
        const otherNodeId = otherNodeIds[Math.floor(Math.random() * otherNodeIds.length)];

        // 选择一个该节点的签名样本
        const borrowedSig = otherSigs[otherNodeId][
            Math.floor(Math.random() * otherSigs[otherNodeId].length)
        ];

        // 篡改主签名字段
        for (const field of signatureFields) {
            if (field === 'signature' && content[field]) {
                content[field] = borrowedSig;
            }
        }

        // 篡改嵌套对象中的签名
        for (const key in content) {
            if (content[key] && typeof content[key] === 'object') {
                for (const field of signatureFields) {
                    if (field === 'signature' && content[key][field]) {
                        content[key][field] = borrowedSig;
                    }
                }
            }
        }
    }

    getRandomNodeId(exclude) {
        // 生成一个随机的非拜占庭节点ID
        let randomId;
        do {
            randomId = Math.floor(Math.random() * (this.nodeNum - this.byzantineNodeNum)) + 1;
        } while (randomId.toString() === exclude);

        return randomId.toString();
    }

    onTimeEvent(event) {
        if (event.functionMeta.name === 'rotateStrategy') {
            // 轮换签名伪造策略
            this.currentForgeryStrategy = (this.currentForgeryStrategy + 1) % 3;
            //console.log(`Rotated signature forgery strategy to: ${this.currentForgeryStrategy}`);

            // 再次注册轮换事件
            this.registerAttackerTimeEvent(
                { name: 'rotateStrategy' },
                15000 // 15秒后再次轮换
            );
        }
        else if (event.functionMeta.name === 'statusReport') {
            // 输出攻击状态报告
            //console.log(`Signature forgery report: forged=${this.forgedSignatures}, tampered=${this.tamperedCertificates}, identities=${this.forgedIdentities}`);

            // 再次注册状态报告
            this.registerAttackerTimeEvent(
                { name: 'statusReport' },
                5000 // 5秒后再次报告
            );
        }
    }

    updateParam() {
        return false; // 不更新参数
    }
}

module.exports = SignatureForgeryAttacker;
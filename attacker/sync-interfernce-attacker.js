'use strict';

/**
 * SyncInterferenceAttacker
 * 通用共识协议攻击器，通过篡改消息内容干扰共识进程
 * 适用于多种BFT协议，包括PBFT, Algorand, HotStuff, LibraBFT, Async-BA, Babble-SSB等
 */
class SyncInterferenceAttacker {
    constructor(transfer, registerAttackerTimeEvent, eventQ, nodeNum, byzantineNodeNum, getClockTime) {
        this.transfer = transfer;
        this.registerAttackerTimeEvent = registerAttackerTimeEvent;
        this.eventQ = eventQ;
        this.nodeNum = nodeNum;
        this.byzantineNodeNum = byzantineNodeNum;
        this.getClockTime = getClockTime;

        // 攻击参数 - 增加默认攻击概率
        this.attackRate = 0.1;                   // 高基础攻击概率
        this.intensityFactor = 1.0;              // 攻击强度因子
        this.dropRate = 0.3;                     // 消息丢弃概率

        // 协议类型检测标志
        this.detectedProtocols = {
            pbft: false,
            hotstuff: false,
            algorand: false,
            babble: false,
            libra: false,
            asyncBA: false
        };

        // 注册定时调整攻击强度
        this.registerAttackerTimeEvent(
            { name: 'adjustAttackIntensity' },
            10000  // 每10秒调整一次攻击强度
        );

    }

    attack(packets) {
        return packets.filter(packet => {
            // 检测协议类型
            this.detectProtocolType(packet);

            // 随机丢弃部分消息
            if (Math.random() < this.dropRate) {
                return false; // 直接丢弃这个消息
            }

            if (!packet.content || Math.random() > this.attackRate * this.intensityFactor) {
                return true;  // 保持不变
            }

            try {
                // 创建内容的深拷贝，避免引用问题
                const originalContent = packet.content;

                // 直接修改原始内容
                this.corruptMessage(originalContent);

                // 检查是否包含特定协议的关键消息类型，并进行针对性攻击
                if (originalContent.type) {
                    this.attackSpecificProtocol(originalContent);
                }

                return true; // 保留已篡改的消息
            } catch (e) {
                // console.log("攻击器错误：", e);
                return true; // 出错时保留原消息
            }
        });
    }

    // 检测协议类型
    detectProtocolType(packet) {
        if (!packet.content || !packet.content.type) return;

        const msgType = packet.content.type;

        if (msgType.includes('pbft')) {
            this.detectedProtocols.pbft = true;
        } else if (msgType.includes('hotstuff') || msgType.includes('new-view')) {
            this.detectedProtocols.hotstuff = true;
        } else if (msgType.includes('algorand') || msgType.includes('proposal') || msgType.includes('vote')) {
            this.detectedProtocols.algorand = true;
        } else if (msgType.includes('babble') || msgType.includes('ssb')) {
            this.detectedProtocols.babble = true;
        } else if (msgType.includes('libra')) {
            this.detectedProtocols.libra = true;
        } else if (msgType.includes('async') || msgType.includes('ba-')) {
            this.detectedProtocols.asyncBA = true;
        }
    }

    // 针对特定协议的攻击
    attackSpecificProtocol(content) {
        const msgType = content.type;

        // PBFT特定攻击
        if (msgType.includes('pbft')) {
            if (content.view !== undefined) {
                // 修改视图号是阻止PBFT进展的有效方式
                content.view += Math.ceil(Math.random() * 3);
            }
            if (content.sequence !== undefined) {
                // 干扰序列号
                content.sequence += Math.floor(Math.random() * 5) - 2;
                if (content.sequence < 0) content.sequence = 0;
            }
        }

        // HotStuff特定攻击
        else if (msgType.includes('hotstuff') || msgType.includes('new-view')) {
            if (content.qc) {
                // 破坏证书
                content.qc.view = (content.qc.view || 0) + 1;
                if (content.qc.signature) {
                    content.qc.signature = "fake_" + Math.random().toString(36).substring(2, 10);
                }
            }
        }

        // Algorand特定攻击
        else if (msgType.includes('algorand') || msgType.includes('proposal') || msgType.includes('vote')) {
            if (content.value && typeof content.value === 'string') {
                // 替换提议值
                content.value = "corrupted_" + Math.random().toString(36).substring(2, 10);
            }
            if (content.round !== undefined) {
                // 修改轮次
                content.round += Math.floor(Math.random() * 3);
            }
        }

        // Babble/SSB特定攻击
        else if (msgType.includes('babble') || msgType.includes('ssb')) {
            if (msgType === 'babble-event' && content.event) {
                // 破坏事件哈希图
                if (content.event.selfParent) {
                    content.event.selfParent = null; // 破坏事件链
                }
                if (content.event.isWitness !== undefined) {
                    content.event.isWitness = !content.event.isWitness;
                }
            }
            else if (msgType === 'babble-block' && content.block) {
                // 篡改区块
                if (content.block.transactions && Array.isArray(content.block.transactions)) {
                    content.block.transactions.push("MALICIOUS_TX_" + Math.random());
                }
            }
            else if (msgType.includes('sync')) {
                // 干扰同步消息
                if (content.events && Array.isArray(content.events)) {
                    // 随机删除一些事件
                    if (content.events.length > 0) {
                        const idx = Math.floor(Math.random() * content.events.length);
                        content.events.splice(idx, 1);
                    }
                }
            }
        }

        // LibraBFT特定攻击
        else if (msgType.includes('libra')) {
            if (content.block) {
                content.block.author = Math.floor(Math.random() * this.nodeNum) + 1;
            }
        }

        // Async-BA特定攻击
        else if (msgType.includes('async') || msgType.includes('ba-')) {
            if (content.value !== undefined) {
                // 随机翻转值（对于二进制共识）
                if (typeof content.value === 'boolean') {
                    content.value = !content.value;
                } else if (typeof content.value === 'number' && (content.value === 0 || content.value === 1)) {
                    content.value = 1 - content.value;
                }
            }
        }
    }

    // 通用消息篡改
    corruptMessage(obj) {
        if (!obj || typeof obj !== 'object') return;

        // 处理数组
        if (Array.isArray(obj)) {
            // 对数组中的每个元素递归调用
            for (let i = 0; i < obj.length; i++) {
                if (typeof obj[i] === 'object' && obj[i] !== null) {
                    this.corruptMessage(obj[i]);
                }
            }
            return;
        }

        // 处理对象

        // 1. 篡改顺序相关字段
        this.corruptOrderingFields(obj);

        // 2. 篡改哈希/签名字段
        this.corruptHashFields(obj);

        // 3. 篡改关键嵌套对象
        for (const key in obj) {
            if (obj[key] && typeof obj[key] === 'object') {
                // 对特殊对象进行处理
                if (key === 'event' || key === 'block' || key === 'vote' ||
                    key === 'message' || key === 'proposal' || key === 'qc') {
                    this.corruptSpecificObject(key, obj[key]);
                }

                // 递归处理所有嵌套对象
                this.corruptMessage(obj[key]);
            }
        }
    }

    // 篡改特定类型的嵌套对象
    corruptSpecificObject(type, obj) {
        if (!obj || typeof obj !== 'object') return;

        switch (type) {
            case 'event':
                // 针对事件的特殊处理
                if (obj.selfParent && Math.random() < 0.7) {
                    obj.selfParent = null;  // 高概率破坏事件链
                }
                if (obj.otherParent && Math.random() < 0.7) {
                    obj.otherParent = "fake_" + Math.random().toString(36).substring(2, 10);
                }
                if (obj.transactions && Array.isArray(obj.transactions)) {
                    obj.transactions.push("INJECTED_" + Math.random().toString(36).substring(2, 10));
                }
                break;

            case 'block':
                // 针对区块的特殊处理
                if (obj.prevHash && Math.random() < 0.6) {
                    obj.prevHash = "modified_" + Math.random().toString(36).substring(2, 10);
                }
                break;

            case 'vote':
            case 'proposal':
                // 针对投票和提议的特殊处理
                if (obj.value !== undefined && Math.random() < 0.8) {
                    if (typeof obj.value === 'boolean') {
                        obj.value = !obj.value;
                    } else if (typeof obj.value === 'string') {
                        obj.value = "corrupted_" + Math.random().toString(36).substring(2, 10);
                    }
                }
                break;
        }
    }

    // 篡改顺序相关字段（轮次、视图号、序列号等）
    corruptOrderingFields(obj) {
        const orderFields = ['round', 'sequence', 'view', 'index', 'height', 'term', 'epoch'];

        for (const field of orderFields) {
            if (obj[field] !== undefined) {
                // 80%概率篡改这些字段
                if (Math.random() < 0.8) {
                    // 大幅修改数值
                    const change = Math.floor(Math.random() * 10) - 3; // -3到+6的变化
                    obj[field] += change;
                    if (obj[field] < 0) obj[field] = 0;
                }
            }
        }
    }

    // 篡改哈希和签名字段
    corruptHashFields(obj) {
        const hashFields = ['hash', 'signature', 'digest', 'id', 'prevHash'];

        for (const field of hashFields) {
            if (obj[field] && typeof obj[field] === 'string' && obj[field].length > 5) {
                // 90%概率篡改这些字段
                if (Math.random() < 0.9) {
                    // 完全替换哈希/签名
                    obj[field] = `malicious_${Math.random().toString(36).substring(2, 15)}`;
                }
            }
        }
    }

    // 处理定时事件
    onTimeEvent(event) {
        if (event.functionMeta.name === 'adjustAttackIntensity') {
            // 加强攻击强度
            this.intensityFactor = Math.min(2.0, this.intensityFactor + 0.2);
            this.dropRate = Math.min(0.5, this.dropRate + 0.05);

            //console.log(`调整攻击强度：intensity=${this.intensityFactor}, dropRate=${this.dropRate}`);

            // 注册下一次调整
            this.registerAttackerTimeEvent(
                { name: 'adjustAttackIntensity' },
                8000 + Math.floor(Math.random() * 4000) // 8-12秒随机间隔
            );
        }
    }

    // 更新参数
    updateParam() {
        return false;  // 不需要额外的参数更新
    }
}


module.exports = SyncInterferenceAttacker;
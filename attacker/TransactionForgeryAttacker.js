'use strict';

/**
 * TransactionForgeryAttacker
 * 此攻击者在分布式账本中篡改或伪造交易记录
 * 主要针对babble协议中的区块和交易数据
 */
class TransactionForgeryAttacker {
    constructor(transfer, registerAttackerTimeEvent, eventQ, nodeNum, byzantineNodeNum, getClockTime) {
        this.transfer = transfer;
        this.registerAttackerTimeEvent = registerAttackerTimeEvent;
        this.eventQ = eventQ;
        this.nodeNum = nodeNum;
        this.byzantineNodeNum = byzantineNodeNum;
        this.getClockTime = getClockTime;

        // 攻击参数
        this.forgeryRate = 0.35;       // 伪造交易的概率
        this.targetNodeIDs = new Set(); // 目标节点

        // 初始化目标节点（随机选择一些非拜占庭节点作为攻击目标）
        const correctNodeNum = this.nodeNum - this.byzantineNodeNum;
        const targetNum = Math.min(Math.ceil(correctNodeNum * 0.4), 5); // 最多选择5个目标

        while (this.targetNodeIDs.size < targetNum) {
            const nodeID = Math.floor(Math.random() * correctNodeNum) + 1;
            this.targetNodeIDs.add(nodeID.toString());
        }

        console.log(`Transaction forgery attacker targeting nodes: ${Array.from(this.targetNodeIDs)}`);
    }

    attack(packets) {
        return packets.map(packet => {
            // 只处理有内容的数据包
            if (!packet.content) return packet;

            // 对区块和交易进行篡改
            if (packet.content.type === 'babble-block' && Math.random() < this.forgeryRate) {
                this.forgeBlockTransactions(packet);
            }
            else if (packet.content.type === 'babble-event' && Math.random() < this.forgeryRate / 2) {
                this.forgeEventTransactions(packet);
            }

            return packet;
        });
    }

    forgeBlockTransactions(packet) {
        const block = packet.content.block;
        if (!block || !block.transactions || block.transactions.length === 0) return;

        // 修改区块中的交易数据
        const transactionCount = block.transactions.length;
        const forgeCount = Math.min(Math.ceil(transactionCount * 0.2), 3); // 最多篡改3笔交易

        for (let i = 0; i < forgeCount; i++) {
            const idx = Math.floor(Math.random() * transactionCount);
            // 替换为伪造的交易
            block.transactions[idx] = `FORGED_TX_${this.getClockTime()}_${Math.random().toString(36).substring(2, 9)}`;
        }

        // 重新计算区块哈希以使其看起来有效
        if (block.hash) {
            block.hash = `forged_hash_${Math.random().toString(36).substring(2, 15)}`;
        }
    }

    forgeEventTransactions(packet) {
        const event = packet.content.event;
        if (!event || !event.transactions) return;

        // 伪造事件中的交易
        if (event.transactions.length > 0) {
            // 替换或添加伪造交易
            event.transactions = [
                ...event.transactions,
                `INJECT_FORGED_${this.getClockTime()}_${Math.random().toString(36).substring(2, 7)}`
            ];
        } else {
            // 如果没有交易，添加伪造交易
            event.transactions = [`INJECT_FORGED_${this.getClockTime()}_${Math.random().toString(36).substring(2, 7)}`];
        }

        // 更新事件哈希
        if (event.hash) {
            event.hash = `forged_event_${Math.random().toString(36).substring(2, 15)}`;
        }
    }

    onTimeEvent(event) {
        // 可以在这里实现定时攻击逻辑
    }

    updateParam() {
        return false; // 不更新参数
    }
}

module.exports = TransactionForgeryAttacker;
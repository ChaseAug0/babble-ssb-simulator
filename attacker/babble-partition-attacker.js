'use strict';

class BabblePartitionAttacker {
    attack(packets) {
        // 模拟网络分区 - 将网络分成两个不相交的部分
        return packets.filter(packet => {
            const srcGroup = parseInt(packet.src) % 2;
            const dstGroup = parseInt(packet.dst) % 2;

            // 只允许同一分区内的节点通信
            if (this.partitionActive && srcGroup !== dstGroup) {
                // 丢弃跨分区的消息
                return false;
            }

            return true;
        });
    }

    onTimeEvent(event) {
        // 切换分区状态
        this.partitionActive = !this.partitionActive;
        this.registerAttackerTimeEvent(
            { name: 'togglePartition' },
            this.partitionDuration * 1000
        );
    }

    updateParam() {
        return false;
    }

    constructor(transfer, registerAttackerTimeEvent, eventQ, nodeNum, byzantineNodeNum, getClockTime) {
        this.transfer = transfer;
        this.registerAttackerTimeEvent = registerAttackerTimeEvent;
        this.eventQ = eventQ;
        this.nodeNum = nodeNum;
        this.byzantineNodeNum = byzantineNodeNum;
        this.getClockTime = getClockTime;

        // 分区相关
        this.partitionActive = false;
        this.partitionDuration = 5; // 5秒

        // 开始分区切换
        this.registerAttackerTimeEvent(
            { name: 'togglePartition' },
            this.partitionDuration * 1000
        );
    }
}

module.exports = BabblePartitionAttacker;
'use strict';

const config = require('../config');

class FailStopAttacker {
    constructor(transfer, registerTimeEvent, eventQ, nodeNum, byzantineNodeNum, getClockTime) {
        this.transfer = transfer;
        this.registerTimeEvent = registerTimeEvent;
        this.getClockTime = getClockTime;
        this.nodeNum = nodeNum;
        this.byzantineNodeNum = byzantineNodeNum;

        // 设置失效节点
        this.failedNodes = new Set();

        // 设置失效时间（秒）- 可以根据需要调整
        this.failTime = 0.5;

        this.nodesToFail = Math.min(byzantineNodeNum, Math.floor(nodeNum / 4));
        this.failuresPerRound = Math.max(1, Math.floor(this.nodesToFail / 5));
        this.failedCount = 0;

        // Register first round of failures
        this.registerTimeEvent(
            { name: 'triggerFailures' },
            this.failTime * 1000
        );
    }

    updateParam() {
        // 重置失效节点集合
        this.failedNodes.clear();
        return false;
    }

    attack(packets) {
        // Allow view change messages to pass through even for failed nodes
        return packets.filter(packet => {
            const isViewChangeMsg = packet.content &&
                (packet.content.type === 'view-change' ||
                    packet.content.type === 'new-view');

            // Allow view change messages to pass, filter others from failed nodes
            return isViewChangeMsg ||
                (!this.failedNodes.has(packet.src) && !this.failedNodes.has(packet.dst));
        });
    }

    onTimeEvent(event) {
        if (event.functionMeta.name === 'triggerFailures') {
            // Fail a subset of nodes at a time
            const startIdx = this.failedCount + 1;
            const endIdx = Math.min(startIdx + this.failuresPerRound - 1, this.nodesToFail);

            for (let i = startIdx; i <= endIdx; i++) {
                this.failedNodes.add('' + i);
            }

            this.failedCount = endIdx;
            console.log(`Nodes ${Array.from(this.failedNodes).join(', ')} have failed at time ${this.getClockTime()}`);

            // Schedule next round of failures if more nodes need to fail
            if (this.failedCount < this.nodesToFail) {
                this.registerTimeEvent(
                    { name: 'triggerFailures' },
                    this.failTime * 1000
                );
            }
        }
    }

    send() {
        // 不需要实现
    }

    onMsgEvent() {
        // 不需要实现
    }
}

module.exports = FailStopAttacker;
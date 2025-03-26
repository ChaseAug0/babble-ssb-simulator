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
        this.failTime = 10;

        // 注册失效事件
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
        // 过滤掉来自失效节点或发往失效节点的数据包
        return packets.filter(packet =>
            !this.failedNodes.has(packet.src) && !this.failedNodes.has(packet.dst)
        );
    }

    onTimeEvent(event) {
        if (event.functionMeta.name === 'triggerFailures') {
            // 选择 byzantineNodeNum 个节点失效
            for (let i = 1; i <= this.byzantineNodeNum; i++) {
                this.failedNodes.add('' + i);
            }
            console.log(`Nodes ${Array.from(this.failedNodes).join(', ')} have failed at time ${this.getClockTime()}`);
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
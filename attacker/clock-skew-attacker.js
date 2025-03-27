'use strict';

/**
 * ClockSkewAttacker
 * 此攻击者通过操纵时间戳和时钟信息干扰共识
 * 在依赖事件顺序和时间戳的系统中特别有效
 */
class ClockSkewAttacker {
    constructor(transfer, registerAttackerTimeEvent, eventQ, nodeNum, byzantineNodeNum, getClockTime) {
        this.transfer = transfer;
        this.registerAttackerTimeEvent = registerAttackerTimeEvent;
        this.eventQ = eventQ;
        this.nodeNum = nodeNum;
        this.byzantineNodeNum = byzantineNodeNum;
        this.getClockTime = getClockTime;

        // 攻击参数
        this.timestampManipulationRate = 0.4;  // 时间戳篡改概率
        this.maxTimeSkew = 5;                  // 最大时间偏移（秒）
        this.targetCriticalEvents = true;      // 是否针对关键事件（轮次结束等）

        // 记录观察到的时间戳范围
        this.observedTimestamps = {
            min: Infinity,
            max: -Infinity,
            avg: 0,
            count: 0
        };

        // 开始周期性变更时钟攻击策略
        this.registerAttackerTimeEvent(
            { name: 'changeClockStrategy' },
            10000 // 10秒后改变策略
        );
    }

    attack(packets) {
        this.updateObservedTimestamps(packets);

        return packets.map(packet => {
            if (!packet.content) return packet;

            // 处理不同类型的消息
            if (packet.content.type === 'babble-event') {
                this.manipulateEventTimestamp(packet);
            }
            else if (packet.content.type === 'babble-block') {
                this.manipulateBlockTimestamp(packet);
            }
            else if (packet.content.type === 'ssb-message') {
                this.manipulateSSBTimestamp(packet);
            }

            return packet;
        });
    }

    updateObservedTimestamps(packets) {
        // 收集观察到的时间戳信息，用于更精确的攻击
        for (const packet of packets) {
            if (!packet.content) continue;

            let timestamp = null;

            if (packet.content.type === 'babble-event' && packet.content.event) {
                timestamp = packet.content.event.timestamp;
            }
            else if (packet.content.type === 'babble-block' && packet.content.block) {
                timestamp = packet.content.block.timestamp;
            }
            else if (packet.content.type === 'ssb-message' && packet.content.message) {
                timestamp = packet.content.message.timestamp;
            }

            if (timestamp !== null && timestamp !== undefined) {
                this.observedTimestamps.min = Math.min(this.observedTimestamps.min, timestamp);
                this.observedTimestamps.max = Math.max(this.observedTimestamps.max, timestamp);
                this.observedTimestamps.avg = (this.observedTimestamps.avg * this.observedTimestamps.count + timestamp) /
                    (this.observedTimestamps.count + 1);
                this.observedTimestamps.count++;
            }
        }
    }

    manipulateEventTimestamp(packet) {
        const event = packet.content.event;
        if (!event || event.timestamp === undefined) return;

        // 判断是否是关键事件（如新轮次开始的见证事件）
        const isCriticalEvent = this.targetCriticalEvents &&
            ((event.isWitness === true) ||
                (event.round !== undefined && event.round > 0));

        // 对关键事件有更高概率篡改
        const manipulationRate = isCriticalEvent ?
            this.timestampManipulationRate * 1.5 :
            this.timestampManipulationRate;

        if (Math.random() < manipulationRate) {
            // 计算时间偏移
            let timeSkew;

            if (Math.random() < 0.6) {
                // 将时间戳调整到比当前时间更远的"未来"
                timeSkew = Math.random() * this.maxTimeSkew;
            } else {
                // 将时间戳调整到"过去"
                timeSkew = -Math.random() * this.maxTimeSkew;
            }

            // 调整时间戳
            event.timestamp += timeSkew;

            // 如果是轮次事件，可能同时调整轮次
            if (isCriticalEvent && event.round !== undefined && Math.random() < 0.3) {
                // 有时调整轮次以与时间戳变化一致
                const roundSkew = timeSkew > 0 ? 1 : -1;
                event.round = Math.max(0, event.round + roundSkew);
            }
        }
    }

    manipulateBlockTimestamp(packet) {
        const block = packet.content.block;
        if (!block || block.timestamp === undefined) return;

        if (Math.random() < this.timestampManipulationRate) {
            // 区块时间戳篡改可能会破坏区块顺序关系
            const timeSkew = (Math.random() * 2 - 1) * this.maxTimeSkew; // 正负偏移
            block.timestamp += timeSkew;

            // 如果篡改了时间戳，可能需要重新计算区块哈希
            if (block.hash) {
                block.hash = `modified_${Math.random().toString(36).substring(2, 15)}`;
            }
        }
    }

    manipulateSSBTimestamp(packet) {
        const message = packet.content.message;
        if (!message || message.timestamp === undefined) return;

        if (Math.random() < this.timestampManipulationRate * 0.8) { // 稍低的概率
            // SSB消息时间戳篡改
            const timeSkew = (Math.random() * 2 - 1) * this.maxTimeSkew; // 正负偏移
            message.timestamp += timeSkew;
        }
    }

    onTimeEvent(event) {
        if (event.functionMeta.name === 'changeClockStrategy') {
            // 根据观察到的系统状态动态调整攻击策略

            // 调整最大时间偏移
            if (this.observedTimestamps.count > 0) {
                // 计算系统时间跨度
                const timespan = this.observedTimestamps.max - this.observedTimestamps.min;

                if (timespan > 0) {
                    // 根据观察到的时间跨度调整偏移量
                    this.maxTimeSkew = Math.min(10, Math.max(2, timespan * 0.2));
                }
            }

            // 调整攻击概率
            if (Math.random() < 0.5) {
                // 随机增减攻击概率
                this.timestampManipulationRate += (Math.random() * 0.2 - 0.1);
                // 限制在合理范围内
                this.timestampManipulationRate = Math.min(0.7, Math.max(0.2, this.timestampManipulationRate));
            }

            // 切换是否针对关键事件
            if (Math.random() < 0.3) {
                this.targetCriticalEvents = !this.targetCriticalEvents;
            }

            console.log(`Changed clock attack strategy: maxSkew=${this.maxTimeSkew}, rate=${this.timestampManipulationRate}, targetCritical=${this.targetCriticalEvents}`);

            // 再次注册，保持周期性变更
            this.registerAttackerTimeEvent(
                { name: 'changeClockStrategy' },
                15000 // 15秒后再次改变
            );
        }
    }

    updateParam() {
        return false; // 不更新参数
    }
}

module.exports = ClockSkewAttacker;
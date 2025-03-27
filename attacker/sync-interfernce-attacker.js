'use strict';

/**
 * SyncInterferenceAttacker
 * 此攻击者干扰数据同步过程，篡改同步数据或同步请求/响应
 * 特别针对节点间的状态同步和检查点(checkpoint)同步
 */
class SyncInterferenceAttacker {
    constructor(transfer, registerAttackerTimeEvent, eventQ, nodeNum, byzantineNodeNum, getClockTime) {
        this.transfer = transfer;
        this.registerAttackerTimeEvent = registerAttackerTimeEvent;
        this.eventQ = eventQ;
        this.nodeNum = nodeNum;
        this.byzantineNodeNum = byzantineNodeNum;
        this.getClockTime = getClockTime;

        // 攻击参数
        this.syncRequestInterferenceRate = 0.3;  // 同步请求干扰概率
        this.syncResponseInterferenceRate = 0.5; // 同步响应干扰概率（更高，因为影响更大）
        this.corruptEventRate = 0.4;            // 事件内容损坏概率

        // 保存节点状态信息
        this.nodeStates = {};
        this.lastSyncRequestTimes = {};

        // 开始周期性攻击
        this.registerAttackerTimeEvent(
            { name: 'intensifySyncAttack' },
            10000 // 10秒后加强攻击
        );
    }

    attack(packets) {
        return packets.map(packet => {
            if (!packet.content) return packet;

            const msgType = packet.content.type;
            const src = packet.src;
            const dst = packet.dst;

            // 更新节点状态信息
            this.trackNodeState(packet);

            // 处理同步请求
            if (msgType === 'babble-sync-request') {
                if (Math.random() < this.syncRequestInterferenceRate) {
                    this.interfereSyncRequest(packet);
                }
            }
            // 处理同步响应
            else if (msgType === 'babble-sync-response') {
                if (Math.random() < this.syncResponseInterferenceRate) {
                    this.interfereSyncResponse(packet);
                }
            }
            // 干扰SSB同步
            else if (msgType === 'ssb-sync-request' || msgType === 'ssb-sync-response') {
                if (Math.random() < this.syncRequestInterferenceRate) {
                    this.interfereSSBSync(packet);
                }
            }

            return packet;
        });
    }

    trackNodeState(packet) {
        const src = packet.src;

        // 初始化源节点的状态
        if (!this.nodeStates[src]) {
            this.nodeStates[src] = {
                lastSeenTime: this.getClockTime(),
                events: new Set(),
                knownRound: 0
            };
        }

        // 更新最后活跃时间
        this.nodeStates[src].lastSeenTime = this.getClockTime();

        // 记录同步请求时间
        if (packet.content && packet.content.type === 'babble-sync-request') {
            this.lastSyncRequestTimes[src] = this.getClockTime();
        }

        // 记录节点知道的轮次
        if (packet.content && packet.content.type === 'babble-event' &&
            packet.content.event && packet.content.event.round !== undefined) {
            this.nodeStates[src].knownRound = Math.max(
                this.nodeStates[src].knownRound,
                packet.content.event.round
            );
        }
    }

    interfereSyncRequest(packet) {
        const request = packet.content;

        // 如果有已知事件信息，篡改它
        if (request.knownEvents) {
            for (const nodeID in request.knownEvents) {
                // 随机将一些已知事件设为null或修改为随机值
                if (Math.random() < 0.4) {
                    if (Math.random() < 0.5) {
                        request.knownEvents[nodeID] = null;
                    } else {
                        request.knownEvents[nodeID] = `fake_event_${Math.random().toString(36).substring(2, 10)}`;
                    }
                }
            }
        }
    }

    interfereSyncResponse(packet) {
        const response = packet.content;

        // 干扰同步响应中的事件
        if (response.events && response.events.length > 0) {
            const eventCount = response.events.length;

            // 选择性删除一些事件
            if (eventCount > 3 && Math.random() < 0.3) {
                const removeCount = Math.floor(eventCount * 0.3); // 删除约30%
                for (let i = 0; i < removeCount; i++) {
                    const idx = Math.floor(Math.random() * response.events.length);
                    response.events.splice(idx, 1);
                }
            }

            // 篡改部分事件的内容
            for (let i = 0; i < response.events.length; i++) {
                if (Math.random() < this.corruptEventRate) {
                    const event = response.events[i];

                    // 破坏事件的关键部分
                    if (event.selfParent && Math.random() < 0.5) {
                        event.selfParent = null; // 破坏事件链
                    }

                    if (event.round !== undefined && Math.random() < 0.4) {
                        // 修改事件的轮次
                        event.round = Math.max(0, event.round + Math.floor(Math.random() * 5) - 2);
                    }

                    // 更新事件哈希以使其看起来有效
                    if (event.hash) {
                        event.hash = `tampered_${Math.random().toString(36).substring(2, 15)}`;
                    }
                }
            }
        }
    }

    interfereSSBSync(packet) {
        if (packet.content.type === 'ssb-sync-request') {
            // 修改请求的起始序列号
            if (packet.content.fromSequence !== undefined) {
                // 随机调整序列号，可能导致节点错过某些消息
                packet.content.fromSequence += Math.floor(Math.random() * 5);
                if (packet.content.fromSequence < 0) packet.content.fromSequence = 0;
            }
        }
        else if (packet.content.type === 'ssb-sync-response') {
            // 篡改响应中的消息
            if (packet.content.messages && packet.content.messages.length > 0) {
                // 随机删除一些消息
                if (packet.content.messages.length > 2 && Math.random() < 0.3) {
                    const idx = Math.floor(Math.random() * packet.content.messages.length);
                    packet.content.messages.splice(idx, 1);
                }

                // 篡改部分消息内容
                for (let i = 0; i < packet.content.messages.length; i++) {
                    if (Math.random() < 0.4) {
                        const message = packet.content.messages[i];
                        // 修改序列号或引用
                        if (message.sequence !== undefined) {
                            message.sequence += Math.floor(Math.random() * 3) - 1;
                            if (message.sequence < 1) message.sequence = 1;
                        }
                    }
                }
            }
        }
    }

    onTimeEvent(event) {
        if (event.functionMeta.name === 'intensifySyncAttack') {
            // 加强攻击强度
            this.syncResponseInterferenceRate = Math.min(0.7, this.syncResponseInterferenceRate + 0.2);
            this.corruptEventRate = Math.min(0.6, this.corruptEventRate + 0.2);

            console.log(`Intensifying sync attack: response rate=${this.syncResponseInterferenceRate}, corrupt rate=${this.corruptEventRate}`);

            // 再次注册，保持周期性攻击
            this.registerAttackerTimeEvent(
                { name: 'intensifySyncAttack' },
                15000 // 15秒后再次加强
            );
        }
    }

    updateParam() {
        return false; // 不更新参数
    }
}

module.exports = SyncInterferenceAttacker;
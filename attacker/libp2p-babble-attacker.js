'use strict';

/**
 * libp2p-Babble 共识协议攻击者
 * 结合多种攻击策略针对共识过程
 */
// class Libp2pBabbleAttacker {
//     constructor(transfer, registerAttackerTimeEvent, eventQ, nodeNum, byzantineNodeNum, getClockTime) {
//         this.transfer = transfer;
//         this.registerAttackerTimeEvent = registerAttackerTimeEvent;
//         this.eventQ = eventQ;
//         this.nodeNum = nodeNum;
//         this.byzantineNodeNum = byzantineNodeNum;
//         this.getClockTime = getClockTime;

//         // 攻击配置
//         this.attackMode = 'adaptive';  // 可选: 'event-tampering', 'network-partition', 'eclipse', 'adaptive'
//         this.attackIntensity = 0.5;    // 0-1范围，数值越高攻击越强
//         this.currentPhase = 0;         // 当前攻击阶段

//         // 分区攻击状态
//         this.partitionActive = false;
//         this.partitionGroups = this._createPartitions();
//         this.partitionDuration = 8;    // 分区持续时间（秒）

//         // 节点信息跟踪
//         this.nodeTracker = {};
//         for (let i = 1; i <= this.nodeNum; i++) {
//             this.nodeTracker[i] = {
//                 lastSeen: 0,
//                 messageCount: 0,
//                 events: new Set(),
//                 blocks: new Set()
//             };
//         }

//         // 注册初始分区切换
//         this.registerAttackerTimeEvent(
//             { name: 'togglePartition' },
//             this.partitionDuration * 1000
//         );

//         // 自适应攻击的切换间隔
//         this.registerAttackerTimeEvent(
//             { name: 'nextAttackPhase' },
//             15 * 1000  // 每15秒切换一次攻击阶段
//         );

//         console.log(`[Attacker] Initialized in '${this.attackMode}' mode with intensity ${this.attackIntensity}`);
//     }

//     /**
//      * 主要攻击方法 - 拦截并可能修改网络包
//      */
//     attack(packets) {
//         // 更新节点跟踪信息
//         this._updateNodeTracker(packets);

//         // 根据当前攻击模式执行相应攻击
//         switch (this.attackMode) {
//             case 'event-tampering':
//                 return this._eventTamperingAttack(packets);
//             case 'network-partition':
//                 return this._networkPartitionAttack(packets);
//             case 'eclipse':
//                 return this._eclipseAttack(packets);
//             case 'adaptive':
//             default:
//                 return this._adaptiveAttack(packets);
//         }
//     }

//     /**
//      * 处理时间事件
//      */
//     onTimeEvent(event) {
//         const functionMeta = event.functionMeta;

//         if (functionMeta.name === 'togglePartition') {
//             // 切换分区状态
//             this.partitionActive = !this.partitionActive;
//             console.log(`[Attacker] Network partition ${this.partitionActive ? 'activated' : 'deactivated'}`);

//             // 安排下一次切换
//             this.registerAttackerTimeEvent(
//                 { name: 'togglePartition' },
//                 this.partitionDuration * 1000
//             );
//         }
//         else if (functionMeta.name === 'nextAttackPhase') {
//             // 切换到下一个攻击阶段
//             this.currentPhase = (this.currentPhase + 1) % 4;
//             console.log(`[Attacker] Switching to attack phase ${this.currentPhase}`);

//             // 安排下一次切换
//             this.registerAttackerTimeEvent(
//                 { name: 'nextAttackPhase' },
//                 15 * 1000
//             );
//         }
//     }

//     /**
//      * 更新节点跟踪信息
//      */
//     _updateNodeTracker(packets) {
//         for (const packet of packets) {
//             const src = parseInt(packet.src);
//             if (!isNaN(src) && src >= 1 && src <= this.nodeNum) {
//                 const tracker = this.nodeTracker[src];
//                 tracker.lastSeen = this.getClockTime();
//                 tracker.messageCount++;

//                 // 跟踪事件和区块
//                 if (packet.content) {
//                     if (packet.content.type === 'babble-event' && packet.content.event) {
//                         tracker.events.add(packet.content.event.hash);
//                     }
//                     else if (packet.content.type === 'babble-block' && packet.content.block) {
//                         tracker.blocks.add(packet.content.block.hash);
//                     }
//                     else if (packet.content.type === 'libp2p-gossip' && packet.content.data) {
//                         if (packet.content.data.type === 'babble-event' && packet.content.data.event) {
//                             tracker.events.add(packet.content.data.event.hash);
//                         }
//                         else if (packet.content.data.type === 'babble-block' && packet.content.data.block) {
//                             tracker.blocks.add(packet.content.data.block.hash);
//                         }
//                     }
//                 }
//             }
//         }
//     }

//     /**
//      * 事件篡改攻击 - 修改事件内容
//      */
//     _eventTamperingAttack(packets) {
//         return packets.map(packet => {
//             // 根据攻击强度决定篡改概率
//             if (Math.random() >= this.attackIntensity) {
//                 return packet; // 不篡改这个包
//             }

//             // 篡改 Babble 事件
//             if (packet.content && packet.content.type === 'babble-event') {
//                 const event = packet.content.event;
//                 if (event) {
//                     this._tamperEvent(event);
//                     console.log(`[Attacker] Tampered with event from ${packet.src}`);
//                 }
//             }
//             // 篡改 libp2p 封装的 Babble 事件
//             else if (packet.content &&
//                 packet.content.type === 'libp2p-gossip' &&
//                 packet.content.data &&
//                 packet.content.data.type === 'babble-event') {
//                 const event = packet.content.data.event;
//                 if (event) {
//                     this._tamperEvent(event);
//                     console.log(`[Attacker] Tampered with gossip event from ${packet.src}`);
//                 }
//             }

//             return packet;
//         });
//     }

//     /**
//      * 篡改单个事件
//      */
//     _tamperEvent(event) {
//         const tamperType = Math.floor(Math.random() * 3);

//         switch (tamperType) {
//             case 0:
//                 // 破坏事件链 - 设置无效的父事件
//                 event.selfParent = `invalid_parent_${Math.random()}`;
//                 break;
//             case 1:
//                 // 注入恶意交易
//                 event.transactions = [`MALICIOUS_TX_${Math.random()}`];
//                 break;
//             case 2:
//                 // 修改时间戳
//                 event.timestamp = event.timestamp - 10000 * Math.random();
//                 break;
//         }

//         // 重新计算/篡改哈希
//         event.hash = `tampered_${event.hash}_${Math.random()}`;
//     }

//     /**
//      * 网络分区攻击 - 将网络分割成隔离组
//      */
//     _networkPartitionAttack(packets) {
//         if (!this.partitionActive) {
//             return packets; // 分区未激活
//         }

//         // 过滤包，实现网络分区
//         return packets.filter(packet => {
//             if (!packet.src || !packet.dst || packet.dst === 'broadcast') {
//                 return true; // 保留广播和无明确src/dst的消息
//             }

//             const srcGroup = this._getNodeGroup(packet.src);
//             const dstGroup = this._getNodeGroup(packet.dst);

//             // 只允许同一组内的通信
//             const allowMessage = srcGroup === dstGroup;

//             if (!allowMessage) {
//                 console.log(`[Attacker] Dropped message from ${packet.src} (group ${srcGroup}) to ${packet.dst} (group ${dstGroup})`);
//             }

//             return allowMessage;
//         });
//     }

//     /**
//      * 日蚀攻击 - 对目标节点进行隔离
//      */
//     _eclipseAttack(packets) {
//         // 找出最活跃的节点（发送消息最多的）
//         const activeNodes = Object.entries(this.nodeTracker)
//             .sort((a, b) => b[1].messageCount - a[1].messageCount)
//             .slice(0, Math.ceil(this.nodeNum * 0.2)) // 取前20%最活跃的节点
//             .map(entry => entry[0]);

//         // 过滤包，隔离活跃节点
//         return packets.filter(packet => {
//             // 如果发送者或接收者是目标节点之一
//             if (activeNodes.includes(packet.src) || activeNodes.includes(packet.dst)) {
//                 // 根据攻击强度决定是否丢弃
//                 if (Math.random() < this.attackIntensity) {
//                     console.log(`[Attacker] Eclipse attack: Dropped message between ${packet.src} and ${packet.dst}`);
//                     return false;
//                 }
//             }
//             return true;
//         });
//     }

//     /**
//      * 自适应攻击 - 根据当前阶段选择不同攻击策略
//      */
//     _adaptiveAttack(packets) {
//         switch (this.currentPhase) {
//             case 0:
//                 // 事件篡改阶段
//                 return this._eventTamperingAttack(packets);
//             case 1:
//                 // 网络分区阶段
//                 return this._networkPartitionAttack(packets);
//             case 2:
//                 // 日蚀攻击阶段
//                 return this._eclipseAttack(packets);
//             case 3:
//                 // 混合攻击阶段 - 结合多种攻击
//                 let modifiedPackets = packets;

//                 // 先应用事件篡改
//                 if (Math.random() < 0.3) {
//                     modifiedPackets = this._eventTamperingAttack(modifiedPackets);
//                 }

//                 // 再应用网络分区
//                 if (this.partitionActive && Math.random() < 0.3) {
//                     modifiedPackets = this._networkPartitionAttack(modifiedPackets);
//                 }

//                 // 最后应用日蚀攻击
//                 if (Math.random() < 0.3) {
//                     modifiedPackets = this._eclipseAttack(modifiedPackets);
//                 }

//                 return modifiedPackets;
//         }

//         return packets; // 默认情况下不修改
//     }

//     /**
//      * 获取节点所在分组
//      */
//     _getNodeGroup(nodeId) {
//         const id = parseInt(nodeId);
//         if (isNaN(id)) return 0;

//         // 检查节点属于哪个分区组
//         for (let i = 0; i < this.partitionGroups.length; i++) {
//             if (this.partitionGroups[i].has(id)) {
//                 return i;
//             }
//         }

//         return 0; // 默认组
//     }

//     /**
//      * 创建网络分区组
//      */
//     _createPartitions() {
//         const numGroups = 2;  // 分成2组
//         const groups = [];

//         for (let i = 0; i < numGroups; i++) {
//             groups.push(new Set());
//         }

//         // 将节点分配到组
//         for (let i = 1; i <= this.nodeNum; i++) {
//             const groupIndex = i % numGroups;
//             groups[groupIndex].add(i);
//         }

//         return groups;
//     }

//     /**
//      * 更新参数
//      * 在模拟运行之间可更新攻击参数
//      */
//     updateParam() {
//         // 可以在这里循环切换攻击模式或强度
//         // 以实现不同运行之间的变化

//         // 示例：每次运行增加攻击强度
//         this.attackIntensity = Math.min(0.9, this.attackIntensity + 0.1);
//         console.log(`[Attacker] Updated attack intensity to ${this.attackIntensity}`);

//         return true; // 返回true表示参数已更新
//     }
// }

// module.exports = Libp2pBabbleAttacker;

'use strict';

class Libp2pBabbleAttacker {
    constructor(transfer, registerAttackerTimeEvent, eventQ, nodeNum, byzantineNodeNum, getClockTime) {
        this.transfer = transfer;
        this.registerAttackerTimeEvent = registerAttackerTimeEvent;
        this.eventQ = eventQ;
        this.nodeNum = nodeNum;
        this.byzantineNodeNum = byzantineNodeNum;
        this.getClockTime = getClockTime;

        // 攻击配置
        this.attackIntensity = 0.3;     // 初始攻击强度
        this.attackMode = 'adaptive';   // 可选: 'tamper', 'partition', 'eclipse', 'adaptive'
        this.currentPhase = 0;          // 当前攻击阶段

        // 分区攻击状态
        this.partitionActive = false;
        this.partitionGroups = this._createPartitions();
        this.partitionDuration = 6;     // 分区持续时间（秒）

        // 节点跟踪
        this.nodeTracker = {};
        for (let i = 1; i <= this.nodeNum; i++) {
            this.nodeTracker[i] = {
                lastSeen: 0,
                messageCount: 0,
                events: new Set(),
                blocks: new Set()
            };
        }

        // 注册初始攻击阶段切换
        this.registerAttackerTimeEvent(
            { name: 'togglePartition' },
            this.partitionDuration * 1000
        );

        // 注册自适应攻击阶段切换
        this.registerAttackerTimeEvent(
            { name: 'nextAttackPhase' },
            10 * 1000  // 每10秒切换一次攻击阶段
        );

        console.log(`[Attacker] Initialized libp2p-babble attacker with intensity ${this.attackIntensity} in '${this.attackMode}' mode`);
    }

    attack(packets) {
        // 更新节点跟踪信息
        this._updateNodeTracker(packets);

        // 根据当前攻击模式执行攻击
        switch (this.attackMode) {
            case 'tamper':
                return this._eventTamperingAttack(packets);
            case 'partition':
                return this._networkPartitionAttack(packets);
            case 'eclipse':
                return this._eclipseAttack(packets);
            case 'adaptive':
            default:
                return this._adaptiveAttack(packets);
        }
    }

    onTimeEvent(event) {
        const functionMeta = event.functionMeta;

        if (functionMeta.name === 'togglePartition') {
            // 切换分区状态
            this.partitionActive = !this.partitionActive;
            console.log(`[Attacker] Network partition ${this.partitionActive ? 'activated' : 'deactivated'}`);

            // 安排下一次切换
            this.registerAttackerTimeEvent(
                { name: 'togglePartition' },
                this.partitionDuration * 1000
            );
        }
        else if (functionMeta.name === 'nextAttackPhase') {
            // 切换到下一个攻击阶段
            this.currentPhase = (this.currentPhase + 1) % 4;
            console.log(`[Attacker] Switching to attack phase ${this.currentPhase}`);

            // 安排下一次切换
            this.registerAttackerTimeEvent(
                { name: 'nextAttackPhase' },
                10 * 1000
            );
        }
    }

    // 事件篡改攻击 - 针对libp2p-babble
    _eventTamperingAttack(packets) {
        return packets.map(packet => {
            // 根据攻击强度决定攻击概率
            if (Math.random() >= this.attackIntensity) {
                return packet; // 不篡改这个包
            }

            // 篡改Babble事件
            if (packet.content && packet.content.type === 'babble-event') {
                const event = packet.content.event;
                if (event) {
                    this._tamperEvent(event);
                    console.log(`[Attacker] Tampered babble event from ${packet.src}`);
                }
            }
            // 检查libp2p封装格式
            else if (packet.content &&
                (packet.content.type === 'libp2p-gossip' || packet.content.type === 'libp2p-msg') &&
                packet.content.data) {
                if (packet.content.data.type === 'babble-event' && packet.content.data.event) {
                    this._tamperEvent(packet.content.data.event);
                    console.log(`[Attacker] Tampered libp2p encapsulated event from ${packet.src}`);
                }
            }

            return packet;
        });
    }

    // 网络分区攻击 - 将网络分割成不相交的部分
    _networkPartitionAttack(packets) {
        if (!this.partitionActive) {
            return packets;
        }

        // 过滤包，实现网络分区
        return packets.filter(packet => {
            if (!packet.src || !packet.dst || packet.dst === 'broadcast') {
                return Math.random() > 0.7; // 70%概率丢弃广播消息
            }

            const srcGroup = this._getNodeGroup(packet.src);
            const dstGroup = this._getNodeGroup(packet.dst);

            // 只允许同一组内通信
            const allowMessage = srcGroup === dstGroup;

            if (!allowMessage && Math.random() < 0.3) {
                console.log(`[Attacker] Dropped message from ${packet.src} (group ${srcGroup}) to ${packet.dst} (group ${dstGroup})`);
            }

            return allowMessage;
        });
    }

    // 日蚀攻击 - 隔离关键节点
    _eclipseAttack(packets) {
        // 找出最活跃的节点
        const activeNodes = Object.entries(this.nodeTracker)
            .sort((a, b) => b[1].messageCount - a[1].messageCount)
            .slice(0, Math.ceil(this.nodeNum * 0.25)) // 取前25%最活跃节点
            .map(entry => entry[0]);

        // 过滤包，隔离活跃节点
        return packets.filter(packet => {
            // 如果发送者或接收者是目标节点之一
            if (activeNodes.includes(packet.src) || activeNodes.includes(packet.dst)) {
                // 根据攻击强度决定是否丢弃
                if (Math.random() < this.attackIntensity) {
                    return false; // 丢弃消息
                }
            }
            return true;
        });
    }

    // 自适应攻击 - 根据当前阶段选择不同攻击策略
    _adaptiveAttack(packets) {
        switch (this.currentPhase) {
            case 0: // 事件篡改阶段
                return this._eventTamperingAttack(packets);
            case 1: // 网络分区阶段
                return this._networkPartitionAttack(packets);
            case 2: // 日蚀攻击阶段
                return this._eclipseAttack(packets);
            case 3: // 混合攻击阶段
                let modifiedPackets = packets;

                // 先应用事件篡改
                if (Math.random() < 0.3) {
                    modifiedPackets = this._eventTamperingAttack(modifiedPackets);
                }

                // 再应用网络分区
                if (this.partitionActive && Math.random() < 0.3) {
                    modifiedPackets = this._networkPartitionAttack(modifiedPackets);
                }

                // 最后应用日蚀攻击
                if (Math.random() < 0.3) {
                    modifiedPackets = this._eclipseAttack(modifiedPackets);
                }

                return modifiedPackets;
        }

        return packets;
    }

    // 辅助方法：篡改事件
    _tamperEvent(event) {
        const tamperType = Math.floor(Math.random() * 4);

        switch (tamperType) {
            case 0:
                // 破坏事件链 - 设置无效的父事件
                event.selfParent = `invalid_parent_${Math.random()}`;
                break;
            case 1:
                // 注入恶意交易
                event.transactions = [`MALICIOUS_TX_${Math.random()}`];
                break;
            case 2:
                // 修改时间戳
                event.timestamp = event.timestamp - 10000 * Math.random();
                break;
            case 3:
                // 篡改round信息
                if (event.round !== undefined) {
                    event.round = -1; // 强制重新分配轮次
                }
                break;
        }

        // 篡改哈希值以避免被检测
        if (event.hash) {
            // 保留原始哈希的一部分，让其看起来更合法
            const originalPrefix = event.hash.substring(0, 10);
            event.hash = `${originalPrefix}_tampered_${Math.random().toString(36).substring(2, 10)}`;
        }

        // 对签名也做相应修改
        if (event.signature) {
            event.signature = `tampered_sig_${Math.random().toString(36).substring(2, 15)}`;
        }
    }

    // 更新节点跟踪信息
    _updateNodeTracker(packets) {
        for (const packet of packets) {
            const src = parseInt(packet.src);
            if (!isNaN(src) && src >= 1 && src <= this.nodeNum) {
                const tracker = this.nodeTracker[src];
                tracker.lastSeen = this.getClockTime();
                tracker.messageCount++;

                // 跟踪事件和区块
                if (packet.content) {
                    if (packet.content.type === 'babble-event' && packet.content.event) {
                        tracker.events.add(packet.content.event.hash);
                    }
                    else if (packet.content.type === 'babble-block' && packet.content.block) {
                        tracker.blocks.add(packet.content.block.hash);
                    }
                    // 处理libp2p封装消息
                    else if ((packet.content.type === 'libp2p-gossip' || packet.content.type === 'libp2p-msg') &&
                        packet.content.data) {
                        if (packet.content.data.type === 'babble-event' && packet.content.data.event) {
                            tracker.events.add(packet.content.data.event.hash);
                        }
                        else if (packet.content.data.type === 'babble-block' && packet.content.data.block) {
                            tracker.blocks.add(packet.content.data.block.hash);
                        }
                    }
                }
            }
        }
    }

    // 获取节点所在分组
    _getNodeGroup(nodeId) {
        const id = parseInt(nodeId);
        if (isNaN(id)) return 0;

        // 检查节点属于哪个分区组
        for (let i = 0; i < this.partitionGroups.length; i++) {
            if (this.partitionGroups[i].has(id)) {
                return i;
            }
        }

        return 0;
    }

    // 创建网络分区组
    _createPartitions() {
        const numGroups = 2;  // 分成2组
        const groups = [];

        for (let i = 0; i < numGroups; i++) {
            groups.push(new Set());
        }

        // 将节点分配到组
        for (let i = 1; i <= this.nodeNum; i++) {
            const groupIndex = i % numGroups;
            groups[groupIndex].add(i);
        }

        return groups;
    }

    // 每次运行更新参数
    updateParam() {
        // 每次运行增加攻击强度
        this.attackIntensity = Math.min(0.9, this.attackIntensity + 0.05);
        console.log(`[Attacker] Updated attack intensity to ${this.attackIntensity}`);

        return this.attackIntensity < 0.9;  // 当达到最大强度时停止更新
    }
}

module.exports = Libp2pBabbleAttacker;
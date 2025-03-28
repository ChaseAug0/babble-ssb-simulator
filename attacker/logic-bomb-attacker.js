'use strict';

/**
 * MinimalLogicBombAttacker
 * 极其保守的逻辑炸弹攻击器，长期保持诚实，在触发条件达成时进行
 * 最小程度的干扰，避免系统崩溃但仍能展示攻击概念。
 */
class LogicBombAttacker {
    constructor(transfer, registerAttackerTimeEvent, eventQ, nodeNum, byzantineNodeNum, getClockTime) {
        this.transfer = transfer;
        this.registerAttackerTimeEvent = registerAttackerTimeEvent;
        this.eventQ = eventQ;
        this.nodeNum = nodeNum;
        this.byzantineNodeNum = byzantineNodeNum;
        this.getClockTime = getClockTime;

        // 协议检测 - 保持简单
        this.protocolStates = {
            pbft: { detected: false, sequence: 0 },
            hotstuff: { detected: false, view: 0 },
            algorand: { detected: false, round: 0 },
            babble: { detected: false, round: 0 },
            libra: { detected: false, round: 0 },
            asyncBA: { detected: false, round: 0 }
        };

        // 攻击状态 - 默认完全诚实
        this.bombDetonated = false;
        this.explosionInProgress = false;
        this.honestProbability = 0.8; // 99%诚实概率，非常低的攻击概率
        this.lastAttackTime = 0;
        this.attackCooldown = 5; // 5秒冷却
        this.attackDuration = 3; // 攻击只持续3秒

        // 触发条件 - 非常宽松
        this.timeTrigger = this.getClockTime() + 10; // 10秒后触发
        this.counterTrigger = 0; // 计数器触发值

        // 注册时间检查
        this.registerAttackerTimeEvent(
            { name: 'checkTrigger' },
            5000 // 3秒检查一次
        );

        // console.log('Minimal Logic Bomb initialized');
    }

    // 主攻击入口
    attack(packets) {
        // 检查协议类型
        this.detectProtocol(packets);

        // 如果还没触发，增加计数器
        if (!this.bombDetonated) {
            this.counterTrigger += packets.length;
            this.checkTimeTrigger();
        }

        // 如果爆炸正在进行，执行攻击
        if (this.explosionInProgress) {
            return this.performMinimalAttack(packets);
        }

        // 否则，完全诚实地传递消息
        return packets;
    }

    // 检测协议类型
    detectProtocol(packets) {
        for (const packet of packets) {
            if (!packet.content || !packet.content.type) continue;

            const msgType = packet.content.type.toLowerCase();

            // 检测PBFT
            if (msgType.includes('pbft') || msgType === 'pre-prepare' ||
                msgType === 'prepare' || msgType === 'commit') {
                this.protocolStates.pbft.detected = true;
                if (packet.content.sequence !== undefined) {
                    this.protocolStates.pbft.sequence = Math.max(
                        this.protocolStates.pbft.sequence,
                        packet.content.sequence
                    );
                }
            }
            // 检测HotStuff
            else if (msgType.includes('hotstuff') || msgType === 'new-view') {
                this.protocolStates.hotstuff.detected = true;
                if (packet.content.view !== undefined) {
                    this.protocolStates.hotstuff.view = Math.max(
                        this.protocolStates.hotstuff.view,
                        packet.content.view
                    );
                }
            }
            // 检测Algorand
            else if (msgType.includes('algorand') || msgType === 'proposal' || msgType === 'vote') {
                this.protocolStates.algorand.detected = true;
                if (packet.content.round !== undefined) {
                    this.protocolStates.algorand.round = Math.max(
                        this.protocolStates.algorand.round,
                        packet.content.round
                    );
                }
            }
            // 检测Babble
            else if (msgType.includes('babble') || msgType.includes('ssb')) {
                this.protocolStates.babble.detected = true;
                if (msgType === 'babble-event' &&
                    packet.content.event &&
                    packet.content.event.round !== undefined) {

                    this.protocolStates.babble.round = Math.max(
                        this.protocolStates.babble.round,
                        packet.content.event.round
                    );
                }
            }
            // 检测Libra
            else if (msgType.includes('libra')) {
                this.protocolStates.libra.detected = true;
                if (packet.content.round !== undefined) {
                    this.protocolStates.libra.round = Math.max(
                        this.protocolStates.libra.round,
                        packet.content.round
                    );
                }
            }
            // 检测AsyncBA
            else if (msgType.includes('async') || msgType.includes('ba-')) {
                this.protocolStates.asyncBA.detected = true;
                if (packet.content.round !== undefined) {
                    this.protocolStates.asyncBA.round = Math.max(
                        this.protocolStates.asyncBA.round,
                        packet.content.round
                    );
                }
            }
        }
    }

    // 检查时间触发器
    checkTimeTrigger() {
        const currentTime = this.getClockTime();

        // 如果正在攻击，不检查
        if (this.explosionInProgress) return;

        // 如果冷却中，检查冷却是否结束
        if (this.bombDetonated &&
            currentTime - this.lastAttackTime >= this.attackCooldown) {

            // 冷却结束，可以再次触发
            this.bombDetonated = false;
        }

        // 检查时间触发
        if (!this.bombDetonated && currentTime >= this.timeTrigger) {
            this.detonateBomb("Time trigger");
        }

        // 检查计数器触发 - 相当于消息量触发
        if (!this.bombDetonated && this.counterTrigger >= 200) { // 200条消息后触发
            this.detonateBomb("Message count trigger");
        }
    }

    // 激活炸弹
    detonateBomb(reason) {
        const currentTime = this.getClockTime();

        this.bombDetonated = true;
        this.explosionInProgress = true;
        this.lastAttackTime = currentTime;

        // console.log(`MINIMAL BOMB TRIGGERED at ${currentTime}! Reason: ${reason}`);

        // 设置持续时间
        this.registerAttackerTimeEvent(
            { name: 'endAttack' },
            this.attackDuration * 1000
        );

        // 设置下一次触发
        this.timeTrigger = currentTime + this.attackCooldown + 20;
        this.counterTrigger = 0;
    }

    // 执行最小干扰的攻击
    performMinimalAttack(packets) {
        // 只修改极少数的包，90%的包仍然正常传递
        return packets.map(packet => {
            // 90%的概率完全不修改
            if (Math.random() < 0.9) {
                return packet;
            }

            // 复制包避免修改原始对象
            const modifiedPacket = JSON.parse(JSON.stringify(packet));

            // 根据检测到的协议执行最小干扰
            if (this.protocolStates.pbft.detected) {
                this.minimalPBFTAttack(modifiedPacket);
            }
            else if (this.protocolStates.hotstuff.detected) {
                this.minimalHotStuffAttack(modifiedPacket);
            }
            else if (this.protocolStates.algorand.detected) {
                this.minimalAlgorandAttack(modifiedPacket);
            }
            else if (this.protocolStates.babble.detected) {
                this.minimalBabbleAttack(modifiedPacket);
            }
            else if (this.protocolStates.libra.detected) {
                this.minimalLibraAttack(modifiedPacket);
            }
            else if (this.protocolStates.asyncBA.detected) {
                this.minimalAsyncBAAttack(modifiedPacket);
            }
            else {
                this.minimalGenericAttack(modifiedPacket);
            }

            return modifiedPacket;
        });
    }

    // PBFT最小干扰
    minimalPBFTAttack(packet) {
        if (!packet.content) return;

        const msgType = packet.content.type;

        // 只对准备阶段消息进行最小修改
        if (msgType === 'prepare') {
            // 小概率修改摘要
            if (packet.content.digest && Math.random() < 0.3) {
                // 只修改最后一个字符
                if (packet.content.digest.length > 0) {
                    const lastChar = packet.content.digest.charAt(packet.content.digest.length - 1);
                    const newChar = lastChar === '0' ? '1' : '0';
                    packet.content.digest = packet.content.digest.slice(0, -1) + newChar;
                }
            }
        }

        // 非常小的延迟 - 最多0.1秒
        packet.delay = (packet.delay || 0) + Math.random() * 0.1;
    }

    // HotStuff最小干扰
    minimalHotStuffAttack(packet) {
        if (!packet.content) return;

        // 小概率给视图号加1
        if (packet.content.view !== undefined && Math.random() < 0.3) {
            packet.content.view += 1;
        }

        // 非常小的延迟 - 最多0.1秒
        packet.delay = (packet.delay || 0) + Math.random() * 0.1;
    }

    // Algorand最小干扰
    minimalAlgorandAttack(packet) {
        if (!packet.content) return;

        // 只对投票消息进行修改
        if (packet.content.type === 'vote') {
            // 小概率翻转布尔值
            if (typeof packet.content.value === 'boolean' && Math.random() < 0.3) {
                packet.content.value = !packet.content.value;
            }
        }

        // 非常小的延迟 - 最多0.1秒
        packet.delay = (packet.delay || 0) + Math.random() * 0.1;
    }

    // Babble最小干扰
    minimalBabbleAttack(packet) {
        if (!packet.content) return;

        // 避免破坏事件链 - 只修改时间戳
        if (packet.content.type === 'babble-event' &&
            packet.content.event &&
            packet.content.event.timestamp !== undefined) {

            // 小幅度调整时间戳
            packet.content.event.timestamp += (Math.random() * 0.2 - 0.1);
        }

        // 非常小的延迟 - 最多0.1秒
        packet.delay = (packet.delay || 0) + Math.random() * 0.1;
    }

    // Libra最小干扰
    minimalLibraAttack(packet) {
        // 类似HotStuff
        this.minimalHotStuffAttack(packet);
    }

    // AsyncBA最小干扰
    minimalAsyncBAAttack(packet) {
        if (!packet.content) return;

        // 小概率修改轮次
        if (packet.content.round !== undefined && Math.random() < 0.3) {
            packet.content.round += 1;
        }

        // 最多0.2秒的延迟
        packet.delay = (packet.delay || 0) + Math.random() * 0.2;
    }

    // 通用最小干扰
    minimalGenericAttack(packet) {
        if (!packet.content) return;

        // 只进行最小延迟 - 0.05秒
        packet.delay = (packet.delay || 0) + Math.random() * 0.05;
    }

    // 处理事件
    onTimeEvent(event) {
        if (event.functionMeta.name === 'checkTrigger') {
            // 检查触发条件
            this.checkTimeTrigger();

            // 再次注册检查
            this.registerAttackerTimeEvent(
                { name: 'checkTrigger' },
                3000 // 3秒后再检查
            );
        }
        else if (event.functionMeta.name === 'endAttack') {
            // 结束攻击
            this.explosionInProgress = false;
            // console.log(`Attack ended at ${this.getClockTime()}`);
        }
    }

    // 更新参数
    updateParam() {
        return false;
    }
}

module.exports = LogicBombAttacker;
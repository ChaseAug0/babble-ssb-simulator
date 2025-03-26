class NoneAttacker {
    constructor() {
        // 无需初始化
    }

    attack(packets) {
        // 不进行攻击，原样返回数据包
        return packets;
    }

    updateParam() {
        // 无参数更新
        return false;
    }

    onTimeEvent() {
        // 不处理时间事件
    }
}

module.exports = NoneAttacker;
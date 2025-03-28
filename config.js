module.exports = {
  // 节点配置
  nodeNum: 16,
  byzantineNodeNum: 4,

  // 协议参数
  lambda: 3,
  protocol: 'pbft',

  // 网络条件
  networkDelay: {
    mean: 1.0,
    std: 0.5,
  },

  // 攻击者配置
  attacker: 'adaptive-attack-strategist',

  // 其他参数
  logToFile: true,
  repeatTime: 50,

  // Babble特定配置
  babble: {
    suspendLimit: 200,
    syncInterval: 500,
  }
};

module.exports = {
	// 节点配置
	nodeNum: 36,               // 网络中总节点数量
	byzantineNodeNum: 1,      // 拜占庭(恶意)节点数量
	// 注：理论容错上限为(n-1)/3，约11.7

	// 协议参数
	lambda: 1,                // 心跳超时时间(秒)，控制节点发送心跳消息的频率
	protocol: 'ssb-babble',   // 使用的共识协议类型

	// 网络条件
	networkDelay: {           // 网络延迟设置
		mean: 0.1,            // 平均延迟(秒)
		std: 0.5,             // 延迟标准差(秒)
	},

	// 攻击者设置
	attacker: 'babble-attacker',  // 使用的攻击者类型

	// 其他参数
	logToFile: true,          // 是否记录日志
	repeatTime: 100,           // 模拟重复次数

	// Babble特有配置
	babble: {
		suspendLimit: 200,    // 未确定事件数量上限，超过会暂停节点
		syncInterval: 500,    // 同步间隔(毫秒)
	}
};
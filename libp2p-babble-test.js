'use strict';

const fs = require('fs');
const path = require('path');
const Simulator = require('./simulator');
const { execSync } = require('child_process');

console.log('=========================================');
console.log('  Babble 协议测试运行器');
console.log('=========================================');

/**
 * 运行单次测试并记录结果
 * @param {Object} config 测试配置
 * @param {string} testName 测试名称
 */
function runTest(config, testName) {
    console.log(`\n开始测试: ${testName}`);
    console.log(`节点配置: ${config.nodeNum} 节点, ${config.byzantineNodeNum} 拜占庭节点`);
    console.log(`协议: ${config.protocol}, 攻击者: ${config.attacker}`);
    console.log(`网络延迟: 平均=${config.networkDelay.mean}秒, 标准差=${config.networkDelay.std}秒`);

    // 创建模拟器
    const simulator = new Simulator(config);

    // 记录运行进度
    let currentRun = 0;
    simulator.onDecision = () => {
        currentRun++;
        console.log(`完成模拟运行 ${currentRun}/${config.repeatTime}`);
    };

    // 运行模拟
    console.log('开始模拟...');
    simulator.startSimulation();

    // 输出结果
    const results = simulator.simulationResults;

    console.log(`\n----- ${testName} 测试结果 -----`);
    if (results.length > 0) {
        const latencies = results.map(r => r.latency);
        const msgCounts = results.map(r => r.totalMsgCount);

        // 计算平均值
        const avgLatency = latencies.reduce((a, b) => a + b, 0) / latencies.length;
        const avgMsgCount = msgCounts.reduce((a, b) => a + b, 0) / msgCounts.length;

        const resultSummary = {
            testName,
            config: {
                nodeNum: config.nodeNum,
                byzantineNodeNum: config.byzantineNodeNum,
                protocol: config.protocol,
                attacker: config.attacker,
                networkDelay: config.networkDelay
            },
            results: {
                avgLatency: avgLatency.toFixed(2),
                avgMsgCount: avgMsgCount.toFixed(2),
                successRate: (results.length / config.repeatTime * 100).toFixed(2)
            }
        };

        // 输出结果
        console.log(`平均延迟: ${avgLatency.toFixed(2)} 秒`);
        console.log(`平均消息数: ${avgMsgCount.toFixed(2)}`);
        console.log(`成功率: ${(results.length / config.repeatTime * 100).toFixed(2)}%`);

        // 保存结果到文件
        fs.writeFileSync(
            `results_${testName.toLowerCase().replace(/\s+/g, '_')}.json`,
            JSON.stringify(resultSummary, null, 2)
        );
    } else {
        console.log('没有完成的模拟运行');
        fs.writeFileSync(
            `results_${testName.toLowerCase().replace(/\s+/g, '_')}.json`,
            JSON.stringify({
                testName,
                config: {
                    nodeNum: config.nodeNum,
                    byzantineNodeNum: config.byzantineNodeNum,
                    protocol: config.protocol,
                    attacker: config.attacker,
                    networkDelay: config.networkDelay
                },
                results: {
                    status: 'failed',
                    message: '没有完成的模拟运行'
                }
            }, null, 2)
        );
    }
}

// 基本配置
const baseConfig = {
    nodeNum: 10,
    byzantineNodeNum: 3,
    lambda: 3,
    protocol: 'libp2p-babble',
    networkDelay: {
        mean: 0.5,
        std: 0.2,
    },
    attacker: 'none',
    logToFile: false,
    repeatTime: 5,
    babble: {
        suspendLimit: 100,
        syncInterval: 500,
    }
};

// 测试场景
const tests = [
    {
        name: '基本正常运行',
        config: { ...baseConfig }
    },
    {
        name: '节点崩溃攻击',
        config: { ...baseConfig, attacker: 'fail-stop' }
    },
    {
        name: '自定义攻击者',
        config: { ...baseConfig, attacker: 'babble-attacker' }
    },
    {
        name: '超出容错限制',
        config: { ...baseConfig, nodeNum: 10, byzantineNodeNum: 4 }
    },
    {
        name: '高网络延迟',
        config: {
            ...baseConfig,
            networkDelay: {
                mean: 2.0,
                std: 1.0,
            }
        }
    },
    {
        name: '网络分区',
        config: { ...baseConfig, attacker: 'babble-partition-attacker' }
    }
];

// 检查攻击者文件是否存在
const attackers = ['babble-attacker.js', 'babble-partition-attacker.js', 'fail-stop.js'];
for (const attacker of attackers) {
    const attackerPath = path.join(__dirname, 'network', attacker);
    if (!fs.existsSync(attackerPath)) {
        console.log(`警告: 找不到攻击者文件 ${attacker}`);
    }
}

// 运行所有测试
console.log(`将运行 ${tests.length} 个测试场景`);
for (let i = 0; i < tests.length; i++) {
    try {
        console.log(`\n[${i + 1}/${tests.length}] 运行测试: ${tests[i].name}`);
        runTest(tests[i].config, tests[i].name);
    } catch (err) {
        console.error(`测试 ${tests[i].name} 失败:`);
        console.error(err);
    }
}

console.log('\n=========================================');
console.log('所有测试完成! 结果已保存到 results_*.json 文件');
console.log('=========================================');
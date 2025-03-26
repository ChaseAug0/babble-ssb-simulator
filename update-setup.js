'use strict';

const fs = require('fs');
const path = require('path');

console.log('========================================');
console.log('  LibP2P-Babble 协议测试环境设置脚本');
console.log('========================================');

// Ensure necessary directories exist
const requiredDirs = [
    'ba-algo',
    'ba-algo/ssb-babble',
    'ba-algo/libp2p-babble',
    'network'
];

console.log('1. 创建必要的目录结构...');
for (const dir of requiredDirs) {
    const fullPath = path.join(__dirname, dir);
    if (!fs.existsSync(fullPath)) {
        fs.mkdirSync(fullPath, { recursive: true });
        console.log(`   创建目录: ${dir}`);
    } else {
        console.log(`   目录已存在: ${dir}`);
    }
}

// Write the fixed protocol implementation to BOTH possible locations
console.log('2. 安装协议实现...');
const protocolSource = path.join(__dirname, 'fixed-babble-protocol.js');

if (fs.existsSync(protocolSource)) {
    // Install to ssb-babble directory
    const ssbBabbleTarget = path.join(__dirname, 'ba-algo', 'ssb-babble', 'index.js');
    fs.copyFileSync(protocolSource, ssbBabbleTarget);

    // Also install to libp2p-babble directory
    const libp2pBabbleTarget = path.join(__dirname, 'ba-algo', 'libp2p-babble', 'index.js');
    fs.copyFileSync(protocolSource, libp2pBabbleTarget);

    console.log('   协议已安装到 ssb-babble 和 libp2p-babble 目录');
} else {
    console.error('   错误: 找不到源文件 fixed-babble-protocol.js');
    console.error('   请确保当前目录中有 fixed-babble-protocol.js 文件');
    process.exit(1);
}

// Ensure the babble-attacker.js is in the correct location
console.log('3. 安装 Babble 攻击者实现...');
const attackerSource = path.join(__dirname, 'babble-attacker.js');
const attackerTarget = path.join(__dirname, 'network', 'babble-attacker.js');

if (fs.existsSync(attackerSource)) {
    fs.copyFileSync(attackerSource, attackerTarget);
    console.log('   Babble 攻击者已安装');
} else {
    console.error('   警告: 找不到源文件 babble-attacker.js');
    console.log('   创建基本攻击者实现...');

    const basicAttacker = `'use strict';

class BabbleAttacker {
    attack(packets) {
        // 对30%的事件消息进行篡改
        return packets.map(packet => {
            if (packet.content && packet.content.type === 'babble-event' && Math.random() < 0.3) {
                // 篡改事件数据
                const event = packet.content.event;

                // 攻击方式1：创建事件分叉
                if (Math.random() < 0.5) {
                    event.selfParent = null; // 破坏事件链
                }
                // 攻击方式2：注入虚假交易
                else {
                    event.transactions = ["MALICIOUS_TX_" + Math.random()];
                }
            }
            return packet;
        });
    }

    updateParam() {
        return false;
    }

    onTimeEvent(event) {
        // 空实现
    }

    constructor(transfer, registerAttackerTimeEvent, eventQ, nodeNum, byzantineNodeNum, getClockTime) {
        this.transfer = transfer;
        this.registerAttackerTimeEvent = registerAttackerTimeEvent;
        this.eventQ = eventQ;
        this.nodeNum = nodeNum;
        this.byzantineNodeNum = byzantineNodeNum;
        this.getClockTime = getClockTime;
    }
}

module.exports = BabbleAttacker;`;

    fs.writeFileSync(attackerTarget, basicAttacker);
    console.log('   创建了基本 Babble 攻击者实现');
}

// Create a symbolic node.js module if not exists
console.log('4. 检查 node 模块...');
const nodeSource = path.join(__dirname, 'node.js');
if (!fs.existsSync(nodeSource)) {
    console.log('   创建基本 Node 类模块...');
    const nodeContent = `'use strict';

class Node {
    constructor(nodeID, nodeNum, network, registerTimeEvent) {
        this.nodeID = nodeID;
        this.nodeNum = nodeNum;
        this.network = network;
        this.registerTimeEvent = registerTimeEvent;
        this.isDecided = false;
        this.clock = 0;
        this.logger = {
            info: (msg) => console.log(\`[Node \${nodeID}] INFO: \${Array.isArray(msg) ? msg.join(' ') : msg}\`),
            warning: (msg) => console.log(\`[Node \${nodeID}] WARNING: \${Array.isArray(msg) ? msg.join(' ') : msg}\`),
            error: (msg) => console.log(\`[Node \${nodeID}] ERROR: \${Array.isArray(msg) ? msg.join(' ') : msg}\`),
            round: (time) => time.toFixed(2)
        };
    }

    send(src, dst, content) {
        this.network.send({
            src: src,
            dst: dst,
            content: content
        });
    }

    onMsgEvent(msgEvent) {
        this.clock = msgEvent.triggeredTime;
    }

    onTimeEvent(timeEvent) {
        this.clock = timeEvent.triggeredTime;
    }
}

module.exports = Node;`;

    fs.writeFileSync(nodeSource, nodeContent);
    console.log('   基本 Node 类已创建');
} else {
    console.log('   node.js 已存在');
}

console.log('5. 创建测试库目录...');
const libDir = path.join(__dirname, 'lib');
if (!fs.existsSync(libDir)) {
    fs.mkdirSync(libDir);
    console.log('   创建 lib 目录');

    // Create a minimal logger.js file
    const loggerContent = `'use strict';

class Logger {
    static clearLogDir() {
        console.log('Log directory cleared');
    }
}

module.exports = Logger;`;

    fs.writeFileSync(path.join(libDir, 'logger.js'), loggerContent);
    console.log('   创建基本 logger.js');
} else {
    console.log('   lib 目录已存在');
}

// Create the test script
console.log('6. 创建测试脚本...');
const testScript = path.join(__dirname, 'libp2p-babble-test.js');
const testContent = `'use strict';

const Simulator = require('./simulator');

// Custom configuration for the LibP2P-Babble protocol
const config = {
    // Node configuration
    nodeNum: 7,                 // Total number of nodes
    byzantineNodeNum: 2,        // Number of Byzantine nodes (less than n/3)

    // Protocol parameters
    lambda: 3,                  // Lambda parameter (seconds)
    protocol: 'libp2p-babble',  // Protocol to use

    // Network conditions
    networkDelay: {
        mean: 0.5,              // Average network delay in seconds
        std: 0.2,               // Standard deviation of network delay
    },

    // Attacker configuration
    attacker: 'babble-attacker', // Use the babble attacker

    // Other parameters
    logToFile: false,           // Disable file logging
    repeatTime: 3,              // Number of simulation runs

    // Babble-specific configuration
    babble: {
        suspendLimit: 100,      // Suspend limit for undetermined events
        syncInterval: 500,      // Sync interval in milliseconds
    }
};

console.log('================================');
console.log(' libp2p-Babble 协议 BFT 测试工具');
console.log('================================');
console.log('初始化模拟器...');

// Initialize simulator with config
const simulator = new Simulator(config);

// Show progress bar during execution
let currentRun = 0;
simulator.onDecision = () => {
    currentRun++;
    console.log(\`完成模拟运行 \${currentRun}/\${config.repeatTime}\`);
};

// Begin simulation
console.log(\`开始模拟 (节点数: \${config.nodeNum}, 拜占庭节点: \${config.byzantineNodeNum})\`);
console.log(\`协议: \${config.protocol}, 攻击者: \${config.attacker}\`);
simulator.startSimulation();

// Display results
console.log('\\n========== 模拟结果 ==========');
const results = simulator.simulationResults;

if (results.length > 0) {
    const latencies = results.map(r => r.latency);
    const msgCounts = results.map(r => r.totalMsgCount);
    
    // Calculate averages
    const avgLatency = latencies.reduce((a, b) => a + b, 0) / latencies.length;
    const avgMsgCount = msgCounts.reduce((a, b) => a + b, 0) / msgCounts.length;
    
    console.log(\`平均延迟: \${avgLatency.toFixed(2)} 秒\`);
    console.log(\`平均消息数: \${avgMsgCount.toFixed(2)}\`);
    console.log(\`成功率: \${(results.length / config.repeatTime * 100).toFixed(2)}%\`);
} else {
    console.log('没有完成的模拟运行');
}`;

fs.writeFileSync(testScript, testContent);
console.log('   测试脚本已创建');

console.log('\n安装完成! 现在可以运行测试脚本:');
console.log('  node updated-setup.js');
console.log('  node libp2p-babble-test.js');
console.log('========================================');
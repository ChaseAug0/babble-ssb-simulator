// attack-runner.js - 运行所有攻击场景的统一脚本（带超时限制）
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const util = require('util');
const writeFileAsync = util.promisify(fs.writeFile);
const appendFileAsync = util.promisify(fs.appendFile);
const existsAsync = util.promisify(fs.exists);
const mkdirAsync = util.promisify(fs.mkdir);

// 配置
const ATTACKERS = [
  'adaptive-attack-strategist',
  'byzantine-attack-coordinator',
  'clock-skew-attacker',
  'equivocation-attacker',
  'fail-stop',
  'logic-bomb-attacker',
  'man-in-the-middle-attacker',
  'message-sequence-manipulator',
  'multi-layer-attack-coordinator',
  'partitioner',
  'signature-forgery-attacker',
  'sync-interfernce-attacker'
];

const PROTOCOLS = [
  'ssb-babble',
  'pbft',
  'hotstuff-NS',
  'algorand',
  'libraBFT',
  'async-BA'
];

const NODE_CONFIGS = [
  [4, 16],
  [8, 32],
  [16, 64]
];

// 超时设置 (15分钟 = 900000毫秒)
const TIMEOUT_MS = 15 * 60 * 1000;

// 确保结果目录存在
const RESULTS_DIR = path.join(__dirname, 'results');
const MAIN_RESULTS_FILE = path.join(RESULTS_DIR, 'attack_results.txt');
const ATTACKER_DIR = path.join(__dirname, 'attackers');

// 自动创建攻击者文件（如果不存在）
async function ensureAttackerExists(attacker) {
  const attackerPath = path.join(ATTACKER_DIR, `${attacker}.js`);

  // 检查攻击者目录是否存在，如果不存在则创建
  if (!await existsAsync(ATTACKER_DIR)) {
    await mkdirAsync(ATTACKER_DIR, { recursive: true });
  }

  // 如果攻击者文件不存在，创建一个基本模板
  if (!await existsAsync(attackerPath)) {
    const attackerTemplate = `'use strict';

class ${toCamelCase(attacker)} {
    attack(packets) {
        // 返回原始数据包 (可以在这里实现具体的攻击逻辑)
        return packets;
    }

    onTimeEvent(event) {
        // 处理时间事件
    }

    updateParam() {
        return false;
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

module.exports = ${toCamelCase(attacker)};`;

    await writeFileAsync(attackerPath, attackerTemplate);
    console.log(`Created attacker template: ${attackerPath}`);
  }
}

// 转换为驼峰命名法 (用于生成类名)
function toCamelCase(str) {
  return str.split('-').map((word, index) => {
    return index === 0 ? word : word[0].toUpperCase() + word.slice(1);
  }).join('');
}

// 更新config.js文件
async function updateConfig(attacker, protocol, byzantineNodes, totalNodes) {
  const configContent = `module.exports = {
  // 节点配置
  nodeNum: ${totalNodes},
  byzantineNodeNum: ${byzantineNodes},

  // 协议参数
  lambda: 3,
  protocol: '${protocol}',

  // 网络条件
  networkDelay: {
    mean: 1.0,
    std: 0.5,
  },

  // 攻击者配置
  attacker: '${attacker}',

  // 其他参数
  logToFile: true,
  repeatTime: 50,

  // Babble特定配置
  babble: {
    suspendLimit: 200,
    syncInterval: 500,
  }
};
`;

  await writeFileAsync(path.join(__dirname, 'config.js'), configContent);
}

// 运行模拟并捕获结果（带超时）
async function runSimulation(attacker, protocol, byzantineNodes, totalNodes) {
  console.log(`运行: ${attacker} 攻击 ${protocol} (${byzantineNodes}/${totalNodes})`);

  const runId = `${attacker}_${protocol}_${byzantineNodes}_${totalNodes}`;
  const outputFile = path.join(RESULTS_DIR, `${runId}.txt`);

  try {
    // 确保攻击者存在
    await ensureAttackerExists(attacker);

    // 更新配置
    await updateConfig(attacker, protocol, byzantineNodes, totalNodes);

    // 运行模拟（使用spawn而不是exec以便获取实时输出）
    return new Promise((resolve, reject) => {
      let output = '';
      let errorOutput = '';
      let timedOut = false;

      const simulation = spawn('node', ['main.js']);

      // 设置超时
      const timer = setTimeout(() => {
        timedOut = true;
        console.log(`  超时: ${runId} (超过15分钟)`);
        simulation.kill('SIGTERM');
      }, TIMEOUT_MS);

      simulation.stdout.on('data', (data) => {
        const chunk = data.toString();
        output += chunk;
      });

      simulation.stderr.on('data', (data) => {
        const chunk = data.toString();
        errorOutput += chunk;
      });

      simulation.on('close', async (code) => {
        clearTimeout(timer);

        const result = timedOut
          ? { success: false, timedOut: true, output, errorOutput }
          : { success: code === 0, code, output, errorOutput };

        // 保存个别结果
        let resultContent = output;
        if (errorOutput) resultContent += `\n\n错误输出:\n${errorOutput}`;
        if (timedOut) resultContent = `超时: 执行超过15分钟\n\n${resultContent}`;
        await writeFileAsync(outputFile, resultContent);

        // 附加到主结果文件
        let mainContent = '----------------------------------------\n' +
          `攻击: ${attacker}\n` +
          `协议: ${protocol}\n` +
          `节点: ${totalNodes} (拜占庭: ${byzantineNodes})\n\n`;

        if (timedOut) {
          mainContent += `超时: 执行超过15分钟\n\n`;
        } else if (!result.success) {
          mainContent += `错误: 退出代码 ${code}\n\n`;
        }

        mainContent += output + '\n\n';

        await appendFileAsync(MAIN_RESULTS_FILE, mainContent);

        console.log(`  已完成: ${runId}${timedOut ? ' (超时)' : result.success ? '' : ' (失败)'}`);
        resolve(result);
      });

      simulation.on('error', (error) => {
        clearTimeout(timer);
        console.error(`  执行错误: ${runId}`, error.message);
        reject(error);
      });
    });
  } catch (error) {
    console.error(`  失败: ${runId}`, error.message);

    // 保存错误输出
    await writeFileAsync(outputFile, `错误: ${error.message}\n\n`);

    // 附加到主结果文件
    await appendFileAsync(MAIN_RESULTS_FILE,
      '----------------------------------------\n' +
      `攻击: ${attacker}\n` +
      `协议: ${protocol}\n` +
      `节点: ${totalNodes} (拜占庭: ${byzantineNodes})\n\n` +
      `错误: ${error.message}\n\n`
    );

    return { success: false, error };
  }
}

// 主执行函数
async function runAllTests() {
  console.log('开始BFT共识攻击模拟...');

  // 确保结果目录存在
  if (!await existsAsync(RESULTS_DIR)) {
    await mkdirAsync(RESULTS_DIR, { recursive: true });
  }

  // 初始化结果文件
  await writeFileAsync(MAIN_RESULTS_FILE,
    'BFT共识协议攻击结果\n' +
    '========================================\n\n'
  );

  for (const attacker of ATTACKERS) {
    for (const [byzantineNodes, totalNodes] of NODE_CONFIGS) {
      for (const protocol of PROTOCOLS) {
        await runSimulation(attacker, protocol, byzantineNodes, totalNodes);
      }
    }
  }

  console.log(`所有测试已完成。结果保存到 ${MAIN_RESULTS_FILE}`);
}

// 处理退出时清理
process.on('SIGINT', () => {
  console.log('\n捕获到SIGINT。正在退出...');
  process.exit(0);
});

// 运行所有测试
runAllTests().catch(err => {
  console.error('致命错误:', err);
});
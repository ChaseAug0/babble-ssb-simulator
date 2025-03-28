#!/usr/bin/env node
'use strict';

/**
 * 跨平台BFT共识协议攻击测试运行器
 * 支持Mac、Linux等环境
 */

const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const util = require('util');

// 异步文件操作
const writeFileAsync = util.promisify(fs.writeFile);
const appendFileAsync = util.promisify(fs.appendFile);
const existsAsync = util.promisify(fs.exists);
const mkdirAsync = util.promisify(fs.mkdir);
const readFileAsync = util.promisify(fs.readFile);
const readdirAsync = util.promisify(fs.readdir);

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

// 目录配置
const RESULTS_DIR = path.join(__dirname, 'results');
const MAIN_RESULTS_FILE = path.join(RESULTS_DIR, 'attack_results.txt');

// 攻击者目录 - 检查两种可能的目录名
let ATTACKER_DIR;

/**
 * 初始化环境
 * 检查并创建必要的目录结构
 */
async function setupEnvironment() {
  console.log('设置测试环境...');

  // 确保结果目录存在
  if (!await existsAsync(RESULTS_DIR)) {
    console.log(`创建结果目录: ${RESULTS_DIR}`);
    await mkdirAsync(RESULTS_DIR, { recursive: true });
  }

  // 确定攻击者目录
  // 首先检查"attacker"目录
  if (await existsAsync(path.join(__dirname, 'attacker'))) {
    ATTACKER_DIR = path.join(__dirname, 'attacker');
    console.log(`找到攻击者目录: ${ATTACKER_DIR}`);
  }
  // 然后检查"attackers"目录
  else if (await existsAsync(path.join(__dirname, 'attackers'))) {
    ATTACKER_DIR = path.join(__dirname, 'attackers');
    console.log(`找到攻击者目录: ${ATTACKER_DIR}`);
  }
  // 如果都不存在，创建"attacker"目录
  else {
    ATTACKER_DIR = path.join(__dirname, 'attacker');
    console.log(`创建攻击者目录: ${ATTACKER_DIR}`);
    await mkdirAsync(ATTACKER_DIR, { recursive: true });
  }

  // 创建备份攻击者模板（确保每个攻击者都有对应文件）
  await ensureAllAttackersExist();

  // 确保配置文件可写
  const configPath = path.join(__dirname, 'config.js');
  try {
    // 尝试读取当前配置（如果存在）
    if (await existsAsync(configPath)) {
      await readFileAsync(configPath, 'utf8');
      console.log('配置文件可访问');
    }
  } catch (error) {
    console.error(`警告: 配置文件访问错误: ${error.message}`);
    console.log('将尝试创建新的配置文件');
  }

  // 初始化结果文件
  await writeFileAsync(MAIN_RESULTS_FILE,
    'BFT共识协议攻击结果\n' +
    '========================================\n\n' +
    `测试开始时间: ${new Date().toLocaleString()}\n` +
    `运行环境: ${process.platform} (${process.arch})\n` +
    `Node.js版本: ${process.version}\n\n`
  );

  console.log('环境设置完成');
}

/**
 * 确保所有攻击者的JS文件都存在
 */
async function ensureAllAttackersExist() {
  for (const attacker of ATTACKERS) {
    await findOrCreateAttacker(attacker);
  }
}

/**
 * 查找或创建攻击者文件
 * 返回攻击者文件的路径
 */
async function findOrCreateAttacker(attacker) {
  // 首先检查attacker目录中是否存在该攻击者
  const possiblePaths = [
    path.join(ATTACKER_DIR, `${attacker}.js`),
    path.join(ATTACKER_DIR, `${attacker.replace(/-/g, '_')}.js`),  // 检查下划线版本
    path.join(ATTACKER_DIR, `${toCamelCase(attacker)}.js`),         // 检查驼峰命名版本
  ];

  // 如果是单复数目录不同，也检查另一个目录
  const otherDir = ATTACKER_DIR.endsWith('attacker')
    ? path.join(__dirname, 'attackers')
    : path.join(__dirname, 'attacker');

  if (await existsAsync(otherDir)) {
    possiblePaths.push(
      path.join(otherDir, `${attacker}.js`),
      path.join(otherDir, `${attacker.replace(/-/g, '_')}.js`),
      path.join(otherDir, `${toCamelCase(attacker)}.js`)
    );
  }

  // 查找是否存在任一路径
  for (const filePath of possiblePaths) {
    if (await existsAsync(filePath)) {
      console.log(`找到攻击者文件: ${filePath}`);
      return filePath;
    }
  }

  // 如果都不存在，创建新的攻击者文件
  const attackerPath = path.join(ATTACKER_DIR, `${attacker}.js`);
  const attackerTemplate = `'use strict';

/**
 * ${attacker} 攻击实现
 */
class ${toCamelCase(attacker)} {
    /**
     * 处理通信数据包
     * @param {Array} packets - 要处理的数据包数组
     * @returns {Array} 可能被修改的数据包数组
     */
    attack(packets) {
        // 数据包处理逻辑
        return packets;
    }

    /**
     * 处理时间事件
     * @param {Object} event - 时间事件对象
     */
    onTimeEvent(event) {
        // 时间事件处理
    }

    /**
     * 更新攻击参数
     * @returns {boolean} 返回false表示没有更多参数要更新
     */
    updateParam() {
        return false;
    }

    /**
     * 构造函数
     */
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

  console.log(`创建攻击者文件: ${attackerPath}`);
  await writeFileAsync(attackerPath, attackerTemplate);
  return attackerPath;
}

/**
 * 转换为驼峰命名法
 */
function toCamelCase(str) {
  return str.split('-').map((word, index) => {
    return word.charAt(0).toUpperCase() + word.slice(1);
  }).join('');
}

/**
 * 更新config.js文件
 */
async function updateConfig(attacker, protocol, byzantineNodes, totalNodes) {
  // 首先查找攻击者文件
  const attackerPath = await findOrCreateAttacker(attacker);

  // 获取攻击者文件名（不带路径和扩展名）
  const attackerFileName = path.basename(attackerPath, '.js');

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
  attacker: '${attackerFileName}',

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

  const configPath = path.join(__dirname, 'config.js');
  try {
    await writeFileAsync(configPath, configContent);
    console.log(`更新配置文件: ${configPath}`);
  } catch (error) {
    console.error(`配置文件写入错误: ${error.message}`);
    throw error;
  }
}

/**
 * 运行模拟并捕获结果
 */
async function runSimulation(attacker, protocol, byzantineNodes, totalNodes) {
  console.log(`运行: ${attacker} 攻击 ${protocol} (${byzantineNodes}/${totalNodes})`);

  const runId = `${attacker}_${protocol}_${byzantineNodes}_${totalNodes}`;
  const outputFile = path.join(RESULTS_DIR, `${runId}.txt`);

  try {
    // 更新配置
    await updateConfig(attacker, protocol, byzantineNodes, totalNodes);

    // 运行模拟
    return new Promise((resolve, reject) => {
      let output = '';
      let errorOutput = '';
      let timedOut = false;

      // 使用spawn运行命令
      const simulation = spawn('node', ['main.js'], {
        cwd: __dirname,  // 确保在正确的目录中运行
        env: { ...process.env }  // 使用当前环境变量
      });

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
        console.error(`  错误输出: ${chunk}`);
      });

      simulation.on('close', async (code) => {
        clearTimeout(timer);

        const result = timedOut
          ? { success: false, timedOut: true, output, errorOutput }
          : { success: code === 0, code, output, errorOutput };

        // 保存个别结果
        let resultContent = `运行配置:\n` +
          `- 攻击者: ${attacker}\n` +
          `- 协议: ${protocol}\n` +
          `- 节点: ${totalNodes} (拜占庭: ${byzantineNodes})\n` +
          `- 时间: ${new Date().toLocaleString()}\n\n` +
          `标准输出:\n${output}\n`;

        if (errorOutput) resultContent += `\n错误输出:\n${errorOutput}`;
        if (timedOut) resultContent = `超时: 执行超过15分钟\n\n${resultContent}`;

        await writeFileAsync(outputFile, resultContent);

        // 附加到主结果文件
        let mainContent = '----------------------------------------\n' +
          `攻击: ${attacker}\n` +
          `协议: ${protocol}\n` +
          `节点: ${totalNodes} (拜占庭: ${byzantineNodes})\n` +
          `时间: ${new Date().toLocaleString()}\n\n`;

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
    await writeFileAsync(outputFile,
      `错误: ${error.message}\n\n` +
      `堆栈跟踪:\n${error.stack || '无堆栈跟踪'}\n`
    );

    // 附加到主结果文件
    await appendFileAsync(MAIN_RESULTS_FILE,
      '----------------------------------------\n' +
      `攻击: ${attacker}\n` +
      `协议: ${protocol}\n` +
      `节点: ${totalNodes} (拜占庭: ${byzantineNodes})\n` +
      `错误: ${error.message}\n\n`
    );

    return { success: false, error };
  }
}

/**
 * 主执行函数
 */
async function runAllTests() {
  console.log('开始BFT共识攻击模拟...');

  // 初始化环境
  await setupEnvironment();

  let totalTests = ATTACKERS.length * NODE_CONFIGS.length * PROTOCOLS.length;
  let completedTests = 0;

  for (const attacker of ATTACKERS) {
    for (const [byzantineNodes, totalNodes] of NODE_CONFIGS) {
      for (const protocol of PROTOCOLS) {
        try {
          await runSimulation(attacker, protocol, byzantineNodes, totalNodes);
        } catch (error) {
          console.error(`运行测试时发生严重错误: ${error.message}`);
          console.error('继续下一个测试...');
        }
        completedTests++;
        console.log(`进度: ${completedTests}/${totalTests} (${Math.round(completedTests / totalTests * 100)}%)`);
      }
    }
  }

  // 添加测试完成标记
  await appendFileAsync(MAIN_RESULTS_FILE,
    '========================================\n' +
    `测试完成时间: ${new Date().toLocaleString()}\n` +
    `共完成: ${completedTests}/${totalTests} 测试\n`
  );

  console.log(`所有测试已完成。结果保存到 ${MAIN_RESULTS_FILE}`);
}

// 处理退出时清理
process.on('SIGINT', () => {
  console.log('\n捕获到SIGINT。正在退出...');
  process.exit(0);
});

// 处理未捕获的异常
process.on('uncaughtException', (err) => {
  console.error('未捕获的异常:', err);
  console.log('继续执行...');
});

// 运行所有测试
runAllTests().catch(err => {
  console.error('致命错误:', err);
});
#!/bin/bash

# 测试不同类型和数量的拜占庭节点
echo "测试 1: 节点崩溃攻击"
sed -i 's/attacker: .*,/attacker: "fail-stop",/' config.js
node main.js > results_fail_stop.txt

echo "测试 2: 自定义攻击者"
sed -i 's/attacker: .*,/attacker: "babble-attacker",/' config.js
node main.js > results_custom_attack.txt

# 测试超出容错限制的情况
echo "测试 3: 超出容错限制 (>n/3 拜占庭节点)"
sed -i 's/byzantineNodeNum: .*,/byzantineNodeNum: 6,/' config.js
node main.js > results_exceeding_limit.txt

# 测试极端网络条件
echo "测试 4: 高网络延迟和丢包率"
sed -i 's/mean: .*,/mean: 2.0,/' config.js
sed -i 's/std: .*,/std: 1.0,/' config.js
node main.js > results_extreme_network.txt

# 测试网络分区情况
echo "测试 5: 模拟网络分区"
# 这需要修改attacker实现来模拟分区
# 将添加的代码复制到babble-partition-attacker.js文件中
sed -i 's/attacker: .*,/attacker: "babble-partition-attacker",/' config.js
node main.js > results_network_partition.txt
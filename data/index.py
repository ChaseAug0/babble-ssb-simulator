import matplotlib.pyplot as plt
import numpy as np

# 定义协议名称（原有的加上新的SSB-Babble）
protocols = ['ADD+v1', 'ADD+v2', 'ADD+v3', 'Algorand', 'Async BA', 
             'PBFT', 'HotStuff+NSL', 'LibraBFT', 'SSB-Babble']

# 从文本文件中提取的SSB-Babble数据（转换为秒）
ssb_babble_means = [
    3341.91 / 1000,  # f=0
    3413.89 / 1000,  # f=1
    3576.63 / 1000,  # f=2
    3742.82 / 1000,  # f=3
    4002.25 / 1000,  # f=4
    4423.41 / 1000   # f=5
]

ssb_babble_stds = [
    115 / 1000,  # f=0
    139 / 1000,  # f=1
    178 / 1000,  # f=2
    232 / 1000,  # f=3
    246 / 1000,  # f=4
    400 / 1000   # f=5
]

# 故障节点数（f值）
f_values = [0, 1, 2, 3, 4, 5]

# 创建一个假设的数据集以匹配现有图表（简化示例）
# 实际使用时需要替换为真实数据
data = np.array([
    # ADD+v1
    [7, 7.1, 7.2, 7.3, 7.4, 7.5],
    # ADD+v2
    [7, 7.1, 7.2, 7.3, 7.4, 7.5],
    # ADD+v3
    [13.5, 13.7, 13.8, 14, 14.1, 14.2],
    # Algorand
    [4.5, 4.6, 4.7, 4.8, 5, 5.8],
    # Async BA
    [13, 13.2, 13.4, 13.6, 13.8, 12.2],
    # PBFT
    [3.3, 3.5, 3.7, 3.9, 4.3, 5],
    # HotStuff+NSL
    [2.5, 3, 3.5, 4, 5, 25],  # HotStuff+NSL with f=5 has a very tall bar
    # LibraBFT
    [2.2, 2.5, 3.5, 3.7, 6, 6.3],
    # SSB-Babble (新添加的数据)
    ssb_babble_means
])

# 标准差数据（简化示例）
std_data = np.array([
    # 为每个协议的每个f值创建标准差值
    [0.3, 0.3, 0.4, 0.4, 0.4, 0.4],  # ADD+v1
    [1, 1, 1, 1, 0.8, 0.8],  # ADD+v2
    [1.5, 1.5, 2, 2, 2, 2],  # ADD+v3
    [0.2, 0.2, 0.2, 0.2, 0.3, 1.5],  # Algorand
    [4, 4, 3.5, 3.5, 3, 3],  # Async BA
    [0.1, 0.1, 0.2, 0.3, 0.5, 0.8],  # PBFT
    [0.1, 0.1, 0.2, 0.3, 0.7, 1],  # HotStuff+NSL
    [0.1, 0.1, 0.2, 0.2, 0.3, 0.3],  # LibraBFT
    ssb_babble_stds  # SSB-Babble 标准差
])

# 创建颜色映射（从浅绿到深绿）
colors = [
    '#D5F5E3',  # 最浅的绿色 (f=0)
    '#ABEBC6',  # (f=1)
    '#82E0AA',  # (f=2)
    '#58D68D',  # (f=3)
    '#2ECC71',  # (f=4)
    '#1D8348'   # 最深的绿色 (f=5)
]

# 创建图形和坐标轴
fig, ax = plt.subplots(figsize=(14, 8))

# 设置x轴位置
x = np.arange(len(protocols))
width = 0.13  # 调整柱子宽度以适应6个并排的柱子

# 绘制所有协议的分组柱状图
for i, f in enumerate(f_values):
    ax.bar(x + i*width - 0.35, data[:, i], width, color=colors[i], 
           yerr=std_data[:, i], capsize=3, 
           label=f'f = {f}')

# 设置x轴标签
ax.set_xticks(x + 0.05)
ax.set_xticklabels(protocols)

# 设置y轴标签
ax.set_ylabel('Latency (s)', fontsize=14)
ax.set_ylim(0, 25)  # 调整y轴限制

# 添加图例
ax.legend(loc='upper left')

# 添加标题
plt.title('Fig. 7: Time usage across different numbers of fail-stop nodes (λ = 1000; N = (1000, 300)).', 
          fontsize=16, fontweight='bold', loc='left', pad=20)

# 调整布局
plt.tight_layout()

# 保存图像
plt.savefig('updated_fig7_with_ssb_babble.png', dpi=300, bbox_inches='tight')

# 显示图像
plt.show()
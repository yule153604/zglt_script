# 中国联通自动化脚本

这是一个专为中国联通APP设计的高效自动化脚本，采用Python编写，旨在帮助用户自动完成日常签到、领现金、权益超市及各类专区活动。脚本基于异步IO架构，支持多账号并发运行，具有高度的稳定性和可扩展性。

## 🛠️ 代码结构详解

```text
中国联通.py
├── 📂 青龙API操作函数
│   ├── ql_get_env .................. 获取青龙环境变量
│   ├── ql_update_env ............... 更新青龙环境变量
│   └── ql_update_cookie_to_token ... 账密登录后自动更新为Token格式
│
├── 📂 MarketRaffleState (全局奖池状态类)
│   ├── __init__ .................... 初始化奖池状态/锁
│   └── check_prizes ................ 查询奖池(全局单次,多账号共享)
│
├── 📂 Logger (日志管理类)
│   ├── __init__ .................... 初始化日志前缀
│   └── log ......................... 输出带时间戳的日志
│
├── 📂 HttpClient (网络请求类)
│   ├── __init__ .................... 初始化 Session/Headers
│   └── request ..................... 发送 HTTP 请求(含重试/Cookie管理)
│
├── 📂 RSAEncrypt (RSA加密类)
│   └── encrypt ..................... RSA加密(用于账密登录)
│
├── 📂 CustomUserService (核心业务类)
│   │
│   ├── 🔧 基础功能
│   ├── __init__ .................... 初始化账号信息(自动识别登录方式)
│   ├── _detect_login_mode .......... 检测登录模式(账密/Token)
│   ├── _generate_appid ............. 生成账密登录用appid
│   ├── online ...................... 登录调度器(自动选择登录方式)
│   ├── _login_with_password ........ 账号密码登录
│   ├── _login_with_token ........... Token登录
│   ├── open_plat_line_new .......... 获取业务 Ticket
│   ├── get_bizchannelinfo .......... 生成业务渠道 Header
│   └── get_epay_authinfo ........... 生成支付认证 Header
│   │
│   ├── 📝 日常签到 (Sign)
│   ├── sign_task ................... 签到任务入口
│   ├── sign_get_continuous ......... 获取签到状态
│   ├── sign_day_sign ............... 执行签到
│   ├── sign_task_center ............ 任务中心(自动完成任务并领取奖励)
│   ├── sign_do_task_from_list ...... 执行任务中心任务
│   └── sign_get_task_reward ........ 领取任务奖励
│   │
│   ├── 💰 天天领现金 (TTLXJ)
│   ├── ttlxj_task .................. 领现金任务入口
│   ├── ttlxj_authorize ............. 业务授权
│   ├── ttlxj_login ................. 业务登录
│   ├── ttlxj_unify_draw_new ........ 执行打卡/抽奖
│   └── ttlxj_query_available ....... 查询余额
│   │
│   ├── 🎁 联通祝福 (Wocare)
│   ├── ltzf_task ................... 祝福任务入口
│   ├── wocare_get_token ............ 获取 Token
│   ├── wocare_api .................. 通用 API 请求(含解密)
│   ├── wocare_get_draw_task ........ 获取任务列表
│   ├── wocare_complete_task ........ 完成任务
│   └── wocare_luck_draw ............ 执行抽奖
│   │
│   ├── 🛒 权益超市 (Market)
│   ├── market_task ................. 超市任务入口
│   ├── market_login ................ 超市登录
│   ├── market_share_task ........... 分享小红书任务(自动完成获取抽奖机会)
│   ├── market_watering_task ........ 浇花任务(支持多次浇花直到完成)
│   ├── market_watering ............. 执行浇花
│   ├── market_raffle_task .......... 抽奖任务(可选展示奖池信息)
│   ├── market_validate_captcha ..... 人机验证处理
│   └── market_raffle ............... 执行抽奖
│   │
│   ├── 🍇 新疆专区 (Xinjiang)
│   ├── xj_task ..................... 新疆任务入口(含归属地校验)
│   ├── xj_do_draw .................. 执行活动抽奖
│   ├── xj_usersday_task ............ 会员日任务入口
│   └── xj_usersday_draw ............ 会员日抽奖
│   │
│   ├── 🏙️ 商都福利 (ShangDu - 河南)
│   ├── shangdu_task ................ 商都任务入口(含归属地校验)
│   ├── shangdu_get_ticket .......... 获取 Ticket
│   ├── shangdu_login ............... 激活 Ticket
│   └── shangdu_signin .............. 执行签到
│   │
│   └── 📱 云手机活动 (Cloud Phone)
│       ├── wostore_cloud_task ........ 云手机任务入口
│       ├── wostore_cloud_login ....... 两步登录获取Token
│       ├── wostore_cloud_get_coupon .. 领取优惠券
│       ├── wostore_cloud_task_list ... 查询任务列表
│       ├── wostore_cloud_get_chance .. 领取抽奖次数
│       └── wostore_cloud_draw ........ 执行抽奖
│
│   ├── 🔒 联通安全管家 (Security Butler)
│   ├── security_butler_task .......... 安全管家任务入口
│   ├── _sec_get_ticket_by_native ..... 获取Ticket
│   ├── _sec_get_auth_token ........... 获取认证Token
│   ├── _sec_add_to_blacklist ......... 添加黑名单任务
│   ├── _sec_mark_phone_number ........ 号码标记任务
│   ├── _sec_sync_address_book ........ 同步通讯录任务
│   ├── _sec_set_interception_rules ... 设置拦截规则任务
│   ├── _sec_view_weekly_summary ...... 查看周报任务
│   ├── _sec_sign_in .................. 签到任务
│   ├── _sec_receive_points ........... 领取积分
│   └── _sec_get_user_info ............ 查询积分信息
│
│   └── ☁️ 联通云盘 (Cloud Disk)
│       ├── cloud_disk_task ........... 云盘任务入口
│       ├── _cloud_get_ticket_by_native 获取Ticket
│       ├── _cloud_get_dispatcher ..... 获取Token
│       ├── _cloud_get_user_info ...... 查询积分信息
│       ├── _cloud_get_task_detail .... 获取任务详情并执行
│       ├── _cloud_dosign ............. 签到任务
│       ├── _cloud_activity_list ...... 浏览活动中心任务
│       ├── _cloud_share_file ......... 分享文件任务
│       ├── _cloud_do_upload .......... 上传文件任务
│       ├── _cloud_do_ai_interaction .. AI通通互动任务
│       ├── _cloud_open_album_backup .. 打开相册备份任务
│       ├── _cloud_do_ai_query_for_lottery DeepSeek对话获取抽奖资格
│       ├── _cloud_check_lottery_times  查询抽奖次数
│       └── _cloud_lottery ............ 执行抽奖
│
│   └── 📚 联通阅读 (Woread)
│       ├── woread_task ............... 阅读任务入口
│       ├── woread_auth ............... 设备预登录获取accesstoken
│       ├── woread_login .............. 账号登录获取usertoken
│       ├── woread_get_book_info ...... 获取书籍信息
│       ├── woread_read_process ....... 模拟阅读任务
│       ├── _woread_heartbeat ......... 阅读心跳上报
│       ├── _woread_add_read_time ..... 添加阅读时长
│       ├── woread_draw_new ........... 抽奖(活动ID:8051)
│       └── woread_queryTicketAccount . 查询话费红包余额
│
└── 🚀 main (主程序入口) ............ 并发调度所有账号任务
```

## ✨ 功能特性

### 双模式登录
- **Token登录**: 推荐方式，使用抓包获取的token_online登录，稳定可靠
- **账密登录**: 使用手机号+登录专用密码直接登录，无需抓包，但易触发风控
- **自动识别**: 脚本自动检测输入格式，选择对应登录方式
- **自动转换**: 账密登录成功后自动将环境变量更新为Token格式（青龙面板）

### 权益超市增强功能
- **接口自动解密**: 自动处理权益超市接口的 AES 加密响应，修复任务列表获取失败的问题
- **分享任务自动完成**: 自动完成分享小红书任务，获取额外抽奖机会
- **每日自动抽奖**: 无条件执行抽奖，不受奖池状态影响
- **奖池信息展示**: 可选功能，抽奖完成后展示今日奖池信息（默认关闭）
- **有效奖品识别**: 自动标记有效奖品（包含月卡/周卡/季卡，排除5G宽视界/沃视频）
- **人机验证处理**: 抽奖触发人机验证时自动处理并继续抽奖
- **浇花任务修复**: 支持多次浇花直到完成目标次数（如60次）
- **全局奖池查询**: 多账号只查询一次奖池，共享结果，节省资源

### 云手机活动
- **自动领券**: 每日自动领取优惠券（如美团生活服务券）
- **任务状态同步**: 自动触发任务状态同步，确保可领取抽奖次数
- **每日抽奖**: 完成任务后自动执行抽奖

### 签到区-任务中心
- **任务自动完成**: 自动浏览任务页面并完成任务
- **奖励自动领取**: 任务完成后自动领取奖励
- **循环执行**: 持续执行直到所有可完成任务都已处理

### 联通安全管家
- **每日签到**: 自动完成安全管家签到任务
- **积分任务**: 自动完成添加黑名单、号码标记、同步通讯录、骚扰拦截设置、查看周报等任务
- **积分领取**: 任务完成后自动领取积分奖励
- **积分统计**: 显示本次运行获得的积分数量

### 联通云盘
- **每日签到**: 自动完成云盘签到任务
- **多项任务**: 支持浏览活动中心、分享文件、上传文件、AI通通互动、打开相册备份等任务
- **积分领取**: 任务完成后自动领取积分奖励
- **DeepSeek抽奖**: 通过DeepSeek对话获取抽奖资格并自动抽奖
- **积分统计**: 显示本次运行获得的积分数量

### 联通阅读
- **自动登录**: 设备预登录+账号登录双重认证
- **模拟阅读**: 自动获取书籍信息并模拟阅读（心跳上报+阅读时长）
- **每日抽奖**: 完成阅读任务后自动执行抽奖
- **余额查询**: 显示话费红包余额

## 🚀 快速开始

### 1. 安装依赖
```bash
pip install httpx

# 必需安装（用于权益超市接口解密及账密登录）：
pip install pycryptodome
```

### 2. 配置账号

脚本通过环境变量 `chinaUnicomCookie` 获取用户登录信息。支持多账号，多个账号之间使用 `@` 符号分隔。

#### 方式一：Token登录（推荐）

格式：`token_online字符串` 或 `token_online#appid`

1. 使用抓包工具（如Stream、Fiddler）抓取中国联通APP的请求
2. 找到 `https://m.client.10010.com/mobileService/onLine.htm` 请求
3. 提取请求体中的 `token_online` 值（可选：同时提取 `appId`）

```bash
# 仅 token_online
export chinaUnicomCookie="your_token_online_string"

# token_online + appid（更稳定）
export chinaUnicomCookie="your_token_online#your_appid"
```

#### 方式二：账密登录

> ⚠️ **注意**: 账密登录容易触发安全风控，建议优先使用Token登录
>
> 💡 **自动转换**: 在青龙面板中使用账密登录成功后，脚本会自动将环境变量更新为 `token_online#appid` 格式，后续运行将使用Token登录

格式：`手机号#登录专用密码`

```bash
# 单账号
export chinaUnicomCookie="18812345678#yourpassword"

# 多账号
export chinaUnicomCookie="18812345678#password1@18887654321#password2"
```

> 登录专用密码需要在联通APP中设置，不是服务密码。

#### 方式三：混合使用

可以同时使用两种登录方式：

```bash
export chinaUnicomCookie="token_string@18812345678#password"
```

### 3. 可选配置

编辑 `中国联通.py` 文件顶部的常量：

```python
SHOW_PRIZE_POOL = False  # 是否显示权益超市奖品池信息，默认关闭
```

### 4. 执行模式切换

脚本默认采用**并行模式**运行多个账号，如需改为**顺序执行**（一个账号完成后再执行下一个），修改 `main()` 函数：

**并行模式（默认）**：
```python
tasks = []
for i, cookie in enumerate(cookies.split('@')):
    if not cookie.strip():
        continue
    user = CustomUserService(cookie, index=i+1)
    tasks.append(user.user_task())

if tasks:
    await asyncio.gather(*tasks)
```

**顺序模式**：
```python
for i, cookie in enumerate(cookies.split('@')):
    if not cookie.strip():
        continue
    user = CustomUserService(cookie, index=i+1)
    await user.user_task()
```

### 5. 运行脚本
```bash
python 中国联通.py
```

### 6. 查看运行结果
脚本运行后，将在控制台输出详细的执行日志。
- **登录状态**: 显示登录成功/失败及脱敏后的手机号（如 `138****5678`）
- **登录方式**: 显示使用的是账密登录还是Token登录
- **任务进度**: 实时显示各个任务的执行情况（如"签到成功"、"获得0.87元立减金"）
- **抽奖结果**: 显示具体的奖品名称（如"5元话费券"、"未中奖"）

#### 奖池查询输出示例（开启 SHOW_PRIZE_POOL 时）
```
============================================================
权益超市奖品池查询
============================================================
今日奖池共 16 个奖品:

  ✅ [01] 爱奇艺VIP月卡
       今日投放: 100 | 总库存: 5000 | 概率: 5.00%
  ❌ [02] 5G宽视界黄金会员月卡
       今日投放: 50 | 总库存: 3000 | 概率: 3.00%
  ❌ [03] 茶百道6元免配券
       今日投放: 5000 | 总库存: 0 | 概率: 15.00%
  ...

============================================================
结论: 当前已放水！有效奖品 3/16 个，可以抽奖
============================================================
```

## ❓ 常见问题与故障排除

### 1. 账密登录相关

| 错误信息 | 原因 | 解决方案 |
|---------|------|---------|
| 密码错误 | 登录专用密码不正确 | 在联通APP中重置登录专用密码 |
| 未设置登录专用密码 | 账号未开启登录专用密码 | 前往联通APP设置登录专用密码 |
| 触发安全风控 | 登录频率过高或异常 | 手动打开联通APP登录一次解除 |
| 账密登录需要pycryptodome | 缺少加密库 | `pip install pycryptodome` |

### 2. Token登录失败处理
如果遇到Token登录失败的情况，请尝试以下步骤：
1. 使用抓包工具获取本机实际的 `device_id` 和 `device_code`
2. 打开 `中国联通.py` 文件，找到 `_login_with_token` 函数
3. 将代码中的 `device_id` 和 `device_code` 替换为抓包获取的实际值

### 3. 权益超市相关
- **浇花状态异常**: 已修复只浇花一次的问题，现在会持续浇花直到完成目标次数
- **奖池信息**: 设置 `SHOW_PRIZE_POOL = True` 可在抽奖后展示今日奖池
- **人机验证**: 触发人机验证时会自动处理，无需手动干预

## 注意事项

- **HTTP/2**: 为保证稳定性，脚本默认关闭了HTTP/2支持
- **异常处理**: 脚本内置了完善的异常捕获机制，单个任务的失败不会影响其他任务或账号的执行
- **隐私安全**: 所有敏感信息（如手机号）在日志输出时均会自动脱敏，保障用户隐私
- **奖池共享**: 权益超市奖池查询只执行一次，所有账号共享结果，避免重复请求

## ⚠️ 免责声明

1. **仅供学习交流**：本项目仅供编程学习和技术交流使用，请勿用于任何商业用途。
2. **合法使用**：请勿将本脚本用于任何非法目的，包括但不限于恶意攻击、刷单等行为。
3. **风险自担**：使用本脚本产生的任何后果（包括但不限于账号封禁、财产损失等）由使用者自行承担，开发者不承担任何责任。
4. **隐私保护**：本项目不会收集用户的任何敏感信息，所有数据均保存在用户本地。
5. **侵权联系**：如果本项目侵犯了您的权益，请及时联系开发者进行处理。

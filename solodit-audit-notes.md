# Solodit 漏洞案例学习笔记

> 训练目标：通过阅读 Solodit 上的 Medium/High 漏洞案例，积累审计思路和漏洞模式识别能力。

---

## 漏洞案例索引

| # | 漏洞名称 | 类型 | 严重等级 | 来源 |
|---|---------|------|---------|------|
| [1](#case-1) | Unchecked `approve()` return causes permanent fund loss | 未检查返回值 / 非标准 ERC20 | Medium | Garden - Code4rena |
| [2](#case-2) | Malicious user can spam orders to wipe out legit orders from one-sided book | Griefing / DoS / 订单簿驱逐 | Medium | GTE - Code4rena |
| [3](#case-3) | Liquidation blocked by pausing or blacklisting NFT contract, trapping expired loans | 外部依赖 / Admin DoS / 清算阻断 | Medium | Shiny - Jan 2026 |
| [4](#case-4) | Chained signature with checkpointer disabled bypasses all checkpointer validation | 签名验证绕过 / Flag 位操控 | High | Sequence - Code4rena |
| [5](#case-5) | Pool manager swaps requestManager between request creation and callback to steal globalEscrow funds | TOCTOU / Manager 替换攻击 / 跨池资金盗窃 | High | Centrifuge V3 - Sherlock |
| [6](#case-6) | redeemNative() reentrancy via malicious swap path token causes double-subtraction and permanent fund freeze | 重入 / CEI 违反 / 会计操控 / 清算级联 | Critical | Notional Finance - Nov 2025 |
| [7](#case-7) | Ceiling division accumulation in delegated withdrawal causes totalDelegatedAmount to exceed amount, locking all funds | 向上取整累加溢出 / 委托提款下溢 / 资金永久锁死 | Critical | BvtRewardVault |
| [8](#case-8) | Malformed `op::get_fees_notification` payload in `fee_manager` breaks fee updates | 跨合约消息格式不匹配 / Payload Schema 破坏 / DoS | Medium | XDAO - Aug 2025 |
| [9](#case-9) | Stake-exit lag + ZK null-key voting power forgery allow consensus takeover with zero stake at risk | TOCTOU / 质押窗口期 / ZK 电路缺陷 / 椭圆曲线单位元 | High/Critical | Symbiotic Relay - Sherlock Jul 2025 |
| [10](#case-10) | Inverted vesting curve exposes full interest immediately after update, enabling MEV sandwich attacks | Vesting 曲线反向 / MEV 套利 / Share Price 操控 | High | LoopVaults - Pashov Jul 2025 |
| [11](#case-11) | Stale totalValues cache after internal trade fees causes incorrect weight deviation check, blocking valid rebalances | 状态缓存未同步 / 手续费未计入 / 权重检查失真 | High | Cove - Jun 2025 |
| [12](#case-12) | Decimal mismatch between bond and stablecoin causes incorrect sqrtPriceX96 and wrong LDF tick bounds | Decimal 不匹配 / Uniswap tick 计算错误 / 流动性分布偏移 | Medium | Bunni - Cyfrin Jun 2025 |
| [13](#case-13) | block.timestamp as DEX swap deadline is a no-op, allowing validators to delay execution for MEV | 无效 Deadline / block.timestamp 误用 / MEV / 验证者操控 | Medium | Hyperhyper - Jun 2025 |
| [14](#case-14) | ERC1271 isValidSignature lacks context binding, enabling historical and cross-chain signature replay | 签名重放 / ERC1271 / EIP-712 上下文缺失 / 跨链重放 | High | SSO Account - May 2025 |
| [15](#case-15) | Bitcoin Observers use empty prevOut in sighash computation, causing all withdrawal transactions to be rejected by the Bitcoin network | Bitcoin sighash 错误 / Taproot BIP341 / UTXO prevOut 缺失 / 提款 DoS | Medium | ZetaChain - Sherlock May 2025 |
| [16](#case-16) | ExecuteRequest queue in Cosmos context not reverted with EVM statedb snapshot, causing reverted inner calls to still dispatch Cosmos messages | 跨VM状态不同步 / EVM revert 不还原 Cosmos 队列 / try/catch 绕过 | High | Initia - Code4rena Apr 2025 |
| [17](#case-17) | Attacker frontruns permit signature submission, causing user's combined permit+action transaction to revert | EIP-2612 Permit / 抢跑 / Griefing DoS / try/catch 缺失 | Medium | LI.FI - Cantina Dec 2024 |

---

## 案例详情

---

### <a id="case-1"></a>案例 #1：Unchecked `approve()` Return — 永久资金锁定

**来源**：Garden · Code4rena · Feb 2026 · Medium
**文件**：`swap/UDA.sol` L38

---

#### 漏洞类型

**未检查 ERC20 `approve()` 返回值**（Unchecked Return Value / Non-standard ERC20）

---

#### 漏洞描述

`UniqueDepositAddress.initialize()` 调用了 `ERC20.approve()`，但**没有检查返回值**：

```solidity
HTLC(_addressHTLC).token().approve(_addressHTLC, amount);  // ❌ 返回值被忽略
```

标准 ERC20（OpenZeppelin）在失败时会 revert，但 **非标准代币（如 USDT、BNB）失败时只返回 `false` 而不 revert**。
于是执行继续向下走，`initiateOnBehalf()` 被调用，但 HTLC 的 allowance 为 0，无法转走代币，资金被永久锁死。

---

#### 攻击链

```
用户存入 USDT
→ initialize() 被调用
→ approve() 返回 false（USDT 特性）
→ 未检测，执行继续
→ 合约标记为 initialized（无法重新初始化）
→ allowance = 0，HTLC 无法 transferFrom
→ 资金永久锁死，无恢复机制
```

---

#### 根因

合约已经 import 了 `SafeERC20`，并在 `recover()` 系函数中使用，但在关键的 `approve()` 处遗漏，直接调用了原生方法。

---

#### 修复方式

用 `SafeERC20.safeApprove()` 替换原生 `approve()`：

```solidity
// ✅ 修复：使用已导入的 SafeERC20
IERC20(HTLC(_addressHTLC).token()).safeApprove(_addressHTLC, amount);
```

`safeApprove` 内部会检查返回值，若为 `false` 则 revert，阻止后续执行。

---

#### 审计思路

1. 搜索所有 `approve()` 调用，检查是否直接调用而非 `safeApprove()`
2. 重点关注涉及**非标准代币**的协议（DEX、跨链桥、HTLC 等）
3. 检查合约是否 import 了 `SafeERC20` 却没有统一使用
4. 查看 `approve()` 之后的逻辑是否依赖 allowance——若依赖，则 silent fail 会造成严重后果
5. 注意 `initializer` 修饰的函数：一旦执行完毕无法重试，错误影响不可逆

---

#### 适用场景

| 场景 | 说明 |
|------|------|
| 跨链桥 / HTLC | approve 后立即调用 transferFrom，最典型 |
| DEX 聚合器 | 在 swap 前 approve router，非标代币易出问题 |
| 一次性初始化合约 | initializer 函数中 approve 失败无法重试 |
| 协议支持 USDT/BNB 等 | 这类代币 approve 失败不 revert |

---

#### 关键词速查

`approve` · `SafeERC20` · `safeApprove` · `USDT` · `non-standard ERC20` · `unchecked return` · `initializer`

---

### <a id="case-2"></a>案例 #2：订单簿 Griefing — 即时过期订单驱逐合法订单

**来源**：GTE · Code4rena · Feb 2026 · Medium
**文件**：`clob/CLOB.sol` L592

---

#### 漏洞类型

**Griefing / DoS — 订单簿驱逐攻击**（Order Book Eviction via Zero-Cost Spam）

---

#### 漏洞描述

订单簿有两个设计：

1. **容量上限**：每侧最多 `maxNumLimitsPerSide` 个限价单，满了就踢掉竞争力最差的订单
2. **无最短存活时间**：创建订单时对 `cancelTimestamp` 没有下限限制，允许设置为"下一秒"过期

攻击者利用这两点组合：提交**大量高价但立刻过期**的订单，将合法用户的订单全部从订单簿中驱逐。由于订单极短时间内就过期，攻击者几乎不承担被成交的风险，到期后还能退款。

---

#### 攻击链

```
攻击者用多个账号（绕过单账号限制）
→ 每个账号提交高价 bid 订单，cancelTimestamp = block.timestamp + 1
→ 订单比现有合法订单更有竞争力（价格更高）
→ CLOB 触发驱逐逻辑，把合法订单踢出订单簿
→ 攻击者订单 1 秒后过期，资金退回
→ 合法用户订单永久丢失，需要重新挂单
→ 攻击者循环重复，持续瘫痪单侧订单簿
```

**为什么只对单侧订单簿有效？**
如果对侧有大量挂单，攻击者提交的高价订单会被直接撮合成交，攻击者反而亏损。只有单侧为空（买单侧或卖单侧无对手盘）时，高价订单不会被成交，攻击才零成本。

---

#### 根因

两个缺陷缺一不可：

| 缺陷 | 说明 |
|------|------|
| 无最短存活时间 | `cancelTimestamp` 可设为当前时间+1秒 |
| 驱逐机制无保护 | 满员时直接踢最差订单，不验证新订单的有效期 |

---

#### 修复方式

1. **强制最短存活时间**（如 10 分钟）：
   ```solidity
   require(order.cancelTimestamp >= block.timestamp + MIN_ORDER_LIVENESS, "Order too short-lived");
   ```
2. **禁止在最短存活期内 cancel**：
   ```solidity
   require(block.timestamp >= order.createTimestamp + MIN_ORDER_LIVENESS, "Cannot cancel yet");
   ```

两者必须同时实施，否则攻击者可以通过 `cancel()` 绕过过期机制。

---

#### 审计思路

1. 凡是有**容量上限 + 驱逐机制**的数据结构，立刻问：**新进来的数据有没有质量门槛？**
2. 检查订单/投票/申请等有时效的操作：**有没有最短存活期限制？**
3. 评估攻击成本：如果攻击者能在不承担任何损失的情况下触发驱逐，就是 Griefing
4. 多账号绕过单账号限制是经典模式，问：**per-address 限制能否被多账号绕过？**
5. 分析攻击的前置条件：此题要求"单侧订单簿"，这类有条件的漏洞评 Medium 而非 High

---

#### 适用场景

| 场景 | 说明 |
|------|------|
| 链上 CLOB / 订单簿 | 最典型，有容量限制 + 驱逐机制 |
| 链上投票 / 提案系统 | 有最大提案数，可被恶意提案驱逐合法提案 |
| 优先队列类合约 | 满员驱逐最差元素，新元素无准入门槛 |
| 任何有 TTL 的链上数据 | 无最短存活期 = 零成本占位 + 立刻释放 |

---

#### 关键词速查

`griefing` · `DoS` · `order book` · `eviction` · `maxNumLimitsPerSide` · `cancelTimestamp` · `minimum liveness` · `spam orders` · `multi-account`

---

### <a id="case-3"></a>案例 #3：清算被外部合约 Pause/Blacklist 永久阻断

**来源**：Shiny · Jan 2026 · Medium
**文件**：`Pawn.sol` L262、`sRWA.sol` L189、L270

---

#### 漏洞类型

**外部依赖导致核心功能 DoS**（External Dependency DoS / Admin-Controlled Griefing）

---

#### 漏洞描述

`PawnShop.liquidate()` 通过调用 RWA NFT 合约的 `burn()` 来完成清算，但这个 `burn()` 受外部合约的两个管控机制保护：

```solidity
// Pawn.sol - 清算函数
function liquidate(uint256 tokenId) external nonReentrant whenNotPaused onlyRole(MANAGER_ROLE) {
    // ...
    IERC721Burnable(address(nftToken)).burn(tokenId); // ⬅ 依赖外部合约状态
}

// sRWA.sol - burn 受 pause 保护
function burn(uint256 tokenId) external onlyTokenOwner(tokenId) whenNotPaused {
    _burn(tokenId);
}

// sRWA.sol - transfer/burn 内部检查黑名单
function _update(address to, uint256 tokenId, address auth) internal override returns (address) {
    if (auth != address(0) && _isBlacklisted[auth]) revert Blacklisted(); // ⬅ PawnShop 被拉黑就revert
}
```

只要 RWA 管理员执行以下任一操作：
- **暂停 RWA 合约**（`pause()`）
- **将 PawnShop 地址加入黑名单**

`liquidate()` 就会永久 revert，到期的贷款无法被清算，抵押物永久锁在 PawnShop 里。

---

#### 攻击链

```
用户正常质押 NFT 开仓
→ 到达 deadline，贷款到期
→ 管理员（有意或无意）pause RWA 或将 PawnShop 加黑名单
→ Manager 调用 liquidate(tokenId)
→ 调用链：liquidate → burn → _update → revert Blacklisted / Paused
→ 贷款无法关闭，抵押物卡死
→ 借款人也无法赎回（deadline 已过），陷入双向锁死
```

**注意**：这不一定是恶意攻击，管理员的**常规维护操作**（暂停合约）也可能无意触发。

---

#### 根因

**协议的核心操作（清算）依赖了外部合约的内部状态**，而该外部合约由第三方管理员控制，协议对其没有任何控制权。这是一种**信任边界混淆**问题：

- 协议信任外部 NFT 的 `burn()` 永远可用
- 实际上 `burn()` 随时可能被外部管理员单方面关闭

---

#### 修复方式

核心思路：**解耦清算逻辑与外部 burn 的强依赖**，提供 fallback 路径：

```solidity
// 方案一：burn 失败时，转移到协议控制地址
function liquidate(uint256 tokenId) external {
    try IERC721Burnable(address(nftToken)).burn(tokenId) {
        // 正常 burn
    } catch {
        // fallback：转移到协议金库，而不是卡死
        IERC721(address(nftToken)).transferFrom(address(this), protocolVault, tokenId);
    }
    pawns[tokenId].active = false;
}

// 方案二：给 PawnShop 一个特殊角色，绕过 pause 和黑名单
// 方案三：修改 RWA，pause 不阻止协议清算 burn
```

同时建议：在 deadline 到达后、清算发生前，允许借款人自行赎回，避免双向锁死。

---

#### 审计思路

1. **找出核心不可失败的操作**：清算、还款、提款——这些一旦被阻断影响极大
2. **追踪这些操作依赖的所有外部调用**，问：外部合约有没有 `pause`、`blacklist`、`onlyOwner` 这类管控机制？
3. **评估外部合约的管理员是谁**：是协议自己还是第三方？第三方控制的永远是风险点
4. **RWA 类资产特别危险**：RWA（真实世界资产）NFT 几乎必然带有合规控制（pause/blacklist/freeze），要默认假设这些机制存在
5. 检查是否存在**双向锁死**：借款人不能赎回，协议也不能清算，资产永久卡死

---

#### 适用场景

| 场景 | 说明 |
|------|------|
| 使用 RWA 作为抵押品的借贷协议 | RWA 必有合规控制，风险最高 |
| 依赖外部 NFT burn/transfer 的协议 | burn 路径被外部控制 |
| 跨协议调用的清算/结算逻辑 | 任何外部调用都可能被管理员阻断 |
| 使用带 pause 机制的代币作为核心资产 | pause 一旦生效，所有操作链断裂 |

---

#### 关键词速查

`external dependency` · `pause` · `blacklist` · `RWA` · `liquidation blocked` · `DoS` · `trust boundary` · `burn` · `fallback path` · `永久锁死`

---

### <a id="case-4"></a>案例 #4：Chained 签名禁用 Checkpointer 标志位，完全绕过配置验证

**来源**：Sequence · Code4rena · Nov 2025 · High
**文件**：`src/modules/auth/BaseSig.sol` L88

---

#### 漏洞类型

**签名验证绕过 — 标志位操控导致安全机制静默跳过**（Signature Validation Bypass via Flag Manipulation）

---

#### 背景：Checkpointer 和 Chained Signature 是什么

Sequence 是一个多签智能合约钱包，支持**配置更新**（谁是签名者、权重阈值等）。

**Checkpointer（检查点器）**：
- 跟踪钱包配置的"最新版本"（imageHash + checkpoint 编号）
- 每次配置更新会产生新的 checkpoint
- 用于确保签名者用的是最新配置，而不是过时的旧配置

**Chained Signature（链式签名）**：
- 当钱包链上配置落后于 checkpointer 时使用
- 结构：`[旧配置→新配置的更新证明链] + [最终操作签名]`
- 本质是把"配置更新历史"内嵌在签名里，一次性验证

**正常安全逻辑**：
```
Config1(checkpoint=1): Alice 是签名者
Config2(checkpoint=2): Alice 被移除，Bob 加入

Alice 用 chained signature：
→ checkpointer 验证最新 snapshot 是 Config2
→ 发现 Alice 不在 Config2 里
→ ❌ 拒绝
```

---

#### 漏洞描述

签名 flag 字节的 **bit 6（0x40）** 控制是否启用 checkpointer。代码逻辑：

```solidity
// BaseSig.sol L88 - 只有 bit6=1 才进入 checkpointer 验证
if (signatureFlag & 0x40 == 0x40 && _checkpointer == address(0)) {
    (_checkpointer, rindex) = _signature.readAddress(rindex);

    if (!_ignoreCheckpointer) {
        // 调用 checkpointer 获取最新 snapshot
        snapshot = ICheckpointer(_checkpointer).snapshotFor(address(this), checkpointerData);
    }
}

// 之后进入 chained 处理
if (signatureFlag & 0x01 == 0x01) {
    return recoverChained(_payload, _checkpointer, snapshot, _signature[rindex:]);
    // ↑ 如果 bit6=0，_checkpointer=address(0)，snapshot={0,0} 全是零值
}
```

攻击者构造外层 flag：`bit6 = 0`（不启用 checkpointer），`bit0 = 1`（使用 chained）：

```
outerFlag = 0x05  // 0b00000101: bit0=1(chained), bit2=1(某类型), bit6=0(无checkpointer)
```

结果：
- `_checkpointer = address(0)`
- `snapshot.imageHash = bytes32(0)`
- `snapshot.checkpoint = 0`

这三个零值传入 `recoverChained()`，后续所有校验都用零值参与判断。

---

#### 绕过链（零值如何使所有检查静默通过）

**检查 1**：内层签名的最终验证

```solidity
// BaseSig.sol L138-140
if (snapshot.imageHash != bytes32(0) && snapshot.imageHash != imageHash && checkpoint <= snapshot.checkpoint) {
    revert UnusedSnapshot(snapshot);
}
// snapshot.imageHash == bytes32(0) → 整个条件为 false → ✅ 直接跳过
```

**检查 2**：recoverChained 中的 snapshot 比对

```solidity
if (_snapshot.imageHash == imageHash) {
    // _snapshot.imageHash = 0，imageHash != 0 → 不进入
    _snapshot.imageHash = bytes32(0);
}
```

**检查 3**：checkpoint 顺序验证

```solidity
if (checkpoint >= prevCheckpoint) {
    revert WrongChainedCheckpointOrder(checkpoint, prevCheckpoint);
}
// prevCheckpoint 初始化为 type(uint256).max
// 攻击者提供任何 checkpoint 值都 < max → ✅ 跳过
```

**检查 4**：最终 snapshot 校验

```solidity
if (_snapshot.imageHash != bytes32(0) && checkpoint <= _snapshot.checkpoint) {
    revert UnusedSnapshot(_snapshot);
}
// _snapshot.imageHash 仍为 0 → ✅ 跳过
```

**结果**：Alice 用 **Config1**（已过时的配置）的签名验证通过，checkpointer 完全被绕过，她对钱包的操作被视为合法。

---

#### 攻击链

```
Config1: Alice 是签名者（checkpoint=1）
Config2: Alice 被移除（checkpoint=2）← checkpointer 已更新至此

攻击者（Alice）：
→ 构造外层 flag：bit6=0（不设 checkpointer），bit0=1（使用 chained）
→ 内层嵌入针对 Config1 的合法签名（Alice 仍在 Config1 里）
→ 所有零值校验静默跳过
→ 恢复出 Config1 的 imageHash，与链上当前状态匹配
→ 签名验证通过 ✅
→ Alice 以被驱逐身份成功授权钱包操作
```

---

#### 根因

**Flag 位的组合没有互斥约束**：`chained=1` 和 `checkpointer=0` 可以同时成立，但语义上这是矛盾的——链式签名的核心目的就是遍历配置更新历史，没有 checkpointer 的链式签名毫无意义，且绕过了全部安全保障。

本质：**功能标志位（feature flags）之间缺少合法性约束检查**。

---

#### 修复方式

在进入 chained 处理前，强制要求 checkpointer 必须已设置：

```solidity
// BaseSig.sol 补丁
if (signatureFlag & 0x01 == 0x01) {
+   if (signatureFlag & 0x40 == 0) {
+       revert MissingCheckpointer();  // chained 必须配合 checkpointer
+   }
    return recoverChained(_payload, _checkpointer, snapshot, _signature[rindex:]);
}
```

一行代码，阻断整条攻击链。

---

#### 审计思路

1. **对所有 flag/bitmask 系统**，枚举 flag 的所有组合，找出"语义上不合法"但代码未禁止的组合
2. **零值在安全校验中的危险性**：`if (x != 0 && ...)` 这类条件，如果 x 可以被操控为 0，则整个条件被短路
3. **追踪安全关键变量的初始化路径**：`_checkpointer`、`snapshot` 等在什么条件下会是零值？零值进入后续逻辑会怎样？
4. **多层嵌套的验证逻辑要逐层看**：外层跳过某个步骤时，内层的哪些假设会被打破？
5. **"chained / nested / recursive" 类签名验证是高危区域**：复杂性高，edge case 多，flag 组合爆炸

---

#### 适用场景

| 场景 | 说明 |
|------|------|
| 多签钱包 / 智能账户 | 配置更新 + 签名验证组合，最典型 |
| 具有版本/配置概念的合约 | checkpoint / snapshot 类机制 |
| 使用 bitmask 控制功能路径的合约 | flag 组合的互斥约束容易遗漏 |
| 零值作为"未初始化"状态参与安全判断 | bytes32(0) / address(0) 短路条件 |

---

#### 关键词速查

`signature bypass` · `bitmask` · `flag manipulation` · `chained signature` · `checkpointer` · `zero value` · `short-circuit` · `evicted signer` · `imageHash` · `snapshot` · `multi-sig wallet`

---

### <a id="case-5"></a>案例 #5：requestManager 替换攻击 — 盗取 globalEscrow 全部待处理存款

**来源**：Centrifuge Protocol V3 · Sherlock · Nov 2025 · High
**文件**：`Spoke.sol` L322、L340、`Hub.sol` L222、`AsyncRequestManager.sol` L254

---

#### 漏洞类型

**TOCTOU（检查时间与使用时间不一致）/ Manager 替换攻击 / 跨池资金盗窃**

---

#### 背景：协议结构

Centrifuge V3 是跨链投资基金协议，核心资金流：

```
用户调用 AsyncVault.requestDeposit()
→ 资金转入 globalEscrow（所有池共享的全局托管账户）
→ Hub 处理请求，批准后回调 Spoke
→ Spoke.requestCallback() 调用当前 requestManager
→ AsyncRequestManager.approvedDeposits() 将资金从 globalEscrow 转入对应池的 poolEscrow
```

`requestManager` 是每个 poolId 对应的可插拔模块，pool 管理员可以随时更换。

---

#### 漏洞描述

**创建请求时**：校验 `msg.sender == 当前 requestManager`

```solidity
// Spoke.sol L322
function request(...) external payable {
    IRequestManager manager = requestManager[poolId];
    require(msg.sender == address(manager), NotAuthorized()); // ✅ 验证发送者
    sender.sendRequest(...);
}
```

**回调时**：使用**此刻的** requestManager，而不是创建请求时的那个

```solidity
// Spoke.sol L340
function requestCallback(...) external auth {
    IRequestManager manager = requestManager[poolId]; // ← 取当前值，不验证是否与创建时一致
    manager.callback(poolId, scId, assetId, payload); // ← 交给当前 manager 处理
}
```

这两个操作之间，pool 管理员可以随意调用 `hub.setRequestManager()` 更换 manager，代码没有任何阻止。

---

#### 攻击链

```
背景：globalEscrow 里存着合法用户 A 存入 POOL_A 的 1000 USDC

① 攻击者创建自己的 attackerPool，拥有 pool 管理员权限

② 攻击者设置 MaliciousRequestManager 为 attackerPool 的 requestManager

③ MaliciousRequestManager 调用 spoke.request()，创建虚假存款请求：
   "attackerPool 有人要存入 1000 USDC"
   → 通过校验（msg.sender == 当前 manager ✅）
   → 请求发往 Hub，Hub 记录 pendingDeposit += 1000

④ 攻击者把 attackerPool 的 requestManager 换成 AsyncRequestManager（合法实现）

⑤ 攻击者作为 pool 管理员调用 batchRequestManager.approveDeposits()
   → 触发回调链：Hub → Spoke.requestCallback()
   → requestCallback 取当前 manager = AsyncRequestManager
   → 调用 AsyncRequestManager.approvedDeposits()

⑥ approvedDeposits() 执行：
   globalEscrow.authTransferTo(asset, tokenId, poolEscrow(attackerPool), 1000)
   → 从 globalEscrow 把 1000 USDC 转入攻击者的 poolEscrow ✅

⑦ 攻击者通过 hub.updateBalanceSheetManager() 给自己 balanceSheet 管理权
   → 调用 balanceSheet.withdraw() 提走所有资金
```

**关键**：globalEscrow 是所有池共享的，攻击者用虚假请求消费了真实用户的资金。

---

#### 深入理解：AsyncRequestManager 是什么？

**`AsyncRequestManager` 不是某个池子的专属管理员，而是协议的通用基础设施合约**。所有异步池子共用同一个 `AsyncRequestManager` 实例，它负责实现标准的存款/赎回回调逻辑。

```
AsyncRequestManager 实例（协议全局唯一）
    ├── Pool_A（RWA 基金）
    ├── Pool_B（货币市场）
    └── Pool_C（attackerPool）
```

`requestManager` 是**按类型共用**，不是一池一个专属合约。攻击 Step 4 换回 `AsyncRequestManager` 的原因：
- 恶意 manager 只负责"制造假账"（伪造 pendingDeposit），它不实现 `onApproveDeposits` 回调
- 换回 `AsyncRequestManager` 后，取款回调路径全部走正常代码，协议视角看不到任何异常
- 攻击者顺利拿到铸造的份额

**正常异步池子全程不需要替换 manager**。因此在系统中观察到某个池子的 `requestManager` 被替换，本身就是强烈异常信号。

---

#### 根因

**请求的"创建者身份"与"回调接收者"没有绑定**。

协议设计隐含了一个假设：创建请求的 manager 和接收回调的 manager 是同一个。但代码没有强制这个约束，而 pool 管理员随时可以替换 manager，制造了 TOCTOU 窗口：

```
创建时：manager = MaliciousManager  → 通过校验
替换后：manager = AsyncRequestManager → 接收回调，操作合法资金
```

本质：**可变状态（requestManager）被用在了对不变性有要求的两阶段操作中**。

---

#### 修复方式

**推荐方案：白名单机制**，只允许经过治理审批的 manager 被设置：

```solidity
// Spoke.sol
mapping(address => bool) public authorizedRequestManagers;

function request(...) external payable {
    IRequestManager manager = requestManager[poolId];
    require(msg.sender == address(manager), NotAuthorized());
+   require(authorizedRequestManagers[address(manager)], UnauthorizedRequestManager());
    // ...
}

// Hub.sol
function setRequestManager(...) external payable {
    _isManager(poolId);
+   require(authorizedHubRequestManagers[address(hubManager)], UnauthorizedHubRequestManager());
    // ...
}
```

这样即使攻击者是 pool 管理员，也无法将恶意 manager 设置为 requestManager。

**备选方案**：在请求中绑定 manager 地址，回调时校验一致性：

```solidity
// 在请求 payload 中记录创建时的 manager
// requestCallback 时验证 requestManager[poolId] == 记录的 manager
```

---

#### 审计思路

1. **找"两阶段操作"**：请求创建 → 请求处理，投票提交 → 投票执行，订单创建 → 订单结算——凡是有时间差的两步操作，问：**两步之间有没有可变状态被信任？**

2. **可插拔模块系统是高危区域**：manager、strategy、hook 等可替换组件，若在操作中途可以被换掉，就存在这类风险

3. **评估 pool 管理员的权限边界**：pool 管理员能不能做"合法但被滥用"的操作？这里 setRequestManager 本身是合法的，但与资金流组合后变成了攻击手段

4. **追踪共享资源（globalEscrow）的访问控制**：谁能触发从 globalEscrow 转账？转账的前提条件是否足够严格？

5. **检查 auth 类函数的调用链**：`authTransferTo` 这类高权限函数，逆向追踪"谁能调用它"，验证调用路径上的每个节点是否都有充分校验

---

#### 适用场景

| 场景 | 说明 |
|------|------|
| 可插拔 manager / strategy 系统 | manager 在两阶段操作中途被替换 |
| 跨链协议的请求-回调模式 | 请求在链A创建，回调在链B执行，中间有时间差 |
| 共享资金池（多池共用一个 escrow） | 一个池的操作可以消耗其他池的资金 |
| 任何"提交→审批→执行"的多步流程 | 各步骤之间的状态绑定容易被遗漏 |

---

#### 关键词速查

`TOCTOU` · `manager swap` · `requestManager` · `globalEscrow` · `two-phase operation` · `pluggable module` · `cross-pool theft` · `callback` · `state binding` · `whitelist`

---

### <a id="case-6"></a>案例 #6：redeemNative() 重入 — 恶意 Swap 路径导致双重扣减与永久资金冻结

**来源**：Notional Finance · Nov 2025 · Critical
**文件**：`AbstractYieldStrategy.sol` `redeemNative()` / `_burnShares()`

---

#### 漏洞类型

**重入攻击 / CEI 原则违反 / 内部会计双重扣减 / 清算级联**（Reentrancy via External Swap Path → Accounting Corruption）

---

#### 背景

Notional V4 是一个收益策略 Vault 协议，用户存入资产换取 shares。`redeemNative()` 允许用户通过指定 DEX（包括 Uniswap V2）赎回份额，将 yieldToken swap 成原始资产。

协议内部用 `s_yieldTokenBalance` 追踪 vault 持有的 yieldToken 数量，用于计算 share price：

```
share price = s_yieldTokenBalance / totalSupply
```

---

#### 漏洞描述

`_burnShares()` 的会计逻辑违反了 CEI（Checks-Effects-Interactions）原则：**先做外部调用（swap），再根据余额差更新内部状态**：

```solidity
// _burnShares() 伪代码
uint256 yieldTokensBefore = ERC20(yieldToken).balanceOf(address(this)); // 快照
_executeTrade(...);  // ← 外部调用！Uniswap V2 swap，期间调用 token.transfer()
uint256 yieldTokensAfter = ERC20(yieldToken).balanceOf(address(this));
uint256 yieldTokensRedeemed = yieldTokensBefore - yieldTokensAfter;
s_yieldTokenBalance -= yieldTokensRedeemed;  // 用余额差更新计数器
```

攻击者在 Uniswap V2 的 swap 路径中插入恶意 ERC20（`yieldToken → maliciousToken → asset`），当 swap 调用 `maliciousToken.transfer()` 时，恶意合约重入并调用 `lendingRouter.initiateWithdraw()`，从 vault 转走 N 个 yieldToken。

---

#### 攻击链

```
yieldTokensBefore = 100（快照）

_executeTrade() 开始（Uniswap V2 swap）
  └─ maliciousToken.transfer() 被调用
       └─ 重入：initiateWithdraw() 执行
            → 从 vault 转走 N=30 个 yieldToken
            → s_yieldTokenBalance -= 30     ← 第一次扣减
            → ERC20 余额变为 70
       └─ 重入结束

swap 完成，M=60 个 yieldToken 被兑走
ERC20 余额变为 10

yieldTokensAfter = 10
yieldTokensRedeemed = 100 - 10 = 90  ← 把 N+M 都计入了
s_yieldTokenBalance -= 90             ← 第二次扣减（包含了已扣过的 N）

实际离开 vault：N + M = 90 ✅
s_yieldTokenBalance 被扣减：N + (N+M) = 120 ❌

→ 30 个 yieldToken 仍在 vault，但账本永久丢失这 30 个 → 资金冻结
```

---

#### 连锁影响

```
s_yieldTokenBalance 被低估
→ share price 下跌
→ 用户 collateralValue 下跌（即使用户没做任何操作）
→ health factor 跌破阈值 → 触发清算
→ 清算调用 redeemNative → 可再次重入
→ 恶性循环，最终全部资金冻结
```

测试数据验证：
```
攻击后 s_yieldTokenBalance : 4.18e18
攻击后 yield token balance  : 9.30e18   ← 账本比实际少了 5.1e18
用户2 collateralValue       : 9.97 → 4.49（腰斩，用户未操作）
share price user2           : 下跌 55%
```

---

#### 根因

1. **CEI 违反**：外部调用（swap）发生在状态更新之前，重入窗口在计数器更新前打开
2. **用余额差而非绝对值计算 redeemed**：`yieldTokensBefore - yieldTokensAfter` 会把重入期间发生的所有余额变化都归入本次赎回，导致多扣
3. **exchangeData 未校验**：允许用户自定义任意 Uniswap V2 路径，攻击者可插入任意中间代币

---

#### 修复方式

**方案一：nonReentrant 守卫**（推荐）

```solidity
function redeemNative(...) external nonReentrant { ... }
// 同时给 initiateWithdraw()、collectFees() 等所有外部入口加守卫
```

**方案二：限制 swap 路径**

```solidity
// 强制只允许 单跳 swap（两个 token），禁止插入中间代币
require(path.length == 2, "Only single-hop swaps allowed");
```

两者应同时实施：nonReentrant 防御当前漏洞，路径校验防御未来类似的重入变体。

---

#### 审计思路

1. **找所有"先外部调用、后更新状态"的模式**：这是 CEI 违反的典型特征，直接产生重入窗口
2. **用"余额差"计算数值的地方都要警惕**：`balanceBefore - balanceAfter` 这种模式，如果中间有外部调用，重入可以操控这个差值
3. **DEX 集成是高危区**：凡是允许用户指定 swap 路径 / token 的地方，恶意 token 的 `transfer()` hook 就是重入入口
4. **追踪内部计数器（`s_xxx`）与实际余额的一致性**：如果两者可以被分离，必然存在会计操控风险
5. **评估重入对 share price 的影响**：share price 被操控 → 健康因子异常 → 清算级联是 DeFi 里的高危连锁

---

#### 适用场景

| 场景 | 说明 |
|------|------|
| 允许用户自定义 swap 路径的协议 | 恶意中间 token 可注入重入 |
| 用余额差计算内部状态的 vault | 重入期间的余额变化被错误归因 |
| 内部计数器与 ERC20 balance 分离维护 | 两者不一致即产生冻结资金 |
| share price 由内部计数器决定的借贷协议 | 计数器被操控 → 价格异常 → 清算 |

---

#### 关键词速查

`reentrancy` · `CEI violation` · `s_yieldTokenBalance` · `balance diff` · `double subtraction` · `fund freeze` · `liquidation cascade` · `malicious token` · `Uniswap V2 path` · `nonReentrant` · `share price manipulation`

---

### <a id="case-7"></a>案例 #7：委托提款向上取整累加溢出 — 所有提款永久失败

**来源**：BvtRewardVault · Critical
**文件**：`src/BvtRewardVault.sol` L155

---

#### 漏洞类型

**整数下溢 / 向上取整累加溢出 / 委托计算逻辑错误**（Ceiling Division Accumulation Overflow → Withdrawal DoS）

---

#### 背景

BvtRewardVault 支持"委托质押"：用户可以把自己的 stake 委托给多个其他用户代持。`withdraw()` 时，合约按比例从各委托方取回相应份额，再从用户自己剩余的 stake 取 `remainingAmount`。

---

#### 漏洞描述

`withdraw()` 存在两个独立 bug，叠加导致所有提款 revert：

**Bug 1：用户被包含在自己的委托列表中**

循环遍历 `users`（委托列表）时，`msg.sender` 自己也在列表里，所以自己的那份 stake 在循环里被计算了一次，循环结束后 `remainingAmount` 又试图再处理一次，**双重计算**。

**Bug 2：多个向上取整累加超过 `amount`**

```solidity
uint256 withdrawAmount = (delegatedAmount * amount + stakes[msg.sender] - 1) / stakes[msg.sender];
```

每一项单独向上取整是合理的，但**多项取整累加后总和会超过原始 `amount`**：

```
stakes[user] = 3，委托 A=1, B=1, 自己=1，提取 amount=2

A: ceil(1×2 / 3) = ceil(0.67) = 1
B: ceil(1×2 / 3) = ceil(0.67) = 1
自己: ceil(1×2 / 3) = ceil(0.67) = 1

totalDelegatedAmount = 3 > amount(2)
remainingAmount = 2 - 3 → 下溢 → revert
```

---

#### 攻击链

```
用户调用 withdraw(amount)
→ 循环对每个委托方用 ceiling division 计算 withdrawAmount
→ 多个 ceil 值累加，totalDelegatedAmount > amount
→ remainingAmount = amount - totalDelegatedAmount → 下溢 revert
→ 所有提款失败
→ 用户资金永久锁死在合约中
```

---

#### 根因

1. **自我委托未排除**：循环未过滤 `msg.sender == user` 的情况，导致自己的份额被计入 `totalDelegatedAmount`，再加上末尾的 `remainingAmount` 处理，形成双重计算
2. **向上取整的累加语义错误**：ceiling division 保证单个值不丢精度，但多个 ceil 值相加会系统性地高估总量，不适合用于"分摊之和 = 总量"的场景

---

#### 修复方式

```solidity
// 修复一：排除自身，循环里只处理真正的委托方
for (uint256 i = 0; i < users.length; i++) {
    address user = users[i];
    if (user == msg.sender) continue;  // ← 跳过自己
    // ...
}

// 修复二：用向下取整，最后把余数统一分配给自己
uint256 withdrawAmount = (delegatedAmount * amount) / stakes[msg.sender]; // floor
// 循环结束后 remainingAmount = amount - totalDelegatedAmount（包含所有舍入损失）
```

---

#### 审计思路

1. **有委托/分配逻辑的合约，检查是否存在自引用**：用户是否可能出现在自己的委托/分配列表中？
2. **多个取整值求和时警惕**：`ceil(a/n) + ceil(b/n) + ...` 的总和可能 > `a+b+...`，不能用于"分摊之和必须等于总量"的场景
3. **提款/分配函数的不变量检查**：`totalDelegatedAmount` 最终必须 ≤ `amount`，在代码里验证这个不变量是否有保证
4. **下溢检查**：Solidity 0.8+ 会自动 revert，但这里的结果是"所有提款永久失败"而不是安全失败，影响同样严重

---

#### 适用场景

| 场景 | 说明 |
|------|------|
| 委托质押 / 代理持仓协议 | 用户可在自己的委托列表中，导致双重计算 |
| 按比例分配资金的合约 | 多个 ceil 取整累加溢出原始总量 |
| 任何"分摊之和 = 总量"的逻辑 | 必须用 floor + 余数处理，不能全用 ceil |

---

#### 关键词速查

`ceiling division` · `delegation` · `underflow` · `withdrawal DoS` · `fund lock` · `self-delegation` · `rounding accumulation` · `remainingAmount`



---

### <a id="case-8"></a>案例 #8：Malformed `op::get_fees_notification` Payload — 跨合约消息格式破坏

**来源**：XDAO · Aug 2025 · Medium
**文件**：`contracts/fee_manager.fc`
**链**：TON（FunC 语言）

---

#### 漏洞类型

**跨合约消息 Payload 格式不匹配**（Interface Contract Violation / Malformed Message Payload）

---

#### 背景

TON 链的合约间通信通过**消息（message）** 实现，类似 EVM 的外部调用，但格式是手动序列化的 cell/slice。合约之间必须对消息格式达成隐式约定（"接口契约"），发送方和接收方都硬编码了同一套字段顺序和类型。

本案例中有两个合约：
- `fee_manager`：负责存储当前费用字典，响应 `op::get_fees` 消息
- `factory`：发送 `op::get_fees` 请求，接收 `op::get_fees_notification` 响应，解析费用字典来更新状态

---

#### 漏洞描述

`fee_manager` 在处理 `op::get_fees` 时，构造返回消息的代码多写了额外字段：

```func
;; ❌ 实际代码（错误）
cell payload = begin_cell()
  .store_op(op::get_fees_notification)
  .store_dict(data::fees)
  .store_slice(data::admin_address)   ;; ← 多余字段
  .store_slice(in_msg_body)           ;; ← 多余字段
.end_cell();
```

而 `factory` 期望的格式是：

```func
;; ✅ factory 期望的格式
cell payload = begin_cell()
  .store_op(op::get_fees_notification)
  .store_uint(query_id, 64)           ;; ← 缺失
  .store_dict(data::fees)
.end_cell();
```

两处偏差：
1. **缺少 `query_id`**：factory 读取的第一个 64 位会拿到错误数据
2. **多出两个 slice**：admin_address 和 原始消息体被附在后面，导致 factory 解析 `data::fees` 时读到错误偏移

---

#### 攻击链

```
factory 发送 op::get_fees
    ↓
fee_manager 收到，构造 malformed payload
    ↓
factory 收到响应，按预期格式解析：
  - 读 op（4字节）→ 正确
  - 读 query_id（8字节）→ 实际读到了 fees dict 的前8字节（错误数据）
  - 读 fees dict → 偏移错误，解析失败
    ↓
factory 解析失败 → 消息 bounce 或状态不更新
    ↓
current_fees 保持旧值（stale）→ 依赖费用数据的操作行为异常
```

---

#### 根因

**没有共享的接口定义**。TON/FunC 没有 Solidity 的 ABI 系统，合约间消息格式完全靠约定，发送方和接收方各自硬编码字段顺序。当一方修改了格式但另一方没有同步更新，就会产生静默的格式不匹配——不报编译错误，运行时才出问题。

本质：**接口契约（Interface Contract）在代码层面没有被强制执行**。

---

#### 修复方式

统一 `fee_manager` 的响应格式，与 `factory` 的预期对齐：

```func
;; ✅ 修复后
cell payload = begin_cell()
  .store_op(op::get_fees_notification)
  .store_uint(query_id, 64)
  .store_dict(data::fees)
.end_cell();
```

移除多余的 `admin_address` 和 `in_msg_body` 字段。

---

#### 审计思路

1. **找到所有跨合约消息的发送和接收对**
   - 搜索 `op::xxx_notification` / `op::xxx_response` 类 op code
   - 对每个 op：找到构造方（store_ 链）和解析方（load_ 链），逐字段对比

2. **逐字段比对序列化顺序**
   - TON FunC 里没有 ABI 保护，任何多一个字段、少一个字段、换顺序都会导致解析错位
   - 重点检查：`query_id` 是否一致存在，dict 的位置是否对齐

3. **检查 bounce 处理**
   - TON 消息 bounce 时会回调 `op = 0xffffffff` 分支，确认合约是否处理了 bounce 导致的状态回滚

4. **对所有 query/response 对做"接口契约检查"**
   - 相当于 EVM 里检查 ABI 编码格式，但这里要手动做

---

#### 适用场景

- TON / FunC 合约（最典型，无 ABI 保护）
- EVM 合约中手动 ABI 编码的场景（如 `abi.encodePacked` 跨合约调用）
- 任何消息/事件格式由双方各自硬编码、没有共享 schema 的系统
- 合约升级后接口格式变更但调用方未同步

---

#### 关键词速查

`malformed payload` · `message format mismatch` · `interface contract violation` · `TON FunC` · `store_slice` · `query_id missing` · `stale fees` · `cross-contract message` · `op code` · `bounce`

---

### <a id="case-9"></a>案例 #9：Stake-exit lag + ZK 零密钥投票权伪造 — 零风险共识接管

**来源**：Symbiotic Relay · Sherlock · Jul 2025 · High/Critical
**文件**：`Settlement.sol`、`circuit.go`
**链**：EVM + ZK 证明系统（BN254）

---

#### 漏洞类型

**Bug 1**：TOCTOU / 质押退出窗口期利用（Stake-exit Lag Exploit）
**Bug 2**：ZK 电路零密钥投票权约束缺失（Null-key Voting Power Forgery）

---

#### 背景

Symbiotic Relay 是一个去中心化验证者网络：
- 运营商质押代币 → 获得投票权
- 链下 relay 根据投票权选出验证者集合 → 调用 `setSigVerifier`
- 验证者对区块头签名，生成 ZK 证明 → 任何人调用 `commitValSetHeader` 提交
- 提交成功后，链接受新的 validator set header

经济安全假设：验证者作恶会被 slash，因此有 stake 才有信任。

---

#### Bug 1：质押退出窗口期利用（Stake-exit Lag）

**攻击链**

```
Epoch 1：
  恶意运营商大量质押 → 投票权超过 quorum
  链下 relay 计算投票权 → setSigVerifier(包含恶意运营商的验证者集合)
  ↑ 此时恶意验证者已写入链上状态
  恶意运营商 → vault.withdraw() 发起提款（开始提款冷却期）

Epoch 2：
  恶意运营商 → vault.claim() 取走全部质押 ← stake = 0，无法被 slash
  但 sigVerifier 仍引用他的验证者私钥！
  恶意运营商用私钥自签 → 构造有效 ZK 证明
  commitValSetHeader(malicious_header) ← public 函数，任何人可调
  ↓
  链接受伪造区块头，攻击者零风险控制共识
```

**根因**

`commitValSetHeader` 是 `public` 函数，且与 `setSigVerifier` 完全解耦：

```solidity
// 任何人都能提交，只要证明验证通过
function commitValSetHeader(...) public {
    // 验证 ZK 证明，使用当前 sigVerifier
    // 如果通过，更新 valSetHeader
}

// 只有 relay 调用，在链下计算后设置
function setSigVerifier(...) external onlyOwner {
    sigVerifier = newVerifier;
}
```

质押状态和验证者集合状态之间没有联动检查，形成时间窗口。

**修复**

```solidity
// 方案1：原子化，一个函数同时 setSigVerifier + commitValSetHeader
function setVerifierAndCommit(...) external onlyRelay { ... }

// 方案2：commitValSetHeader 加权限
function commitValSetHeader(...) external onlyRelay { ... }
```

---

#### Bug 2：ZK 电路零密钥投票权约束缺失

**背景：BN254 椭圆曲线单位元**

BN254 是以太坊 ZK 证明常用曲线。曲线上的"无穷远点"（point at infinity）记为 `(0, 0)`，是加法的单位元：

```
P + (0,0) = P  （对任意点 P 成立）
```

因此，把 `(0,0)` 加入 BLS 聚合公钥，对结果**没有任何影响**，也不需要对应的私钥来生成签名。

**电路漏洞**

circuit.go 中，`valsetHash` 的计算逻辑：

```go
// 累积 MIMC 哈希
mimcApi.Write(ValidatorData[i].Key.X, Key.Y, VotingPower)
valsetHashTemp := mimcApi.Sum()

// 如果 key = (0,0) 就跳过（不加入哈希）
valsetHash = api.Select(
    api.And(IsZero(X), IsZero(Y)),
    valsetHash,      // key=0 → 保持旧值
    valsetHashTemp,  // key≠0 → 更新
)
```

关键问题：**电路没有约束"key=(0,0) 时 votingPower 必须=0"**。

`IsNonSigner=false` 的 `(0,0)` 验证者的投票权会被计入 quorum 总数，但他的公钥加入聚合后毫无影响。

**攻击构造**

```
验证者列表（按要求排序，(0,0) 必须在末尾）：
  [OP1: key=真实公钥, power=1, IsNonSigner=false]
  [(0,0): key=(0,0), power=99999999, IsNonSigner=false]  ← 伪造

ZK 电路验证过程：
  1. valsetHash：OP1 计入，(0,0) 在末尾被跳过 → 哈希与链上记录一致 ✓
  2. 聚合公钥 = OP1.pubkey + (0,0) = OP1.pubkey → 只需 OP1 的私钥签名 ✓
  3. 总投票权 = 1 + 99999999 = 100000000 > quorum ✓
  4. 证明通过

结果：投票权=1 的运营商完全控制网络
```

**根因**

```go
// ❌ 缺失约束：零密钥必须零投票权
// circuit.go 只处理了 valsetHash 跳过，但没有限制 power
```

**修复**

```go
// ✅ 在电路中强制约束
isNullKey := api.And(fieldFpApi.IsZero(&circuit.ValidatorData[i].Key.X),
                      fieldFpApi.IsZero(&circuit.ValidatorData[i].Key.Y))
// 如果 key 为零，votingPower 必须为零
api.AssertIsEqual(
    api.Select(isNullKey, circuit.ValidatorData[i].VotingPower, zero),
    zero,
)
```

---

#### 两个漏洞的关系

| | Bug 1 | Bug 2 |
|--|--|--|
| 攻击条件 | 需要真实的大额质押 | 只需任意最小质押 |
| 利用方式 | 先质押再提款，窗口期作恶 | 构造假验证者填充投票权 |
| 技术层面 | 逻辑/时序漏洞 | 密码学/电路约束缺失 |
| 危害 | 可控共识，但需要时机 | 直接控制共识，无门槛 |

Bug 2 危害更大：只需 1 个投票权就可以发动攻击，完全绕过 quorum 机制。

---

#### 审计思路

**针对 PoS / 质押系统**
1. 梳理"质押状态"和"投票权/验证者集合状态"的同步机制
2. 是否存在时间窗口：质押已减少，但投票权仍有效？
3. commitXxx 类函数是否 public？是否需要额外权限控制？
4. 提款流程（withdraw + claim）是否与验证者集合更新原子绑定？

**针对 ZK 电路审计**
1. 找所有 `Select`、`IsZero` 逻辑，检查分支条件是否完整约束了所有字段
2. 对于特殊点（单位元、无穷远点）：是否有对应的约束（power=0？排除在外？）
3. 累积型哈希（MIMC、Poseidon）：元素的顺序和包含/排除逻辑是否一致？
4. 聚合签名验证：是否有"幽灵签名者"（不持有私钥却贡献投票权）的可能？

---

#### 适用场景

- 任何 PoS/质押型验证者网络（Symbiotic、EigenLayer 等中间件）
- 使用 BLS 聚合签名 + ZK 证明的系统
- 含有"选举"和"执行"分离步骤的协议（setSomething + doSomething 模式）
- ZK 电路中对特殊曲线点的处理（无穷远点、生成元等）

---

#### 关键词速查

`TOCTOU` · `stake-exit lag` · `voting power` · `quorum bypass` · `ZK circuit` · `null key` · `point at infinity` · `BN254` · `BLS aggregation` · `valsetHash` · `MIMC` · `IsNonSigner` · `commitValSetHeader` · `setSigVerifier` · `slash avoidance`

---

### <a id="case-10"></a>案例 #10：Vesting 曲线方向写反 — MEV 三明治攻击

**来源**：LoopVaults · Pashov Audit Group · Jul 2025 · High
**文件**：vault 合约（`_vestingInterest()`）

---

#### 漏洞类型

**Vesting 曲线反向**（Inverted Vesting Curve / MEV Sandwich / Share Price Manipulation）

---

#### 背景

Vault 的利息不是实时更新的，而是每隔 `updateInterval` 批量写入，每次更新 `lastTotalAssets` 会突然跳升。这个跳升会被 MEV 机器人利用（抢跑 deposit → 等 update → 立刻 redeem 套利）。

为了防御这种攻击，协议设计了 vesting 机制：update 后不立刻暴露全部利息，而是在 `vestingDuration` 时间内线性释放。核心公式：

```solidity
function totalAssets() public view override returns (uint256) {
    return lastTotalAssets - _vestingInterest();
}
```

`_vestingInterest()` 返回"还未释放的利息"，值越大 → totalAssets 越低 → share price 越低 → MEV 无利可图。

---

#### 漏洞描述

```solidity
// ❌ 错误实现
function _vestingInterest() internal view returns (uint256) {
    if (block.timestamp - lastUpdate >= vestingDuration) return 0;

    uint256 __vestingInterest = (block.timestamp - lastUpdate) * vestingInterest / vestingDuration;
    return __vestingInterest;
}
```

| 时刻 | elapsed | 返回值 | totalAssets |
|------|---------|--------|-------------|
| 刚更新（t=0） | 0 | **0**（利息全部可见！） | lastTotalAssets（最高） |
| 中途（t=T/2） | T/2 | vestingInterest/2 | 中间值 |
| 结束（t=T） | T | vestingInterest（利息被隐藏） | 最低 |

曲线方向完全反了：update 后的瞬间利息全部暴露，vesting 的防 MEV 作用为零。

---

#### 攻击链

```
MEV 机器人发现 update 交易在 mempool
    ↓
抢跑：以低 share price deposit
    ↓
update 执行：lastTotalAssets 跳升
             _vestingInterest() 返回 0（t=0）
             totalAssets() = lastTotalAssets（立刻全额）
    ↓
MEV 立刻 redeem：以高 share price 卖出
    ↓
无风险套利，利润来自其他存款人的利息
```

---

#### 根因

vesting 的正确语义是"**已过时间越长，隐藏的利息越少**"，即递减曲线。代码写成了递增曲线：

```
正确：隐藏利息 = (vestingDuration - elapsed) / vestingDuration × vestingInterest
错误：隐藏利息 = elapsed / vestingDuration × vestingInterest
```

一个减号写错方向，防御机制变成了反向操作。

---

#### 公式逐项说明

**✅ 正确公式**：`(vestingDuration - elapsed) * vestingInterest / vestingDuration`

| 变量 | 含义 | 例子 |
|------|------|------|
| `vestingDuration` | vesting 总时长，利息从完全隐藏到完全释放需要多久 | 100 秒 |
| `elapsed` | 距离上次 update 已过去的时间（`block.timestamp - lastUpdate`） | 30 秒 |
| `vestingDuration - elapsed` | 距离 vesting 结束还剩多少时间 | 70 秒 |
| `(vestingDuration - elapsed) / vestingDuration` | **还剩多少比例未释放** | 70% |
| `vestingInterest` | 本次 update 新增的利息总量（update 时写入的固定值） | 100 USD |

代入数字：
```
t=0：  (100-0)  / 100 × 100 = 100 USD 未释放 → totalAssets = 1100-100 = 1000
t=30： (100-30) / 100 × 100 = 70 USD  未释放 → totalAssets = 1100-70  = 1030
t=50： (100-50) / 100 × 100 = 50 USD  未释放 → totalAssets = 1100-50  = 1050
t=100：(100-100)/ 100 × 100 = 0 USD   未释放 → totalAssets = 1100-0   = 1100
```

**❌ 错误公式**：`elapsed * vestingInterest / vestingDuration`

语义变成了"**已释放多少比例**"而不是"还剩多少比例"：

```
t=0：  0   / 100 × 100 = 0 USD   → totalAssets = 1100（利息全部暴露！）
t=30： 30  / 100 × 100 = 30 USD  → totalAssets = 1070（利息反而越来越隐藏）
t=50： 50  / 100 × 100 = 50 USD  → totalAssets = 1050
t=100：进入 >= 分支 → 0           → totalAssets = 1100（又全部暴露）
```

两条曲线对比：

```
totalAssets
     │
1100 ├─●─────────────────────────────────● ← 错误：t=0 就全暴露，中间反而下凹
     │  ╲                               ╱
1050 │    ╲                           ╱
     │      ╲─────────────────────── ╱
1000 │
     │
     │  ●                               ← 正确：t=0 完全隐藏
1000 │    ╲
1050 │      ╲────────────────────────
1100 │                                ●  ← 正确：t=T 完全释放
     └──────────────────────────────────→ 时间
        t=0                          t=T
```

---

#### vesting 的局限性

vesting **不能完全消灭套利**，只能缩小窗口和利润空间。攻击者仍然可以在 t=50% 时买入、t=100% 时卖出，拿走后半段释放的利息。

但 vesting 实现了两个目标：
1. **消灭无风险瞬间套利**——攻击者必须持仓等待，承担时间风险和市场风险
2. **稀释利润**——持仓时间越长，机会成本越高，套利吸引力越低

`vestingDuration` 设置得越长，威慑效果越强。这是经济上的威慑，不是数学上的完全阻断。

---

#### 修复方式

```solidity
// ✅ 修复后
uint256 __vestingInterest = (vestingDuration - (block.timestamp - lastUpdate))
                            * vestingInterest / vestingDuration;
```

| 时刻 | 返回值 | totalAssets |
|------|--------|-------------|
| 刚更新（t=0） | vestingInterest（最大，利息全部隐藏） | 最低，MEV 无利可图 |
| 中途（t=T/2） | vestingInterest/2 | 线性释放中 |
| 结束（t=T） | 0 | lastTotalAssets，利息完全释放 |

---

#### 审计思路

1. **找所有防 MEV / 防闪贷的保护机制**，单独验证其数学方向
   - vesting、time-weighted、TWAP 等机制都有"方向性"，正向和反向效果完全相反
2. **在 t=0 和 t=T 两个端点代入数字验证**
   - t=0 时保护值应最大（最保守），t=T 时应归零
   - 如果 t=0 时返回 0，基本可以判定方向写反了
3. **检查 totalAssets() 的组成**
   - 任何涉及减法的 totalAssets 公式，被减项的变化方向都要仔细核对

---

#### 适用场景

- 任何使用 vesting 保护 share price 的 ERC4626 金库
- 批量更新利息的协议（利息不是实时累积而是周期写入）
- 涉及线性释放、时间加权的防 MEV 设计

---

#### 关键词速查

`vesting` · `MEV` · `sandwich attack` · `share price` · `totalAssets` · `inverted curve` · `linear release` · `ERC4626` · `lastUpdate` · `vestingDuration`

---

### <a id="case-11"></a>案例 #11：totalValues 缓存未同步 — 手续费导致权重检查失真

**来源**：Cove · Jun 2025 · High
**文件**：basket 再平衡逻辑

---

#### 漏洞类型

**状态缓存未同步**（Stale Cache / Out-of-sync State / Fee Not Accounted）

---

#### 背景

Cove 协议支持多个 basket（资产篮子），每个 basket 持有多种代币并有目标权重。再平衡时，协议先做 basket 间的内部 swap，再做外部交易，最后检查权重是否满足目标。

再平衡的完整调用链：

```
_initializeBasketData()    → 初始化每个 basket 的总 USD 价值，写入 totalValues[]
_processInternalTrades()   → basket 间内部 swap（收取手续费）← 此处改变了实际价值
_validateExternalTrades()  → 验证外部交易，使用 totalValues[]
_isTargetWeightMet()       → 检查权重偏差，使用 totalValues[]  ← 此处用了旧值
```

---

#### 漏洞描述

`_processInternalTrades()` 执行内部 swap 时，对 sell 和 buy 两侧都收取手续费：

```solidity
info.feeOnSell = sellAmount * swapFee / 20_000;
self.collectedSwapFees[trade.sellToken] += info.feeOnSell;

info.feeOnBuy = initialBuyAmount * swapFee / 20_000;
self.collectedSwapFees[trade.buyToken] += info.feeOnBuy;
```

手续费从两个 basket 中扣除，导致它们的实际 USD 总价值下降。但 `totalValues[]` 数组在整个过程中**从未更新**，仍然保存着 `_initializeBasketData()` 时计算的旧值。

---

#### 权重检查为什么出错

```solidity
uint256 afterTradeWeight = FixedPointMathLib.fullMulDiv(
    assetValueInUSD,    // 某资产的实际价值（实时）
    _WEIGHT_PRECISION,
    totalValues[i]      // basket 总价值（旧值，未扣手续费，偏高）
);
if (MathUtils.diff(proposedTargetWeights[j], afterTradeWeight) > _MAX_WEIGHT_DEVIATION) {
    return false;
}
```

分母 `totalValues[i]` 偏高 → `afterTradeWeight` 偏低 → 与目标权重的偏差被高估。

**数字示例**：

```
初始：basket 总价值 = 1000 USD
      资产 A = 500 USD，目标权重 = 50%
      内部 swap 手续费 = 20 USD

手续费扣除后实际状态：
  basket 总价值 = 980 USD
  资产 A       = 490 USD

正确检查（totalValues 更新后）：
  afterTradeWeight = 490 / 980 = 50.0%
  偏差 = |50% - 50%| = 0%  → 通过 ✓

实际检查（totalValues 未更新）：
  afterTradeWeight = 490 / 1000 = 49.0%
  偏差 = |50% - 49%| = 1%  → 可能超过阈值被拒绝 ✗
```

合法的再平衡因为分母用了旧值，被误判为权重不达标而 revert，再平衡功能实际上被阻断。

---

#### 根因

`totalValues[]` 是一个在函数开始时计算的**快照**，后续的 `_processInternalTrades()` 改变了实际状态（扣除手续费），但没有同步更新这个快照。最终消费这个快照的 `_isTargetWeightMet()` 拿到了过时的数据。

典型的**缓存与实际状态脱节**问题，根本原因是多步骤流程中中间步骤的副作用（手续费）没有被传播到共享状态。

---

#### 修复方式

在 `_processInternalTrades()` 中传入 `totalValues[]` 数组，每次收取手续费后同步扣减对应 basket 的总价值：

```
手续费扣除时：
  totalValues[fromBasketIndex] -= feeOnSellInUSD
  totalValues[toBasketIndex]   -= feeOnBuyInUSD
```

---

#### 审计思路

1. **找所有"先计算快照、后执行操作"的模式**
   - 数组或变量在函数开头初始化，后续多个步骤分别使用它
   - 问：这些步骤中有没有任何操作会改变快照所代表的真实状态？

2. **手续费是最常见的"隐性状态改变"**
   - swap、transfer、redeem 等操作往往附带手续费
   - 手续费减少了资产总量，但缓存的总值往往没有同步

3. **多步骤流程中检查共享状态的函数**
   - 如果一个校验函数在流程末尾运行，而它依赖的数据在中间步骤中被改变，就要确认数据是否实时更新

4. **在复杂流程中画出数据流**
   - 哪些变量在哪个步骤被写入？
   - 哪些变量在哪个步骤被读取？
   - 中间有没有写入操作影响了读取时的预期值？

---

#### 适用场景

- 多步骤再平衡、清算、结算流程
- 任何在流程开始时缓存价值/余额快照的合约
- 涉及手续费扣除的复合操作（swap、redeem、transfer）
- 权重、比例、偏差等依赖总量的校验逻辑

---

#### 关键词速查

`stale cache` · `out-of-sync state` · `swap fee` · `totalValues` · `weight deviation` · `basket rebalance` · `snapshot` · `multi-step flow` · `fee not accounted`

---

### <a id="case-12"></a>案例 #12：Decimal 不匹配导致 Uniswap tick 计算错误

**来源**：Bunni · Cyfrin · Jun 2025 · Medium
**文件**：`OracleUniGeoDistribution.sol`，`floorPriceToRick()`

---

#### 漏洞类型

**Token Decimal 不匹配**（Decimal Assumption / sqrtPriceX96 Miscalculation / Uniswap Tick Error）

---

#### 背景

Bunni 协议的 `OracleUniGeoDistribution` 根据外部预言机价格计算流动性分布的边界 tick（rick）。核心函数 `floorPriceToRick()` 把预言机返回的 WAD 格式价格转换成 Uniswap V3 的 `sqrtPriceX96`，再转换成 tick。

---

**Uniswap V2 vs V3：流动性模型对比**

Uniswap V2 使用全局流动性：

```
x × y = k
L = sqrt(k)   ← 全局常数，覆盖 0~∞ 整个价格范围，资金利用率低
```

Uniswap V3 引入**集中流动性**：LP（Liquidity Provider，往池子里存币赚手续费的人）可以选择只在某个价格区间内提供流动性：

```
LP 仓位 = {tickLower: -200, tickUpper: +100, L: 5000}
          价格下界         价格上界         区间内流动性强度
```

多个 LP 的区间叠加，流动性在不同价格段的深度各不相同：

```
LP A [-200, +100] L=5000：  [=================]
LP B [-100, +200] L=3000：        [=================]

重叠区间 [-100, +100] 活跃 L = 8000（滑点最小）
```

---

**Tick 是什么**

Tick 是 Uniswap V3 用来离散化价格轴的整数坐标：

```
price = 1.0001^tick
```

每个 tick 代表约 0.01% 的价格变化。tick=0 时 price=1，tick=100 时 price≈1.01。

每个 tick 上存着 `liquidityNet`，记录价格穿越该 tick 时活跃流动性的净变化：

```
价格从左往右穿越 tickLower → +L（该 LP 区间进入活跃）
价格从左往右穿越 tickUpper → -L（该 LP 区间退出活跃）
```

一笔大额 swap 是**分段计算**的：价格每穿越一个 tick，L 更新一次，再用新 L 算下一段。每段内部的数学和 V2 完全相同（核心公式不变，只是区间算法变了）：

```
dx = L × (1/sqrt(P1) - 1/sqrt(P2))
dy = L × (sqrt(P2) - sqrt(P1))
```

---

**Uniswap V3 价格的本质**：

Uniswap 的价格是**原始 token 数量比**，包含 decimals：

```
price = token1 原始数量 / token0 原始数量
      = (人类可读数量 × 10^decimals1) / (人类可读数量 × 10^decimals0)
```

所以两个 token 的 decimals 不同时，原始比例和人类可读比例之间有差距。

---

#### 漏洞描述

```solidity
function floorPriceToRick(uint256 floorPriceWad, int24 tickSpacing) public view returns (int24 rick) {
    // 把 WAD 格式价格转换为 sqrtPriceX96
    uint160 sqrtPriceX96 = ((floorPriceWad << 192) / WAD).sqrt().toUint160();
    rick = sqrtPriceX96.getTickAtSqrtPrice();
    rick = bondLtStablecoin ? rick : -rick;
    rick = roundTickSingle(rick, tickSpacing);
}
```

代码做的事：`floorPriceWad / WAD`，即把 WAD 格式的价格缩放回 1 的比例。

这隐含了一个假设：**两个 token 的 decimals 相同**。

---

#### 两种情况对比

**Bond（18 decimals）+ DAI（18 decimals），bond 价格 = 1 USD**

```
Uniswap 需要的原始比例：1e18 / 1e18 = 1
oracle 返回：1e18（WAD）
代码计算：1e18 / 1e18 = 1  ✓  匹配
```

**Bond（18 decimals）+ USDC（6 decimals），bond 价格 = 1 USD**

```
Uniswap 需要的原始比例：1e6 / 1e18 = 1e-12
oracle 返回：1e18（WAD，只表达 USD 价格，不含 decimals 差异）
代码计算：1e18 / 1e18 = 1  ✗  实际应该是 1e-12，差了 1e12 倍
```

转换成 tick 后偏差极大：

```
DAI/WETH  sqrtPriceX96：1,611,883,263,...
USDC/WETH sqrtPriceX96：1,618,353,216,855,...  ← 大了约 1e6 倍
```

换算成 tick 偏差（以 USDC/ETH 为例，ETH=3000 USDC）：

```
正确的原始比例 = 3000 × 10^6 / 10^18 = 3×10^-9
正确 tick      = log(3×10^-9) / log(1.0001) ≈ -207,000

错误的原始比例 = 3×10^21（把 WAD 价格当原始比值）
错误 tick      = log(3×10^21) / log(1.0001) ≈ +483,000

偏差：约 70 万个 tick，方向完全反转
```

这个 tick 被用来设置 swap 的价格限制（`sqrtPriceLimitX96`，即"最差能接受的价格"）。
正确限制应贴近当前价格，错误的 tick 跑到了一个不可能到达的极端位置，**价格保护形同虚设**——任何 sandwich 攻击都不会触发这个限制。

流动性分布的 tick 边界完全偏离实际价格范围，协议为 bond/USDC 对设置的流动性分布是错误的。

---

#### 根因

预言机返回的价格是 **USD 人类可读价格**（WAD 格式），而 Uniswap 需要的是**原始 token 数量比**。

当两个 token decimals 相同时，两者恰好一致；当 decimals 不同时，需要额外的缩放因子来弥补差距：

```
正确的原始比例 = 人类可读价格 × 10^stablecoinDecimals / 10^bondDecimals
```

代码没有这一步，hardcode 了"两者 decimals 相同"的假设。

---

#### 修复方式

在 WAD 展开后，补上 decimals 差值的缩放：

```solidity
// 修复后
uint256 decimalAdjusted = floorPriceWad * (10 ** stablecoinDecimals) / (10 ** bondDecimals);
uint160 sqrtPriceX96 = ((decimalAdjusted << 192) / WAD).sqrt().toUint160();
```

验证：
```
DAI（18）：1e18 × 1e18 / 1e18 / 1e18 = 1        ✓
USDC（6）：1e18 × 1e6  / 1e18 / 1e18 = 1e-12    ✓
```

---

#### 注意：团队选择不修复

团队明确表示接受"bond 和 stablecoin decimals 相同"的假设，认为这是合理的使用限制。这说明该漏洞的实际影响取决于协议支持哪些 stablecoin——如果只支持 DAI/FRAX 等 18 decimals 的稳定币则无影响，支持 USDC/USDT（6 decimals）则会触发。

---

#### 审计思路

1. **任何涉及 Uniswap sqrtPriceX96 / tick 计算的函数**，检查两个 token 的 decimals 是否被正确处理
   - Uniswap 价格是原始数量比，不是人类可读比，decimals 差值必须补偿

2. **预言机价格的 decimals 语义**
   - Chainlink 返回的价格通常是 8 decimals
   - 协议内部的 WAD 格式是 18 decimals
   - 两者都不等于"Uniswap 原始比例"，使用时必须区分

3. **hardcoded 假设的审计方法**
   - 搜索代码里有没有注释写着"assume X has 18 decimals"或类似字样
   - 找到后问：如果换一个 decimals 不同的 token，会发生什么？

4. **测试矩阵**
   - 对所有价格/比例计算，测试 6/18/8 等常见 decimal 组合
   - 结果应该在合理范围内，如果出现 1e12 量级的差异就是 decimal 问题

---

#### 适用场景

- Uniswap V3 / V4 流动性管理协议
- 任何把预言机价格转换为链上价格比例的合约
- 涉及多种 stablecoin（USDC、USDT、DAI 混用）的协议
- sqrtPriceX96、tick、price ratio 计算

---

#### 关键词速查

`decimal mismatch` · `sqrtPriceX96` · `tick` · `Uniswap V3` · `WAD` · `oracle price` · `token decimals` · `USDC` · `price ratio` · `LDF` · `floorPriceToRick`

---

### <a id="case-13"></a>案例 #13：`block.timestamp` 作为 DEX swap deadline 是无效保护

**来源**：Hyperhyper · Jun 2025 · Medium
**文件**：`PositionInteractionFacet.sol`

---

#### 漏洞类型

**无效 Deadline / block.timestamp 误用**（Invalid Deadline / MEV / Validator Manipulation）

---

#### 背景

DEX swap（尤其是 Uniswap V3）支持 `deadline` 参数，用于防止交易被无限期延迟执行。Uniswap 合约内部检查：

```solidity
require(block.timestamp <= deadline, "Transaction too old");
```

deadline 的设计意图是：用户在签名时指定"这笔 tx 最晚必须在时间 T 前被打包，否则作废"。

---

#### 漏洞描述

```solidity
IV3SwapRouter.ExactOutputSingleParams memory params = IV3SwapRouter.ExactOutputSingleParams({
    ...
    deadline: block.timestamp + 30 minutes,  // ← 问题所在
    ...
});
```

问题：`block.timestamp` 是**执行时**的区块时间戳，不是用户提交时的时间。

展开 Uniswap 的 deadline 检查：

```
require(block.timestamp <= block.timestamp + 30 minutes)
```

这个条件**永远成立**，deadline 完全失去保护意义。

---

#### 攻击链

```
用户提交 tx → 进入 mempool（此时市场价格良好）
    ↓
恶意验证者/MEV bot 扣押这笔 tx，等待市场价格对自己有利
    ↓
25 分钟后市场价格已变差（对用户而言）
    ↓
验证者将 tx 打包进块
此时 block.timestamp = 25分钟后的时间
deadline = block.timestamp + 30min → 还有30分钟，依然通过
    ↓
用户以远差于预期的价格成交
```

**30 分钟 buffer 实际上给了验证者长达 30 分钟的操控窗口**——即使把 buffer 去掉改成 `block.timestamp`，结果相同，依然是 no-op。

---

#### 根因

`block.timestamp` 是区块打包时由验证者写入的值，用它作为 deadline 的基准，等于让验证者自己决定 deadline 什么时候开始计时。用户无法约束执行时机。

---

#### 修复方式

由用户在调用时传入 deadline，写入 calldata：

```solidity
function executeSwap(
    address assetIn,
    address assetOut,
    uint256 amountOut,
    uint256 deadline  // ← 用户指定，签名时确定
) external {
    IV3SwapRouter.ExactOutputSingleParams memory params = IV3SwapRouter.ExactOutputSingleParams({
        ...
        deadline: deadline,  // ← 直接使用用户指定值
        ...
    });
}
```

用户在前端签名时设置 `deadline = now + 20min`（用本地时间），这个值被写入 calldata，验证者无法篡改。如果验证者延迟超过 20 分钟，`block.timestamp > deadline` 条件触发，交易 revert。

---

#### 注意：deadline ≠ 滑点保护

| 参数 | 保护的是 | 对应参数 |
|--|--|--|
| deadline | 时间维度：防止交易被延迟执行 | `deadline` |
| 价格滑点 | 价格维度：防止价格偏离太多 | `amountInMaximum` / `sqrtPriceLimitX96` |

两者独立，都需要正确设置，缺一不可。

---

#### 审计思路

1. **搜索所有 DEX swap 调用**，检查 deadline 参数
   - `deadline: block.timestamp` → 100% 无效
   - `deadline: block.timestamp + X` → 同样无效，X 只是延长了验证者的操控窗口

2. **deadline 应该来自哪里？**
   - 正确：来自函数参数（用户在签名时提供）
   - 错误：合约内部用 `block.timestamp` 计算

3. **同时检查滑点参数**
   - `amountInMaximum` 设置合理吗？
   - `sqrtPriceLimitX96` 是否为 0（无价格保护）？

---

#### 适用场景

- 任何集成 Uniswap V3 / Curve / 其他 DEX 的协议
- 使用 `ExactInputSingleParams` / `ExactOutputSingleParams` 的合约
- 批量操作或自动化合约（更容易忽略 deadline 设计）

---

#### 关键词速查

`block.timestamp` · `deadline` · `MEV` · `validator manipulation` · `Uniswap swap` · `ExactOutputSingleParams` · `no-op deadline` · `mempool delay`

---

### <a id="case-14"></a>案例 #14：ERC1271 `isValidSignature` 缺少上下文绑定，导致签名重放

**来源**：SSO Account OIDC Recovery Solidity Audit · May 2025 · High
**文件**：`ERC1271Handler.sol`，`isValidSignature()`

---

#### 漏洞类型

**签名重放攻击**（Signature Replay / ERC1271 Context Binding / EIP-712 缺失）

---

#### 背景

**ERC1271** 是智能合约钱包的签名验证标准，接口为：

```solidity
function isValidSignature(bytes32 hash, bytes memory signature) 
    external view returns (bytes4 magicValue);
```

外部协议调用这个接口来验证"某个操作是否经过该智能账户的 owner 授权"。

**与 EOA 签名的本质区别**：

EOA 签名时，`ecrecover` 只能恢复出签名者地址，签名本身对"签的是什么"没有内在约束。安全性完全依赖 hash 的构造——如果 hash 没有绑定足够的上下文，签名就可以被复用。

---

#### 漏洞描述

`isValidSignature` 对 EOA 签名（65 字节）的验证逻辑只做：

```
1. 恢复签名者地址
2. 检查是否等于 k1owner
3. 如果匹配 → 返回 magicValue（视为有效）
```

没有检查：
- hash 是怎么构造的
- 这个 hash 是否已经被使用过
- 这个签名是否针对当前合约/当前链

同时，替代验证方法中 EIP-712 的逻辑被移除，原本 `_hashTypedDataV4` 会将 chainId 和 verifier 合约地址纳入 hash，移除后这两个绑定都消失了。

---

#### 攻击链

**场景 1：历史签名重放**

```
用户曾经签名授权了操作 A（hash_A + sig_A）
    ↓
操作 A 执行完毕，用户认为授权已失效
    ↓
攻击者发现另一个场景 B 也接受相同的 hash_A
    ↓
攻击者调用场景 B，传入 hash_A + sig_A
isValidSignature 返回 valid → 场景 B 被执行
```

**场景 2：跨链重放（EIP-712 被移除后）**

```
用户在 Chain A 上签名，hash 不含 chainId
    ↓
攻击者把相同的 hash + sig 提交到 Chain B
isValidSignature 同样返回 valid
    ↓
同一个签名在多条链上都有效
```

**场景 3：跨账户重放**

```
同一个 EOA 控制多个智能账户 (Account_1, Account_2)
hash 不含 verifier 合约地址
    ↓
用户在 Account_1 上签名的操作
攻击者拿到 hash + sig，提交给 Account_2
Account_2 的 isValidSignature 同样返回 valid
```

---

#### 根因

签名只绑定了"签名者身份"，没有绑定"签名的意图上下文"：

| 缺少的绑定 | 导致的问题 |
|--|--|
| 无 nonce / 使用记录 | 历史签名可重放 |
| 无 chainId | 跨链重放 |
| 无 verifier 合约地址 | 跨智能账户重放 |

---

#### 修复方式：ERC7739

ERC7739 提出了一套防御性重哈希方案，在 app 层 hash 外再包一层 EIP-712 结构：

```
最终 hash = EIP712({
    domain: { chainId, verifyingContract },   ← 绑定链和合约
    TypedDataSign: {
        appHash,                               ← 原始 app 数据（用户可读）
        account, accountNonce                  ← 防跨账户重放
    }
})
```

优点：
- chainId 绑定 → 跨链重放失败
- verifyingContract 绑定 → 跨账户重放失败
- 嵌套 EIP-712 结构 → 用户签名时仍能看到可读内容
- Solady 的 `ERC1271.sol` 提供了标准实现

---

#### 审计思路

1. **搜索所有 `isValidSignature` 实现**
   - hash 的构造过程是否包含 chainId？
   - 是否包含 verifier 合约地址（`address(this)`）？
   - 是否有 nonce 或使用标记防止重放？

2. **检查 EIP-712 domain 是否完整**
   - `_hashTypedDataV4` 是否被正确调用？
   - domain separator 是否包含 `chainId` 和 `verifyingContract`？

3. **跨账户场景**
   - 协议是否支持同一 EOA 管理多个智能账户？
   - 如果是，签名是否绑定了具体的账户地址？

4. **标准库使用**
   - 推荐直接使用 Solady 的 `ERC1271.sol`（已实现 ERC7739）
   - 或 OpenZeppelin 的 `SignatureChecker` + 完整 EIP-712 domain

---

#### 适用场景

- 智能合约钱包（AA wallet, Safe, ZKsync 账户）
- 任何实现 `isValidSignature` 的合约
- 多链部署的合约（同一地址部署在多条链上）
- 支持多个智能账户共享同一 EOA 的协议

---

#### 关键词速查

`ERC1271` · `isValidSignature` · `signature replay` · `EIP-712` · `chainId` · `verifyingContract` · `ERC7739` · `cross-chain replay` · `cross-account replay` · `k1owner` · `domain separator`

---

### <a id="case-15"></a>案例 #15：Bitcoin Observer 使用空 prevOut 计算 sighash，导致所有提款交易被网络拒绝

**来源**：ZetaChain Cross-Chain · Sherlock · May 2025 · Medium
**文件**：`SignTx()`，Bitcoin Observer 签名逻辑

---

#### 漏洞类型

**Bitcoin sighash 计算错误**（Invalid Sighash / Taproot BIP341 / UTXO prevOut Missing）

---

#### 背景

**Bitcoin UTXO 模型**：

Bitcoin 没有"账户余额"，只有 UTXO（Unspent Transaction Output，未花费的交易输出）。每笔交易的输入必须引用一个已存在的 UTXO：

```
UTXO = {
    txid: 前序交易 ID,
    vout: 输出索引,
    scriptPubKey: 锁定脚本（定义谁能花费），
    amount: 金额
}
```

**Taproot（BIP341）sighash 机制**：

Taproot 是 Bitcoin 的 SegWit v1 升级。签名时，sighash 必须承诺（commit）每个输入对应的前序输出（previous output）的 scriptPubKey 和 amount：

```
sighash = hash(
    tx 基本数据,
    每个输入的 prevOut.scriptPubKey,  ← 必须是链上真实数据
    每个输入的 prevOut.amount         ← 必须是链上真实数据
)
```

这是 BIP341 的安全改进：防止硬件钱包在不知道输入金额的情况下被欺骗签名（防止"fee attack"）。

**ZetaChain 的 Observer**：跨链协议中负责监听和签名 Bitcoin 交易的节点，使用 TSS（Threshold Signature Scheme，门限签名）。

---

#### 漏洞描述

```go
// 错误代码
sigHashes := txscript.NewTxSigHashes(tx,
    txscript.NewCannedPrevOutputFetcher([]byte{}, 0))
//  ↑ 对所有输入返回相同的：空 scriptPubKey + 0 金额
```

`NewCannedPrevOutputFetcher([]byte{}, 0)` 是一个"固定值"的 fetcher，无论查询哪个 UTXO，都返回相同的空 script 和 0 金额。

这导致 Observer 计算出的 sighash 使用了虚假的 prevOut 数据，而不是链上真实 UTXO 的数据。

---

#### 攻击链

```
Observer 构建 Bitcoin 提款交易
    ↓
用空 script + 0 金额计算 sighash → 得到错误的 sighash_wrong
    ↓
Observer 用 TSS 对 sighash_wrong 签名
    ↓
将签名后的交易广播到 Bitcoin 网络
    ↓
Bitcoin 节点从链上查询真实 UTXO 数据
重新计算 sighash_correct（使用真实 scriptPubKey + 真实 amount）
    ↓
sighash_correct ≠ sighash_wrong → 签名验证失败
    ↓
Bitcoin 网络拒绝该交易
```

**后果**：所有 Bitcoin 提款交易全部失败，用户无法从 Bitcoin 网络提款，资金被锁死在跨链合约中。

---

#### 根因

**本质：Legacy 和 Taproot 的 sighash 规则不同，代码没有跟上升级。**

**Legacy sighash**（Taproot 之前）：

```
sighash = hash(tx数据 + 当前输入的脚本)
```

prevOut 的金额和脚本**不参与**计算，传什么进去都不影响结果。`NewCannedPrevOutputFetcher([], 0)` 在 Legacy 场景下是合法的占位写法。

**Taproot sighash（BIP341）**：

```
sighash = hash(tx数据 + 每个输入的 prevOut.scriptPubKey + prevOut.amount)
```

2021 年 Taproot 升级专门把 prevOut 数据纳入 sighash，目的是防止硬件钱包被伪造金额欺骗。prevOut 必须是链上真实数据，传空值会算出错误的 hash。

**开发者的错误路径：**

```
旧代码（Legacy）：NewCannedPrevOutputFetcher([], 0) → 没问题
复制到新代码（Taproot）：NewCannedPrevOutputFetcher([], 0) → 编译通过，语义错误
```

`btcd` 库的 API 两种场景接受同一接口，编译器不报错，只有广播到真实 Bitcoin 网络时才暴露。本地用 mock 数据测试完全发现不了这个问题。

---

#### 修复方式

构建一个包含每个输入对应真实 UTXO 数据的 fetcher：

```go
prevOutFetcher := txscript.NewMultiPrevOutFetcher(nil)
for i, input := range tx.TxIn {
    prevOut := selected.UTXOs[i]  // 从已选择的 UTXO 集合中取
    script, err := hex.DecodeString(prevOut.ScriptPubKey)
    if err != nil {
        return nil, err
    }
    amount := int64(prevOut.Amount * btcutil.SatoshiPerBitcoin)
    prevOutFetcher.AddPrevOut(input.PreviousOutPoint, &wire.TxOut{
        Value:    amount,
        PkScript: script,
    })
}
sigHashes := txscript.NewTxSigHashes(tx, prevOutFetcher)
```

每个输入都使用它实际引用的 UTXO 的真实 scriptPubKey 和 amount。

---

#### 审计思路

1. **跨链协议中涉及非 EVM 链的签名逻辑**，需要熟悉目标链的签名规范
   - Bitcoin Taproot：sighash 必须承诺 prevOut 数据
   - Bitcoin Legacy：部分类型不需要 prevOut 金额（但 Taproot 必须）

2. **搜索 `NewCannedPrevOutputFetcher` 的使用**
   - 在生产代码中出现这个函数几乎是 bug——它是测试工具
   - 检查它是否被用在需要真实 UTXO 数据的 Taproot 场景

3. **跨链桥的 Bitcoin 签名路径**
   - 追踪从"用户发起提款"到"Bitcoin 交易广播"的完整流程
   - 重点检查 sighash 的构造：prevOutFetcher 是否正确填充？

4. **检查测试覆盖**
   - 这类 bug 常见原因是测试使用 mock 数据，没有测试真实 Bitcoin 网络广播
   - 真实广播测试（integration test）能发现这类问题

---

#### 适用场景

- 跨链协议中涉及 Bitcoin 签名的组件
- TSS / MPC 签名方案中的 Bitcoin 交易构建
- 任何使用 `btcd` / `txscript` 库处理 Taproot 交易的 Go 代码

---

#### 关键词速查

`Bitcoin` · `sighash` · `Taproot` · `BIP341` · `UTXO` · `prevOut` · `scriptPubKey` · `NewCannedPrevOutputFetcher` · `NewMultiPrevOutFetcher` · `TSS` · `Observer` · `跨链提款` · `txscript`

---

### <a id="case-16"></a>案例 #16：EVM revert 不还原 Cosmos 消息队列，导致被 try/catch 捕获的内层调用仍然执行 Cosmos 消息

**来源**：Initia · Code4rena · Apr 2025 · High
**文件**：`x/evm/precompiles/cosmos/contract.go`，`x/evm/keeper/context.go`

---

#### 漏洞类型

**跨 VM 状态不同步**（Cross-VM State Desync / EVM Snapshot vs Cosmos Context / ExecuteRequest Queue Not Reverted）

---

#### 背景

**MiniEVM 架构**：

Initia 的 MiniEVM 是一个同时支持 Cosmos SDK 和 EVM 的链。它提供了一个特殊的 `cosmos precompile`，允许 Solidity 合约在 EVM 执行过程中派发 Cosmos SDK 消息（如 IBC 跨链转账、原生模块调用等）。

设计上的执行流程：

```
EVM 调用开始
    ↓
Solidity 调用 cosmos precompile → Cosmos 消息被加入 ExecuteRequest 队列（存在 Cosmos context 中）
    ↓
EVM 调用成功结束
    ↓
统一执行队列里的所有 Cosmos 消息
```

**EVM statedb snapshot 机制**：

EVM 内部调用（call/create）会在执行前创建 statedb snapshot。若内层调用 revert，EVM 会还原到该 snapshot，撤销所有 EVM 状态变化（storage、余额等）。

**两套状态的分离**：

| 状态类型 | 存储位置 | revert 时是否回滚 |
|--|--|--|
| EVM 状态（storage、余额） | EVM statedb | 是，随 snapshot 还原 |
| Cosmos 消息队列（ExecuteRequest） | Cosmos context | 否，独立于 EVM statedb |

---

#### 漏洞描述

```go
// cosmos precompile 把消息加入队列（context 里的指针）
messages := ctx.Value(types.CONTEXT_KEY_EXECUTE_REQUESTS).(*[]types.ExecuteRequest)
*messages = append(*messages, types.ExecuteRequest{...})

// EVM 调用结束后统一执行队列
requests := sdkCtx.Value(types.CONTEXT_KEY_EXECUTE_REQUESTS).(*[]types.ExecuteRequest)
k.dispatchMessages(sdkCtx, *requests)
```

问题：内层 EVM 调用创建新的 statedb snapshot，但**不创建新的 Cosmos context**，两者共享同一个 ExecuteRequest 队列指针。

当内层调用 revert 时：
- EVM statedb 回滚 ✓
- Cosmos context 队列**不回滚** ✗

---

#### 攻击链

```solidity
// 外层调用
function recursive(uint64 n) external {
    try this.nested(n) {
        // 捕获内层 revert，外层继续执行
    } catch {}
}

// 内层调用
function nested(uint64 n) external {
    COSMOS_CONTRACT.execute_cosmos(msg);  // msg 进入共享队列
    revert();  // 内层 revert
}
```

```
外层 recursive() 开始
    ↓
调用 nested()，EVM 创建 statedb snapshot_1
    ↓
nested() 内：execute_cosmos(msg) → msg 追加到 Cosmos context 队列
nested() 内：revert()
    ↓
EVM 还原到 snapshot_1（EVM 状态回滚）
但 Cosmos context 队列不变，msg 仍在队列中
    ↓
外层 catch 捕获 revert，外层调用继续
外层调用成功结束
    ↓
执行队列中所有消息 → msg 被执行！
```

**后果**：

本应被 revert 撤销的 Cosmos 操作（如 IBC 转账）被意外执行，资金可能被永久锁定或丢失。攻击者可以构造 revert-but-catch 模式，触发任意 Cosmos 消息而不影响 EVM 状态。

---

#### 根因

EVM 的 revert/snapshot 机制只管理 EVM statedb 内的状态。ExecuteRequest 队列存储在 Cosmos context 中，完全独立于 EVM statedb，EVM 的 snapshot 还原操作无法感知也无法回滚这个队列。

本质上是**两套执行环境（EVM + Cosmos）的状态边界没有统一管理**。

---

#### 修复方式

在创建 EVM statedb snapshot 时，同步保存当前 ExecuteRequest 队列的快照；在还原 snapshot 时，同步还原队列到对应状态：

```
创建 snapshot：
    statedb.snapshot() + 保存当前 queue 长度/状态

还原 snapshot：
    statedb.revertToSnapshot() + 截断 queue 到保存的状态
```

Initia 的修复：在 snapshot 机制中维护 execute request 队列，确保 revert 时队列同步回滚。

---

#### 审计思路

1. **跨 VM / 跨执行环境的协议**，重点检查状态边界
   - EVM revert 能撤销哪些状态？不能撤销哪些？
   - 如果有"外挂"执行队列（消息队列、回调列表），是否随 EVM snapshot 一起管理？

2. **try/catch 模式**
   - Solidity 的 try/catch 捕获外部调用的 revert
   - 被捕获的 revert 不会传播，但内层操作可能已经污染了外部状态

3. **Cosmos-EVM 混合链的特殊风险**
   - Cosmos 消息（IBC、staking、gov）的副作用在 EVM revert 时是否能被撤销？
   - 如果不能，任何"先派发消息再 revert"的模式都是潜在漏洞

4. **检查 context 的作用域**
   - 内层调用是否与外层共享 context？
   - 共享的 context 里有没有可变状态（队列、计数器）？

---

#### 适用场景

- Cosmos-EVM 混合链（Evmos、Initia、Berachain 等）
- 任何允许 EVM 调用触发链外副作用的系统
- 跨链消息系统中 EVM 和消息队列并存的架构

---

#### 关键词速查

`ExecuteRequest` · `Cosmos precompile` · `EVM snapshot` · `try/catch` · `statedb revert` · `Cosmos context` · `IBC` · `跨VM状态不同步` · `minievm` · `MsgCall` · `消息队列未清除`

---

### <a id="case-17"></a>案例 #17：permit 被抢先提交，导致用户的合并交易失败 — Griefing DoS

**来源**：LI.FI · Cantina · Dec 2024 · Medium
**链接**：[solodit.cyfrin.io](https://solodit.cyfrin.io/issues/griefing-attack-possible-by-frontrunning-the-calldiamondwitheip2612signature-function-call-cantina-none-lifi-pdf)
**文件**：`callDiamondWithEIP2612Signature()`

---

#### 漏洞类型

**EIP-2612 Permit 抢跑 / Griefing DoS**（Permit Frontrun / try/catch 缺失）

---

#### 背景

EIP-2612 的 `permit` 允许任何人代替 owner 提交签名来设置 allowance。这是有意设计的（支持 relayer gasless 授权），但也意味着**签名一旦进入 mempool，任何人都可以抢先提交**。

LI.FI 的 `callDiamondWithEIP2612Signature` 将 `permit` 调用和后续操作合并进同一笔交易，没有对 `permit` 调用使用 try/catch。

---

#### 漏洞描述

```solidity
// ❌ 问题代码
function callDiamondWithEIP2612Signature(...) external {
    IERC20Permit(token).permit(owner, spender, amount, deadline, v, r, s);
    // ↑ 如果 permit 失败（签名已被使用），整笔交易 revert

    // 后续的 swap / bridge 操作
    _executeAction(...);
}
```

`permit` 的签名只能使用一次（内部维护 nonce）。攻击者从 mempool 复制签名参数，抢先调用 `ERC20.permit()`，签名被消耗；用户的交易打包时再次调用 `permit` → 签名已使用 → revert。

---

#### 攻击链

```
用户签名 permit → 提交 callDiamondWithEIP2612Signature → 进入 mempool
    ↓
攻击者监控 mempool，复制 permit 参数，直接调用 ERC20.permit()
攻击者交易先被打包：allowance 被正确设置，nonce +1
    ↓
用户交易被打包：
  permit() → 签名 nonce 已失效 → revert
  整笔交易失败，用户操作未执行
    ↓
攻击者重复上述操作 → 用户无法通过该接口执行任何操作
```

攻击者**无法获利**（allowance 被设置给了正确的 spender），但可以持续 grief 用户，使其无法使用协议。

---

#### 根因

混淆了两个不同的目标：
- **`permit` 调用成功** ≠ **allowance 已足够**

无论是用户自己提交的 permit 还是攻击者抢先提交的，最终 allowance 都被正确设置。`permit` 失败不代表授权失败，只代表"这次调用没有设置"，但授权目的可能已经达成（由抢跑者完成了）。

---

#### 修复方式

```solidity
// ✅ 正确写法：permit 失败无所谓，检查 allowance 才是目的
try IERC20Permit(token).permit(owner, spender, amount, deadline, v, r, s) {
} catch {}

// permit 之后必须验证 allowance 是否满足，而不是依赖 permit 成功
if (IERC20(token).allowance(owner, spender) < amount) revert InsufficientAllowance();
```

---

#### 审计思路

1. **搜索 `permit(` 的所有调用**，检查是否包裹了 try/catch
2. **try/catch 后是否验证 allowance**，而不是假设 permit 成功
3. **permit + 后续操作合并进同一笔交易的模式**，天然对抢跑敏感
4. **攻击者能否获利** 决定严重等级：纯 grief（Medium）vs 资金盗取（High/Critical）

---

#### 适用场景

- 任何将 `permit` 和后续操作合并的函数
- 支持 ERC20 permit 的 DEX aggregator / bridge 协议
- 接受用户传入 permit 签名参数的合约

---

#### 关键词速查

`EIP-2612` · `permit` · `frontrun` · `griefing` · `DoS` · `try/catch` · `allowance` · `mempool` · `nonce` · `IERC20Permit`

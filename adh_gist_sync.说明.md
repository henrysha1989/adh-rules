# `adh_gist_sync.py` 详细说明

> 版本：2026-09-30（**数据源分开**）。纯 Python 标准库，无第三方依赖。
> 本文件是脚本的设计/原理/流程/功能说明，供维护与排障参考。

---

## 0. ⚠️ 2026-09-30 重大变更：两个数据源**结果分开**

> 背景：小火箭宿主机（iphone17pm）**不再用自建 DoH 接入 ADH** ⇒ ADH 与小火箭规则**独立运行**，
> ADH 只服务其他客户端（只有拦截/放行两态）。owner 要求：公用一个脚本，但**结果互不串**。

| 数据源 | 去向 | 说明 |
|---|---|---|
| **ADH querylog** | `reject-custom.list` / `direct-custom.list` / `proxy-custom.list` | 3 个清单**只吃 ADH**；手机 db 不再参与任何判断 |
| **手机 `proxy-*.db`** | **`hongguo-ad.list`**（红果/番茄专表） | 唯一去向；见下面「红果专表」一节 |

配套改动：
1. **不再并入** `ads/directs/proxies`、**不再写证据池**（`obs_add`）、**不再**用手机 REJECT 记录续期 LRU 时钟、
   **不再**当 `guard_proxy` 的路由证据 ⇒ 那 3 个清单的行为完全由 ADH 决定，可预期、不依赖手机是否上传了 db。
2. **删除** `shadowrocket_domains()`（旧的两源合并入口，留着就是隐患）；新增 `shadowrocket_rejected()`
   （只取手机实际 REJECT 的主机）+ `hongguo_family()`（族口径）+ `run_hongguo_only()`。
3. **`CLIENT_DROP_ONLY` 清空**：它存在的理由是「手机侧有 DROP 规则、ADH 别先拦」，手机不走 ADH 后这条理由消失，
   继续放行只会让**其他客户端**少一层 DNS 拦截 ⇒ 这些域恢复由 ADH 拦（历史清单在脚本里注释留档，可一键恢复）。
4. ADH 侧对 hongguo 的域**照旧拦**（owner 选择）：它们已不经 `reject_des`，所以在 ADH 那一侧**单独并进来**，
   只喂 ADH、不写那 3 个清单。

**顺手修掉两个潜藏 bug**（都会静默出问题）：
- `parse_domains()` 的动作正则 `([A-Z]+)$` **不认 `REJECT-DROP`** ⇒ hongguo-ad.list 与 RAW 区的 DROP 规则一直被
  静默忽略（手工区去重失效、写入护栏形同虚设）。改成 `[A-Z][A-Z-]*`。
- `repo_sync_set()` 的「缺 AUTO 标记」护栏用 `not auto` 判断，**分不清「标记缺失」与「标记在、自动区为空」**
  ⇒ 给新文件建自动区时会被自己挡住（`hongguo-ad.list` 就卡在这）。改成真的去找标记行。

---

## 1. 一句话定位

一个定时运行的自净化脚本：读 **AdGuard Home 查询日志**判定「拦截 / 直连 / 代理」并写回 ADH 自定义规则与
GitHub 仓库（3 个 custom.list）；同时把**手机连接日志**里实测被拦的**红果/番茄族**主机写进 `hongguo-ad.list`。
两者共用一个脚本，但结果互不串（见上面第 0 节）。

---

## 2. 核心原理

### 2.1 三通道分类
每个域名只要一出现，就被判定进且仅进一个通道：

| 通道 | 含义 | 落地位置 |
| --- | --- | --- |
| **拦截 ad** | 广告 / 追踪 / 隐私域 | ADH `user_rules`（`\|\|d^`）+ 仓库 `adh-custom.txt` → CI 转 `reject-custom.list` |
| **直连 direct** | 国内低延迟媒体 / 核心 CDN / 信令 | ADH `@@\|\|d^` + 仓库 `direct-custom.list` |
| **代理 proxy** | 需要走代理的境外服务 | 仓库 `proxy-custom.list` |
| NA | 判不出来 | 丢弃（不落地） |

判定优先级（`classify()`）：**参考黑名单(ad) > 直连特征 > 广告特征 > 代理特征 > 空**。

### 2.2 双数据源（互补）
1. **AdGuard Home querylog**：本机 DNS 的实时记录，覆盖**直连/本机解析**的流量。
2. **Shadowrocket 连接日志（`proxy-*.db`）**：手机偶尔导出上传，覆盖 ADH **看不到**的 **代理 / remote-dns** 流量，且带手机端「实际命中规则 + 结果」。

两个源最终汇入**同一套** `classify()` + 合并 + 收敛逻辑（"判断逻辑同 ADH"）。

### 2.3 双向落地
脚本一轮运行会**同时**：
- `POST /control/filtering/set_rules` 写 **ADH 自定义规则**；
- `PUT /contents/...` 写 **GitHub 仓库**三份清单文件。

仓库侧再经 GitHub Action 自动转译 → 手机订阅。所以「ADH 与 GitHub 保持同步」是脚本内建行为。

### 2.4 收敛式写入（converge）
`adh_sync_rules(converge="||" / "@@||")` 是**全量替换**语义：把 ADH 里所有该类型、但不在本轮 add 列表里的规则**删除**。因此：
- 只在 ADH 界面手改、仓库里没有的规则，下一轮会被覆盖/删除；
- 通配规则（含 `*`）例外——**永不删除**（无法用域名集合表达，见 §9）。

仓库文件则由 `repo_sync_set()` **只收敛「自动区」**，手工区原样保留。

### 2.5 手工区 / 自动区（铁律）
每份清单文件里有一条**自动收集标记**：

```
! ===== 自动收集（以下内容由脚本管理，勿手改）=====   ← adh-custom.txt
# ===== 自动收集（以下内容由脚本管理，勿手改）=====   ← *.list
```

- **标记之上 = 手工区**：只由人维护，脚本**原样保留、不收敛**。
- **标记之下 = 自动区**：脚本按 `desired` 集合增删。
- **FAIL-SAFE**：标记丢失时，整个文件被当作**手工区**（绝不收敛）——防止「整表被当成自动区而清空」（2026-09-19 事故的教训）。

---

## 3. 数据源细节

### 3.1 AdGuard Home querylog — `adh_domains()`
- 认证：Basic（`ADH_USER`/`ADH_PASS`）。
- **分页回读**：`limit=QUERYLOG_LIMIT`(默认 10000) 每页，用 `older_than=<上页最旧时间>` 往前翻，直到缓冲区起点（或超过 `QUERYLOG_HOURS` 窗口；0=整个缓冲区）。避免单页只覆盖最新 ~1h 的漏扫。
- 逐条处理：
  - `reason ∈ ALLOWED_REASONS`（放行）→ `classify()` → ad/direct/proxy。
  - `reason ∈ BLOCKED_REASONS`（ADH 已拦，`FilteredBlackList`）→ **仅当** `INGEST_BLOCKED_AD` 开、`classify()=="ad"`、不在 `EXEMPT`、且非 `$client=` 作用域规则时，**镜像**进 ad 通道（防止「ADH 拦了、客户端没规则 → 翻转走代理」）。
- 输出：`(ads, directs, proxies)`。

### 3.2 Shadowrocket 连接日志 — `shadowrocket_*`
- 目录 `SR_DB_DIR`（默认 `/vol01/1001/shadowrocket-db`），文件 `SR_DB_GLOB`（`*.db`），SQLite。
- 表 `logging(url, ua, result, type, created)`（FTS3）；`type ∈ REJECT/DIRECT/PROXY`，`result` = 命中规则串（如 `DOMAIN-SUFFIX,x,REJECT`、`GEOIP,CN,DIRECT`、`FINAL,PROXY`）。
- `sr_extract_host()`：从 `url` 取主机名——去 scheme/path/query/端口/用户信息；**丢弃 IP 字面量**（IPv4/IPv6）。
- ~~`shadowrocket_domains()`~~ **2026-09-30 已删除**（旧的两源合并入口）。现在用 `shadowrocket_rejected()`：
  只读打开（`?mode=ro`），只取手机**实际被 REJECT**的主机 → Counter。**不跑 classify()、不写证据池** ——
  这批数据只去 `hongguo-ad.list`（口径见 `hongguo_family()`）。
- `shadowrocket_scan()`：只在**新/变化**的文件上跑——状态记 `basename → "size:mtime"`（`.sr-db-state.json`）；半拷贝/被占用/损坏的库会抛异常 → **跳过**，下轮重试；只有处理成功才写入状态（不会丢）。
- **诊断输出**：手机 REJECT 的主机名里，凡是属于 `FORCE_DIRECT` 的 → 报警「已放行却仍被拦」（= 手机订阅没刷新 / 残留规则）。stdout + Telegram。

---

## 4. 端到端流程（`main()` 逐步）

1. `--selftest` 直接跑自检并退出。
2. `load_env()` 载入同目录 `.env`（可选）。
3. 载入参考黑名单 `load_adlist()` → `ADLIST`；读仓库手工区 `repo_manual_domains()` → `manual_rej`；`EXEMPT = manual_rej ∪ FORCE_DIRECT`。（**必须在分类前就绪**，因为 `classify()` 依赖这两个全局。）
4. 读 **ADH querylog** → `ads, directs, proxies`。
5. 读 **Shadowrocket 新/变化日志** → **不并入三通道**（2026-09-30 起）；只 ① 统计 stale 诊断
   ② 把红果/番茄族里实测被 REJECT ≥`HONGGUO_MIN_HITS` 次的主机记入 `.hongguo_state.json`（首次运行会回填全部历史库）。
6. `MERGE_CHANNELS`（默认 `direct,proxy`）：把直连/代理主机名**塌缩到 base domain**（`api.a.com → a.com`）。拦截**不塌缩**。
7. 读仓库现有集合 `repo_sets()` → `rej_x / dir_x / prox_x`。
8. 计算目标集合：
   - `reject_des = ads | (rej_x ∩ manual_rej)` → `prune_subsumed()`
   - `direct_des = directs | dir_x`，`proxy_des = proxies | prox_x`
   - `FORCE_DIRECT`：从 reject 剔除、并入 direct（并豁免自动拦截）
   - `FORCE_REJECT`：从 direct/proxy 剔除、并入 reject
9. `guard_shadow(direct_des, reject_des)`：直连父域若**盖住**拦截子域，按是否在国内清单决定丢/留（见 §9）。
10. `resolve_conflicts`（`CONFLICT_CHECK=1`）：跨通道冲突按 **拦截 > 直连 > 代理** 保留高优先；显式 `FORCE_DIRECT` 永远赢。
11. `--check`：打印到此为止即退出（**不写**）。
12. `PROBE_ENABLE`：**新增**的直连/代理候选，用干净公共解析器（`223.5.5.5,119.29.29.29`）实测；明确 NXDOMAIN 的丢弃，探针不可用则保留。（拦截桶不做实测。）
13. `ROUTE_PROBE`：对新增/变更的直连/代理候选，用本地代理做对照，判断到底该 direct 还是 proxy，必要时**翻转**。
14. **写 ADH**：`adh_sync_rules(converge="||")` 写拦截（含手工区通配规则），`converge="@@||"` 写放行。
15. **写仓库**：`repo_sync_set()` 收敛 `adh-custom.txt` / `direct-custom.list` / `proxy-custom.list` 的自动区。
16. **Telegram 通知**（非 dry-run）：命中数、新增/删减、新冲突、手机 stale。
17. `--compact`：走一次性归并清理分支（§11）。

---

## 5. 分类逻辑 `classify(domain)`

```
if ADLIST 命中 且 domain 不在 EXEMPT(后缀匹配) → "ad"
elif DIRECT_RE 命中                            → "direct"
elif is_suspected(AD_RE 命中 且不在 PROTECTED) → "ad"
elif PROXY_RE 命中                             → "proxy"
else                                           → None
```

- `DIRECT_RE`：`rtcxyz.com / volccdn.com / bytevcloud.com / amemv.com / zijieapi.com / snssdk.com / douyinvod.com / douyinpic.com`。
- `AD_RE`：`dsp. / pangolin / pangle / dailygn / ecombdapi / zztfly / ugsdk / aiclk / analytics`
  ＋**通用遥测标签**（2026-09-25 owner 同意后加，**边界锚定**，只匹配整段标签）：
  `(^|\.)(log|logs|log[0-9]+|mon|mon[0-9]+|monitor[0-9]*|metric|metrics|stat|stats|stat[0-9]+|track|tracker|tracking|report|reports|collect|beacon|pixel|telemetry|event|events)(\.|$)`。
  实测（3,562 个 allowed 域名）：**ad 16→41、proxy 31→9、direct 不变**；多出 22 个 `*.metric.gstatic.com` ＋ wechatpay/qq/microsoft 各 1。
  （同日删掉冗余的 `-dsp.` / `.dsp.`：`re.search` 是子串匹配，`dsp.` 已完全覆盖二者，增量命中实测 0。）
- `PROTECTED`：`reading / novel / douyin / snssdk / byteimg / volccdn / apple / zijieapi / bytegecko / ecombdimg / fnnas`（命中则**不**按广告处理，子串匹配）。`fnnas` 是 2026-09-25 遥测词上线时补的豁免——飞牛 NAS 自家服务域，实测被新规则命中 1 次。
- `PROXY_RE`：google/youtube/openai/github/telegram/twitter/facebook/netflix/discord/spotify… 等。
- `EXEMPT` 用**后缀匹配**（`in_domset`）：父域豁免会覆盖其子域（如 `polaris.zijieapi.com` 覆盖 `polaris5-normal-zb.zijieapi.com`）。
- `ADLIST` = Hagezi wildcard multi（经 `git.521989.xyz` 加速，缓存 24h，失败退缓存/空）。

---

## 6. 函数清单

**配置 / I/O**
- `load_env()` / `cfg(key)`：`.env` → 环境变量 → `DEFAULTS`（优先级：真实 env > .env > DEFAULTS）。
- `http(method,url,headers,body)`：统一 urllib 请求，返回 `(status, text)`。

**分类 & 集合**
- `in_domset(host,set)` 后缀匹配；`is_suspected()` 广告特征判定。
- `classify()` 三通道判定（见 §5）。
- `base_domain()`（+`MULTI_TLD`）塌缩到可注册域。
- `load_adlist()` / `load_cn_domains()`：带缓存的参考清单，优雅降级。
- `prune_subsumed()`：删掉「被父规则覆盖」的冗余子域（无损）。
- `guard_shadow()`：处理「直连父域盖住拦截子域」。
- `resolve_conflicts()`：跨通道冲突去重（高优先胜）。

**数据源**
- `adh_domains()`；`sr_extract_host()` / `shadowrocket_rejected()` / `shadowrocket_scan()` / `sr_db_state_load()/save()`；
  `cfg_csv()` / `hongguo_family()` / `hongguo_state_load()/save()` / `run_hongguo_only()`。

**探活**
- `probe_domain()`（干净解析器解析测试）；`curl_reach()`（直连/代理可达性）。

**仓库读写**
- `repo_manual_domains()` / `repo_manual_wildcards()`：读手工区（含通配）。
- `repo_sets()`：读现有三份清单为集合。
- `repo_sync_set()`：收敛某文件的自动区。
- `compact_repo_file()` / `refresh_header()`。

**ADH 写入**
- `adh_sync_rules()`：收敛写 `user_rules`（`converge` 全量替换，保护 `*` 规则）。
- `compact_adh()`：把 `@@` 放行压到 base domain。

**其它**
- `guard_drop()` 安全阀；`parse_domains()`；`split_manual()`+`AUTO_MARK`；`tg_send()`；`selftest()`；`compact()`；`main()`。

---

## 7. 关键配置（`DEFAULTS`）

| 键 | 默认 | 说明 |
| --- | --- | --- |
| `ADH_URL/USER/PASS` | 本机/账号 | ADH 地址与凭据 |
| `ADH_WRITE` | `1` | 是否写回 ADH user_rules |
| `REPO` | `henrysha1989/shadowrocket-adr-rules` | 仓库 |
| `REPO_PATH / REPO_DIRECT_PATH / REPO_PROXY_PATH` | `adh-custom.txt / direct-custom.list / proxy-custom.list` | 三份落地文件 |
| `QUERYLOG_LIMIT / QUERYLOG_HOURS` | `10000 / 0` | 每页条数 / 回看窗口（0=整缓冲区） |
| `MERGE_CHANNELS` | `direct,proxy` | 塌缩为 base domain 的通道 |
| `CONFLICT_CHECK` | `1` | 跨通道冲突处理 |
| `SR_DB_ENABLE / SR_DB_DIR / SR_DB_GLOB` | `1 / /vol01/1001/shadowrocket-db / *.db` | Shadowrocket 日志源（只喂 hongguo 专表 + 诊断） |
| `HONGGUO_ENABLE / HONGGUO_PATH` | `1 / hongguo-ad.list` | 红果专表：开关与仓库内路径 |
| `HONGGUO_MIN_HITS / HONGGUO_TTL_DAYS / HONGGUO_ACTION` | `3 / 90 / REJECT-DROP` | 单库内 REJECT 次数门槛 / 保留天数 / 动作 |
| `HONGGUO_KEYWORDS / HONGGUO_FQNOVEL_ROOT / HONGGUO_FQNOVEL_EXTRA / HONGGUO_EXCLUDE` | 见脚本 | 族口径与内容 CDN 硬排除 |
| `FORCE_DIRECT` | 一长串 | 强制直连 + 豁免自动拦截（字节核心服务/直播域等） |
| `FORCE_REJECT` | `queniuck.com,kuiniuca.com,onethingpcs.com,jomodns.cn` | 强制拦截 |
| `ADLIST_ENABLE / ADLIST_URLS / ADLIST_CACHE_HOURS` | `1 / Hagezi multi / 24` | 参考黑名单 |
| `CN_LIST_URL` | blackmatrix7 China_Domain | 国内清单（供 shadow guard） |
| `INGEST_BLOCKED_AD` | `1` | 镜像 ADH 已拦（且参考清单也判 ad）的域 |
| `PROBE_ENABLE / PROBE_RESOLVERS / PROBE_TIMEOUT` | `1 / 223.5.5.5,119.29.29.29 / 4` | 绑前解析实测 |
| `ROUTE_PROBE / ROUTE_PROXY / ROUTE_TIMEOUT` | `1 / socks5h://127.0.0.1:2080 / 5` | 直连↔代理路由校正 |
| `SAFETY_MIN_DROP / SAFETY_MAX_DROP_PCT` | `5 / 30` | 安全阀阈值 |
| `AUTO_REJECT_TTL_DAYS` | `14` | 自动拦截域「最后见到后」保留天数（LRU/防抖动；0=关闭） |
| `COLLAPSE_BLACKLIST` | 一串大厂根基域 | 这些根域下的主机**不塌缩**、保留完整 FQDN |
| `TELEGRAM_BOT_TOKEN / CHAT_ID / PROXY` | — | 通知（token 在 `.env`） |

> 🔐 凭据（`ADH_PASS` / `REPO_TOKEN` / `TELEGRAM_BOT_TOKEN`）已从源码移到工作区 **`.env`（`chmod 600`）**；源码 `DEFAULTS` 里对应值已置空。优先级：真实 env > `.env` > `DEFAULTS`。工作区非 git 仓库，`.env` 不会被提交。

---

## 8. 落地与下发链路

```
脚本一轮
 ├─ ADH user_rules           （拦截 ||d^  +  放行 @@||d^）
 │    └─ 拦截目标 = reject_des（只来自 ADH）∪ hongguo 专表候选（只喂 ADH，不写那 3 个清单）
 └─ GitHub 仓库
      ├─ adh-custom.txt      ── GitHub Action(convert.yml) ──▶ reject-custom.list
      ├─ direct-custom.list
      ├─ proxy-custom.list
      ├─ hongguo-ad.list     （只来自手机 db：实测被 REJECT ≥N 次的红果/番茄族主机，一律 REJECT-DROP）
      └─ (update_readme_counts.py 刷新 README 规则量)
                                   │
                                   ▼ 手机订阅
                          Shadowrocket 拦截/直连/代理（+ 红果专表）
```

- `convert.py`：`||d^`→`DOMAIN-SUFFIX,d,REJECT`，`@@||d^`→`DOMAIN-SUFFIX,d,DIRECT`，`||kw*^`→`DOMAIN-KEYWORD,kw,REJECT`；跳过 `IP-CIDR,` 等。
- 手机端改动**需手动刷新订阅**才生效。

---

## 9. 安全阀与不变量

1. **`guard_drop`**：一次写入若删除 ≥ `SAFETY_MIN_DROP`(5) **且** > `SAFETY_MAX_DROP_PCT`(30%) → **中止**（需 `--force`）。防误判/读失败导致整表被清。
2. **`split_manual` FAIL-SAFE**：标记缺失 → 整文件视为手工区，绝不收敛。
3. **仓库读取失败 → ABORT**（重试 3 次后 `sys.exit`），绝不静默返回空集合（否则会清空规则）。
4. **通配规则保护**：收敛时跳过含 `*` 的规则；`repo_manual_wildcards()` 每轮把手工区 `||...*^` 重新推给 ADH。
5. **参考清单优雅降级**：拉取失败 → 用缓存 → 再不行用内置 `AD_RE`（不硬失败）。
6. **SR 半拷贝/锁库**：读取失败即跳过，下轮重试；状态仅成功时更新。
7. **`EXEMPT` 后缀豁免**：手工区/FORCE_DIRECT 的**子域**也不会被自动拦截。
8. **`cfg_bool()`**：功能开关用严格布尔解析（`0/false/no/off/空`=关）——修复了 `cfg()` 把 `"0"` 当真的老问题。
9. **单实例锁**：`main()` 用 `fcntl.flock` 锁 `/tmp/adh_gist_sync.lock`，cron 与手动不会并发写。
10. **自动拦截保留期（LRU）**：自动广告域在「最后被看到」后保留 `AUTO_REJECT_TTL_DAYS`(默认14) 天，避免「手机本地拦掉→ADH 看不到→掉出→又放行」的抖动。

---

## 10. 状态 / 缓存文件（均在脚本目录）

| 文件 | 作用 |
| --- | --- |
| `.env` | 可选：覆盖 DEFAULTS |
| `.adlist-cache.txt/.json` | 参考黑名单缓存 |
| `.cn-cache.txt/.json` | 国内清单缓存 |
| `.adh_conflicts.json` | 上轮冲突（用于「新冲突」去重告警） |
| `.sr-db-state.json` | 已处理的 SR 日志文件 `basename → size:mtime` |
| `.hongguo_state.json` | hongguo 候选池 `host → 最后命中时间戳`（空/缺 = 触发首次全量回填） |
| `.auto_reject_state.json` | 自动拦截域 → 最后见到时间戳（LRU 保留期用） |
| `.env`（`chmod 600`） | 凭据（ADH/GitHub/Telegram），不入库 |

---

## 11. 命令行

```bash
python3 adh_gist_sync.py              # 正常一轮（会写 ADH + 仓库）
python3 adh_gist_sync.py --dry-run    # 演练：只打印 +N/-N，不写
python3 adh_gist_sync.py --check      # 只算不写（到冲突分析为止）
python3 adh_gist_sync.py --selftest   # 纯函数自检
python3 adh_gist_sync.py --compact    # 一次性：把列表/ADH 放行压到 base domain
python3 adh_gist_sync.py --force      # 允许越过 guard_drop 安全阀
```

---

## 12. 定时调度

- 宿主 cron：`/etc/cron.d/adh-gist-sync`，**每 4 小时**（`0 */4 * * *`，00/04/08/12/16/20）。
- 以 **root** 运行 wrapper `/usr/local/sbin/adh-gist-sync.sh`（打时间戳后跑脚本），日志 `/var/log/adh-gist-sync.log`。
- root 身份才能读 `/vol01/1001/shadowrocket-db`（agent 用户读不了）。

---

## 13. 注意事项 / 已知局限

- **手机订阅需手动刷新**，否则改了不生效。
- **自动拦截区是「按当前 querylog 窗口重新推导」的**：某域被手机拦住后 ADH 看不到其查询，过一阵会自己掉出列表（自净化的副作用）。
- **手动只在 ADH 里加的规则会被覆盖**（改为「改仓库」）。
- `MERGE_CHANNELS` 会把直连/代理**塌缩到 base domain**（粒度偏粗）。
- 新增直连/代理会**探活+路由校正**，只在内网可解析的域可能被误丢/误翻转。
- ~~功能开关关不掉~~ **已修复（2026-09-21）**：新增 `cfg_bool()`，`X=0` / `X=` 现在真能关闭。
- 同一时刻（cron + 手动）并发运行会各自写 ADH/仓库 → 尽量别手跑，先 `--dry-run`。
- 凭据明文在脚本里。

---

## 14. 排障提示

- 只读预演：`--dry-run` / `--check`。
- 日志：`/var/log/adh-gist-sync.log`。
- ADH 侧核对：`GET /control/filtering/status` 的 `user_rules`。
- 参考清单/国内清单拉取：看 stdout 的 `adlist ...` / `cn list ...` 行。
- 「手机还拦着已放行域」：看 stale 诊断行 → 让手机刷新订阅。

---

## 15. 变更记录

### 2026-09-21（晚，依第三方评审落地）
- **`cfg_bool(key, default)`**（新增）：严格布尔开关解析（env 存在即权威；`0/false/no/off/空` → False）。8 处开关（`ADLIST_ENABLE`/`INGEST_BLOCKED_AD`/`ADH_WRITE`×2/`SR_DB_ENABLE`/`CONFLICT_CHECK`/`PROBE_ENABLE`/`ROUTE_PROBE`）改用它 → 开关终于能关。
- **单实例锁**：`main()` 起始 `fcntl.flock(LOCK_EX|LOCK_NB)` 锁 `/tmp/adh_gist_sync.lock`，抢不到即退出（`--selftest` 除外）。
- **凭据外置**：`ADH_PASS`/`REPO_TOKEN`/`TELEGRAM_BOT_TOKEN` → `.env`（600）；源码置空。
- **自动拦截保留期（LRU）**：新状态 `.auto_reject_state.json`，`reject_des = (ads | auto_keep) | (rej_x ∩ manual_rej)`；`auto_keep` = 最后见到在 `AUTO_REJECT_TTL_DAYS`(14) 天内者；手机端 REJECT（SR 日志）也刷新时钟。防「拦截→掉出→放行」抖动。
- **塌缩黑名单**：`COLLAPSE_BLACKLIST`（多用途大厂根基域）下的主机**不塌缩**、保留完整 FQDN，避免塌缩父域顺带放行同级广告子域。
- 验证：`--check` / `--dry-run` 通过。dry-run 输出：ADH **+12/-3**（拦截）、**+72/-0**（放行）；`adh-custom.txt` +12；`direct-custom.list` +72（其中 ~71 来自塌缩黑名单的 ByteDance API/CDN FQDN）。

### 2026-09-25（owner 要求「审计判断系统、提准确率、精简不冗余」）
- **判断系统实测审计**（用一个一次性 harness 把真实 querylog 过一遍 classify；schema 与源文件同源，不进仓库）：
  数据 = 85,450 条记录 → 唯一域名 allowed 3,562 / blocked 709。结果：**拦截 16 / 直连 571 / 代理 31 / 丢弃 2,944**；命中来源 ADLIST 85、AD_RE 5、DIRECT_RE 571、PROXY_RE 31；**EXEMPT 救下 74**（Hagezi 命中但手工区/FORCE_DIRECT 豁免）；`PROTECTED` 豁免 0；镜像侧 blocked 709 中判 ad 98。
- **模式使用率**（allowed + blocked 两个集合）：AD_RE 里 `dsp.` 4 次、`analytics` 5、`ecombdapi` 17、`dailygn` 5、`pangolin` 3、`ugsdk` 1；`pangle`/`zztfly`/`aiclk` 两集合均 0（保留作家族覆盖）。`DIRECT_RE` 里 `volccdn.com`/`bytevcloud.com` 0 命中（保留作保险）。`PROXY_RE` 36 条里只有 6 条命中（google/gstatic/googleapis/wikipedia/wikimedia/reddit）。
- **删冗余**：`AD_RE` 去掉 `-dsp.` / `.dsp.`（被 `dsp.` 完全覆盖）；删掉死函数 `refresh_header()`（无任何调用）。改动后重跑同一份数据：六个桶**逐字节一致**（零行为变化），代码 1546 → 1539 行。
- **查证后「不必改」的**：① 丢弃桶里 496 个 `pull-*` 直播拉流端点（douyincdn 417 / douyinliving 55 / pstatp 12 / ixigua 8）——查手机连接日志（53,815 条），`douyincdn.com` **20/20 全部 DIRECT**（命中手机自带 `DOMAIN-SUFFIX,douyincdn.com,DIRECT`）⇒ 手机侧已覆盖，**不加规则**（避免冗余）。② `PROTECTED` 用子串匹配（实测 0 影响），改边界匹配会翻转品牌家族域名，**保持原样**。
- **选项（未采纳，待 owner 定）**：给 `AD_RE` 加通用遥测词（`log/mon/metric/stat/track/report/collect/beacon/pixel/telemetry/event`，边界锚定）。实测影响：ad 16 → 42（多 22 个 `*.metric.gstatic.com` + `fnnas.com`/`wechatpay.cn`/`qq.com`/`microsoft.com` 各 1），proxy 31 → 9。⚠️ 其中 `fnnas.com` 是飞牛 NAS 自己的服务域，拦掉有实质风险 ⇒ 若采纳必须先给它加豁免。

### 2026-09-25（续：owner 拍板「遥测词加、死支路删」）

- **加通用遥测标签**到 `AD_RE`（边界锚定，见 §5）。实测（3,562 allowed）：**ad 16→41、proxy 31→9、direct 不变**；多出来的是 22 个 `*.metric.gstatic.com` ＋ `wechatpay.cn`/`qq.com`/`microsoft.com` 各 1；`fnnas.com` 被新加的 PROTECTED 豁免挡下（`PROTECTED 子串豁免` 0→1）。
  - ⚠️ 副作用：`gstatic.com` 因出现 reject 子域，会走既有冲突裁决（reject > proxy）——可能被从 proxy 列表剔除；手机 FINAL=PROXY，实际路由不受影响，日志里会打印这条冲突。
- **删掉 gist 死支路**：`gist_sync()` 函数 ＋ `GIST_ID`/`GIST_TOKEN`/`GIST_FILENAME`/`TARGET` 四个 DEFAULTS 键 ＋ `main()` 里的分支（本部署只用 repo，09-19 之后没走过）。代码 1539 → 1495 行。`.env` 里的 `GIST_TOKEN` 行由 owner 自行删除（root:600，脚本已不再读取）。

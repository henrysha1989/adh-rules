# adh-rules —— AdGuard Home 侧（独立项目）

> 2026-10-01 从 [`shadowrocket-adr-rules`](https://github.com/henrysha1989/shadowrocket-adr-rules) 拆出来。
> **两个仓库完全独立**：这个仓库只服务 ADH（DNS 层），另一个只服务手机小火箭（客户端分流），
> 互不引用、不共享状态。

> 更新时间：2026-10-11 08:01:55（UTC+0800）

## 内容

| 文件 | 说明 |
|---|---|
| `adh-custom.txt` | **ADH 的过滤清单**（AdGuard 语法 `\|\|域名^`）。脚本每天采集"漏网之鱼"写它的自动区；手工区（`! ===== 自动收集` 标记之上）由 owner 维护（起底规则 + `@@…$important` 放行） |
| `adh_gist_sync.py` | 采集脚本（纯标准库）。宿主 cron `/etc/cron.d/adh-gist-sync` → wrapper → `/vol1/1000/Docker/deepseek-harness/workspace/adh_gist_sync.py` |
| `adh_gist_sync.说明.md` | 设计/原理/排障说明（⚠️ 部分章节写于拆分之前，见文首提示） |
| `convert.py` + `.github/workflows/convert.yml` | 历史遗留：曾把 `adh-custom.txt` 转成小火箭的 `reject-custom.list`。**已停用**（拆分后小火箭侧由 `sr_analyze.py` 直接生成），留档 |

## 订阅地址（ADH「过滤器 → DNS 过滤器」里填这个）

```
https://git.521989.xyz/https://raw.githubusercontent.com/henrysha1989/adh-rules/main/adh-custom.txt
```

⚠️ **2026-10-01 起生效的地址就是上面这条**（原来指向 `shadowrocket-adr-rules`，拆分后旧地址不再更新）。
直连 `https://raw.githubusercontent.com/henrysha1989/adh-rules/main/adh-custom.txt` 也可（国内不稳，建议用加速前缀）。

## 运行

```sh
# cron 自动（宿主，每 4 小时一次，但有日更闸门：同一自然日只真跑一轮）
#   /etc/cron.d/adh-gist-sync → /usr/local/sbin/adh-gist-sync.sh → adh_gist_sync.py

# 手动
python3 adh_gist_sync.py --check          # 只读，算一遍不写
python3 adh_gist_sync.py --dry-run        # 同上
python3 adh_gist_sync.py --selftest
python3 adh_gist_sync.py --watch          # 只读监控（spike/triage），可发 Telegram
```

`ADH_WRITE=0`（默认）：**不再**通过 API 改 ADH 的 `user_rules`，一切走"过滤清单订阅"。
手机小火箭侧的 db 分析与三张清单，**不在本仓库**：见 `shadowrocket-adr-rules`。

#!/usr/bin/env python3
"""Two-channel collector: classify AdGuard Home querylog domains and push them out.

  ads     -> ADH user_rules (||domain^) + repo adh-custom.txt (AdGuard syntax,
             converted by the repo's Action into reject-custom.list)
  direct  -> repo direct-custom.list (DOMAIN-SUFFIX,domain,DIRECT)
  proxy   -> repo proxy-custom.list  (DOMAIN-SUFFIX,domain,PROXY)

Sources (both feed the same classify()/merge pipeline):
  1. AdGuard Home querylog (live, from this host).
  2. Shadowrocket connection-log exports (`proxy-*.db`, sqlite `logging` table) that the
     [已迁出] 手机 db 的解析现在归独立项目 sr/sr_analyze.py，本脚本只处理 ADH querylog。
     (proxied / remote-dns).

Stdlib only (no `requests`).

All values live in DEFAULTS below (ADH is LAN-only), and any of them can be overridden
via env vars / a `.env` file next to this script (priority: real env var > .env > DEFAULTS).

  ADH_URL / ADH_USER / ADH_PASS / REPO / REPO_TOKEN / CLIENT_IP

Usage:  ./adh_gist_sync.py [--dry-run] [--selftest]
"""
import base64
import glob
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timedelta, timezone

# ADH is LAN-only, so these live here. Override any via env / .env.
DEFAULTS = {
    "ADH_URL": "http://127.0.0.1:3000",
    "ADH_USER": "hjiuuh",
    "ADH_PASS": "",
    "CLIENT_IP": "",
    # ⚠️ 2026-09-30 晚：**改成 0**。owner 把脚本产出（adh-custom.txt，AdGuard 格式）作为
    #   「过滤清单」订阅进 ADH，由 ADH 自己定时拉取 ⇒ 脚本不再直接改 user_rules。
    #   必须关掉的原因：本脚本的写回是 `converge="||"`（全量收敛），会删掉 user_rules 里
    #   所有不在「自动分析目标集」里的 `||` 规则 —— 包括 owner 手写的那批。
    #   置回 "1" 可恢复直接写（那时请确认目标集里包含你想保留的手工规则）。
    "ADH_WRITE": "0",
    # 2026-09-25：`TARGET=gist` 那条支路已删（本部署只用 repo；gist 是 09-19 之前的旧通道）。
    "REPO": "henrysha1989/adh-rules",              # 2026-10-01 拆分：ADH 侧独立仓库（与小火箭仓库无关）
    # ⚠️ 2026-09-30 起 REPO_PATH(=adh-custom.txt) 是**给 ADH 订阅的规则集**（AdGuard 格式），
    #    cron 只写它；三个 custom.list 改由 `--sr-analyze` 写（见 REPO_REJECT_PATH）。
    "REPO_PATH": "adh-custom.txt",                  # ADH 规则集（AdGuard 语法）：cron 的唯一输出
    "REPO_REJECT_PATH": "reject-custom.list",       # 拦截清单：只由 --sr-analyze 写
    "REPO_DIRECT_PATH": "direct-custom.list",       # direct-whitelist output (Shadowrocket syntax)
    "REPO_PROXY_PATH": "proxy-custom.list",         # proxy output (Shadowrocket syntax)
    "REPO_BRANCH": "main",
    "REPO_TOKEN": "",  # scopes: gist, repo, workflow
    "TELEGRAM_BOT_TOKEN": "",  # reused from docker-monitor (apprise)
    "TELEGRAM_CHAT_ID": "8058009815",
    # api.telegram.org 必须走代理。原来写 127.0.0.1:2080 —— 宿主跑没问题，但从 dsh 容器跑会
    # ECONNREFUSED（容器里 2080 不在本机）。改成 192.168.3.35:2080：宿主与容器都通。2026-09-27
    "TELEGRAM_PROXY": "http://192.168.3.35:2080",
    "QUERYLOG_LIMIT": "10000",                     # max querylog entries per request (page size)
    "QUERYLOG_HOURS": "0",                         # lookback window in hours; 0 = scan the entire querylog buffer
    # ── 两套模式（2026-09-30 晚 owner 定调，架构转向）──────────────────────────
    # ① **默认（cron）= ADH-only**：读 ADH querylog 抓漏网之鱼 → 只写 `adh-custom.txt`
    #    （**AdGuard 格式**，`||d^` 拦 + `@@||d^` 放），owner 把这个文件当**规则集**订阅进 ADH，
    #    之后跟着 ADH 自己的刷新周期自动更新。**不再**写三个 custom.list，也**不再**转换格式。
    # ② **`--sr-analyze`（手动，owner 上传 db 后跑）**：分析手机 db，找出
    #    ㈠ 拦截漏网之鱼（classify 判广告、手机却没拦）
    #    ㈡ 直连偷跑代理（classify 判直连、手机却走了代理）
    #    → 直接写三个 custom.list；动作由脚本按证据自动判定（见 SR_DROP_PATTERNS）。
    # 红果专表 hongguo-ad.list 已于 2026-09-30 取消（内容并入 reject-custom.list）。
    # ⚠️ ADH 侧是否**忽略**小火箭那三个清单里的内容。默认 "0"（暂不忽略，保持现状）。
    #    置 "1" 后 ADH 的拦截目标集只来自它自己的 querylog 分析 + force_reject，
    #    `reject-custom.list` / `direct-custom.list` / `proxy-custom.list` 的手工区**不再**被读作
    #    「owner 意图」⇒ 两个数据源彻底分开。切换时机由 owner 定（2026-09-30：等下一轮 cron 跑完、
    #    自动区有了自己的新增之后再切）。
    "ADH_IGNORE_SR_LISTS": "0",
    # 🎯 2026-09-30 owner「规则要准确，不是越多越好」——
    # **信号/埋点族名优先于"直连域名族"**。否则同一族名在不同域名下会一边 DROP 一边直连：
    #   实测 `mon11-misc-lf.fqnovel.com` 判 ad（参考黑名单收了）→ DROP，
    #   而 `mon11-misc-lf.amemv.com` / `mon0-misc-lf.amemv.com` /
    #   `abtest3-misc-lq.zijieapi.com` / `live-player-log.zijieapi.com`
    #   因为挂在字节系"直连族"域名下、参考黑名单又没收 ⇒ 被判 direct → 写进**直连表**（埋点走直连）。
    # 命中即判 ad（进 reject 分析；被 EXEMPT/放行父域覆盖的仍然放行）。
    "SIGNAL_PATTERNS": "-misc-lf,-misc-lq,-applog,live-player-log,-ad-sign,reading-ad,ads-normal,telemetry",
    "MERGE_CHANNELS": "direct,proxy",                 # collapse hostnames -> base domain (comma list)
    "CONFLICT_CHECK": "1",                           # resolve cross-channel conflicts before writing (reject>direct>proxy)
    # 2026-09-26（owner：冲突时实测，拦截优先但不误伤国内 App/网站）：
    #   evidence = 实测裁决 —— 先试「降级」再考虑「放行」，拦截优先，只有真证据才放行。
    #   legacy   = 旧行为（一律保拦截，直接剔除低位通道）。
    # 无论哪种模式，FORCE_REJECT / 参考黑名单(ADLIST)命中 / 广告型 FQDN 都保持拦截。
    "CONFLICT_POLICY": "evidence",
    "CONFLICT_DOWNGRADE": "1",                       # 允许把「宽拦截父域（含子域）」降级为只拦广告型子域
    # 「放行」必须同时满足：该域名在实测窗口里被**正常解析**用过(>= 阈值)、不在参考黑名单、且
    # 冲突的直连 FQDN 全部对得上参考黑名单/广告特征。任一不满足 → 退回「降级」或「保拦截」。
    "CONFLICT_EVIDENCE_MIN": "3",                    # 判「确实在用」的最小正常解析次数
    "CONFLICT_MAX_HOSTS": "12",                      # 单域名最多取多少个实测 FQDN 细节（防内存爆）
    # 降级/放行后的合规复核：对放行域名查「国内清单(CN)覆盖」+「直连是否真的通」。
    # 只是**复核与告警**，不是放行前提（放行前提是实测流量证据）。
    "CONFLICT_VERIFY": "1",
    # 全量重判审计（2026-09-26 owner：「把已经存在的几百条记录用新规则重新跑一下」）：
    # 每轮把「现有拦截表 + 本轮新广告域」全部用 decide_one() 过一遍，出
    # `reclassify-report.{md,json}`（只读，不改 ADH/仓库）。`--audit` = 只跑审计不写。
    "AUDIT_RECLASSIFY": "1",
    # 只读监控（`--watch`）：从 ADH querylog 找「某域名被拦后疯狂重试」的尖峰，
    # 有异常才通过 Telegram 报（复用 TELEGRAM_* 与 TELEGRAM_PROXY），没异常一声不吭。
    # 判据 = 该域名最近窗口的每分钟被拦数 vs 它自己过去 24h 的中位数（自比自，避免跨域比较）。
    "WATCH_WINDOW_MIN": "30",                        # 最近窗口（分钟）
    "WATCH_BASE_HOURS": "24",                        # 基线回看（小时）
    "WATCH_MIN_EVENTS": "200",                       # 最近窗口被拦次数下限（低于此不报）
    "WATCH_RATIO": "8",                              # 最近速率 / 基线中位数 的倍数阈值
    "WATCH_DEDUP_HOURS": "6",                        # 同一域名多久内不重复报
    "WATCH_STATE": ".adh-watch-state.json",
    # ADH 侧误伤 triage（随 `--watch` 一起跑，只读）：在被拦域里找「≥2 客户端在查 +
    # 不像广告 + 不在白名单」的，只对**新增**的发通知。补 AUDIT_RECLASSIFY 的盲区
    # （它只审客户端那 496 条，覆盖不到 ADH 的订阅大表）。2026-09-27。
    "TRIAGE_ENABLE": "1",
    "TRIAGE_MIN_EVENTS": "5",                        # 被拦次数下限（低于此不报）
    "TRIAGE_LOOKBACK_H": "24",                       # 只看最近 N 小时（querylog 是历史窗口）
    "TRIAGE_RECHECK": "1",                          # 报告前用 check_host 复核「当前是否仍被拦」
    "TRIAGE_STATE": ".adh-triage-state.json",
    # 强制直连+豁免：从拦截里剔除、加白、且镜像永不再自动拦截。
    # 2026-09-20 21:xx 新增一批：它们是「CNAME 落到 *.bytedns1/3.com」的字节核心服务，
    # 被 ||bytedns1.com^/||bytedns3.com^ 按 CNAME 链误拦（抖音卡顿根因），故整批加白。
    "FORCE_DIRECT": (
        "amdc.m.taobao.com,"
        "aweme.snssdk.com,api.amemv.com,api-play.amemv.com,api-play-hj.amemv.com,"
        "webcast.amemv.com,webcast-core-m.amemv.com,is.snssdk.com,is.snssdk.com.bytedns1.com,"
        "ib.snssdk.com,security.snssdk.com,frontier-aweme-zjg-ipainner.amemv.com,"
        "life-service-open.zijieapi.com,vcs-hj.zijieapi.com,webcast-open.douyin.com,"
        "webcast-open-lf.douyin.com,im-open.douyin.com,-mgsdk-sign.byteimg.com,"
        "mssdk3-normal-hj.zijieapi.com,mssdk3-normal-hl.zijieapi.com,mssdk3-normal-lf.zijieapi.com,"
        "tnc0-alisc1.zijieapi.com.230b2a2545cfa773.queniuck.com,tr.byteurl.cn,"
        "pitaya.bytedance.com,scc.bytedance.com,m.baike.com,render.ecombdpage.com,"
        "log-report.rtc.volcvideo.com,lf-cdn-tos.bytescm.com,lf1-cdn-tos.bytescm.com,"
        "lf-leads-fe-scm.bytecdn.com,lf26-effect-302.byteeffecttos.com,"
        "lf3-effectcdn-tos.byteeffecttos.com,lf3-static.bytednsdoc.com,lf3-ttcdn-tos.pstatp.com,"
        "bytedns1.com,bytedns3.com,"   # CNAME 落地域：整域拦截会按 CNAME 链误伤字节服务，必须放行
        # 2026-09-20 22:15 owner「先撤」：系统/功能服务（非广告/隐私），属过杀 → 放行
        "input.shouji.sogou.com,ws-keyboard.shouji.sogou.com,worldwide.sogou.com,"
        # 2026-09-27：i.snssdk.com —— 当初因"客户端假响应方案(T8: REJECT-ARRAY)"而放行，
        # 但**假响应方案已被否决**（实测重试翻倍）；现 owner 决定**彻底放行**（2026-09-27 晚）。
        # ⚠️ 这个豁免**必须保留**：它在参考黑名单(ADLIST)里命中、classify()=ad，
        #    一旦移出 FORCE_DIRECT 就会被重新判成广告拦回去。
        #    实测证据见 memory：ADH 全量 195h 只有 9 次查询（对比 is. 318 / aweme. 183），
        #    CNAME 落正规华为云 CDN（不是 queniuck 那类域名前置），手机侧 ~24 次/分、无风暴。
        "i.snssdk.com,"
        # 2026-09-27：T2 放行的两个 HTTPDNS 域也在 FORCE_DIRECT 里声明，
        # 否则 ADH 侧既不拦也不放（客户端靠 RAW 区的 DIRECT 放行，ADH 却无白名单）。
        "dig.bdurl.net,dns.weixin.qq.com.cn,"
        "update.wps.cn,ks.pull.yximgs.com,tx-kmpaudio.pull.yximgs.com,"
        "api.tuisong.baidu.com,apd-pcdnwxlogin.teg.tencent-cloud.net,"
        "rms-drcn.platform.dbankcloud.cn,browsercfg-drcn.cloud.dbankcloud.cn,"
        "u.meizu.com,api-flow.flyme.cn,"
        "mum.alibabachengdun.com,mum.alibabachengdun.net,"
        "sdkoptedge.chinanetcenter.com,appcfg.v.qq.com,"
        # 2026-09-21 owner 报「抖音直播卡」。以下域名被整域/子域 REJECT 误杀（直播拉流 CDN、
        # 边缘加速/PCDN 调度、直播信令），ADH 实测命中数千次 → 整域放行并豁免自动拦截：
        "bytegecko.com,qrstuvwxyzab.com,ndcpp.com,douyinstatic.com,"
        "douyinvod.com,douyinpic.com,bytednsdoc.com,"
        # 2026-09-30 owner：抖音**电商**（ecombdapi 系）手机侧已全直连，但旧 user_rules 迁移来的
        # 自动区里还留着 `||ecombdapi.com^` 整域拦截 ⇒ 走 ADH DNS 的客户端会把电商打死。
        # 整域放行 + 豁免自动拦截（ADH 侧自己的口径；手机侧另有独立项目 sr/sr_analyze.py）。
        "ecombdapi.com,"
        # polaris = 字节配置/信令中心，Hagezi 按机房变体逐条列为广告 → 全量放行
        "polaris3-normal-gl2.zijieapi.com,polaris3-normal-hl.zijieapi.com,"
        "polaris3-normal-lf.zijieapi.com,polaris3-normal-lq.zijieapi.com,"
        "polaris3-normal-xh.zijieapi.com,polaris3-normal-zb.zijieapi.com,"
        "polaris5-normal-gl2.zijieapi.com,polaris5-normal-hl.zijieapi.com,"
        "polaris5-normal-lf.zijieapi.com,polaris5-normal-lq.zijieapi.com,"
        "polaris5-normal-xh.zijieapi.com,polaris5-normal-zb.zijieapi.com,"
        # 2026-09-27 owner 批准修误伤（审查报告 findings）：
        # 微软遥测族，两个不同根因分别被误判为广告 ——
        #   ① *.events.data.microsoft.com 被参考黑名单(ADLIST)收录
        #   ② *.dsp.mp.microsoft.com 命中脚本的 `dsp\.` 广告特征
        # 实测证据反向：同族放行 40 / 拦截 30。按**根域**豁免（in_domset 含子域匹配），
        # 覆盖 mobile/v10/v20.events.data 与 cp501/geo/kv501.prod.do.dsp 共 6 条。
        # 加入后会：从 reject 剔除、进 direct；ADH 侧 converge 掉这些 `||…^`；
        # 仓库自动区对应条目由 repo_sync_set 自动移除（勿手改）。
        "events.data.microsoft.com,dsp.mp.microsoft.com,"
        # 2026-09-27 owner 二次批准（ADH querylog 误伤 triage，见 memory）：
        # 这三条都不在手工区，是被**订阅大表**误收的，放行不影响手工区那 267 条的意图。
        #   whoami.akamai.net  939 次/2 客户端 —— Akamai 出口 IP 探测，标准基础设施
        #                      （Privacy 表按"指纹识别"收）
        #   mmgame.qpic.cn     240 次/7 客户端 —— 腾讯游戏域（qpic.cn 是腾讯图片 CDN）
        #   id6.me             204 次/3 客户端 —— 中国移动一键登录/本机号码认证，登录功能依赖
        "whoami.akamai.net,mmgame.qpic.cn,id6.me,"
        # 2026-09-27 owner 第三次批准（triage 首跑抓到的第 1 条）：
        # 微信子域被订阅表误收。用**精确域**而不是 `weixin.qq.com` 根域 ——
        # 微信主域太重要、不该整域放行，且 `weixin.qq.com` 下确实存在统计/广告子域。
        "szlong.weixin.qq.com,"
        # 2026-09-30 owner：公司自建系统（钉钉工作台里的 H5 应用 / OA）。
        #   真身 = megarobo.com / megarobo.tech / megarobo.info（OA 在 oa.megarobo.info）
        #   + yunmart.com（webapp-dd.yunmart.com）。2026-09-29 钉钉 web「网络连接异常」的真因
        #   就是这几族没被显式直连 ⇒ 掉进漏网之鱼走代理，内网系统看到境外 IP → 风控。
        #   整域放行 + 豁免自动拦截（ADH 侧口径），ADH 侧对应
        #   `@@||域名^$important` 已在 adh-custom.txt 手工区（yunmart 同批补上）。
        "megarobo.com,megarobo.tech,megarobo.info,yunmart.com"
    ),
    # 强制拦截：广告/隐私域名（域名前置 CDN 底座）+ PCDN，从直连/代理剔除并加黑。
    # ⚠️ 2026-09-20 21:xx：bytedns1.com/bytedns3.com 已移除 —— 它们既是广告前置底座、
    # 也是字节服务的 CNAME 落地域，整域拦截会按 CNAME 链误伤抖音核心接口（见 FORCE_DIRECT 注释）。
    "FORCE_REJECT": "queniuck.com,kuiniuca.com,onethingpcs.com,jomodns.cn",
    # 只在客户端（小火箭）丢包拦截、**不写进 ADH user_rules** 的域名。2026-09-27 owner 定调「功耗优先」：
    #   这族的客户端规则是 REJECT-DROP（丢包），而 ADH 的 DNS 拦截是另一条**失败信号**：
    #   域名在 ADH 侧 NXDOMAIN + 客户端 TCP 被丢 ⇒ SDK 连收两次失败，更容易进入激进重试；
    #   且每次都要多一轮系统 DNS + 一次 App 唤醒。实测该族曾达 260 万事件/小时（纯烧电）。
    #   ⇒ 移除 ADH 的 DNS 拦截，只留客户端 DROP（静默、SDK 不重试），拦截效果不变。
    # 与 FORCE_REJECT 的区别：FORCE_REJECT 仍然会写进 ADH。
    "CLIENT_DROP_ONLY": (
        # ⚠️ 2026-09-30 起**清空**（owner 决定）：小火箭宿主机（iphone17pm）已不再用自建 DoH
        #    接入 ADH ⇒ ADH 与小火箭规则**独立运行**，ADH 只服务其他客户端（只有拦截/放行两态）。
        #    本表存在的理由是「手机侧有 DROP 规则，ADH 别在 DNS 层先拦住」——手机不走 ADH 之后
        #    这条理由消失；继续放行只会让**其他客户端**少一层 DNS 拦截。
        #    ⇒ 这些域恢复由 ADH 拦（前提是它们被判为 ad，历史上确实是），
        #      手机侧的 DROP 规则（`adh-custom.txt` RAW 区）照旧生效，两边互不影响。
        #    ⚠️ 曾经因为「ADH 也放行」而调过这里的域名（要恢复就把下面注释解开）：
        # "v11-reading-ad.qznovelvod.com,v26-reading-ad.qznovelvod.com,"
        # "v5-bd-daily-reading-ad.qznovelvod.com,v5-se-sjy-daily-reading-ad.qznovelvod.com,"
        # "v5-ex-reading-ad.qznovelvod.com,v6-daily-reading-ad.qznovelvod.com,"
        # "v6-reading-ad.qznovelvod.com,v9-reading-ad.qznovelvod.com,"
        # "v13-reading-ad.qznovelvod.com,v95-zjjx2tc-reading-ad.qznovelvod.com,"
        # "v95-aw-reading-ad.qznovelvod.com,v95-se-zjwztc-reading-ad.qznovelvod.com,"
        # "v96-sz-daily-reading-ad.qznovelvod.com,"
        # "ad.fqnovel.com,mon-.fqnovel.com,mon11-misc-lf.fqnovel.com,"
        # "mon11-misc-lq.fqnovel.com,mon3-misc-lf.fqnovel.com,"
        # "rtlog5-applog-lf.fqnovel.com,"
        # "i.snssdk.com,"
        # "applog.zijieapi.com"
        ""
    ),
    "ADLIST_ENABLE": "1",                            # 参考黑名单交叉比对：命中即判 reject
    "ADLIST_URLS": "https://git.521989.xyz/https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/multi.txt",
    "ADLIST_CACHE_HOURS": "24",                     # 本地缓存有效期（小时）
    # 国内域名清单（blackmatrix7 China_Domain）：用来判断“会 shadow 掉 reject 子域的直连父域”
    # 是否仍被国内清单覆盖（覆盖则可安全从直连表剔除，否则保留并告警）。
    "CN_LIST_URL": "https://git.521989.xyz/https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/China/China_Domain.list",
    "INGEST_BLOCKED_AD": "1",                        # 镜像 ADH 已拦(reason∈BLOCKED_REASONS)的域名进 reject：否则 ADH 拦了、客户端没规则会"翻转"成走代理
    "PROBE_ENABLE": "1",                             # 新增域名绑前实测：干净解析器验证可解析
    "PROBE_RESOLVERS": "223.5.5.5,119.29.29.29",     # 用于实测的公共解析器（不经 ADH）
    "PROBE_TIMEOUT": "4",
    "ROUTE_PROBE": "1",                             # 绑前用代理实测路由（直连 vs 代理）
    "ROUTE_PROXY": "socks5h://127.0.0.1:2080",       # 对照组：socks5/http 代理
    "ROUTE_TIMEOUT": "5",
    # 安全阀：一次写入若删除条数 ≥ SAFETY_MIN_DROP 且 > 现有×SAFETY_MAX_DROP_PCT% 条，直接中止
    # （防止误判 / 读取失败 / 标记丢失导致整表被清）。确实要清时加 --force。
    "SAFETY_MIN_DROP": "5",
    "SAFETY_MAX_DROP_PCT": "30",
    # 自动拦截保留期（天）：自动收集的广告域在“最后一次被看到”后仍保留这么久才淘汰，
    # 避免「手机本地拦掉→ADH 看不到→掉出列表→又放行」的来回抖动。0 = 关闭（沿用旧行为）。
    # 2026-09-27：14 → **90**。因为正式版手机 DNS 已改本地 DoT（不再经 ADH），
    # 手机这条最活跃的 querylog 来源没了；ADH 只剩其他客户端（魅族/小米/PC/平板），
    # 它们的域名集合小得多 ⇒ 自动区续期变慢。而手机 DB 是**时不时上传**（不是每天），
    # 只要某个域在 90 天内的某次 DB 里出现过就会被续期（SR db 的 REJECT 域会经 classify()
    # 进 ads ⇒ 自动刷新 ar_state），留足余量避免清单白白缩水。
    # 副作用可控：淘汰得慢一点 = 少量已失效的广告域多留一阵，不影响正常上网。
    "AUTO_REJECT_TTL_DAYS": "90",
    # 拦截表审查状态：记「可疑条目 + 首次发现时间」，只对新出现的发通知（避免每天重复刷）。
    # 与 `.adh_conflicts.json` 同套路。0/空 = 用默认文件名。
    "REVIEW_STATE": ".review-state.json",
    # 塌缩黑名单：这些多用途大根域下的主机**不塌缩**到根域名，保留完整 FQDN，
    # 避免把「未被拦截的同级广告/打点子域」随父域一起放行。逗号分隔。
    # 注意：amemv/zijieapi/snssdk 等 DIRECT_RE 基座**故意不列**——它们的「塌缩父域盖住
    # 拦截子域」已被 guard_shadow 兜住（有已知拦截子域时父域直接丢弃），再列只会白白
    # 多出 ~72 条冗余直连 FQDN + 自冲突。2026-09-21。
    "COLLAPSE_BLACKLIST": (
        "qq.com,tencent.com,tencent-cloud.net,gtimg.com,"
        "alicdn.com,aliyuncs.com,taobao.com,tmall.com,alibaba.com,alipay.com,aliyun.com,"
        "baidu.com,bdstatic.com,jd.com,360.cn,qihoo.com,"
        "bytedance.com,byteimg.com,bytecdn.com,pstatp.com,"
        "miui.com,xiaomi.com,huawei.com,apple.com,"
        "weibo.com,sinaimg.cn,sina.com.cn,zhihu.com,bilibili.com,kuaishou.com,"
        "meituan.com,dianping.com,pinduoduo.com"
    ),
    # 日更闸门（2026-09-25，owner「改成24小时更新，每天早上8点（中国）」；
    #          2026-09-29 修正：改成"每个本地日期只跑一次"）：
    # cron 仍是每 4 小时唤醒一次（宿主 /etc/cron.d 我够不到），闸门规则：
    #   本地时间 >= SYNC_HOUR，且**今天还没成功跑过** ⇒ 开跑。
    # 为什么不再用「间隔 N 小时」：间隔闸门会自锁在首次运行的那个整点 ——
    #   实测首次在 20:10 跑完，次日 16:00 只差 10 分钟不达 20h 被跳过，于是永远锁在 20:00；
    #   SYNC_HOUR=8 只拦更早的小时、并不能把它拉到 8 点。改成日期判定后不会再漂移。
    # 好处：错过 08:00 会在当天后续唤醒补跑，且一天最多一轮，不用改宿主 cron。
    # 立刻强制跑一轮：`python3 adh_gist_sync.py --force`（该开关同时跳过 guard_drop 安全阀）。
    # 想关掉闸门（回到"每次唤醒都跑"）：把下面两个值都置空。
    "SYNC_HOUR": "8",                                # 从本地这个小时起才允许跑（0-23）
    "SYNC_MIN_INTERVAL_H": "",                       # 额外的"最小间隔"保险；留空 = 不检查（日期闸门已保证一天一次）
}

HERE = os.path.dirname(os.path.abspath(__file__))

AD_RE = re.compile("|".join([
    # 2026-09-25 审计：`\.dsp\.` / `-dsp\.` 是纯冗余 —— re.search 子串匹配下 `dsp\.` 已覆盖
    # 二者；实测（3562 allowed + 709 blocked）两条的增量命中均为 0，故删除。`pangle`/`zztfly`/
    # `aiclk` 本次两集合均 0 命中，但属家族特征（穿山甲等），保留作未来覆盖。
    r"dsp\.",
    r"pangolin", r"pangle", r"dailygn",
    r"ecombdapi", r"zztfly",
    # 2026-09-20: 'ydycdn' REMOVED - it is 亿点云计算(珠海) 的 edge/PCDN CDN (SaaS CDN),
    # not an ad domain; blocking it throttled apps (phone hit *.ydycdn.com 285x) and
    # matched no external ad list. Re-add only with real evidence.
    r"ugsdk", r"aiclk", r"analytics",
    # 2026-09-25（审计后 owner 同意加）：通用遥测/埋点子域。**只匹配整段标签**（锚定 `(^|\.)…(\.|$)`），
    # 避免 09-21 那种「子串命中误伤 CDN」的坑（例：`scdn.co` 命中 `xhscdn.com`）。
    # 实测影响（3,562 allowed 域名）：ad 16→41、proxy 31→9 —— 多出的是 22 个 `*.metric.gstatic.com`
    # 加 wechatpay/qq/microsoft 各 1；`fnnas.com` 同时进 PROTECTED 豁免（飞牛自家服务域）。
    r"(^|\.)(log|logs|log[0-9]+|mon|mon[0-9]+|monitor[0-9]*|metric|metrics|stat|stats|stat[0-9]+"
    r"|track|tracker|tracking|report|reports|collect|beacon|pixel|telemetry|event|events)(\.|$)",
]))
PROTECTED = [
    "reading", "novel", "douyin", "snssdk", "byteimg",
    "volccdn", "apple", "zijieapi", "bytegecko", "ecombdimg",
    # 2026-09-25：遥测词上线后实测会命中 `log.fnnas.com`（飞牛 NAS 自家服务域）→ 加豁免，
    # 避免把 NAS 的云端/远程访问埋点当广告拦掉。
    "fnnas",
]
# Direct-whitelist patterns: CN low-latency media / core CDN / signalling.
DIRECT_RE = re.compile("|".join([
    r"rtcxyz\.com", r"volccdn\.com", r"bytevcloud\.com",
    r"amemv\.com", r"zijieapi\.com", r"snssdk\.com",
    r"douyinvod\.com", r"douyinpic\.com",
]))
# Proxy patterns: services normally reached through the proxy. Built from bare domains so every
# entry is boundary-anchored: (^|\.)d($|\.). An UNANCHORED pattern like r"scdn\.co" substring-
# matched any host containing "scdn.co" - 小红书 CDN *.xhscdn.com ("xh"+"cdn.com") contains it -
# which flipped DIRECT domains to PROXY (owner bug report 2026-09-21). Keep this list bounded.
_PROXY_DOMAINS = [
    "google.com", "googlevideo.com", "gstatic.com", "googleapis.com",
    "youtube.com", "ytimg.com", "ggpht.com",
    "openai.com", "chatgpt.com", "anthropic.com", "claude.ai",
    "github.com", "githubusercontent.com", "githubassets.com",
    "telegram.org", "t.me", "twitter.com", "x.com", "twimg.com",
    "facebook.com", "fbcdn.net", "instagram.com", "cdninstagram.com",
    "whatsapp.net", "whatsapp.com", "netflix.com", "nflxvideo.net", "nflximg.net",
    "wikipedia.org", "wikimedia.org", "reddit.com", "redditstatic.com",
    "discord.com", "discordapp.com", "spotify.com", "scdn.co",
]
PROXY_RE = re.compile("|".join(r"(^|\.)%s($|\.)" % re.escape(d) for d in _PROXY_DOMAINS))
ALLOWED_REASONS = {"NotFilteredNotFound", "NotFilteredWhiteList", ""}
# ADH reasons that mean the query was blocked (used only when INGEST_BLOCKED_AD is on).
BLOCKED_REASONS = {"FilteredBlackList"}

# Populated at runtime by main(): reference ad/privacy blocklist + manual-section exemption.
ADLIST = set()   # suffixes from ADLIST_URLS
EXEMPT = set()   # owner's manual-section domains: never auto-rejected
# owner 的放行意图（权威）：FORCE_DIRECT + 放行清单手工区 + ADH `@@` 白名单。
# 与 EXEMPT 的区别：EXEMPT 只防"自动拦截"，OWNER_ALLOW 是**硬约束** ——
# 任何通道（ads / auto_keep / 仓库 reject 区）里的同域条目都必须被剔除。2026-09-27。
OWNER_ALLOW = set()

# 2026-09-26：实测证据。key = base_domain，value = 聚合（**不含域名原文的打印**，只落盘/入库）。
# 收集来源与 classify() 同源：ADH querylog 的放行记录 + Shadowrocket 连接日志。
OBS = {}
_OBS_KEYS = ("total", "allowed", "blocked", "ad_like", "other_like", "direct_like",
             "proxy_like", "cn_hint", "allow_total")


def host_ok(host):
    """A hostname usable in rules/logs: non-empty, no wildcard/space, no NUL byte and no
    literal `\\000` escape (ADH/手机日志里偶发 `ffvl\\000w-...` 这类非法名字). 2026-09-26."""
    return bool(host) and not any(c in host for c in ("*", " ", "\x00", "\\"))


def obs_add(host, reason, kind, allowed):
    """Fold one observed query/connection into the per-base-domain evidence pool.

    `host` is an FQDN (or base domain). `kind` is classify(host) or None.
    Cheap: no network, no extra state files (evidence lives for one run)."""
    host = (host or "").strip().lower().rstrip(".")
    if not host_ok(host):
        return
    try:
        b = base_domain(host)
    except Exception:  # noqa: BLE001 - 证据收集绝不影响主流程
        return
    o = OBS.get(b)
    if o is None:
        o = OBS[b] = dict.fromkeys(_OBS_KEYS, 0)
        o["hosts"] = {}
        o["host_allowed"] = {}          # per-host 放行次数：判「这个域名自己有没有在被用」
    o["total"] += 1
    if o["hosts"].get(host, 0) < 100000:
        o["hosts"][host] = o["hosts"].get(host, 0) + 1
    if allowed:
        o["allowed"] += 1
        o["host_allowed"][host] = o["host_allowed"].get(host, 0) + 1
    else:
        o["blocked"] += 1
    if kind == "ad":
        o["ad_like"] += 1
    elif kind == "direct":
        o["direct_like"] += 1
    elif kind == "proxy":
        o["proxy_like"] += 1
    else:
        o["other_like"] += 1
    if allowed:
        o["allow_total"] += 1


def obs_get(dom):
    """Evidence for a domain, tolerating FQDN keys (falls back to its base domain)."""
    o = OBS.get(dom)
    if o is None:
        o = OBS.get(base_domain(dom))
    return o


def in_domset(host, domset):
    """True if host equals, or is a subdomain of, any entry in domset."""
    host = host.lower()
    parts = host.split(".")
    return any(".".join(parts[i:]) in domset for i in range(len(parts)))


def is_suspected(domain):
    """Ad-looking domain that is not on the do-not-touch allowlist."""
    return bool(AD_RE.search(domain)) and not any(k in domain for k in PROTECTED)


def _signal_patterns():
    """`SIGNAL_PATTERNS` -> 小写子串列表（埋点/信号族名）。每次现算，避免测试里改 env 不生效。"""
    return [p.strip().lower() for p in cfg("SIGNAL_PATTERNS").split(",") if p.strip()]


def classify(domain):
    """Return "direct", "ad", "proxy", or None.

    Precedence: reference-blocklist match (ad/privacy) > **signal-family name (ad)** > direct
    > ad-pattern > proxy. Domains under a manual-section domain (EXEMPT) are never auto-rejected."""
    d = domain.lower()
    # EXEMPT 用后缀匹配：FORCE_DIRECT / 手工区父域的**子域**同样豁免（如 polaris.zijieapi.com
    # 覆盖 polaris5-normal-zb.zijieapi.com）。2026-09-21：修直播误杀时引入。
    if ADLIST and in_domset(d, ADLIST) and not in_domset(d, EXEMPT):
        return "ad"
    # 🎯 2026-09-30 owner「准确」：信号/埋点**族名**优先于域名族（见 SIGNAL_PATTERNS 注释）。
    # 放在 DIRECT_RE 之前，是为了让 `mon*-misc` / `-applog` / `live-player-log` 这类
    # 无论挂在哪个 CDN 域名下都判 ad —— 而不是"挂在字节系域名上就直连"。
    if not in_domset(d, EXEMPT):
        for p in _signal_patterns():
            if p in d:
                return "ad"
    if DIRECT_RE.search(d):
        return "direct"
    if is_suspected(d):
        return "ad"
    if PROXY_RE.search(d):
        return "proxy"
    return None


def load_adlist():
    """Fetch (and cache) the reference ad/privacy blocklists; return a suffix set.

    Graceful degradation: on fetch failure fall back to the cached copy; if none,
    return an empty set so the built-in AD_RE patterns still work (no hard failure)."""
    if not cfg_bool("ADLIST_ENABLE", True):
        return set()
    urls = [u.strip() for u in cfg("ADLIST_URLS").split(",") if u.strip()]
    if not urls:
        return set()
    cache = os.path.join(HERE, ".adlist-cache.txt")
    meta_path = os.path.join(HERE, ".adlist-cache.json")
    hours = float(cfg("ADLIST_CACHE_HOURS") or 24)
    try:
        meta = json.load(open(meta_path, encoding="utf-8"))
    except Exception:  # noqa: BLE001
        meta = {}
    if (meta.get("urls") == urls and os.path.exists(cache)
            and (time.time() - meta.get("ts", 0)) < hours * 3600):
        with open(cache, encoding="utf-8") as fh:
            return {l.strip() for l in fh if l.strip()}
    entries, ok = set(), False
    print(f"adlist cache stale/missing -> downloading {len(urls)} list(s) "
          f"(~4 MB, through the accelerator) ...", flush=True)
    for u in urls:
        status, text = http("GET", u, timeout=60, headers={"User-Agent": "Mozilla/5.0"})
        if status != 200:
            print(f"adlist fetch failed: {u} -> HTTP {status}")
            continue
        ok = True
        for line in text.splitlines():
            s = line.strip().lower()
            if not s or s[0] in "!#[":
                continue
            if s.startswith("*."):
                s = s[2:]
            if s:
                entries.add(s)
    if not ok or not entries:
        if os.path.exists(cache):
            print("adlist refresh failed; using cached copy")
            with open(cache, encoding="utf-8") as fh:
                return {l.strip() for l in fh if l.strip()}
        print("adlist unavailable; built-in patterns only")
        return set()
    try:
        with open(cache, "w", encoding="utf-8") as fh:
            fh.write("\n".join(sorted(entries)) + "\n")
        with open(meta_path, "w", encoding="utf-8") as fh:
            json.dump({"ts": time.time(), "urls": urls}, fh)
    except Exception:  # noqa: BLE001
        pass
    print(f"adlist loaded: {len(entries)} entr(ies)")
    return entries


def load_cn_domains():
    """Fetch (and cache) the CN domain list (blackmatrix7 China_Domain) as a suffix set.
    Graceful degradation: fetch failure falls back to cache, then to an empty set."""
    url = cfg("CN_LIST_URL")
    if not url:
        return set()
    cache = os.path.join(HERE, ".cn-cache.txt")
    meta_path = os.path.join(HERE, ".cn-cache.json")
    hours = float(cfg("ADLIST_CACHE_HOURS") or 24)
    try:
        meta = json.load(open(meta_path, encoding="utf-8"))
    except Exception:  # noqa: BLE001
        meta = {}
    if (meta.get("url") == url and os.path.exists(cache)
            and (time.time() - meta.get("ts", 0)) < hours * 3600):
        with open(cache, encoding="utf-8") as fh:
            return {l.strip() for l in fh if l.strip()}
    status, text = http("GET", url, timeout=60, headers={"User-Agent": "Mozilla/5.0"})
    if status != 200:
        print(f"cn list fetch failed: {url} -> HTTP {status}")
        if os.path.exists(cache):
            with open(cache, encoding="utf-8") as fh:
                return {l.strip() for l in fh if l.strip()}
        return set()
    out = set()
    for line in text.splitlines():
        s = line.strip().lower()
        if not s or s[0] in "#!":
            continue
        for pre in ("domain-suffix,", "domain,"):
            if s.startswith(pre):
                s = s[len(pre):]
        s = s.lstrip(".").strip("^ ")
        if s and re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", s):
            out.add(s)
    if out:
        try:
            with open(cache, "w", encoding="utf-8") as fh:
                fh.write("\n".join(sorted(out)) + "\n")
            with open(meta_path, "w", encoding="utf-8") as fh:
                json.dump({"ts": time.time(), "url": url}, fh)
        except Exception:  # noqa: BLE001
            pass
    return out


def prune_subsumed(domset, label="reject"):
    """Drop entries that are a subdomain of another entry in the same set: the broader rule
    already covers them (DOMAIN-SUFFIX matches subdomains), so they are pure duplicates.
    Lossless. 2026-09-20."""
    out = set()
    for d in sorted(domset, key=lambda x: (x.count("."), x)):
        if not any(d.endswith("." + o) for o in out):
            out.add(d)
    dropped = len(domset) - len(out)
    if dropped:
        print(f"subsume: dropped {dropped} redundant {label} entr(ies) already covered by a parent rule")
    return out


def prune_shadowed(domset, higher, label=""):
    """跨清单遮蔽过滤：丢掉那些**父域在更高优先级清单里**的条目。

    为什么需要它（2026-09-27 发现）：`prune_subsumed` 只在**同一集合内**做父域塌缩，
    所以像 `csi.gstatic.com`（父域 `gstatic.com` 在 proxy）不会被它清掉。
    但配置里清单顺序是 reject → proxy → direct，SHADOW 清单在前 ⇒ 这些 direct 条目
    **永远命中不到**，是死规则（实测 5 条：csi.gstatic.com / t.e.x.com /
    analytics.pgncs.notion.so / exp.notion.so / intake-analytics.wikimedia.org）。

    安全性：只影响**仓库写入**；`OWNER_ALLOW`（白名单）用的是未过滤的集合，
    所以 ADH 侧这些域仍然解析正常、不会被重新拦截。"""
    out = {d for d in domset if not any(d.endswith("." + h) for h in higher)}
    dropped = len(domset) - len(out)
    if dropped:
        print(f"shadow: dropped {dropped} {label} entr(ies) 被更高优先清单的父域遮蔽（死规则）")
    return out


def guard_shadow(direct_des, reject_des):
    """Drop DIRECT entries that are a parent of a REJECT entry: under first-match the parent
    would swallow the more-specific reject (and its DNS would bypass ADH). Only dropped when
    the parent is covered by the CN list (so its other children still route direct); otherwise
    it is kept and warned about. 2026-09-20."""
    risky = {d for d in direct_des if any(r.endswith("." + d) for r in reject_des)}
    if not risky:
        return
    cn = load_cn_domains()
    dropped, kept = [], []
    for d in sorted(risky):
        if any(d == c or d.endswith("." + c) for c in cn):
            dropped.append(d)
        else:
            kept.append(d)
    if dropped:
        direct_des -= set(dropped)
        print(f"shadow guard: dropped {len(dropped)} direct parent(s) that shadowed reject "
              f"children (covered by CN list): {dropped}")
    if kept:
        print(f"shadow guard: ⚠️ kept {len(kept)} direct parent(s) NOT in CN list "
              f"(they shadow reject children): {kept}")


def guard_proxy(proxy_des, force_direct, observed_direct):
    """Never send a directly-reachable domain through the proxy.

    Drops PROXY candidates that (a) are covered by the CN domain list, or (b) were observed
    routed DIRECT by the phone (Shadowrocket log `type`). Both are evidence the domain works
    direct; a classifier misclassification must not flip it to PROXY. 2026-09-21 (owner:
    "不希望该走直连，但却走了代理")."""
    if not proxy_des:
        return proxy_des
    cn = load_cn_domains()
    cand = proxy_des - force_direct
    cn_hit = {d for d in cand if cn and in_domset(d, cn)}
    obs_bases = {base_domain(h) for h in observed_direct}
    obs_hit = {d for d in (cand - cn_hit) if d in obs_bases or in_domset(d, obs_bases)}
    for d in sorted(cn_hit):
        print(f"proxy guard: {d} in CN list -> DIRECT (not proxied)")
    for d in sorted(obs_hit):
        print(f"proxy guard: {d} observed DIRECT on phone -> DIRECT (not proxied)")
    return proxy_des - cn_hit - obs_hit


def probe_domain(domain, resolvers, timeout=4):
    """Live-test a candidate domain with clean public resolver(s) (NOT the local ADH).

    Returns (True, detail) if it resolves, (False, detail) if it clearly does not
    resolve (NXDOMAIN / invalid hostname), or (None, detail) if the probe itself is
    unavailable (no dig / resolver unreachable) - in that case we keep the domain.
    """
    if not re.match(r"^[a-z0-9*][a-z0-9._-]*$", domain):
        return False, "invalid hostname"
    if not shutil.which("dig"):
        return None, "dig unavailable"
    saw_clean, unknown = False, []
    for r in resolvers:
        try:
            out = subprocess.run(
                ["dig", "+short", f"+time={timeout:g}", "+tries=1", "A", domain, "@" + r],
                capture_output=True, text=True, timeout=timeout + 4)
        except Exception as e:  # noqa: BLE001
            unknown.append(f"{r}: {e}")
            continue
        ans = [l.strip() for l in out.stdout.splitlines() if l.strip()]
        if out.returncode == 0 and ans:
            return True, ",".join(ans[:3])
        if out.returncode == 0:
            saw_clean = True  # clean NXDOMAIN / empty answer
        else:
            unknown.append(f"{r}: rc={out.returncode}")
    if saw_clean:
        return False, "unresolved (NXDOMAIN)"
    return None, "; ".join(unknown) or "probe unavailable"


def curl_reach(domain, proxy="", timeout=6):
    """True if an HTTP(S) request to `domain` completes (optionally via `proxy`);
    False if it fails; None if curl is unavailable."""
    if not shutil.which("curl"):
        return None
    args = ["curl", "-s", "-o", "/dev/null", "-k",
            "--connect-timeout", f"{timeout:g}", "--max-time", f"{timeout:g}"]
    if proxy:
        args += ["-x", proxy]
    for scheme in ("https", "http"):
        try:
            r = subprocess.run(args + [f"{scheme}://{domain}/"], capture_output=True,
                               text=True, timeout=timeout + 4)
        except Exception:  # noqa: BLE001
            return None
        if r.returncode == 0:
            return True
    return False


def repo_manual_domains(owner, name, token, branch="", path=None):
    """Domains sitting in the hand-curated (above-marker) sections of the repo files.
    Reads are loud: a transient API error retries, then ABORTS instead of returning an
    empty set (an empty manual set would make the converges wipe the curated rules)."""
    def content(_path):
        headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}
        api = f"https://api.github.com/repos/{owner}/{name}/contents/{_path}"
        last = ""
        for _ in range(3):
            status, text = http("GET", api + (f"?ref={branch}" if branch else ""), headers)
            if status == 200:
                return base64.b64decode(json.loads(text)["content"]).decode()
            if status == 404:
                return ""
            last = f"HTTP {status} {text[:120]}"
            time.sleep(2)
        sys.exit(f"repo manual read failed: {path} -> {last}")
    out = set()
    for path, cmt in ((cfg("REPO_DIRECT_PATH"), "#"), (cfg("REPO_PROXY_PATH"), "#"),
                      (cfg("REPO_PATH"), "!")):
        manual, _ = split_manual(content(path), cmt)
        out |= parse_domains("\n".join(manual))
    return out


def repo_manual_domains_of(owner, name, token, branch, path, comment="#"):
    """指定仓库文件「手工区」（标记之上）里的域名集合。

    只用于「跳过 owner 手工已明确处理的域」这类判断 —— 读失败返回空集，**不参与任何收敛**。"""
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}
    api = f"https://api.github.com/repos/{owner}/{name}/contents/{path}"
    status, text = http("GET", api + (f"?ref={branch}" if branch else ""), headers)
    if status != 200:
        return set()
    manual, _ = split_manual(base64.b64decode(json.loads(text)["content"]).decode(), comment)
    return parse_domains("\n".join(manual))


def repo_manual_allow_domains(owner, name, token, branch=""):
    """owner 手工写在**放行清单**（`direct-custom.list` / `proxy-custom.list`）里的域名。

    ⚠️ 必须与 `repo_manual_domains()` 区分开：后者读的是三份文件的全部手工区，
    **把「放行」和「拦截」混在一起**，调用方却当"人工区拦截"用 ——
    结果 owner 手工写的放行条目会被并进 reject（2026-09-27 owner 指出）。

    本函数只收放行意图；读失败就 loud-fail（返回空集会让放行被忽略）。"""
    def content(path):
        headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}
        api = f"https://api.github.com/repos/{owner}/{name}/contents/{path}"
        last = ""
        for _ in range(3):
            status, text = http("GET", api + (f"?ref={branch}" if branch else ""), headers)
            if status == 200:
                return base64.b64decode(json.loads(text)["content"]).decode()
            if status == 404:
                return ""
            last = f"HTTP {status} {text[:120]}"
            time.sleep(2)
        sys.exit(f"repo manual-allow read failed: {path} -> {last}")
    out = set()
    for path in (cfg("REPO_DIRECT_PATH"), cfg("REPO_PROXY_PATH")):
        manual, _ = split_manual(content(path), "#")
        out |= parse_domains("\n".join(manual))
    return out


def repo_manual_wildcards(owner, name, token, branch=""):
    """Raw `||...*^` wildcard/keyword block rules from the hand-curated section of
    REPO_PATH. They cannot round-trip through the domain sets (parse_domains drops `*`),
    so they are collected verbatim and re-pushed to ADH on every sync. 2026-09-21."""
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}
    api = f"https://api.github.com/repos/{owner}/{name}/contents/{cfg('REPO_PATH')}"
    for _ in range(3):
        status, text = http("GET", api + (f"?ref={branch}" if branch else ""), headers)
        if status == 200:
            content = base64.b64decode(json.loads(text)["content"]).decode()
            manual, _ = split_manual(content, "!")
            return {l.strip() for l in manual
                    if l.strip().startswith("||") and "*" in l}
        if status == 404:
            return set()
        time.sleep(2)
    return set()


MULTI_TLD = {
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "com.hk", "net.hk",
    "org.hk", "com.tw", "com.au", "co.uk", "org.uk", "co.jp", "co.kr",
    "com.sg", "com.my",
}


def base_domain(host):
    """Collapse a hostname to its registrable base domain (e.g. a.b.douyinvod.com -> douyinvod.com)."""
    parts = host.strip(".").split(".")
    if len(parts) <= 2:
        return host
    if ".".join(parts[-2:]) in MULTI_TLD:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def load_env(path=os.path.join(HERE, ".env")):
    """Load KEY=VALUE pairs from `.env` into os.environ (real env vars win).

    Fail-soft: `.env` is root:600, so a non-root run (e.g. the in-container `--check`)
    cannot read it -- that must not crash the script, because those credentials can also
    come from the real environment. 2026-09-26."""
    if not os.path.exists(path):
        return
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
    except OSError as e:
        print(f"[..] .env unreadable ({e.strerror}); relying on the environment",
              flush=True)


def cfg(key):
    return os.environ.get(key) or DEFAULTS.get(key, "")


def cfg_bool(key, default=False):
    """Strict boolean flag: '1/true/yes/on' -> True; anything else ('0/false/no/off' or an
    empty value) -> False. Use for feature toggles -- `cfg()` returns raw strings and '0'
    is truthy, so `cfg()` cannot disable anything. A value present in the environment (or
    .env) is authoritative even when empty, so `X=""` / `X="0"` now really disables X.
    2026-09-21."""
    v = os.environ[key] if key in os.environ else DEFAULTS.get(key)
    if v is None:
        return default
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def http(method, url, headers=None, body=None, timeout=30):
    headers = dict(headers or {})
    # ⚠️ 必须带 UA：加速站（Cloudflare）对 urllib 默认 UA(`Python-urllib/3.x`) 直接 403
    headers.setdefault("User-Agent", "dsh-rules-sync/1.0")
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def adh_domains(base, user, pw, client_ip="", limit=None, hours=None):
    """Read the ADH querylog over the last `hours` window (paged backwards) and return the
    (ad, direct, proxy) allowed-domain sets.

    NB: a single unpaged request only returns the newest N entries (~1h on a busy LAN), so the
    old limit=500 silently missed everything between cron runs. We now page back with
    `older_than` until the buffer start or the lookback window is covered."""
    auth = base64.b64encode(f"{user}:{pw}".encode()).decode()
    limit = int(limit if limit is not None else (cfg("QUERYLOG_LIMIT") or 10000))
    hours = float(hours if hours is not None else (cfg("QUERYLOG_HOURS") or 0))
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours) if hours > 0 else None
    ads, directs, proxies = set(), set(), set()
    int_obs = set()    # 2026-09-26: 被 ADH 拦过的域名（实测证据用，不参与分类）
    ingest_blocked = cfg_bool("INGEST_BLOCKED_AD", True)
    blk_n = 0
    older = ""
    scanned = 0
    newest_t = ""
    oldest_seen = ""
    for _ in range(500):  # safety cap
        q = f"limit={limit}"
        if older:
            q += "&older_than=" + urllib.parse.quote(older)
        status, text = http(
            "GET",
            f"{base.rstrip('/')}/control/querylog?{q}",
            {"Authorization": f"Basic {auth}"},
        )
        if status != 200:
            sys.exit(f"ADH querylog fetch failed: HTTP {status}")
        data = json.loads(text).get("data", [])
        if not data:
            break
        oldest = ""
        for item in data:
            t = item.get("time", "")
            if t:
                oldest = t
            if client_ip and item.get("client") != client_ip:
                continue
            reason = item.get("reason", "")
            domain = (item.get("question") or {}).get("name", "").strip()
            if not domain:
                continue
            obs_add(domain, reason, classify(domain), reason in ALLOWED_REASONS)
            if reason not in ALLOWED_REASONS:
                if reason in BLOCKED_REASONS and not any(
                        "$client" in ((r or {}).get("text") or "")
                        for r in (item.get("rules") or [])):
                    int_obs.add(domain)     # 实测证据：ADH 实际拦过它（全局规则）
                # ADH already blocked this query. The collector normally hunts for what
                # ADH *let through*, so blocked entries are skipped - but with
                # INGEST_BLOCKED_AD we MIRROR the block into the reject set so a domain
                # the phone would otherwise PROXY has a client-side reject too.
                # ⚠️ 2026-09-20: only mirror domains the reference ad/privacy list ALSO
                # flags (classify()=="ad"). An unfiltered mirror turned "blocked once"
                # into "blocked forever" and swept in service CDNs (Volcano vc-*.ndcpp.com,
                # ByteDance *.bytedns1.com chains, ydycdn.com) -> Douyin lag/breakage.
                # Skip EXEMPT (manual whitelist) and client-scoped rules ($client=).
                if (ingest_blocked and reason in BLOCKED_REASONS and domain not in EXEMPT
                        and classify(domain) == "ad"
                        and not any("$client" in ((r or {}).get("text") or "")
                                    for r in (item.get("rules") or []))):
                    if domain not in ads:
                        blk_n += 1
                    ads.add(domain)
                continue
            kind = classify(domain)
            if kind == "direct":
                directs.add(domain)
            elif kind == "ad":
                ads.add(domain)
            elif kind == "proxy":
                proxies.add(domain)
        scanned += len(data)
        if not newest_t:
            newest_t = data[0].get("time", "") or ""
        oldest_seen = oldest or oldest_seen
        if len(data) < limit:
            break  # reached the start of the buffer
        try:
            ot = datetime.fromisoformat(oldest.replace("Z", "+00:00"))
        except Exception:  # noqa: BLE001
            break
        if cutoff is not None and ot < cutoff:
            break
        older = oldest
    win = f"{hours:g}h window" if hours > 0 else "whole buffer"
    print(f"scanned {scanned} querylog entr(ies) over {win}")
    # 覆盖时长自检（2026-09-25 起同步改为每天 08:00 跑一次）：ADH 的内存 querylog 是容量上限
    # 决定的，不是按时间保留。若某轮缓冲只够 <26h，说明间隔期内的记录会被漏读 —— 直接把覆盖
    # 时长打进日志，一眼能看出够不够；不够就得调 ADH 的 querylog.size_memory 或缩短周期。
    try:
        if newest_t and oldest_seen:
            span_h = (datetime.fromisoformat(newest_t.replace("Z", "+00:00"))
                      - datetime.fromisoformat(oldest_seen.replace("Z", "+00:00"))).total_seconds() / 3600
            warn = "  ⚠️ 覆盖不足 26h，日更会漏读（调大 querylog.size_memory 或缩短周期）" if span_h < 26 else ""
            print(f"querylog coverage: {span_h:.1f}h"
                  f"（oldest {oldest_seen} → newest {newest_t}）{warn}")
    except Exception as e:  # noqa: BLE001 - 自检失败不影响主流程
        print(f"querylog coverage: n/a ({e})")
    if ingest_blocked:
        print(f"ingest-blocked: +{blk_n} domain(s) blocked by ADH & not covered by phone")
    return ads, directs, proxies, int_obs


# ---------------------------------------------------------------------------
# Shadowrocket connection-log source (proxy-*.db exports uploaded to the NAS)
# ---------------------------------------------------------------------------




# ---------------------------------------------------------------------------
# 小火箭 db 分析（--sr-analyze）：结果只写三个 custom.list。2026-09-30 owner 定调。
# ---------------------------------------------------------------------------
def cfg_csv(key):
    """逗号配置项 -> 小写集合。"""
    return {x.strip().lower() for x in cfg(key).split(",") if x.strip()}


# ---------------------------------------------------------------------------
# 小火箭 db 分析（`--sr-analyze`）—— 只写三个 custom.list，**不**参与 cron。2026-09-30 owner 定调。
#   ㈠ 拦截漏网之鱼：classify() 判「广告」、但手机实际走了 DIRECT/PROXY（没拦住）
#   ㈡ 直连偷跑代理：classify() 判「直连」、但手机实际走了 PROXY
#   动作由脚本按证据自动判定（SR_DROP_PATTERNS / 频次），逐条打印依据供 review。
# ---------------------------------------------------------------------------




















def tg_send(token, chat_id, text, proxy=""):
    """POST a message to the Telegram Bot API (optionally through an HTTP proxy)."""
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    data = urllib.parse.urlencode(
        {"chat_id": chat_id, "text": text, "disable_web_page_preview": "true"}
    ).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    handlers = [urllib.request.ProxyHandler({"https": proxy, "http": proxy})] if proxy else []
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(req, timeout=25) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return f"HTTP {e.code}"
    except Exception as e:  # noqa: BLE001 - report whatever went wrong to the log
        return f"error: {e}"


def watch_fetch(base, user, pw, limit=50000, pages=6):
    """抓最近若干页 querylog（最新在前），用于只读监控。返回 [{time,name,reason,client}]。"""
    auth = base64.b64encode(f"{user}:{pw}".encode()).decode()
    out, older = [], ""
    for _ in range(pages):
        q = f"limit={limit}" + (f"&older_than={urllib.parse.quote(older)}" if older else "")
        status, text = http("GET", f"{base.rstrip('/')}/control/querylog?{q}",
                            {"Authorization": f"Basic {auth}"})
        if status != 200:
            print(f"watch: querylog fetch failed HTTP {status}")
            break
        data = json.loads(text).get("data", [])
        if not data:
            break
        for it in data:
            name = ((it.get("question") or {}).get("name") or "").strip().lower()
            if not name or not host_ok(name):
                continue
            out.append({"time": (it.get("time") or ""), "name": name,
                        "reason": it.get("reason") or "", "client": it.get("client") or ""})
        if len(data) < limit:
            break
        older = data[-1].get("time") or ""
    return out


def watch_spikes(entries, window_min=30, base_hours=24, min_events=200, ratio=8.0):
    """找「最近窗口内被拦次数暴增」的域名。

    对每个在最近窗口有被拦记录的域名：算它最近窗口的速率，与它自己在过去 base_hours
    里的中位数速率比。自比自 ⇒ 不受「域名之间量级差异」影响。返回 [(name, recent, base_med, r)]。"""
    if not entries:
        return []
    def ts(e):
        try:
            return datetime.fromisoformat(e["time"].replace("Z", "+00:00"))
        except Exception:  # noqa: BLE001
            return None
    now = max((ts(e) for e in entries if ts(e)), default=None)
    if now is None:
        return []
    recent_from = now - timedelta(minutes=window_min)
    base_from = now - timedelta(hours=base_hours)
    recent, base = {}, {}
    for e in entries:
        t = ts(e)
        if t is None or (e["reason"] or "") in ALLOWED_REASONS:
            continue
        if t >= recent_from:
            recent[e["name"]] = recent.get(e["name"], 0) + 1
        elif t >= base_from:
            base.setdefault(e["name"], []).append(t)
    out = []
    for name, n in recent.items():
        if n < min_events:
            continue
        times = base.get(name, [])
        if not times:
            out.append((name, n, 0.0, float("inf")))
            continue
        # 基线：把 base_hours 切成 window_min 大小的小格，取每格计数的中位数
        bucket = Counter()
        for t in times:
            key = int((t - base_from).total_seconds() // (window_min * 60))
            bucket[key] += 1
        slots = max(1, int(base_hours * 60 / window_min))
        counts = [bucket.get(i, 0) for i in range(slots)]
        counts.sort()
        med = counts[len(counts) // 2]
        r = n / med if med else float("inf")
        if r >= ratio:
            out.append((name, n, med, r))
    out.sort(key=lambda x: -x[1])
    return out[:8]


def adh_triage_check(entries, state_path, dry_run=False):
    """ADH 侧误伤 triage（只读）：在被拦域里找「像误伤」的，只对**新增**的报。

    为什么需要它：`AUDIT_RECLASSIFY` 只审**客户端那份 reject 清单**（496 条），
    而 ADH 实际拦的域要广得多（手工区 + 5 份订阅大表，实测 792 个域名）。
    订阅大表误伤只能从 ADH 侧发现 —— 2026-09-27 就是靠这个临时分析抓到
    `whoami.akamai.net`(939次/2客户端) / `mmgame.qpic.cn`(240次/7客户端) / `id6.me`(登录依赖)。

    判据（保守，宁少报）：被拦(reason=FilteredBlackList) + **≥2 个不同客户端** +
    不像广告/埋点 + 不在 ADH 白名单里。单客户端不报（可能是某台设备自己的东西）。

    ⚠️ 两个坑（2026-09-27 实测踩到）：
      ① querylog 是**历史窗口**（buffer 里 190+ 小时，`watch_fetch` 默认只取最近 6 页），域在放行之后，放行前的旧请求
         依然在记录里 —— 首跑时已放行的 whoami/mmgame/id6 全被当成"新增候选"。
         所以这里先按 `TRIAGE_LOOKBACK_H`（默认 24h）裁掉旧记录。
      ② 裁完还可能压在边界上，所以再向 ADH 复核一次 check_host，只报**当前确实仍被拦**的。
    """
    import re as _re
    ad_re = _re.compile(AD_RE.pattern, _re.I)
    protected = ("novel", "douyin", "snssdk", "byteimg", "volccdn", "apple",
                 "zijieapi", "bytegecko", "ecombdimg", "fnnas")
    # ① 只看最近 TRIAGE_LOOKBACK_H 小时
    lb = float(cfg("TRIAGE_LOOKBACK_H") or 6)
    cut = (datetime.now().astimezone() - timedelta(hours=lb)).isoformat()
    recent = [e for e in entries if (e.get("time") or "") >= cut]
    allow, blocked = set(), {}
    for e in recent:
        name = (e.get("name") or "").strip().lower()   # watch_fetch 给的是扁平结构
        if not name:
            continue
        rsn = e.get("reason") or ""
        if rsn == "NotFilteredWhiteList":
            allow.add(name)
            continue
        if rsn != "FilteredBlackList":
            continue
        cur = blocked.get(name) or {"n": 0, "clients": set()}
        cur["n"] += 1
        cur["clients"].add(e.get("client") or "?")
        blocked[name] = cur
    # ③ owner 放行意图（FORCE_DIRECT + 放行清单手工区 + ADH `@@`）也要算"已放行"。
    # 只从 querylog 的 NotFilteredWhiteList 推是不够的：新批准的域在 ADH 侧可能还没生效，
    # 会被误报成"误伤候选"（2026-09-27 owner 要求：「豁免的、已议定正确的」必须一起评估）。
    allow |= {d for d in OWNER_ALLOW}
    if cfg_bool("TRIAGE_RECHECK", True):
        base, user, pw = cfg("ADH_URL"), cfg("ADH_USER"), cfg("ADH_PASS")
        auth = base64.b64encode(f"{user}:{pw}".encode()).decode()
        st, tx = http("GET", f"{base.rstrip('/')}/control/filtering/status",
                      {"Authorization": f"Basic {auth}"})
        if st == 200:
            for r in (json.loads(tx).get("user_rules") or []):
                if r.startswith("@@||"):
                    allow.add(r[4:].split("^")[0].split("$")[0].lower())
    cands = {}
    for d, v in blocked.items():
        if len(v["clients"]) < 2:
            continue
        if any(k in d for k in protected) or ad_re.search(d):
            continue
        if any(d == a or d.endswith("." + a) for a in allow):
            continue
        cands[d] = {"n": v["n"], "clients": len(v["clients"]), "rule": ""}
    min_n = int(cfg("TRIAGE_MIN_EVENTS") or 5)
    cands = {d: v for d, v in cands.items() if v["n"] >= min_n}
    # ② 向 ADH 复核：只保留「当前确实仍被拦」的（历史记录可能早于白名单添加）
    if cands and cfg_bool("TRIAGE_RECHECK", True):
        base, user, pw = cfg("ADH_URL"), cfg("ADH_USER"), cfg("ADH_PASS")
        auth = base64.b64encode(f"{user}:{pw}".encode()).decode()
        hh = {"Authorization": f"Basic {auth}"}
        still = {}
        for d, v in cands.items():
            st, tx = http("GET", f"{base.rstrip('/')}/control/filtering/check_host"
                                f"?name={urllib.parse.quote(d)}", hh)
            if st != 200:
                still[d] = v            # 复核失败就当仍被拦，宁可多报
                continue
            if (json.loads(tx).get("reason") or "").startswith("Filtered"):
                still[d] = v
        removed = len(cands) - len(still)
        if removed:
            print(f"triage: check_host 复核剔除 {removed} 个（已放行/已失效）")
        cands = still
    try:
        st = json.load(open(state_path, encoding="utf-8"))
    except Exception:  # noqa: BLE001
        st = {}
    fresh = {d: v for d, v in cands.items() if d not in st}
    print(f"triage: 被拦域 {len(blocked)} 个 -> 候选 {len(cands)} 个, 新增 {len(fresh)} 个")
    if not fresh:
        return 0, ""
    lines = [f"🔍 ADH 拦截表误伤候选（新增 {len(fresh)} 条）"]
    for d, v in sorted(fresh.items(), key=lambda x: -x[1]["n"])[:10]:
        lines.append(f"• {d} — 被拦 {v['n']} 次 / {v['clients']} 个客户端")
    lines += ["", "判据：被拦 + ≥2 客户端 + 不像广告 + 不在白名单。",
              "处理：确认误伤 → 加进脚本 FORCE_DIRECT（自动生成 $important 白名单）"]
    report = "\n".join(lines)
    if dry_run:
        return len(fresh), report      # 预览也给出报告，便于验证；只是不写状态
    now = time.time()
    for d in cands:
        st.setdefault(d, now)
    # 只保留还在候选里的域，避免状态文件无限增长
    st = {d: t for d, t in st.items() if d in cands}
    try:
        json.dump(st, open(state_path, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    except OSError:
        pass
    return len(fresh), report


def watch_run(dry_run=False):
    """只读监控：找重试尖峰，有异常才 Telegram。返回 (异常数, 报告文本)。"""
    base, user, pw = cfg("ADH_URL"), cfg("ADH_USER"), cfg("ADH_PASS")
    entries = watch_fetch(base, user, pw)
    if not entries:
        return 0, "querylog 为空（监控跳过）"
    w = int(cfg("WATCH_WINDOW_MIN") or 30)
    spikes = watch_spikes(entries, w, int(cfg("WATCH_BASE_HOURS") or 24),
                          int(cfg("WATCH_MIN_EVENTS") or 200), float(cfg("WATCH_RATIO") or 8))
    state_path = os.path.join(HERE, cfg("WATCH_STATE") or ".adh-watch-state.json")
    try:
        state = json.load(open(state_path, encoding="utf-8"))
    except Exception:  # noqa: BLE001
        state = {}
    now_ts = time.time()
    dedup_h = float(cfg("WATCH_DEDUP_HOURS") or 6)
    fresh = []
    for name, n, med, r in spikes:
        last = float(state.get(name, 0))
        if now_ts - last < dedup_h * 3600:
            continue
        fresh.append((name, n, med, r))
    print(f"watch: {len(entries)} entr(ies) scanned, {len(spikes)} spike(s), {len(fresh)} new")
    # ADH 侧误伤 triage（复用同一份 entries，不重复拉取）
    triage_path = os.path.join(HERE, cfg("TRIAGE_STATE") or ".adh-triage-state.json")
    t_n, t_report = (0, "")
    if cfg_bool("TRIAGE_ENABLE", True):
        t_n, t_report = adh_triage_check(entries, triage_path, dry_run=dry_run)
    parts = []
    if fresh:
        lines = [f"⚠️ ADH 重试尖峰 {datetime.now().astimezone():%m-%d %H:%M}",
                 f"窗口 {w} 分钟（基线=过去 {cfg('WATCH_BASE_HOURS')}h 同域名中位数）"]
        for name, n, med, r in fresh[:5]:
            ratio = "∞" if med == 0 else f"{r:.0f}x"
            lines.append(f"• {name}：{n} 次 / {w}min（基线中位数 {med:g} → {ratio}）")
        if len(fresh) > 5:
            lines.append(f"…另有 {len(fresh) - 5} 个")
        lines.append("定位：开小火箭日志 5–10 分钟复现 → 导 DB 分析")
        parts.append("\n".join(lines))
    if t_report:
        parts.append(t_report)
    report = "\n\n".join(parts)
    if not fresh and not t_report:
        return 0, ""
    if not dry_run:
        if fresh:
            for name, *_ in fresh:
                state[name] = now_ts
            try:
                json.dump(state, open(state_path, "w", encoding="utf-8"))
            except OSError:
                pass
        tok, chat = cfg("TELEGRAM_BOT_TOKEN"), cfg("TELEGRAM_CHAT_ID")
        if tok and chat:
            print("watch telegram:", tg_send(tok, chat, report, cfg("TELEGRAM_PROXY")))
        else:
            print("watch: 未配置 Telegram，仅打印")
            print(report)
    else:
        print(report)
    return len(fresh) + t_n, report






def adh_sync_rules(base, user, pw, add_lines, remove_lines=(), dry_run=False, converge=None):
    """Converge ADH user_rules: drop `remove_lines`, add missing `add_lines` (full replace).
    With `converge` (a rule prefix like '||' or '@@||'), also drop every existing rule of
    that kind that is not in `add_lines`, so stale auto-added rules get purged too."""
    auth = base64.b64encode(f"{user}:{pw}".encode()).decode()
    h = {"Authorization": f"Basic {auth}"}
    status, text = http("GET", f"{base.rstrip('/')}/control/filtering/status", h)
    if status != 200:
        sys.exit(f"ADH filtering status failed: HTTP {status}")
    existing = json.loads(text).get("user_rules") or []

    drop = set(remove_lines)
    if converge:
        want = set(add_lines)
        # 保留通配规则（||...*^ / keyword）：它们无法用域名集合表达，收敛会误删。2026-09-21
        drop |= {r for r in existing
                 if r.startswith(converge) and r not in want and "*" not in r}
    kept = [r for r in existing if r not in drop]
    removed = [r for r in existing if r in drop]
    add = [l for l in add_lines if l not in kept]
    if not add and not removed:
        print("ADH user_rules already up to date")
        return [], []
    guard_drop("ADH user_rules", len(existing), len(removed))
    if dry_run:
        print(f"[dry-run] ADH user_rules: +{len(add)} / -{len(removed)}")
        return add, removed
    status, text = http("POST", f"{base.rstrip('/')}/control/filtering/set_rules",
                        h, {"rules": kept + add})
    if status != 200:
        sys.exit(f"ADH set_rules failed: HTTP {status} {text[:200]}")
    print(f"ADH user_rules: +{len(add)} / -{len(removed)}")
    return add, removed


def check_allow_conflicts(path=None):
    """ADH 清单内自检：手工区的 `@@||d^$important` 放行，与自动区的 `||d^` 拦截是否**同域打架**。

    `$important` 优先 ⇒ 打架时实际生效的是**放行**（2026-10-01 实测：19 条信号族全被自己的放行压住，
    ADH 其实一条没拦）。故意放行（在 FORCE_DIRECT 里）不算问题。
    """
    path = path or os.path.join(HERE, "ops", "adh", "adh-custom.txt")
    try:
        lines = [l.strip() for l in open(path, encoding="utf-8") if l.strip() and not l.startswith("!")]
    except OSError as e:
        return [f"读不到 {path}: {e}"]
    allow = {l[4:].split("^")[0]: l for l in lines if l.startswith("@@||")}
    block = {l[2:].split("^")[0] for l in lines if l.startswith("||")}
    fd = {d.strip() for d in cfg("FORCE_DIRECT").split(",") if d.strip()}
    bad = [(d, "FORCE_DIRECT 里的故意放行（OK）" if in_domset(d, fd) else "**陈旧遗留：与自动区拦截打架**")
           for d in allow if d in block]
    if not bad:
        return ["清单自检：放行/拦截无打架 ✓"]
    out = [f"清单自检：{len(bad)} 条放行与自动区拦截同域（`$important` 会让**放行**生效）"]
    out += [f"   {d} ← {why}" for d, why in sorted(bad)]
    return out


def parse_domains(text):
    """Collect domains from an AdGuard (`||d^`) or Shadowrocket (`DOMAIN-X,d,ACTION`) file.

    ⚠️ 2026-09-30 修：动作原先写成 `([A-Z]+)$`，**不认带连字符的 `REJECT-DROP`**
    ⇒ hongguo-ad.list / adh-custom.txt RAW 区那些 DROP 规则一直被静默忽略
    （manual_dom 为空 ⇒ 手工区去重失效、写入护栏也形同虚设）。改成 `[A-Z][A-Z-]*`。
    仍**不**识别裸 `DOMAIN,host,ACTION`（只有 `DOMAIN-XXX`）—— 既有行为，本轮不动；
    RAW 区那几条裸 DOMAIN 靠 `raw_domains` 单独保护，不依赖这里。"""
    out = set()
    for line in text.splitlines():
        s = line.strip()
        if not s or s[0] in "!#" or s.startswith("@@||"):
            continue
        if s.startswith("||"):
            d = s[2:].rstrip("^").strip()
            if d and "*" not in d:
                out.add(d)
        else:
            # ⚠️ 2026-09-30 补：**裸 `DOMAIN,host,ACTION` 也要认**（原来只认 `DOMAIN-XXX,`）。
            #    漏认的代价实测可见：`reject-custom.list` 手工区那条 `DOMAIN,i.snssdk.com,REJECT-DROP`
            #    因此不算"手工管辖" ⇒ `--sr-analyze` 每轮都把它报成「疑似误伤 i.snssdk.com ×184」，
            #    而这其实是 owner 2026-09-29 用 CLIENT_DROP_ONLY 配方**故意**做的客户端丢包（只报不写，但吵）。
            #    注意方向：多认出来的都是**手工区**的域名 ⇒ 只会让分析更保守（跳过、不自动删）。
            m = re.match(r"^DOMAIN(-[A-Z]+)?,[^,]+,([A-Z][A-Z-]*)$", s)
            # `DOMAIN-KEYWORD`（以及将来的 DOMAIN-REGEX）的值是**关键字**不是域名，正则却一样匹配
            # ⇒ 会把 `tesla` / `reading-ad` 当域名塞进 EXEMPT/OWNER_ALLOW，并让 ADH 收到
            # `@@||tesla^$important` 这种无意义的放行。列表里已开始用关键字，在这里挡掉。
            if m and s.split(",", 1)[0] not in ("DOMAIN-KEYWORD", "DOMAIN-REGEX"):
                out.add(s.split(",")[1])
    return out


AUTO_MARK = {
    "#": "# ===== 自动收集（以下内容由脚本管理，勿手改）=====",
    "!": "! ===== 自动收集（以下内容由脚本管理，勿手改）=====",
}


def split_manual(existing, comment):
    """Split a list file into (manual lines, auto lines) around the AUTO marker.

    FAIL-SAFE: if the marker is missing (legacy file, or someone edited it away) the WHOLE
    file is treated as MANUAL and nothing is converged. The opposite direction (whole file =
    auto) silently deleted hand-curated rules on 2026-09-19; it is never taken again."""
    mark = AUTO_MARK.get(comment)
    lines = existing.splitlines()
    if mark:
        stripped = [l.strip() for l in lines]
        if mark in stripped:
            i = stripped.index(mark)
            return lines[:i], lines[i + 1:]
    return lines, []


def guard_drop(label, before, removed_n):
    """Refuse a runaway deletion: abort if a write would remove >= SAFETY_MIN_DROP entries
    AND more than SAFETY_MAX_DROP_PCT% of the existing set, unless --force is given."""
    pct = float(cfg("SAFETY_MAX_DROP_PCT") or 30)
    floor = int(float(cfg("SAFETY_MIN_DROP") or 5))
    if not (removed_n >= floor and removed_n > before * pct / 100.0):
        return
    msg = f"{label}: would drop {removed_n}/{before} entries (>{pct:g}%)"
    if "--dry-run" in sys.argv:
        print(f"\u26a0\ufe0f  [dry-run] {msg} - a real run would ABORT here (use --force to allow)")
        return
    if "--force" in sys.argv:
        print(f"\u26a0\ufe0f  {msg} (--force)")
        return
    sys.exit(f"\u26d4 {msg}. Refusing (safety valve). Re-run with --force if intended.")


def repo_sync_set(owner, name, path, token, desired, line_fmt="||{d}^", comment="!",
                  branch="", dry_run=False):
    """Converge only the AUTO section of a repo file to `desired` (add new, drop stale);
    the manual section above the marker is preserved verbatim. Header refreshed on change."""
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}
    api = f"https://api.github.com/repos/{owner}/{name}/contents/{path}"
    status, text = http("GET", api + (f"?ref={branch}" if branch else ""), headers)
    if status == 200:
        meta = json.loads(text)
        sha = meta["sha"]
        existing = base64.b64decode(meta["content"]).decode()
    elif status == 404:
        sha, existing = None, ""
    else:
        sys.exit(f"repo read failed: HTTP {status} {text[:200]}")

    manual, auto = split_manual(existing, comment)
    manual = [l.rstrip() for l in manual
              if l.strip() and not re.match(r"^[!#]\s*(updated|auto-added)\b", l.strip())]
    have = parse_domains("\n".join(auto))
    manual_dom = parse_domains("\n".join(manual))
    # ⚠️ 2026-09-27 加的护栏：AUTO 标记缺失时 split_manual 会 fail-safe 把**整个文件**当人工区，
    # 于是 auto 为空 ⇒ 本函数变成"只追加、永不删除"，而且**静默无声**。
    # 实测 `reject-custom.list` 就是这种状态（它是 CI 从 adh-custom.txt 转换生成的，用 `#` 前缀，
    # 从不带我们期望的 `! ===== 自动收集…` 标记）⇒ 想从里面删 kv501… 永远删不掉。
    # 这里做两件事：① 检出这种情况就**拒绝写入**（不追加 494 条把文件搞成 1000+ 行）；
    # ② 明确打印是哪个文件、该怎么修。生成的 list 本该由 CI 重新生成，脚本不该去收敛它。
    # ⚠️ 2026-09-30 修：判据原先用 `not auto`，但「标记在、自动区还是空的」同样满足 `not auto`
    #    ⇒ **首次给一个新文件建自动区时会被自己挡住**（hongguo-ad.list 就是这么卡住的；
    #    那 3 个老文件自动区早已非空，所以这个坑一直没暴露）。改成**真的去找标记行**。
    has_mark = bool(AUTO_MARK.get(comment)) and \
        AUTO_MARK[comment] in [l.strip() for l in existing.splitlines()]
    if not has_mark and existing.strip() and have == set() and manual_dom:
        print(f"repo_sync_set: ⚠️ {path} 缺 AUTO 标记（`{comment} ===== 自动收集…`）——"
              f"整个文件被当作人工区，本函数无法收敛（只追加不删除）。")
        print(f"repo_sync_set: ⚠️ 跳过 {path} 的写入以免重复追加（该文件应由上游重新生成）")
        return [], []
    want = {d for d in desired if d not in manual_dom}
    added, removed = sorted(want - have), sorted(have - want)
    guard_drop(path, len(have), len(removed))
    mark = AUTO_MARK.get(comment, "")
    # line_fmt 可以是模板串，也可以是**可调用**（--sr-analyze 需要每个域自带动作：
    # 同一个 reject 清单里 REJECT 与 REJECT-DROP 混排）。2026-09-30
    if callable(line_fmt):
        fmt = lambda doms: sorted(line_fmt(d) for d in doms)
    else:
        fmt = lambda doms: sorted(line_fmt.format(d=d) for d in doms)
    body_old = "\n".join(manual + ([mark] if mark else []) + fmt(have))
    body_new = "\n".join(manual + ([mark] if mark else []) + fmt(want))
    if body_old == body_new:
        print(f"no change; {path} up to date")
        return [], []
    stamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %z")
    head = f"{comment} updated: {stamp}"
    content = head + ("\n" + body_new if body_new else "") + "\n"
    if dry_run:
        print(f"[dry-run] {path}: +{len(added)} / -{len(removed)}")
        return added, removed

    body = {"message": f"{path}: +{len(added)} / -{len(removed)} @ {stamp}",
            "content": base64.b64encode(content.encode()).decode()}
    if sha:
        body["sha"] = sha
    if branch:
        body["branch"] = branch
    status, text = http("PUT", api, headers, body)
    if status not in (200, 201):
        sys.exit(f"repo write failed: HTTP {status} {text[:200]}")
    print(f"{path}: +{len(added)} / -{len(removed)}")
    return added, removed


def repo_update_rule_deltas(owner, name, token, branch, deltas):
    """Write this run's per-channel (+a/-b) markers onto the README「当前规则量」line.

        拦截 **399** 条（+2/-0） / 直连 **92** 条（+0/-0） / 代理 **23** 条（+0/-0）

    分工：**计数**由 CI 的 `update_readme_counts.py` 从 list 文件数 DOMAIN- 行生成（它被改成
    原样保留这里的（+a/-b）标记）；**增删**只有同步脚本知道（repo_sync_set 的 added/removed），
    所以由脚本补这一段。两边各管一段，不抢同一行写。
    注：拦截的增删取自 `adh-custom.txt` 自动区（= CI 生成的 `reject-custom.list` 的增删；
    手工区是人改的，不算脚本的功劳）。失败只告警，绝不让同步失败。"""
    # 2026-10-01 拆分后：本仓库只有 adh-custom.txt（小火箭三张表在另一个仓库）
    labels = ((cfg("REPO_PATH"), "拦截"),)
    summary = " / ".join(f"{lab} +{deltas.get(p, (0, 0))[0]}/-{deltas.get(p, (0, 0))[1]}"
                         for p, lab in labels)
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}
    api = f"https://api.github.com/repos/{owner}/{name}/contents/README.md"
    status, text = http("GET", api + (f"?ref={branch}" if branch else ""), headers)
    if status != 200:
        print(f"README deltas: read failed HTTP {status}")
        return
    meta = json.loads(text)
    old = base64.b64decode(meta["content"]).decode()
    new, hits = old, 0
    for path, lab in labels:
        a, r = deltas.get(path, (0, 0))
        pat = re.compile(rf"({re.escape(lab)} \*\*\d+\*\* 条)(（\+\d+/-\d+）)?")
        new, n = pat.subn(lambda m: f"{m.group(1)}（+{a}/-{r}）", new, count=1)
        hits += n
    if not hits:
        print("README deltas: 计数行没匹配上，跳过（计数格式变了？）")
        return
    # 更新时间行：本脚本每跑一轮就刷新（2026-09-25 起同步改为每天 08:00 CST 一次），
    # 所以即使某天没有规则增删，这行也会如实往前走 —— 它就是"pipeline 最近一次跑"的时间。
    # CI 的 update_readme_counts.py 也会写它（list 变更时），两者相隔几秒，结果一致。
    ts_line = "> 更新时间：" + datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S（UTC%z）")
    if re.search(r"^> 更新时间：.*$", new, flags=re.M):
        new, _ = re.subn(r"^> 更新时间：.*$", lambda _m: ts_line, new, flags=re.M)
    else:
        m_ts = re.search(r"^> 当前规则量：.*$", new, flags=re.M)
        if m_ts:
            new = new[:m_ts.end()] + "\n" + ts_line + new[m_ts.end():]
    if new == old:
        print(f"README deltas: 无变化（{summary}）")
        return
    body = {"message": f"README: 本次同步增删 {summary}",
            "content": base64.b64encode(new.encode()).decode(), "sha": meta["sha"]}
    if branch:
        body["branch"] = branch
    status, text = http("PUT", api, headers, body)
    if status not in (200, 201):
        print(f"README deltas: write failed HTTP {status} {text[:160]}")
    else:
        print(f"README deltas: {summary}")


def repo_sets(owner, name, token, branch=""):
    """Read the existing repo list files -> (reject, direct, proxy) domain sets.
    Reads retry then ABORT on API errors (a silent empty read would wipe the lists)."""
    def content(path):
        headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}
        api = f"https://api.github.com/repos/{owner}/{name}/contents/{path}"
        last = ""
        for _ in range(3):
            status, text = http("GET", api + (f"?ref={branch}" if branch else ""), headers)
            if status == 200:
                return base64.b64decode(json.loads(text)["content"]).decode()
            if status == 404:
                return ""
            last = f"HTTP {status} {text[:120]}"
            time.sleep(2)
        sys.exit(f"repo read failed: {path} -> {last}")
    reject = set()
    for line in content(cfg("REPO_PATH")).splitlines():
        line = line.strip()
        if line.startswith("||"):
            d = line[2:].rstrip("^").strip()
            if d and "*" not in d:
                reject.add(d)
    direct, proxy = set(), set()
    for line in content(cfg("REPO_DIRECT_PATH")).splitlines():
        m = re.match(r"^DOMAIN-SUFFIX,([^,]+),DIRECT$", line.strip())
        if m:
            direct.add(m.group(1))
    for line in content(cfg("REPO_PROXY_PATH")).splitlines():
        m = re.match(r"^DOMAIN-SUFFIX,([^,]+),PROXY$", line.strip())
        if m:
            proxy.add(m.group(1))
    return reject, direct, proxy


def resolve_conflicts(chans):
    """chans = [(name, set), ...] in descending priority. Lower-priority domains that
    collide with a higher-priority one (exact or parent/child) are dropped."""
    drops = {name: set() for name, _ in chans}
    notes = []
    for i in range(len(chans)):
        hn, high = chans[i]
        for j in range(i + 1, len(chans)):
            ln, low = chans[j]
            for h in sorted(high):
                for l in sorted(low):
                    if h == l or h.endswith("." + l) or l.endswith("." + h):
                        drops[ln].add(l)
                        notes.append(f"{l} ({ln}) ↔ {h} ({hn}) → 保 {hn}")
    return drops, notes


_CN_CACHE = []
_CN_OVERRIDE = None     # 仅 --selftest 用：打桩 CN 清单，避免离线用例联网


def _cn_domains():
    """CN 清单只在一次运行里加载一次（裁决里每个冲突项都要查它）。"""
    if _CN_OVERRIDE:
        return _CN_OVERRIDE
    if not _CN_CACHE:
        _CN_CACHE.append(load_cn_domains())
    return _CN_CACHE[0]


def _obs_used(dom, mind):
    """该域名**自己（或同一条链上的直连父域/子域）**在实测里被正常解析用过。

    per-host 统计：`microsoft.com` 桶里别的主机的放行数**不算** `mobile.events.data.
    microsoft.com` 在用（2026-09-26 实测踩过：那 4 个微软遥测域名自身只有 2~5 次查询）。
    无 per-host 明细时退回整桶近似。"""
    o = obs_get(dom)
    if not o:
        return False
    per = o.get("host_allowed")
    if per is None:
        return o.get("allowed", 0) >= mind
    if per.get(dom, 0) >= mind:
        return True
    related = sum(n for h, n in per.items()
                  if h == dom or h.endswith("." + dom) or dom.endswith("." + h))
    return related >= mind


def _obs_is_all_ad(dom):
    """实测里所有非放行的广告型特征都指向「只有广告在用」：没有任何非广告特征命中。"""
    o = obs_get(dom)
    if not o:
        return False
    return o.get("ad_like", 0) > 0 and o.get("other_like", 0) == 0 and o.get("direct_like", 0) == 0


def obs_is_ad_ish(dom):
    """该域名实测里广告型主机占多数（用于审计里解释「为什么它保持拦截」）。"""
    o = obs_get(dom)
    if not o:
        return False
    return o.get("ad_like", 0) > (o.get("other_like", 0) + o.get("direct_like", 0))


def host_allowed(o, host):
    """该主机在实测里被正常解析过几次（无 per-host 统计时按整桶放行数近似）。"""
    per = (o or {}).get("host_allowed")
    if per is None:
        return (o or {}).get("allowed", 0)
    return per.get(host, 0)


def rel_evidence(r, o):
    """与域名 `r` 相关的实测主机：`r` 自己 + 它的子域/父域（排除同 base 桶里的旁支）。

    2026-09-26 实测教训：`microsoft.com` 桶里 6 个主机的 37 次放行，被算成了
    `mobile.events.data.microsoft.com` 的「在用」证据 —— 后者自己 7 天只有 4 次查询、还全被拦。
    返回 (allowed, hosts)：allowed = 相关主机各自的**放行**次数之和。"""
    hosts = dict((o or {}).get("hosts") or {})
    rel = {h: n for h, n in hosts.items()
           if h == r or h.endswith("." + r) or r.endswith("." + h)}
    allowed = sum(host_allowed(o, h) for h in rel)
    return allowed, rel


def _norm_fqdns(hosts, limit=12):
    """按出现次数取前 N 个 FQDN（用于把「宽拦截」降级成「只拦命中广告特征的 FQDN」）。"""
    return [h for h, _ in sorted(hosts.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]]


def _name_of(dom, o):
    """实测里代表该域名的具体名字：精确同名优先，否则取它下面出现最多的子域。

    例：拦截域名 = 实测主机本身（宽拦截盖到它）→ 返回它自己；
    拦截项是实测主机的父域 → 返回那个具体子域。"""
    hosts = (o or {}).get("hosts") or {}
    if dom in hosts:
        return dom
    kids = [h for h in hosts if h.endswith("." + dom)]
    if not kids:
        return ""
    return max(kids, key=lambda h: (hosts[h], h))


def _downgrade_entries(dom, fqdns):
    """把宽拦截父域换成它下面更具体的广告型 FQDN 规则：广告照拦，被误伤的其它子域放行。

    只在「该父域本身是实测主机 FQDN」时使用（见 resolve_conflicts_evidence 分支 C）；
    选不中任何广告型 FQDN 时退回保拦截（由调用方处理）。"""
    out = set()
    for h in fqdns:
        if h != dom and not h.endswith("." + dom):
            continue
        if classify(h) == "ad" or (ADLIST and in_domset(h, ADLIST)):
            out.add(h)
    return out


def decide_one(r, direct, proxy, force_reject=(), protected=(), max_hosts=12,
               min_evidence=3, allow_downgrade=True):
    """单域名裁决（**唯一**规则实现 —— 冲突裁决与全量重判 `--audit` 共用）。

    返回 (verdict, reason, extra)：
      "keep"      保拦截
      "release"   释放（extra = 该释放的实测主机集合，用于 ADH 白名单）
      "downgrade" 降级（extra = 换成拦截的广告型 FQDN 集合）

    顺序 = 拦截优先：owner 显式/手工区 / 参考黑名单 → 只有广告流量 → 纯代理冲突
    → 无正常解析证据 → 降级（换成更具体规则）→ 释放（有可证直连冲突）→ 否则保拦截。"""
    if r in set(force_reject) or r in set(protected):
        return "keep", "owner 显式/手工区", None
    if ADLIST and in_domset(r, ADLIST):
        return "keep", "参考黑名单命中", None
    o = obs_get(r)
    mind = int(min_evidence or 3)
    if _obs_is_all_ad(r):
        return "keep", "实测仅广告型流量", None
    d_hits = sorted({d for d in direct
                     if d == r or d.endswith("." + r) or r.endswith("." + d)})
    p_hits = sorted({p for p in proxy
                     if p == r or p.endswith("." + r) or r.endswith("." + p)})
    if p_hits and not d_hits:
        return "keep", "纯代理冲突（只剔代理项）", None
    if not _obs_used(r, mind):
        return "keep", f"实测无正常解析记录（自身放行 {host_allowed(o, r)} < {mind}）", None
    obs_hosts = set((o or {}).get("hosts", {}))
    sub = [d for d in d_hits if d.endswith("." + r)]
    parent = [d for d in d_hits if r.endswith("." + d)]
    # 「可证」= 冲突的那个名字（或它在实测里的直连子域）**被正常解析过**
    # （per-host 统计；无明细时看整桶放行数）。2026-09-26
    def _name_used(h):
        return h in obs_hosts and host_allowed(o, h) > 0
    sub_obs = [d for d in sub if _name_used(d)
               or any(_name_used(h) for h in obs_hosts if h.endswith("." + d))]
    parent_obs = [d for d in parent if _name_used(d)]
    proven = _name_used(r) or bool(sub_obs) or bool(parent_obs)
    normal_like = bool(o and (o.get("other_like", 0) + o.get("direct_like", 0) +
                              o.get("proxy_like", 0)) > 0)
    # C. 降级（优先于释放）：这个域名下头实测到「广告型子域」，就把整域规则换成那些更具体的
    #    子域规则 —— 拦截不丢（广告照拦），同时不再用一个宽规则盖住整个域名。
    #    没有广告型子域 → 换出来还是拦它自己 = 无效动作，不做。2026-09-26
    fqdns = _norm_fqdns(o.get("hosts", {}), max_hosts) if o else []
    ad_kids = [h for h in fqdns
               if h != r and h.endswith("." + r) and
               (classify(h) == "ad" or (ADLIST and in_domset(h, ADLIST)))]
    if ad_kids and allow_downgrade:
        entries = _downgrade_entries(r, ad_kids)
        if entries and entries != {r}:
            return "downgrade", f"降级为拦 {len(entries)} 个广告型子域", entries
    # B. 释放：这个域名自己（或与它同一条链的直连子域/父域）被正常解析用过时，不能再留着
    #    整域拦截（会连带砸掉在用的那条）。per-host 统计下只认「相关主机」的放行数。
    if normal_like and proven:
        related_allowed, _rel = rel_evidence(r, o)
        cn_hit = bool(_cn_domains() and in_domset(r, _cn_domains()))
        why = "实测在用" + ("（CN 清单亦覆盖）" if cn_hit else "")
        return ("release", f"释放拦截（{why}，相关主机实测放行 {related_allowed} 次）",
                {d for d in (sub_obs + parent_obs + [r]) if d and d in obs_hosts})
    return "keep", "无实测正常主机 / 无具体直连冲突", None


def resolve_conflicts_evidence(reject, direct, proxy, force_reject=frozenset(),
                               protected=frozenset(), max_hosts=12, min_evidence=3,
                               allow_downgrade=True):
    """实测裁决（2026-09-26，owner：冲突时实测，拦截优先但不误伤国内 App/网站）。

    逐条冲突取证，四档（A 保拦截 / B 释放 / C 降级 / D 纯代理冲突保拦截），
    单条规则见 `decide_one()`。只处理**有冲突**的条目（无冲突的照旧保留）。

    释放 = 从 reject 移除且**不**给整域 ADH `@@` 白名单（除非它本来就在 direct 集合里）；
    返回 (rel, drop, downgrade, keep, notes, counts)；`drop` 从 ADH 待删 `@@` 里排除。
    """
    rel, drop, downgrade, keep = set(), set(), set(), set()
    counts = {"conflicts": 0, "keep": 0, "release": 0, "downgrade": 0, "proxy_keep": 0}
    notes = []
    for r in sorted(reject):
        d_hits = {d for d in direct if d == r or d.endswith("." + r) or r.endswith("." + d)}
        p_hits = {p for p in proxy if p == r or p.endswith("." + r) or r.endswith("." + p)}
        if not d_hits and not p_hits:
            continue
        counts["conflicts"] += 1
        verdict, reason, extra = decide_one(
            r, direct, proxy, force_reject=force_reject, protected=protected,
            max_hosts=max_hosts, min_evidence=min_evidence, allow_downgrade=allow_downgrade)
        notes.append(f"{r}: {reason}")
        if verdict == "release":
            rel.add(r)
            drop |= extra or set()
            counts["release"] += 1
        elif verdict == "downgrade":
            downgrade |= extra or set()
            counts["downgrade"] += 1
        else:
            keep.add(r)
            counts["proxy_keep" if reason.startswith("纯代理") else "keep"] += 1
    if not allow_downgrade:
        for d in list(downgrade):
            keep.add(d)
            downgrade.discard(d)
    keep -= downgrade          # 降级项不再按原规则拦截
    drop -= keep               # 保拦截的域名不参与白名单删除
    return rel, drop, downgrade, keep, notes, counts


def audit_reclassify(reject, direct, proxy, new_ads=(), force_reject=frozenset(),
                     protected=frozenset(), max_hosts=12, min_evidence=3,
                     allow_downgrade=True):
    """全量重判（`--audit` / `AUDIT_RECLASSIFY=1`）：用同一份 decide_one() 把
    「现有拦截表 + 本轮新分类的广告域」**全部**过一遍，只出报告、不写任何东西。

    与 resolve_conflicts_evidence 的差别：不再跳过「无冲突」的条目，所以能回答
    「这几百条里哪些该放行 / 该降级 / 哪些近 7 天没证据只能按原判保留」。

    返回 (findings, counts, rel, downgrade)；findings = [(域名, 判定, 理由, 原状态, 有无证据, 放行数, 拦截数)]。
    """
    rel, downgrade, keep = set(), set(), set()
    counts = {"total": 0, "keep": 0, "release": 0, "downgrade": 0,
              "old_keep": 0, "new_ad": 0, "no_evidence": 0}
    findings = []
    for r in sorted(set(reject) | set(new_ads)):
        old_state = "reject" if r in reject else "new-ad"
        counts["total"] += 1
        counts["old_keep" if old_state == "reject" else "new_ad"] += 1
        o = obs_get(r)
        if o is None:
            counts["no_evidence"] += 1
        verdict, reason, extra = decide_one(
            r, direct, proxy, force_reject=force_reject, protected=protected,
            max_hosts=max_hosts, min_evidence=min_evidence, allow_downgrade=allow_downgrade)
        becomes = ()
        ads_kept = ()
        if verdict == "release":
            rel.add(r)
            counts["release"] += 1
            # 释放 ≠ 放走广告：这个域名下头命中广告模式的实测子域仍会被拦（换成子域规则）。
            if o:
                ads_kept = tuple(sorted(
                    h for h in _norm_fqdns(o.get("hosts", {}), max_hosts)
                    if h != r and h.endswith("." + r) and
                    (classify(h) == "ad" or (ADLIST and in_domset(h, ADLIST)))))
        elif verdict == "downgrade":
            downgrade |= extra or set()
            counts["downgrade"] += 1
            becomes = tuple(sorted(extra or ()))
        else:
            keep.add(r)
            counts["keep"] += 1
            # 说明性统计：它「更像广告」但这个域名本身就是那条最具体的广告规则
            # （换成子域规则还是拦它自己）—— 审计里标出来，免得看着像漏判。
            if obs_is_ad_ish(r):
                counts["noop_downgrade"] = counts.get("noop_downgrade", 0) + 1
        findings.append({"domain": r, "verdict": verdict, "reason": reason, "old": old_state,
                         "has_evidence": o is not None, "allowed": (o or {}).get("allowed", 0),
                         "blocked": (o or {}).get("blocked", 0),
                         "becomes": list(becomes), "ads_kept": list(ads_kept),
                         "kept": verdict == "keep"})
    return findings, counts, rel, downgrade


def write_audit_report(findings, counts, out_dir=HERE, manual=frozenset()):
    """全量重判结果落盘：JSON（明细）+ Markdown（给人看）。**域名原文只进文件。**

    `manual` = 人工区域名集合（用于在报告里标注「需手删」还是「会自动收敛」）。"""
    manual_set = set(manual)
    stamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M")
    json_path = os.path.join(out_dir, "reclassify-report.json")
    md_path = os.path.join(out_dir, "reclassify-report.md")
    payload = {
        "at": stamp,
        "counts": counts,
        "findings": findings,
    }
    try:
        with open(json_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=1)
    except OSError as e:
        print(f"audit report write failed: {e}")
        return "", ""
    by_verdict = {}
    for x in findings:
        by_verdict.setdefault(x["verdict"], []).append(x)
    lines = [f"# 拦截表全量重判（新规则实测复核） {stamp}", "",
             "> 只读审计：**不改 ADH、不改仓库**。明细见同目录 `reclassify-report.json`。", "",
             f"- 参与重判：**{counts['total']}** 条"
             f"（现有拦截 {counts['old_keep']} + 本轮新广告 {counts['new_ad']}）",
             f"- 保持拦截：**{counts['keep']}**"
             f"（其中 {counts['no_evidence']} 条近 7 天无实测证据，按原判保留）",
             f"- 建议释放：**{counts['release']}**",
             f"- 建议降级：**{counts['downgrade']}**", ""]
    for v, title in (("release", "## 建议释放"), ("downgrade", "## 建议降级")):
        rows = sorted(by_verdict.get(v, []), key=lambda x: -x["allowed"])
        lines += [f"{title}（{len(rows)}）", ""]
        if not rows:
            lines.append("（无）")
        else:
            # 2026-09-27：加「归属」列。教训 —— kv501 那次排查绕了很久，因为报告没标明
            # 条目是在**人工区**还是**自动区**：人工区的行受 split_manual 保护、
            # repo_sync_set 永远删不掉，必须手工删；自动区的会被下一轮同步自动收敛。
            # 备注：`old` 字段由 audit_reclassify 填（reject / new-ad），这里翻译成可读位置。
            lines += ["| 域名 | 归属 | 原状态 | 实测放行 | 实测拦截 | 仍拦的广告子域 | 理由 |",
                      "|---|---|---|---|---|---|---|"]
            for x in rows[:60]:
                bw = ", ".join(f"`{b}`" for b in x.get("becomes", [])) or \
                     (", ".join(f"`{b}`" for b in x.get("ads_kept", [])) or "—")
                loc = "人工区（需手删）" if x["domain"] in manual_set \
                      else ("新采集" if x.get("old") == "new-ad" else "自动区（会自动收敛）")
                lines.append(f"| `{x['domain']}` | {loc} | {x['old']} | {x['allowed']} "
                             f"| {x['blocked']} | {bw} | {x['reason']} |")
            if len(rows) > 60:
                lines.append(f"| … | | | | | | 其余 {len(rows) - 60} 条见 JSON |")
        lines.append("")
    try:
        with open(md_path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
    except OSError as e:
        print(f"audit md write failed: {e}")
        return json_path, ""
    return json_path, md_path


def dump_evidence(released=(), downgraded=(), counts=None, top_hosts=15):
    """落盘冲突实测证据（域名明细只进文件，不进对话/日志）。返回文件路径。

    每个 zone 只留出现次数最高的 top_hosts 个主机名，避免把整份 querylog 落成几十 MB。"""
    if not OBS:
        return ""
    path = os.path.join(HERE, ".conflict_evidence.json")
    zones = {}
    for d, o in sorted(OBS.items()):
        hosts = o.get("hosts") or {}
        zones[d] = {k: v for k, v in o.items() if k != "hosts"}
        zones[d]["hosts"] = {h: c for h, c in
                             sorted(hosts.items(), key=lambda kv: (-kv[1], kv[0]))[:top_hosts]}
    out = {
        "at": datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %z"),
        "counts": counts or {},
        "released": sorted(released),
        "downgraded": sorted(downgraded),
        "zones": zones,
    }
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(out, fh, ensure_ascii=False)
        return path
    except Exception:  # noqa: BLE001 - 证据落盘失败不影响主流程
        return ""


def conflict_verify(rel_list, cn, max_check=20, timeout=4, resolvers=()):
    """放行项合规复核：国内清单(CN)覆盖 + 直连能不能解析。只告警/落盘，不改变裁决。

    返回 [(domain, in_cn, resolve_ok, detail)]；纯函数便于离线单测。"""
    out = []
    for d in sorted(rel_list)[:max_check]:
        in_cn = bool(cn and in_domset(d, cn))
        ok, detail = probe_domain(d, list(resolvers), timeout) if resolvers else (None, "no resolver")
        out.append((d, in_cn, ok, detail))
    return out


def _ev(**kw):
    """Test helper: build an OBS entry from keyword evidence fields.

    `host_allowed` 缺省时按「hosts 里除 (blocked) 提示外的所有主机都算放行」构造，
    贴近真实 obs_add() 的 per-host 统计。"""
    o = dict.fromkeys(_OBS_KEYS, 0)
    for k, v in kw.items():
        o[k] = v
    if not o.get("hosts"):
        o["hosts"] = {}
    if "host_allowed" not in kw:
        o["host_allowed"] = dict(o["hosts"])
    return o


def _evidence_selftest():
    """冲突证据裁决的离线用例（--selftest 里跑，不需要网络）。

    合成域名 + 直接注入 OBS + 打桩 CN 清单，验证「拦截优先但不误伤国内 App/网站」。"""
    global OBS, ADLIST, EXEMPT, _CN_CACHE, _CN_OVERRIDE, OWNER_ALLOW
    saved = (OBS, ADLIST, EXEMPT, _CN_CACHE, _CN_OVERRIDE, OWNER_ALLOW)
    try:
        ADLIST, EXEMPT, _CN_CACHE, _CN_OVERRIDE = set(), set(), [set()], []
        def with_cn(*doms):
            global _CN_OVERRIDE
            _CN_OVERRIDE = set(doms)
        # 1) FORCE_REJECT / 手工区(protected) / 参考黑名单命中 → 永远保持拦截（即使实测在用）
        with_cn("a.com")
        OBS = {"a.com": _ev(allowed=50, other_like=50, hosts={"a.com": 50})}
        r = resolve_conflicts_evidence({"a.com"}, {"a.com"}, set(), force_reject={"a.com"})
        assert "a.com" in r[3] and "a.com" not in r[0], r
        r = resolve_conflicts_evidence({"a.com"}, {"a.com"}, set(), protected={"a.com"})
        assert "a.com" in r[3] and "a.com" not in r[0], r
        ADLIST = {"a.com"}
        r = resolve_conflicts_evidence({"a.com"}, {"a.com"}, set())
        assert "a.com" in r[3], r
        ADLIST = set()
        # 2) 实测只有广告型流量 → 保拦截（拦得准），哪怕在 CN 清单里
        with_cn("a.com")
        OBS = {"a.com": _ev(allowed=9, ad_like=9, hosts={"x.dsp.a.com": 9})}
        r = resolve_conflicts_evidence({"a.com"}, {"a.com"}, set())
        assert r[5]["keep"] == 1 and "a.com" in r[3], r
        # 3) 宽拦截父域 ↔ 直连子域，父域下面实测到广告型子域 → 降级（只拦那个广告子域）
        with_cn("a.com")
        OBS = {"a.com": _ev(allowed=40, other_like=30, ad_like=10,
                            hosts={"a.com": 40, "cdn.a.com": 30, "ad.dsp.a.com": 10})}
        r = resolve_conflicts_evidence({"a.com"}, {"cdn.a.com"}, set())
        assert r[2] == {"ad.dsp.a.com"} and "a.com" not in r[3], r
        # 3b) 冲突项与它所在域名在实测里都没被正常用过（只有被拦）→ 保拦截
        with_cn("a.com")
        OBS = {"a.com": _ev(blocked=45, other_like=45,
                            hosts={"www.a.com": 40, "cdn.a.com": 5},
                            host_allowed={})}
        r = resolve_conflicts_evidence({"a.com"}, {"cdn.a.com"}, set())
        assert "a.com" in r[3] and not r[0] and not r[2], r
        # 4) 有冲突、但没有「可证直连冲突」、名字下头有更具体的广告型子域 → 降级
        with_cn("x.com")
        OBS = {"x.com": _ev(allowed=40, blocked=60, other_like=40, ad_like=10,
                            hosts={"x.com": 40, "ad.log0.x.com": 10})}
        r = resolve_conflicts_evidence({"x.com"}, {"sub.x.com"}, set())
        assert r[2] == {"ad.log0.x.com"} and "x.com" not in r[3], r
        # 4b) 更具体的拦截规则 + 它下面还有广告型子域 → 继续降级到子域（拦截不丢）
        with_cn("x.com")
        OBS = {"x.com": _ev(allowed=40, blocked=60, other_like=40, ad_like=10,
                            hosts={"ad.log0.x.com": 40, "sub.ad.log0.x.com": 10})}
        r = resolve_conflicts_evidence({"ad.log0.x.com"}, {"ad.log0.x.com"}, set())
        assert r[2] == {"sub.ad.log0.x.com"} and "ad.log0.x.com" not in r[3], r
        # 5) 拦截子域 ↔ 直连父域，父域实测在用 → 释放（避免整域误伤）
        with_cn("a.com")
        OBS = {"a.com": _ev(allowed=30, other_like=30, hosts={"a.com": 30}),
               "ad.a.com": _ev(allowed=5, other_like=5, hosts={"ad.a.com": 5})}
        r = resolve_conflicts_evidence({"ad.a.com"}, {"a.com"}, set())
        assert "ad.a.com" in r[0] and r[5]["release"] == 1, r
        # 6) 无任何实测证据 → 保拦截
        OBS = {}
        r = resolve_conflicts_evidence({"a.com"}, {"a.com"}, set())
        assert "a.com" in r[3] and r[5]["keep"] == 1, r
        # 7) 实测只有「被拦」记录（手机在躲它）→ 保拦截
        OBS = {"a.com": _ev(blocked=99, other_like=99, hosts={"a.com": 99},
                            host_allowed={})}
        r = resolve_conflicts_evidence({"a.com"}, {"a.com"}, set())
        assert "a.com" in r[3] and not r[0], r
        # 8) 纯代理冲突 → 保拦截（不进降级/放行）
        with_cn("g.com")
        OBS = {"g.com": _ev(allowed=40, other_like=40, hosts={"g.com": 40})}
        r = resolve_conflicts_evidence({"g.com"}, set(), {"g.com"})
        assert "g.com" in r[3] and r[5]["proxy_keep"] == 1, r
        # 9) 关闭降级开关时不做降级（改为释放/保拦截，取决于证据）
        with_cn("a.com")
        OBS = {"a.com": _ev(allowed=40, other_like=30, ad_like=10,
                            hosts={"a.com": 40, "x.dsp.a.com": 10})}
        r = resolve_conflicts_evidence({"a.com"}, {"a.com"}, set(), allow_downgrade=False)
        assert not r[2], r
        # 10) 放行证据不足（allowed 少于阈值）→ 保拦截，且 ADH 白名单删除集合里不含它
        with_cn("a.com")
        OBS = {"a.com": _ev(allowed=2, other_like=2, hosts={"a.com": 2})}
        r = resolve_conflicts_evidence({"a.com"}, {"a.com"}, set())
        assert "a.com" in r[3] and not r[0], r
        # 12) 连接级风暴检测：用中位数做基线（P95 会被尖峰自身污染 → 漏报，实测踩过）
        # 11) 实测只有「被拦」记录的域名永远保拦截（不会因为 ad_like=0 被误放行）
        OBS = {"a.com": _ev(blocked=99, ad_like=99, hosts={"x.dsp.a.com": 99})}
        r = resolve_conflicts_evidence({"a.com"}, {"a.com"}, set())
        assert "a.com" in r[3] and not r[0], r
    finally:
        OBS, ADLIST, EXEMPT, _CN_CACHE, _CN_OVERRIDE, OWNER_ALLOW = saved


def selftest():
    assert is_suspected("x.dsp.example.com")
    assert is_suspected("ad.analytics.foo.com")
    assert not is_suspected("reading.douyin.com")   # protected
    assert not is_suspected("api.example.com")      # no ad pattern
    assert classify("x.dsp.example.com") == "ad"
    assert classify("v26.rtcxyz.com") == "direct"
    assert classify("is.snssdk.com") == "direct"    # direct wins over protected
    assert classify("lf.bytegecko.com") is None     # protected, no direct pattern
    assert classify("api.example.com") is None
    assert classify("www.google.com") == "proxy"
    assert classify("api.openai.com") == "proxy"
    assert base_domain("v5-gzb-jltc-a.douyinvod.com") == "douyinvod.com"
    assert base_domain("a.b.com.cn") == "b.com.cn"
    assert base_domain("google.com") == "google.com"
    drops, _ = resolve_conflicts([("拦截", {"pangolin.snssdk.com"}),
                                  ("直连", {"snssdk.com", "ok.com"}), ("代理", set())])
    assert drops["直连"] == {"snssdk.com"}
    _evidence_selftest()
    assert parse_domains("||a.com^\n# c\nDOMAIN-SUFFIX,b.com,DIRECT\n") == {"a.com", "b.com"}
    # fail-safe split: a missing marker must NOT turn manual rules into auto (2026-09-19 wipe)
    assert split_manual("a\nb\n", "!") == (["a", "b"], [])
    man, aut = split_manual(f"a\n{AUTO_MARK['!']}\nb\n", "!")
    assert man == ["a"] and aut == ["b"]
    # SR 分析的动作自动判定（2026-09-30）：信号/埋点族 → DROP；低频 → 普通 REJECT
    print("selftest ok")


def last_sync_state_path():
    return os.path.join(HERE, ".last-sync.json")


def sync_gate_check(dry, force):
    """日更闸门：返回 (是否该跑, 原因)。dry / --force 一律放行；状态缺失或配置崩了也放行
    （宁可多跑一轮，也不能把管线卡死）。

    ⚠️ 2026-09-29 踩坑与修正：原先只按「距上次成功 >= SYNC_MIN_INTERVAL_H 小时」判，
    配合宿主 cron 的 `0 */4`（0/4/8/12/16/20 点唤醒）会**自锁在首次运行的那个整点** ——
    首次 20:10 跑完 ⇒ 次日 16:00 距上次只有 19.8h（差 10 分钟不达 20h）被跳过 ⇒ 20:00 才跑
    ⇒ 永远锁在 20:00。`SYNC_HOUR=8` 只拦住更早的小时，**并不能把它拉到 8 点**。
    实测提交时间 09-28 20:10 / 09-29 20:11（北京时间），而原注释写的是「实际就是每天 08:00」。
    修正：改成「**每个本地日期只跑一次**」—— 当天 >= SYNC_HOUR 的首次唤醒就跑，
    错过 08:00 会在当天后续唤醒补跑，且照定义**不可能漂移**。
    """
    if dry or force:
        return True, "dry-run / --force 放行"
    h_raw, m_raw = cfg("SYNC_HOUR"), cfg("SYNC_MIN_INTERVAL_H")
    if not h_raw and not m_raw:
        return True, "闸门已关闭（SYNC_HOUR / SYNC_MIN_INTERVAL_H 为空）"
    try:
        hour = int(h_raw or 8)
        min_h = float(m_raw) if m_raw else 0.0
    except Exception:  # noqa: BLE001
        return True, "闸门配置不可解析，放行"
    now = datetime.now().astimezone()
    last = 0.0
    try:
        with open(last_sync_state_path(), encoding="utf-8") as fh:
            last = float(json.load(fh).get("ts") or 0)
    except Exception:  # noqa: BLE001 - 没有 / 坏了的状态 = 该跑
        last = 0.0
    if now.hour < hour:
        return False, f"本地 {now:%H:%M} 早于 SYNC_HOUR={hour:02d}:00，等下一次唤醒"
    if last:
        last_local = datetime.fromtimestamp(last).astimezone()
        if last_local.strftime("%Y-%m-%d") == now.strftime("%Y-%m-%d"):
            return False, f"今天（{last_local:%m-%d %H:%M}）已同步过，等明天 >= {hour:02d}:00"
    age_h = (time.time() - last) / 3600 if last else None
    if min_h > 0 and age_h is not None and age_h < min_h:
        return False, f"距上次成功同步 {age_h:.1f}h < {min_h:g}h"
    return True, f"到点可跑（上次成功 {'无记录' if age_h is None else f'{age_h:.1f}h 前'}）"


def mark_sync_done():
    try:
        with open(last_sync_state_path(), "w", encoding="utf-8") as fh:
            json.dump({"ts": time.time(),
                       "when": datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %z")}, fh)
    except Exception:  # noqa: BLE001 - 状态写不进不该影响同步结果
        pass


def adh_rules_clean(dry=False, keep_allows=True):
    """清空 ADH「自定义过滤规则」(user_rules)。

    背景（2026-09-30）：ADH 现在通过**过滤清单**取规则（脚本产出的 adh-custom.txt 等），
    user_rules 里历史上由本脚本 API 推上去的那批已经冗余。

    ⚠️ 默认 `keep_allows=True`：**保留 `@@` 放行规则**。上游大表是 19 万/28 万条，
    没有这些 `$important` 放行，正常访问会被拦死（历史上就是这么救回 id6.me / weixin /
    firebaselogging / safebrowsing / reddit 那批的）。要连放行一起清：加 `--all`。
    无论是否 dry-run，**先备份**到 `ops/adh/user_rules-backup-<stamp>.txt` 再动手。"""
    base = cfg("ADH_URL").rstrip("/")
    auth = base64.b64encode(f"{cfg('ADH_USER')}:{cfg('ADH_PASS')}".encode()).decode()
    h = {"Authorization": f"Basic {auth}"}
    status, text = http("GET", f"{base}/control/filtering/status", h)
    if status != 200:
        sys.exit(f"ADH filtering status failed: HTTP {status}")
    existing = json.loads(text).get("user_rules") or []
    blocks = [r for r in existing if r.startswith("||")]
    allows = [r for r in existing if r.startswith("@@")]
    other = [r for r in existing if r not in blocks and r not in allows]
    print(f"ADH user_rules 现状：{len(existing)} 条 —— 拦截(||) {len(blocks)} / "
          f"放行(@@) {len(allows)} / 其它 {len(other)}")
    for r in other[:5]:
        print(f"   其它：{r}")
    keep = (allows + other) if keep_allows else other
    drop = [r for r in existing if r not in keep]
    if not drop:
        print("没有需要清理的条目")
        return
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    bpath = os.path.join(HERE, "ops", "adh", f"user_rules-backup-{stamp}.txt")
    try:
        os.makedirs(os.path.dirname(bpath), exist_ok=True)
        with open(bpath, "w", encoding="utf-8") as fh:
            fh.write("\n".join(existing) + "\n")
        print(f"已备份现状 -> {bpath}")
    except Exception as e:  # noqa: BLE001 - 备份不了就不动手
        sys.exit(f"备份失败，中止（不冒这个险）：{e}")
    if dry:
        print(f"[dry-run] 将删除 {len(drop)} 条，保留 {len(keep)} 条"
              + ("（含全部 @@ 放行）" if keep_allows else "（连放行一起清了）"))
        return
    status, text = http("POST", f"{base}/control/filtering/set_rules", h, {"rules": keep})
    if status != 200:
        sys.exit(f"ADH set_rules failed: HTTP {status} {text[:200]}")
    print(f"✅ ADH user_rules 已清理：-{len(drop)}，保留 {len(keep)} 条")
    print(f"   回滚：把 {bpath} 的内容贴回 ADH「自定义过滤规则」再应用即可")


def main():
    if "--selftest" in sys.argv:
        return selftest()
    load_env()
    if "--watch" in sys.argv:          # 只读监控：不写 ADH/仓库，只可能发 Telegram
        watch_run(dry_run="--dry-run" in sys.argv)
        return
    if "--sr-watch" in sys.argv:
        sys.exit("--sr-watch 已迁到独立项目：python3 sr/sr_analyze.py（本脚本只管 ADH）")
    # Single-instance guard: a manual run overlapping a cron run would race on the ADH
    # user_rules / repo files / local state files. Non-blocking -> just exit. 2026-09-21.
    _lock = None
    try:
        import fcntl
        _lock = open("/tmp/adh_gist_sync.lock", "w")
        fcntl.flock(_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print("another adh_gist_sync instance is running; exiting")
        return
    except Exception:  # noqa: BLE001 - no fcntl (non-Linux) / no /tmp: proceed unlocked
        pass
    dry = ("--dry-run" in sys.argv) or ("--check" in sys.argv)
    force = "--force" in sys.argv
    if "--check-allows" in sys.argv:
        for line in check_allow_conflicts():
            print(line)
        return 0
    if "--adh-rules-clean" in sys.argv:
        # 清空 ADH 自定义过滤规则（默认保留 @@ 放行；--all 连放行一起清）
        return adh_rules_clean(dry=dry, keep_allows="--all" not in sys.argv)
    if "--sr-analyze" in sys.argv:
        # 2026-10-01 起小火箭侧独立成项目（两源彻底分开，避免互相污染）：
        #   手机 db → 体检报告 + 三张自建表   ⇒   python3 sr/sr_analyze.py [--write]
        sys.exit("--sr-analyze 已迁到独立项目：python3 sr/sr_analyze.py（本脚本只管 ADH）")
    ok, why = sync_gate_check(dry, force)
    if not ok:
        print(f"skip: {why}（--force 可强制跑一轮）")
        return
    print(f"[..] gate: {why}", flush=True)
    merge_ch = {x.strip() for x in cfg("MERGE_CHANNELS").split(",") if x.strip()}
    print(f"[..] start (dry={dry}); loading reference blocklist ...", flush=True)

    # Reference ad/privacy blocklist + manual-section exemption must be ready BEFORE
    # classification (classify() consults the module globals).
    global ADLIST, EXEMPT
    ADLIST = load_adlist()
    print(f"[..] blocklist ready: {len(ADLIST)} entr(ies); reading repo manual sections ...", flush=True)
    o0, n0 = cfg("REPO").split("/", 1)
    force_direct_cfg = {d.strip() for d in cfg("FORCE_DIRECT").split(",") if d.strip()}
    # ── owner 放行意图 = 权威输入（2026-09-27 owner 定调：
    #    「拦截是我的意图，但确保正常访问时不可以妥协的」）────────────────────
    # 来源，冲突时一律以「放行」为准：
    #   ① FORCE_DIRECT（脚本里显式批准）
    #   ② 放行清单手工区（direct-custom.list / proxy-custom.list 里 owner 手写的条目）
    #   ③ ADH 里已有的 `@@||…^` 白名单（triage 侧合并）
    global OWNER_ALLOW
    _ignore_sr = cfg_bool("ADH_IGNORE_SR_LISTS", False)
    if _ignore_sr:
        print("[..] ADH_IGNORE_SR_LISTS=1：不读小火箭三个清单（彻底分开）", flush=True)
    OWNER_ALLOW = set(force_direct_cfg) | (set() if _ignore_sr else
                                           repo_manual_allow_domains(o0, n0, cfg("REPO_TOKEN"),
                                                                     cfg("REPO_BRANCH")))
    # 拦截人工区必须**扣掉放行意图**：`rej_x & manual_rej` 会把「人工区写着拦」的域
    # 重新并进 reject，而人工区受 split_manual 保护、repo_sync_set 永远删不掉它们
    # ⇒ 放行意图会被人工区永久压住（2026-09-27 线上实测 24 条：
    #    id6.me / szlong.weixin.qq.com / firebaselogging* / safebrowsing / imasdk / reddit 等）。
    # 扣掉之后：放行的赢、且这些域不再出现在 `reject_des` 里 ⇒ 会自动进 direct-des。
    manual_rej_all = repo_manual_domains(o0, n0, cfg("REPO_TOKEN"), cfg("REPO_BRANCH"))
    manual_rej = {d for d in manual_rej_all if not in_domset(d, OWNER_ALLOW)}
    _oa_manual = len(manual_rej_all) - len(manual_rej)
    if _oa_manual:
        print(f"[..] manual 拦截区：{_oa_manual} 条被放行意图覆盖（人工区写着拦但已放行，放行优先）")
    EXEMPT = set(manual_rej_all) | force_direct_cfg
    print(f"[..] owner-allow intent: {len(OWNER_ALLOW)} domain(s) "
          f"(FORCE_DIRECT + 放行清单手工区)", flush=True)
    print(f"[..] manual(拦截区): {len(manual_rej)} domain(s); reading ADH querylog at {cfg('ADH_URL')} ...", flush=True)

    ads, directs, proxies, int_obs = adh_domains(cfg("ADH_URL"), cfg("ADH_USER"), cfg("ADH_PASS"),
                                                 cfg("CLIENT_IP"),
                                                 cfg("QUERYLOG_LIMIT"), cfg("QUERYLOG_HOURS"))
    print(f"[..] querylog: {len(ads)} ad / {len(directs)} direct / {len(proxies)} proxy allowed host(s)",
          flush=True)

    # ⚠️ 2026-10-01 起：**本脚本只管 ADH**（手机 db 由独立项目 `sr/sr_analyze.py` 处理，
    #   两者不共享任何状态、不互相读表）。ADH 这一轮只吃自己的 querylog。

    collapse_blk = {d.strip() for d in cfg("COLLAPSE_BLACKLIST").split(",") if d.strip()}
    for name in ("ad", "direct", "proxy"):
        if name not in merge_ch:
            continue
        cur = {"ad": ads, "direct": directs, "proxy": proxies}[name]
        # Collapse hostnames to their base domain, EXCEPT under a COLLAPSE_BLACKLIST root
        # (multi-purpose bases where a swept-in parent would also cover sibling ad/tracking
        # subdomains) - those keep the full FQDN. 2026-09-21.
        merged = {(d if (d in collapse_blk or base_domain(d) in collapse_blk) else base_domain(d))
                  for d in cur}
        held = len({d for d in merged if base_domain(d) in collapse_blk})
        if held:
            print(f"collapse blacklist: kept {held} {name} host(s) as full FQDN")
        if len(merged) != len(cur):
            print(f"merged {name}: {len(cur)} host(s) -> {len(merged)} base domain(s)")
        if name == "ad":
            ads = merged
        elif name == "direct":
            directs = merged
        else:
            proxies = merged
    print(f"found {len(ads)} ad / {len(directs)} direct / {len(proxies)} proxy domain(s)")

    if "--compact" in sys.argv:
        # ⚠️ 2026-09-30 起停用：`--compact` 会重写 direct-custom.list / proxy-custom.list，
        #    而这两个文件现在由 `--sr-analyze` **独占**管理（小火箭侧）。ADH 侧只管 reject 拦截。
        sys.exit("--compact 已停用：三个 custom.list 由 --sr-analyze 独占管理（见 --sr-analyze）")

    owner, name = cfg("REPO").split("/", 1)
    tok, br = cfg("REPO_TOKEN"), cfg("REPO_BRANCH")
    rej_x, dir_x, prox_x = (set(), set(), set()) if cfg_bool("ADH_IGNORE_SR_LISTS", False) \
        else repo_sets(owner, name, tok, br)
    # Auto-reject retention (LRU / last-seen): keep an auto-collected ad rule for
    # AUTO_REJECT_TTL_DAYS after it was last seen, instead of dropping it the instant it
    # leaves the querylog window. Without this a domain the phone blocks locally stops
    # reaching ADH -> falls out of 'ads' -> gets unbanned -> reappears (block/unblock
    # flapping). ADH-blocked domains still log, and phone REJECTs (SR db) refresh the clock.
    # 2026-09-21.
    ar_state_path = os.path.join(HERE, ".auto_reject_state.json")
    now_ts = time.time()
    ttl_days = float(cfg("AUTO_REJECT_TTL_DAYS") or 90)
    try:
        with open(ar_state_path, encoding="utf-8") as fh:
            ar_state = {k: float(v) for k, v in json.load(fh).items()}
    except Exception:  # noqa: BLE001
        ar_state = {}
    for d in ads:
        ar_state[d] = now_ts
    # ⚠️ 2026-09-30 起**不再**用手机 REJECT 记录续期这个 LRU 时钟：3 个清单只吃 ADH。
    #    （旧行为：`for h in sr_rejected` 命中就顺延 90 天，等于手机数据间接决定
    #      reject-custom.list 的保留期。）手机侧数据现在只去 hongguo-ad.list。
    for d in (rej_x - manual_rej):             # existing auto-section entries: start their clock
        ar_state.setdefault(d, now_ts)
    auto_keep = {d for d, t in ar_state.items() if now_ts - t < ttl_days * 86400}
    expired = len(ar_state) - len(auto_keep)
    ar_state = {d: t for d, t in ar_state.items() if d in auto_keep}  # drop expired
    if not dry:
        try:
            with open(ar_state_path, "w", encoding="utf-8") as fh:
                json.dump(ar_state, fh, ensure_ascii=False)
        except Exception:  # noqa: BLE001
            pass
    print(f"auto-reject retention: {len(auto_keep)} kept (<= {ttl_days:g}d since last seen), "
          f"{expired} expired")

    # Keep reject entries only if ad-confirmed (ads, from the reference list), seen within the
    # retention window, hand-written in the manual section, or explicitly force-rejected (added
    # further below). Stale auto-mirrored entries no reference list confirms are dropped - they
    # were the false-positive breakage (Volcano/ByteDance CDNs). 2026-09-20 / TTL 2026-09-21.
    reject_des = (ads | auto_keep) | (rej_x & manual_rej)
    # 清掉脏条目（含 \x00 / 通配 / 空白的名字）：它们没法写成有效规则，只会污染决策与日志。
    dirty = {d for d in reject_des if not host_ok(d)}
    if dirty:
        reject_des -= dirty
        print(f"reject sanitize: dropped {len(dirty)} malformed entr(ies) (NUL/wildcard/space)")
    reject_des = prune_subsumed(reject_des)
    direct_des, proxy_des = directs | dir_x, proxies | prox_x
    # ── owner 放行意图 = 硬约束（2026-09-27 owner：「拦截是我的意图，
    #    但确保正常访问时不可以妥协的」）────────────────────────────────
    # OWNER_ALLOW = FORCE_DIRECT ∪ 放行清单手工区 ∪（ADH 白名单在 triage 侧另算）。
    # 任何通道（ads / auto_keep / 仓库 reject 区）里落在它之下（含子域）的条目一律剔除。
    # 放在 direct_des 定义之后，且用后缀匹配 —— 精确匹配的坑在 force_direct 上踩过一次。
    owner_allow = set(OWNER_ALLOW)
    if owner_allow:
        oa_hit = {d for d in (reject_des | direct_des | ads) if in_domset(d, owner_allow)}
        if oa_hit:
            reject_des -= oa_hit
            direct_des |= oa_hit
            ads -= oa_hit
            print(f"owner-allow override: {len(oa_hit)} host(s) 剔除出拦截 -> DIRECT")
    force_direct = {d.strip() for d in cfg("FORCE_DIRECT").split(",") if d.strip()}
    if force_direct:
        # ⚠️ 必须用**后缀匹配**，不能 `-=`（集合差 = 精确匹配）：FORCE_DIRECT 的语义一直是
        # 「这个域及其子域都放行」（同文件 sr_stale 判断就用 in_domset）。2026-09-27 修：
        # 原先 `reject_des -= force_direct` 导致写父域（如 dsp.mp.microsoft.com）时
        # 子域（cp501.prod.do.dsp.mp.microsoft.com）仍被拦 —— 父域豁免形同虚设。
        fd_hit = {d for d in (reject_des | direct_des | ads) if in_domset(d, force_direct)}
        reject_des -= fd_hit
        direct_des |= fd_hit
        ads -= fd_hit              # 也从"新广告"里剔除，否则审查会把它当释放建议反复报
        print(f"force-direct override: {len(fd_hit)} host(s) -> DIRECT")
    force_reject = {d.strip() for d in cfg("FORCE_REJECT").split(",") if d.strip()}
    if force_reject:
        direct_des -= force_reject
        proxy_des -= force_reject
        reject_des |= force_reject
        print(f"force-reject override: {sorted(force_reject)}")
    # 手机实测路由证据（旧 sr_obs_direct）自 2026-09-30 起不再参与：那 3 个清单只吃 ADH。
    # 传空集 ⇒ guard_proxy 只按 ADH 观测 + 国内清单判断，行为可预期、不依赖手机是否上传了 db。
    proxy_des = guard_proxy(proxy_des, force_direct, set())
    print(f"lists: {len(rej_x)} reject / {len(dir_x)} direct / {len(prox_x)} proxy domain(s)")
    guard_shadow(direct_des, reject_des)

    drop_direct, drop_proxy, notes = set(), set(), []
    downgraded, released = set(), set()
    if cfg_bool("CONFLICT_CHECK", True):
        if (cfg("CONFLICT_POLICY") or "evidence").strip().lower() == "evidence":
            # 2026-09-26：实测裁决（拦截优先，但用 querylog/手机日志证据避免误伤国内直连）。
            max_hosts = int(cfg("CONFLICT_MAX_HOSTS") or 12)
            min_ev = int(cfg("CONFLICT_EVIDENCE_MIN") or 3)
            allow_dg = cfg_bool("CONFLICT_DOWNGRADE", True)
            _rel, drop_direct, downgraded, _keep, notes, cnt = resolve_conflicts_evidence(
                reject_des, direct_des, proxy_des, force_reject=force_reject,
                protected=manual_rej, max_hosts=max_hosts, min_evidence=min_ev,
                allow_downgrade=allow_dg)
            released = set(_rel)
            if _rel:
                reject_des -= _rel
            if downgraded:
                reject_des |= downgraded
            reject_des = prune_subsumed(reject_des)
            # 降级/放行涉及的直连子域：有实测证据的并进 ADH 白名单（否则它仍会被 ADH 拦）。
            direct_des |= {d for d in drop_direct if d in OBS}
            drop_proxy = set()
            # 「ADH 在拦、但实测同时又被正常解析」= 最危险的一类（phone 侧没规则就翻成走代理）
            active_mirror = {d for d in reject_des
                             if obs_get(d) and obs_get(d).get("allowed", 0) and
                             obs_get(d).get("blocked", 0) and d in int_obs}
            if active_mirror:
                print(f"conflict evidence: ⚠️ {len(active_mirror)} reject entr(ies) 实测里既被拦又被放行"
                      f"（明细见 .conflict_evidence.json）")
            print(f"conflict evidence: {cnt['conflicts']} conflict zone(s) -> "
                  f"保拦截 {cnt['keep'] + cnt['proxy_keep']} / 降级 {cnt['downgrade']} / 放行 {cnt['release']}")
        else:
            drops, notes = resolve_conflicts([("拦截", reject_des), ("直连", direct_des), ("代理", proxy_des)])
            drop_direct, drop_proxy = drops["直连"], drops["代理"]
            direct_des -= drop_direct
            proxy_des -= drop_proxy
            print(f"conflict check: {len(notes)} conflict(s) -> keep 拦截, drop lower")
        if force_direct:  # explicit owner intent always wins over the conflict heuristic
            direct_des |= force_direct
            proxy_des -= force_direct
            released -= force_direct
            downgraded -= force_direct
            # ⚠️ 2026-09-27 补：冲突裁决会把 force-direct 域**重新塞回 reject_des**
            # （decide_one 里 `参考黑名单命中` 就判 keep，例如 *.dsp.mp.microsoft.com），
            # 而上面几行只清了 direct/proxy，没清 reject ⇒ 结果同一域既进 direct-custom.list
            # 又进 reject-custom.list（实测 kv501…dsp.mp.microsoft.com 就是这样双写）。
            # 这里补一次剔除（后缀匹配，覆盖子域），并同步清掉 `ads` 残留
            # ——否则它会经 ads 通道再被写回仓库（第 2423 行附近）。
            _fd_left = {d for d in (reject_des | ads) if in_domset(d, force_direct)}
            if _fd_left:
                reject_des -= _fd_left
                direct_des |= _fd_left
                ads -= _fd_left
                print(f"force-direct override (post-conflict): {len(_fd_left)} host(s) -> DIRECT")
            # owner 放行意图同样要在这里再兜一次（裁决会把条目重新塞回 reject —— 同一个坑踩过两次）
            if OWNER_ALLOW:
                _oa2 = {d for d in (reject_des | ads) if in_domset(d, OWNER_ALLOW)}
                if _oa2:
                    reject_des -= _oa2
                    direct_des |= _oa2
                    ads -= _oa2
                    print(f"owner-allow override (post-conflict): {len(_oa2)} host(s) -> DIRECT")
        for n in notes[:40]:
            print("  " + n)

    # 全量重判审计：现有拦截表 + 本轮新广告域，用同一份 decide_one() 全部过一遍。
    # 只读 —— 不改 ADH、不改仓库；报告落 reclassify-report.{md,json}。2026-09-26
    audit = ("--audit" in sys.argv) or cfg_bool("AUDIT_RECLASSIFY", False)
    if audit:
        a_findings, a_counts, _a_rel, _a_dg = audit_reclassify(
            reject_des, direct_des, proxy_des, new_ads=ads, force_reject=force_reject,
            protected=manual_rej,
            max_hosts=int(cfg("CONFLICT_MAX_HOSTS") or 12),
            min_evidence=int(cfg("CONFLICT_EVIDENCE_MIN") or 3),
            allow_downgrade=cfg_bool("CONFLICT_DOWNGRADE", True))
        a_json, a_md = write_audit_report(a_findings, a_counts, manual=frozenset(manual_rej))
        print(f"audit: 重判 {a_counts['total']} 条 -> 保拦截 {a_counts['keep']}"
              f"（其中 {a_counts['no_evidence']} 条无实测证据）"
              f" / 建议释放 {a_counts['release']} / 建议降级 {a_counts['downgrade']}")
        for x in a_findings:
            if x["verdict"] in ("release", "downgrade"):
                print(f"  audit {x['verdict']}: {x['domain']}（原 {x['old']}，"
                      f"实测放行 {x['allowed']} / 拦截 {x['blocked']}）")
        if a_md:
            print(f"audit report: {os.path.basename(a_md)} + {os.path.basename(a_json)}")

        # 审查的「变化检测」（2026-09-27 owner：担心误归类，要定期 review）。
        # 报告每轮都会生成，但**没人翻文件**就等于没有审查 —— 所以这里只做一件事：
        # 把「本轮新冒出来的可疑条目」跟上一轮对比，有新的才通知（沿用冲突通知的
        # state-file diff 模式，避免每天重复刷同一条）。历史累积落 review-state.json，
        # 于是「哪些是早就报过、一直没人处理」也能一眼看出来。
        rev_path = os.path.join(HERE, cfg("REVIEW_STATE") or ".review-state.json")
        susp = [x for x in a_findings if x["verdict"] in ("release", "downgrade")]
        cur_susp = {x["domain"]: {"verdict": x["verdict"], "reason": x.get("reason", ""),
                                  "allowed": x.get("allowed", 0), "blocked": x.get("blocked", 0),
                                  "old": x.get("old", ""), "becomes": list(x.get("becomes", ())),
                                  "ads_kept": list(x.get("ads_kept", ()))}
                    for x in susp}
        try:
            with open(rev_path, encoding="utf-8") as fh:
                rev = json.load(fh)
        except Exception:  # noqa: BLE001
            rev = {}
        known = rev.get("findings") or {}
        new_keys = [d for d in cur_susp if d not in known]
        gone_keys = [d for d in known if d not in cur_susp]
        pending = [d for d in cur_susp if d in known]      # 早报过、仍未处理
        stamp = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M")
        for d, v in cur_susp.items():
            if d not in known:
                v["first_seen"] = stamp
            else:
                v["first_seen"] = known[d].get("first_seen", stamp)
            v["last_seen"] = stamp
        payload = {
            "at": stamp,
            "counts": a_counts,
            "findings": cur_susp,
            "pending_since": {d: cur_susp[d]["first_seen"] for d in pending},
        }
        if not dry:
            try:
                with open(rev_path, "w", encoding="utf-8") as fh:
                    json.dump(payload, fh, ensure_ascii=False, indent=1)
            except OSError as e:
                print(f"review state write failed: {e}")
        print(f"review: {len(cur_susp)} 可疑 / 新增 {len(new_keys)} / 仍未处理 {len(pending)}"
              f" / 已消失 {len(gone_keys)}"
              f"（无实测证据按原判保留 {a_counts['no_evidence']} 条）")
        if new_keys and not dry:
            lines = [f"⚠️ 拦截表审查：{len(new_keys)} 条新可疑（{stamp}）", ""]
            for d in new_keys[:15]:
                v = cur_susp[d]
                lines.append(f"· {v['verdict']} {d}（原 {v['old']}，"
                             f"实测放行 {v['allowed']} / 拦截 {v['blocked']}）")
            if pending:
                lines += ["", f"另有 {len(pending)} 条早报过、仍未处理："]
                lines += [f"· {d}（首见 {cur_susp[d]['first_seen']}）" for d in pending[:10]]
            if len(new_keys) > 15:
                lines.append(f"… 其余见 reclassify-report.md")
            lines += ["", "处理入口：改 adh-rules 仓库的 adh-custom.txt，"
                          "或把域名加进脚本 FORCE_DIRECT（放行）。"]
            if cfg("TELEGRAM_BOT_TOKEN") and cfg("TELEGRAM_CHAT_ID"):
                try:
                    print("review telegram:",
                          tg_send(cfg("TELEGRAM_BOT_TOKEN"), cfg("TELEGRAM_CHAT_ID"),
                                  "\n".join(lines), cfg("TELEGRAM_PROXY")))
                except Exception as e:  # noqa: BLE001 - 通知失败不影响主流程
                    print(f"review telegram failed: {e}")

    # 证据明细落盘（域名原文只进文件，不进对话/日志）2026-09-26
    ev_path = dump_evidence(released, downgraded,
                            {"released": len(released), "downgraded": len(downgraded),
                             "policy": "evidence"})
    if ev_path:
        print(f"conflict evidence dump: {os.path.basename(ev_path)} "
              f"({len(released)} released / {len(downgraded)} downgraded)")

    if "--check" in sys.argv or "--audit" in sys.argv:
        return

    # 放行项合规复核：CN 清单覆盖 + 直连可达（只告警，不改变裁决）2026-09-26
    if released and cfg_bool("CONFLICT_VERIFY", True):
        resolvers = [r.strip() for r in cfg("PROBE_RESOLVERS").split(",") if r.strip()]
        cn = load_cn_domains()
        for d, in_cn, ok, detail in conflict_verify(released, cn, 20,
                                                    float(cfg("PROBE_TIMEOUT") or 4), resolvers):
            if in_cn:
                tag = "CN 清单覆盖（国内正常访问应无碍）"
            elif ok is False:
                tag = f"⚠️ 干净解析器解析失败（{detail}）——确认误伤请回退 CONFLICT_POLICY=legacy"
            elif ok:
                tag = "直连可解析"
            else:
                tag = f"未实测（{detail}）"
            print(f"conflict verify: {d} -> {tag}")

    # Pre-bind live test: new DIRECT/PROXY candidates must resolve on a clean resolver before
    # binding. The reject bucket comes from blocklist/AD_RE classification (basically correct),
    # so per owner it is NOT live-tested - it is just written to ADH custom rules + repo.
    if cfg_bool("PROBE_ENABLE", True):
        resolvers = [r.strip() for r in cfg("PROBE_RESOLVERS").split(",") if r.strip()]
        pto = float(cfg("PROBE_TIMEOUT") or 4)
        for label, des, have in (("直连", direct_des, dir_x),
                                 ("代理", proxy_des, prox_x)):
            newdoms = sorted((des - have) - force_direct)  # FORCE_DIRECT = explicit allow, never auto-dropped
            if not newdoms:
                continue
            bad = []
            for dom in newdoms:
                ok, detail = probe_domain(dom, resolvers, pto)
                if ok is False:
                    bad.append(dom)
                    print(f"probe skip [{label}] {dom} -> {detail}")
            if bad:
                des -= set(bad)
                print(f"probe: dropped {len(bad)} unresolved {label} domain(s)")

    # Route analysis: for new direct/proxy candidates, use the proxy as a control to decide
    # whether the domain is really direct or needs the proxy (ads are never routed - just reject).
    if cfg_bool("ROUTE_PROBE", True) and cfg("ROUTE_PROXY"):
        proxy, rto = cfg("ROUTE_PROXY"), float(cfg("ROUTE_TIMEOUT") or 5)
        for d in sorted(((direct_des - dir_x) | (proxy_des - prox_x)) - force_direct):
            guess = "direct" if d in direct_des else "proxy"
            d_ok = curl_reach(d, "", rto)
            p_ok = curl_reach(d, proxy, rto)
            if d_ok is None and p_ok is None:
                continue
            if d_ok and not p_ok:
                route = "direct"
            elif p_ok and not d_ok:
                route = "proxy"
            else:
                route = guess  # both (prefer guess) or neither (keep guess)
            if route != guess:
                (proxy_des.discard(d), direct_des.add(d)) if route == "direct" \
                    else (direct_des.discard(d), proxy_des.add(d))
                print(f"route probe: {d} {guess} -> {route} (direct={d_ok} proxy={p_ok})")

    # （红果专表 hongguo-ad.list 已于 2026-09-30 取消：内容并入 reject-custom.list）

    # ── RAW 区保护（2026-09-27 补：发现 mon11 的 DROP 被我上一轮删错而失效）──
    # `adh-custom.txt` 的 RAW 区里，**单域规则**（如 `DOMAIN,xxx,REJECT-DROP`）会与自动区
    # **必然重复**：`||xxx^` 也被自动区收录 ⇒ CI 从全文生成时会产出两条，
    # 而自动区那条（普通 REJECT）在顺序上先命中 ⇒ **RAW 的 DROP 被降级成 REJECT**。
    # 这正是红果重试风暴的触发条件。
    # 修法：凡在 RAW 区有规则的域，**不再写入仓库的 reject 自动区**（RAW 区就是它的权威定义）。
    # 注意：只影响仓库写入；`reject_des` 不动，所以 ADH 侧该拦的还拦（保护其他客户端）。
    raw_domains = set()
    try:
        _auth_h = {"Authorization": f"token {tok}", "Accept": "application/vnd.github+json"}
        _api = f"https://api.github.com/repos/{owner}/{name}/contents/{cfg('REPO_PATH')}"
        _st, _tx = http("GET", _api + (f"?ref={br}" if br else ""), _auth_h)
        if _st == 200:
            _ls = base64.b64decode(json.loads(_tx)["content"]).decode().splitlines()
            _b = next((i for i, l in enumerate(_ls) if l.strip() == "! RAW-BEGIN"), None)
            _e = next((i for i, l in enumerate(_ls) if l.strip() == "! RAW-END"), None)
            if _b is not None and _e is not None and _b < _e:
                for _line in _ls[_b + 1:_e]:
                    _s = _line.strip()
                    if not _s or _s.startswith("!"):
                        continue
                    _p = _s.split(",")
                    if len(_p) >= 2 and _p[0] in ("DOMAIN", "DOMAIN-SUFFIX"):
                        raw_domains.add(_p[1].strip().lower())
                print(f"raw-block: {len(raw_domains)} domain rule(s) — 从 reject 自动区排除"
                      f"（RAW 区是权威定义，避免自动区的 REJECT 把 DROP 降级）")
    except Exception as e:  # noqa: BLE001 - 读失败就不排除，宁可重复也别丢规则
        print(f"raw-block: 读取失败({e})，跳过排除")
    added, removed = [], []
    if cfg_bool("ADH_WRITE", True):
        mwild = repo_manual_wildcards(owner, name, tok, br)
        # CLIENT_DROP_ONLY：客户端 DROP 已覆盖，**不要**再在 ADH 加 DNS 拦截
        # （否则 SDK 同时收到 DNS 失败 + TCP 丢包两个信号，更易激进重试）。见 cfg 注释。
        client_drop = {d.strip() for d in cfg("CLIENT_DROP_ONLY").split(",") if d.strip()}
        # hongguo 专表的域**照旧在 ADH 拦**（owner 2026-09-30 的选择）：它们已不再经
        # reject_des（那条路现在只吃 ADH），所以在 ADH 这一侧单独并进来 ——
        # 只喂 ADH，不写那 3 个 custom.list。扣 client_drop 是因为那批是「客户端丢包已覆盖、
        # ADH 要主动放行」的域，优先级更高。
        adh_reject = sorted({d for d in reject_des if d not in client_drop} - client_drop)
        if client_drop:
            print(f"client-drop-only: {len(client_drop)} domain(s) kept off ADH "
                  f"(client-side REJECT-DROP handles them)")
        adh_sync_rules(cfg("ADH_URL"), cfg("ADH_USER"), cfg("ADH_PASS"),
                       sorted({f"||{d}^" for d in adh_reject} | mwild),
                       [f"||{d}^" for d in sorted(force_direct)], dry_run=dry,
                       converge="||")
        # 白名单：**只写 `$important` 那一种**，不再先写普通 `@@`。
        # 原因（2026-09-27 实测）：普通 `@@` 压不住订阅大表，真正生效的是 `$important`；
        # 而下面的"第二步"又会补 `$important` ⇒ 先写普通再补重要的双写会留下每个域两条
        # 例外（实测一次同步就产生 106 条冗余，把 user_rules 从 597 顶到 705）。
        # 这里跳过 will_be_important 的域；`converge="@@||"` 顺带清掉历史遗留的普通 `@@`
        # —— 那些域已经在 `$important` 集合里，删掉不影响判定。
        will_be_important = set(direct_des) | client_drop
        imp_lines = [f"@@||{d}^$important" for d in sorted(will_be_important)]
        # add_lines 里**同时带上 `$important` 那批**：`converge="@@||"` 的语义是
        # 「删掉所有不在 add_lines 里的 @@ 规则」，若不带它们就会被整批删除、
        # 再由第二步补回——白名单要经历一次"全删→重补"，中途失败就是裸奔。
        # 带上之后：只清掉普通 `@@` 冗余（历史 106 条），`$important` 全程在位。
        adh_sync_rules(cfg("ADH_URL"), cfg("ADH_USER"), cfg("ADH_PASS"),
                       ([f"@@||{d}^" for d in sorted(direct_des - will_be_important)]
                        + imp_lines),
                       [f"@@||{d}^" for d in sorted(drop_direct | force_reject)], dry_run=dry,
                       converge="@@||")
        # 第二步：**读回时**给"我们想放行的域"补 `$important`。
        # 为什么必须带 $important：订阅大表里有更宽的通配拦截（如 `||mon*-misc-lf.fqnovel.com^`），
        # 普通 `@@` 压不过它 —— 2026-09-27 实测：给 whoami.akamai.net 加普通 `@@` 后
        # check_host **仍是 FilteredBlackList**，改带 `$important` 才翻成 NotFilteredWhiteList。
        # 覆盖范围：direct_des（我们自己的直连清单）+ client_drop（客户端 DROP 那批）。
        #   不扩展的后果：上面那个 `@@||` 收敛调用只写普通 `@@`，等于**整批白名单形同虚设**。
        # ADH 会把 `$important` 原样存下来（实测），所以去重要同时认裸文本与带 `$important` 两种。
        # 覆盖范围必须是**所有"想让它解析成功"的域**，而不只是 direct_des：
        #   direct_des  —— 直连清单
        #   client_drop —— 客户端 DROP 那批（19 条，ADH 不该拦它们的 DNS）
        #   OWNER_ALLOW —— owner 放行意图（含被判"走代理"的那批！）
        # ⚠️ 2026-09-27 补：owner 放行意图里有 18 条被 route probe 判为「直连不通、走代理」，
        # 于是进了 proxy_des、拿不到这里的 `$important` ⇒ 订阅大表一拦，**DNS 解析不了、
        # 连代理都连不上**（实测 firebaselogging.googleapis.com / alb.reddit.com /
        # ct.pinterest.com / telemetry.proton.me 仍是 FilteredBlackList）。
        # 「走代理」也是"要能正常访问"，所以白名单必须覆盖它们。
        allow_targets = sorted(set(direct_des) | set(client_drop) | set(OWNER_ALLOW))
        if allow_targets and not dry:
            auth = base64.b64encode(f"{cfg('ADH_USER')}:{cfg('ADH_PASS')}".encode()).decode()
            hh = {"Authorization": f"Basic {auth}"}
            st2, tx2 = http("GET", f"{cfg('ADH_URL').rstrip('/')}/control/filtering/status", hh)
            if st2 == 200:
                cur = json.loads(tx2).get("user_rules") or []
                # ⚠️ 去重必须按**「是否已有带 $important 的版本」**判断，不能按裸文本：
                # 上面的 `@@||` 收敛会先写入普通 `@@||d^`，若按裸文本去重就会被认为"已存在"，
                # 永远升不到 $important ⇒ 白名单继续被大表压住（实测 whoami 就是普通 @@ 压不住）。
                # ADH 会把 `$important` 原样存储（实测），所以这个判断是幂等的。
                has_imp = {r.split("$")[0] for r in cur
                           if r.startswith("@@||") and "$important" in r}
                want_ex = [f"@@||{d}^" for d in allow_targets
                           if f"@@||{d}^" not in has_imp]
                if want_ex:
                    guard_drop("ADH important-allow", len(cur), len(want_ex))
                    st3, tx3 = http("POST", f"{cfg('ADH_URL').rstrip('/')}/control/filtering/set_rules",
                                    hh, {"rules": cur + [f"{r}$important" for r in want_ex]})
                    if st3 == 200:
                        print(f"ADH important-allow: +{len(want_ex)} domain(s) "
                              f"(overrides wildcard blocklist hits)")
                    else:
                        print(f"ADH important-allow failed: HTTP {st3} {tx3[:160]}")
    if not cfg("REPO_TOKEN"):
        sys.exit("REPO_TOKEN missing (needs `repo` scope)")
    # 语义去重（2026-09-27 第三方审计指出）：`prune_subsumed` 原先**只作用于 reject**，
    # direct/proxy 没做 ⇒ 父域已在同一清单时，子域条目是纯冗余
    # （实测代理清单 44 条、直连清单 7 条，如 gstatic.com 覆盖的 32 条 dnsotls 探针）。
    # 放在**这里**（最后写入前）而不是更早：guard_shadow / guard_proxy / 冲突裁决都依赖
    # 具体的域粒度，过早塌缩会改变它们的判断。此处的塌缩是无损的（DOMAIN-SUFFIX 本就覆盖子域）。
    direct_out = prune_subsumed(direct_des, label="direct")
    proxy_out = prune_subsumed(proxy_des, label="proxy")
    # 跨清单遮蔽：direct 被 proxy 的父域盖住、reject 被 proxy 的父域盖住 ⇒ 都是死规则
    direct_out = prune_shadowed(direct_out, proxy_out, label="direct")
    reject_out = prune_shadowed(reject_des - raw_domains, proxy_out, label="reject")
    reject_out = prune_subsumed(reject_out, label="reject")
    # 收尾再塌缩一次：跨清单遮蔽过滤后可能剩出"子域在、父域也在"的组合
    # （实测 is.snssdk.com.bytedns1.com / lf3-static.bytednsdoc.com 漏过一轮），
    # 这一步保证写入形态稳定，与过滤顺序无关。
    direct_out = prune_subsumed(direct_out, label="direct(收尾)")
    if raw_domains:
        _skipped = sorted(d for d in reject_des if d in raw_domains)
        if _skipped:
            print(f"reject auto-section: 排除 {len(_skipped)} 条 RAW 区已定义的域")
    # ⚠️ 2026-09-30：本模式（cron / ADH-only）**只写 adh-custom.txt**，不再写三个 custom.list
    #   —— 那三个改由 `--sr-analyze` 从手机 db 生成。reject_out/direct_out/proxy_out 仍算出来
    #   供 ADH 侧的放行/拦截判定与日志使用。
    plans = [(cfg("REPO_PATH"), reject_out, "||{d}^", "!")]
    per_path = {}
    for path, desired, fmt, cmt in plans:
        a, r = repo_sync_set(owner, name, path, tok, desired, fmt, cmt, br, dry)
        per_path[path] = (len(a), len(r))
        added += a
        removed += r
    if not dry:
        try:
            repo_update_rule_deltas(owner, name, tok, br, per_path)
        except Exception as e:  # noqa: BLE001 - 统计标记失败不影响同步主流程
            print(f"README deltas: skipped ({e})")

    if not dry and cfg("TELEGRAM_BOT_TOKEN") and cfg("TELEGRAM_CHAT_ID"):
        def short(xs):
            return ", ".join(xs[:25]) + (" …" if len(xs) > 25 else "")
        new_conf = notes
        if notes:
            state = os.path.join(HERE, ".adh_conflicts.json")
            prev = []
            if os.path.exists(state):
                try:
                    with open(state, encoding="utf-8") as fh:
                        prev = json.load(fh)
                except Exception:  # noqa: BLE001
                    prev = []
            new_conf = [n for n in notes if n not in prev]
            try:
                with open(state, "w", encoding="utf-8") as fh:
                    json.dump(notes, fh)
            except Exception:  # noqa: BLE001
                pass
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M")
        lines = [f"ADH→GitHub 同步 {stamp}",
                 f"命中 {len(ads)} ad / {len(directs)} direct / {len(proxies)} proxy"]
        if added:
            lines.append("新增 %d：%s" % (len(added), short(added)))
        if removed:
            lines.append("删减 %d：%s（保拦截）" % (len(removed), short(removed)))
        if not added and not removed:
            lines.append("无新增/删减")
        if new_conf:
            lines.append("⚠ 新冲突 %d：%s" % (len(new_conf), "；".join(new_conf[:4])))
        if released or downgraded:
            changed = sorted(released | downgraded)
            lines.append("冲突裁决：放行 %d / 降级 %d 条：%s%s" % (
                len(released), len(downgraded), short(changed) if changed else "",
                "（明细 .conflict_evidence.json）"))
        if sr_stale:
            lines.append("⚠ 手机仍拦截已放行域 %d：%s" % (
                len(sr_stale), ", ".join(f"{h}x{c}" for c, h in sr_stale[:5])))
        print("telegram:", tg_send(cfg("TELEGRAM_BOT_TOKEN"), cfg("TELEGRAM_CHAT_ID"),
                                   "\n".join(lines), cfg("TELEGRAM_PROXY")))

    if not dry:
        mark_sync_done()
        print("[..] 本轮完成，已记录时间（日更闸门下次以此计时）", flush=True)


if __name__ == "__main__":
    main()

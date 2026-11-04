# DSH Sudo 访问模式

[![npm](https://img.shields.io/npm/v/dsh-sudo-mode)](https://www.npmjs.com/package/dsh-sudo-mode)
[![license](https://img.shields.io/npm/l/dsh-sudo-mode)](./LICENSE)

> 给 [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) 增加一个「Sudo 访问」权限档位：模型执行 root 命令前，由你在系统密码框中手动输入密码。


给当前 DSH 增加第四个权限档位 **Sudo 访问**。它不是让模型直接拿到 root，而是在模型调用 `sudo_exec` 工具时：

1. 模型必须先用 `purpose` 说明这条命令的作用；
2. DSH 弹出系统密码框，显示这条命令的作用和完整命令；
3. 用户核对命令后，手动输入 root 密码；
4. 密码只通过 `SUDO_ASKPASS` 管道交给 `sudo`，不进入对话、模型上下文或日志；
5. 密码框进程在启动前通过 `PR_SET_DUMPABLE=0` 关闭了同用户进程的 `/proc` / ptrace 读取面；
6. `sudo` 执行命令，工具返回 stdout / stderr / 退出码；
7. 每次执行前用 `sudo -k` 清除旧凭据，所以每次都要重新输入密码。

## 远程/无图形会话快速失败

- 二次确认框默认等待 **120 秒**；无人点击会自动关闭并返回超时错误。可用 `DSH_SUDO_CONFIRM_TIMEOUT`（秒）覆盖，设为 `0` 表示永不超时。
- 弹窗前会用 `/usr/bin/xdpyinfo` 探活当前显示，并扫描本机 X socket 和当前用户拥有的 `/tmp/xauth_*`。DSH 启动后切换桌面环境也不会继续使用失效的 `DISPLAY` / `XAUTHORITY`。
- 找不到可用图形会话时，**不会 spawn zenity**，而是 2～3 秒内直接返回：`已拒绝：这台机器当前没有可用的图形会话（试过 :0 / :1），无法弹出授权窗口。提权确认必须在电脑本机的图形桌面上完成，远程或纯命令行环境无法提权。`
- 这不会让远程会话获得提权能力；只是让“没人能在本机点确认”的情况快速失败，而不是静默等待 10 分钟。

## 安装

已发布为 npm 包。推荐在 DSH 插件管理器里直接填包名，它会从 npm 安装并加入当前 profile：

```text
plugin_manager install_bundle dsh-sudo-mode
```

也可以从 GitHub 仓库安装：

```text
plugin_manager install_bundle github:Float-dream1/dsh-sudo-mode
```

本地开发时可以把仓库目录交给本地安装：

```text
plugin_manager install_bundle /path/to/dsh-sudo-mode
```

安装后重启 DSH，在输入框下方的权限选择器里选择 **Sudo 访问**。

## 使用

选择 **Sudo 访问** 后，让模型执行需要 root 的命令。模型会调用 `sudo_exec`，密码框会弹出并显示命令作用与完整命令。

### 只读命令不需要 root 密码

`ls`、`tree`、`find`、`stat`、`cat`、`head`、`tail`、`du`、`df`、`file`、`readlink`、`git status/log/diff`、`docker ps`、`virsh list` 等只读命令**不提权**：只弹一个确认框，点确认后以当前用户执行，不会出现密码框。

- 只读命令仍然先经过黑名单、SSH、局域网、虚拟机/容器和密码爆破检查；`docker ps`、`virsh list` 仍会弹红色确认，只是不要求密码；
- 只读列表按命令名判断，自定义脚本、`bash -c` 或未列出的命令仍可能走提权/密码流程；
- 目标只有 root 可读时，非提权执行会返回权限错误，这是预期行为，不要尝试绕过文件权限。

## 高危命令二次确认

需要 root 的命令，密码框之前会先弹出一个独立的确认框，默认按钮是「取消」。只有点「继续执行」才会进入密码框；点「取消」不会执行。只读命令没有密码框，只保留这层确认。

确认框分两档：

- **红色：黑名单命中**。系统写死的高危命令（见下）直接触发，不需要模型打分，也不会被模型评分或提示词覆盖；
- **黄色：模型评分超阈值**。没有命中黑名单时，模型给出 `danger_score`（0-100）：单条命令超过 80、整段脚本超过 70 时触发黄色确认。

覆盖范围包括：

- `rm`、`mv`、`chmod`、`chown`、`kill` / `pkill` / `killall`；
- `reboot`、`shutdown`、`poweroff`、`halt`；
- `mkfs` / `mke2fs` / `wipefs` / `fdisk` / `parted` / `dd`；
- `efibootmgr`、`grub-install`、`grub-mkconfig`、`update-grub`、`bootctl`、`refind-install`，以及涉及 `/boot/efi`、`/boot/loader`、`/etc/fstab` 等引导/挂载路径的命令；
- `find -delete`、`find -exec rm`、fork bomb 等模式；
- `virsh`、`docker`、`lxc` / `lxd`：管理、停止、销毁或重配虚拟机/容器；
- `unlink`、`shred`、`truncate` 等删除/覆写文件的命令。

`systemctl` 的启动、停止、重启等普通服务操作不触发二次确认；但 `systemctl reboot` 和 `systemctl poweroff` 会触发，因为它们会直接重启或关闭系统。所有 systemctl 操作仍受 sudo 密码框和命令展示约束。

黑名单会先做归一化和模糊识别：`r\m`、`r''m`、`r$IFS m`、`/bin/rm`、`xargs rm`、`bash -c "rm ..."`、`busybox rm`、`base64 -d ... | sh` 等常见写法都会归一到同一类命令，不依赖模型评分。它不可能覆盖所有 shell 混淆；遇到可疑写法请直接拒绝。

## SSH、局域网、虚拟机与密码安全

### SSH / 局域网审核

- 任何 `ssh`、`scp`、`sftp`、`mosh`、`autossh`、`sshpass`，以及通过 SSH 的 `rsync` / `git@...` / `ssh://...`，都会被视为需要用户审核的操作。
- 访问私网地址（`10.*`、`192.168.*`、`172.16-31.*`、IPv6 ULA/link-local、`.local`）或使用 `nmap`、`nc`/`netcat`、`telnet`、`arp-scan`、`fping`、`smbclient`、`rdesktop`、`vncviewer`、对私网地址的 `ping`/`curl`/`wget`，同样需要用户审核。
- 局域网判断会解析 IPv4/IPv6 字面量、CIDR（如 `10.0.0.0/8`）和通配符（如 `192.168.*.*`、`10.*.*.*`、`172.16.*.*`）；解析出私网地址后，**任何**针对该地址的操作都进入第一处理队列，不再看 `danger_score`。
- 调用 `ipaddress` 解析网段时，模型必须先说明用途；该命令同样进入第一处理队列审核。`ipaddress` 只是辅助判断，不改变“私网地址一律审核”的规则。
- **SSH 失败自动阻断**：同一会话 60 秒内连续 3 次 SSH 连接/认证失败，后续 SSH 会被自动阻断 5 分钟；适用于 `bash`、`terminal_send` 和 `sudo_exec`。这是硬阻断，不需要密码框，也不经过模型评分。终端里直接输入的非 sudo `ssh` 不在该统计内。
- 对模型的 `bash` 和 `terminal_send` 调用，pre-execute 钩子会返回 `ask`，由 DSH 弹出审批；对 `sudo_exec`，则走红色二次确认 + 密码框。

### 虚拟机 / 容器

`virsh`、`docker`、`lxc`、`lxd` 一律按高危处理。特别是以下操作会额外标注“修改虚拟机/容器配置或用户”：

- `virsh edit`、`define`、`undefine`、`destroy`、`shutdown`、`reboot`、`reset`、`attach-*` / `detach-*`、`setmem`、`setmaxmem`、`setvcpus`、`qemu-agent-command`、`guest-exec`；
- `lxc config ...`，或在容器里执行 `useradd` / `usermod` / `passwd` / `userdel`；
- `docker run --privileged`、`--pid=host`、`--network=host`、挂载 `/:/host`，或在容器里修改用户/密码。

不要为了“清理环境”停止正在工作的虚拟机或容器；必须先说明影响并让用户确认。

### 禁止爆破 / 猜测 root 密码

这是硬性拒绝，不是二次确认：

- 禁止使用 `hydra`、`john`、`hashcat`、`medusa`、`patator`、`ncrack`、`crowbar`、`brutespray`、`crackmapexec` / `nxc`、`chntpw`；
- 禁止用 `sshpass`、`expect` 循环、`echo password | su`、`for ...; do su ...; done` 等方式尝试密码；
- 禁止读取 `/etc/shadow` / `/etc/gshadow` 后用 `john` / `hashcat` 破解；
- 无论宿主机、虚拟机、容器、SSH、`su`、`sudo` 还是弱口令，都不得尝试。没有密码就停止并询问用户，不要猜。

判定顺序是固定的：**第一队列（SSH、局域网、`ipaddress`、虚拟机/容器、密码爆破、毁灭性黑名单）→ 模型评分**。第一队列命中时直接警告/拒绝，不会继续执行评分逻辑；因此模型给出的 `danger_score` 再低也不能覆盖这些规则。SSH 失败自动阻断也在第一队列之前检查。

### 模型评分与脚本

- `sudo_exec` 增加 `danger_score`（0-100 整数）和 `kind`（`command` / `script`）参数。
- 单条命令阈值 80，整段脚本阈值 70；分数必须严格大于阈值才弹黄色确认。
- 用户给的是脚本时，模型应对整个脚本评分，并先检查脚本中是否含黑名单命令；黑名单仍优先。
- 包管理器（pacman / apt / dnf / zypper 等）的普通 `install`、`update` 基础操作按低风险处理；但用包管理器执行任意脚本、删除或修改系统配置时仍要如实评分。
- 模型评分是**提示性**的，不是安全边界：模型可能低估危险，所以黑名单和密码框仍然必须保留。

### 暂不实现：批量自动化预授权

“先统计 root 任务数量、提前让用户输入一次密码、后续命令复用”的方案**没有合并**。原因是一个能提前缓存 root 凭据的模型，等于在后续所有命令执行前就拥有了 root 权限，安全边界不成立。当前仍是每条 root 命令单独弹密码框、单独用 `sudo -k` 清除凭据。

## 终端里的 sudo

Sudo 访问模式下，DSH 终端里的 `sudo <命令>` 也可以直接使用。终端仍运行在原来的 `workspace-write` 沙箱里，但 `sudo` 包装器会把命令通过 Unix socket 交给 host broker。只读命令（如 `sudo ls`）只弹确认框、不提权；写操作/提权操作才弹密码框，显示完整命令，用户输入 root 密码后执行，输出回传终端。

限制：

- 只支持非交互命令，例如 `sudo apt update`、`sudo systemctl restart nginx`；
- 只读命令（`sudo ls` 等）只弹确认框，不提权，以当前用户执行；目标只有 root 可读时返回权限错误；
- 不支持 `sudo vim`、`sudo -i`、需要 TTY 的交互式程序；
- 只拦截直接输入的 `sudo <命令>`，不拦截脚本里写死的 `/usr/bin/sudo`；
- broker 每次执行前都会重新检查当前权限模式必须是 **Sudo 访问**，否则拒绝；
- 终端只做黑名单和模糊识别（SSH、局域网、虚拟机/容器、引导/分区等红色二次确认；密码爆破直接拒绝），**没有模型危险度评分**；需要模型解释命令作用、并按评分触发黄色确认时，让助手调用 `sudo_exec`。
- 终端里直接输入的非 sudo 命令（包括直接 `ssh`、`ping 192.168.x.x`、`docker ...`）不经过本插件；需要审核时交给聊天里的 `bash` / `sudo_exec`。

终端 sudo 与 `sudo_exec` 是两条独立入口：终端命令不经过模型，因此没有 `purpose` 段落，确认框/密码框只显示终端命令本身；需要模型解释命令作用时，仍让助手调用 `sudo_exec`。只读命令在终端里同样只确认、不提权。

## 审计、截屏与确认限速

### 审计日志

每条 root 命令（成功、取消、超时、被拒、异常）都会追加一行 JSONL 到 `~/.config/dsh-desktop/harness/sudo-audit.jsonl`，文件权限 `0600`，只追加、不重写。字段包括时间、会话、cwd、命令、类别、评分、确认结果、退出码、耗时和客户端 PID。日志写入失败不会影响命令执行。

密码本身不会进入日志；但命令输出可能包含秘密，不要把 `/etc/shadow`、token 等打印到 stdout。

### 截屏 / 录屏

`import -window root`、`-screen`、`x:` 截图，`spectacle`、`grim`、`scrot`、`flameshot`、`maim`、`xwd`、`gnome-screenshot`，`ffmpeg -f x11grab`，以及 `xdotool getwindowfocus` / `getactivewindow` 都归入 `screen-capture` 黑名单，命中即红色确认。普通 `import a.png b.png` 和普通 `ffmpeg` 转码不会误伤。

### 确认限速

二次确认框有模块级限速：同一会话每分钟最多 1 次；连续 2 次取消/超时后冷却 5 分钟，冷却期内直接拒绝并写审计。只有黑名单/评分确认框受限速，普通的 sudo 密码框不受影响。

## Broker 连接来源校验

`broker.sock` 前面有一个 Python `peer-gate.py`：它用 Unix socket 的 `SO_PEERCRED` 读取连接进程的 UID/PID，要求 UID 与 DSH 相同、连接进程确实是 `sudo-client.py`，并沿 `/proc/<pid>/status` 的 PPid 向上检查最多 5 层，找到 DSH 进程才转发请求；不满足时直接断开，并写一条 `reason: "refused:peer"` 的审计记录。

gate 只通过自己的 stdin/stdout 与 host 插件通信，不再额外暴露内部 socket，因此沙箱里的进程即使拿到 `DSH_SESSION_ID`，也不能绕过来源检查直接连接 host broker。正常 DSH 终端里的 `sudo` 仍然可用；普通系统终端里的 `sudo` 不经过这个 broker，不受影响。

## 工作区边界

- 普通文件修改仍然使用 `write` / `edit` 工具，权限档位是 `workspace-write`，不是 `danger-full-access`。
- `workspace-write` 只允许写工作区根目录、`/tmp` 和系统临时目录；工作区外写入会被沙箱拒绝，模型必须带 `sandbox_permissions` 和 `justification` 请求升级，并由 DSH 弹出审批。
- `sudo_exec` 只用于系统级 root 命令，不应用来代替普通文件修改；如果 root 命令会改工作区外文件，密码框会显示完整命令，用户输入密码即表示对该命令授权。

## 安全边界

- 这是一个**任意 root 命令**能力。密码框会显示模型写的 `purpose`，但最终执行的是对话里展示的 `command`；请务必核对命令。高危命令的二次确认只是额外提醒，不是安全审计。
- 密码由 `zenity` 直接交给 `sudo`，插件不读取、不记录密码；密码不会出现在工具参数、工具结果、会话历史或长期记忆里。
- 但 root 命令自己的输出会被工具结果记录：不要让命令打印 `/etc/shadow`、token 等秘密；这和密码本身是两回事。
- 只应在明确需要系统级操作时切换到此模式；普通文件操作继续使用「工作区可写」。
- 需要系统已安装 `sudo` 和 `zenity`（当前机器二者都有）。

## License

MIT

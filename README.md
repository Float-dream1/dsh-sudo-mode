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

## 安装

已发布为 npm 包。安装后重启 DSH：

```bash
npm install dsh-sudo-mode
```

或在 DSH 插件管理器里直接填包名：

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

## 高危命令二次确认

对极高危命令，密码框之前会先弹出一个独立的确认框，默认按钮是「取消」。只有点「继续执行」才会进入密码框；点「取消」不会执行。

覆盖范围包括：

- `rm`、`mv`、`chmod`、`chown`、`kill` / `pkill` / `killall`；
- `reboot`、`shutdown`、`poweroff`、`halt`；
- `mkfs` / `mke2fs` / `wipefs` / `fdisk` / `parted` / `dd`；
- `efibootmgr`、`grub-install`、`grub-mkconfig`、`update-grub`、`bootctl`、`refind-install`，以及涉及 `/boot/efi`、`/boot/loader`、`/etc/fstab` 等引导/挂载路径的命令；
- `find -delete`、`find -exec rm`、fork bomb 等模式。

`systemctl` 的启动、停止、重启等普通服务操作不触发二次确认；但 `systemctl reboot` 和 `systemctl poweroff` 会触发，因为它们会直接重启或关闭系统。所有 systemctl 操作仍受 sudo 密码框和命令展示约束。

终端 broker 和 `sudo_exec` 共用同一套分类器。分类器只做“是否弹二次确认”的判断，不替代你对完整命令的核对。

## 终端里的 sudo

Sudo 访问模式下，DSH 终端里的 `sudo <命令>` 也可以直接使用。终端仍运行在原来的 `workspace-write` 沙箱里，但 `sudo` 包装器会把命令通过 Unix socket 交给 host broker；host 弹出密码框显示完整命令，用户输入 root 密码后执行，输出回传终端。

限制：

- 只支持非交互命令，例如 `sudo apt update`、`sudo systemctl restart nginx`；
- 不支持 `sudo vim`、`sudo -i`、需要 TTY 的交互式程序；
- 只拦截直接输入的 `sudo <命令>`，不拦截脚本里写死的 `/usr/bin/sudo`；
- broker 每次执行前都会重新检查当前权限模式必须是 **Sudo 访问**，否则拒绝。

终端 sudo 与 `sudo_exec` 是两条独立入口：终端命令不经过模型，因此没有 `purpose` 段落，密码框只显示终端命令本身；需要模型解释命令作用时，仍让助手调用 `sudo_exec`。

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

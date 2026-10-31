# DSH Sudo 访问模式

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

这是一个 DSH bundle，不是 npm 包。用 DSH 的插件管理器从仓库安装，然后重启客户端：

```text
plugin_manager install_bundle github:<owner>/dsh-sudo-mode
```

也可以把仓库目录交给本地安装：

```text
plugin_manager install_bundle /path/to/dsh-sudo-mode
```

安装后重启 DSH，在输入框下方的权限选择器里选择 **Sudo 访问**。

## 使用

选择 **Sudo 访问** 后，让模型执行需要 root 的命令。模型会调用 `sudo_exec`，密码框会弹出并显示命令作用与完整命令。

## 工作区边界

- 普通文件修改仍然使用 `write` / `edit` 工具，权限档位是 `workspace-write`，不是 `danger-full-access`。
- `workspace-write` 只允许写工作区根目录、`/tmp` 和系统临时目录；工作区外写入会被沙箱拒绝，模型必须带 `sandbox_permissions` 和 `justification` 请求升级，并由 DSH 弹出审批。
- `sudo_exec` 只用于系统级 root 命令，不应用来代替普通文件修改；如果 root 命令会改工作区外文件，密码框会显示完整命令，用户输入密码即表示对该命令授权。

## 安全边界

- 这是一个**任意 root 命令**能力。密码框会显示模型写的 `purpose`，但最终执行的是对话里展示的 `command`；请务必核对命令。
- 密码由 `zenity` 直接交给 `sudo`，插件不读取、不记录密码；密码不会出现在工具参数、工具结果、会话历史或长期记忆里。
- 但 root 命令自己的输出会被工具结果记录：不要让命令打印 `/etc/shadow`、token 等秘密；这和密码本身是两回事。
- 只应在明确需要系统级操作时切换到此模式；普通文件操作继续使用「工作区可写」。
- 需要系统已安装 `sudo` 和 `zenity`（当前机器二者都有）。

## License

MIT

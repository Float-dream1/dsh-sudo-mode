# Security

`dsh-sudo-mode` intentionally gives the model a way to run arbitrary commands as root after you type your password. Treat it as a high-risk capability.

- The password is typed into a system `zenity` dialog. It is passed to `sudo` through `SUDO_ASKPASS`; the plugin does not read it, log it, or put it in tool arguments/results.
- The root command's stdout/stderr is returned to the model and stored in the DSH session. Do not run commands that print secrets.
- The password dialog shows the full command and the model-written purpose. Review the command before typing the password.
- The plugin clears cached sudo credentials with `sudo -k` before and after each command.
- Normal file edits remain under DSH's `workspace-write` sandbox; writes outside the workspace require the normal DSH approval path.

Report security issues privately to the repository owner rather than opening a public issue with exploit details.

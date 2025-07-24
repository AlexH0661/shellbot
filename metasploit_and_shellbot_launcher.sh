#!/usr/bin/env bash
set -eux pipefail

# Create tmux session
tmux new -d -s "shellbot"

# Initialise MetaSploit framework
tmux send -t "shellbot:" "sudo msfdb init && sudo msfconsole -x 'load msgrpc Pass=Password1'" Enter
tmux splitw -t "shellbot:" -dh

# Initialise ShellBot
tmux send -t "shellbot:.1" ". ./.venv/bin/activate && shellbot" Enter
tmux attach -t "shellbot"

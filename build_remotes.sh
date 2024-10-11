#! env bash

BUILD_TYPE="debug"

for host in $(cat remotes.txt); do
  echo "Building on $host"
  ssh $host "rm -rf /tmp/portsentry"
  rsync -az -e ssh ../portsentry $host:/tmp/
  ssh $host "cd /tmp/portsentry && ./build.sh clean && ./build.sh $BUILD_TYPE"
  if [ $? -ne 0 ]; then
    echo "ERROR: Failed to build on $host"
    exit 1
  fi
  echo
done

if [ -n "$1" ]; then
  exit 0
fi

tmux new -s rat -d
tmux split-window -h
tmux split-window -v -t 0
tmux split-window -v -t 2

tmux select-pane -t 0
tmux send-keys 'ssh root@deb-portsentry rat.sh' C-m

tmux select-pane -t 1
tmux send-keys 'ssh root@netbsd /usr/sbin/rat.sh' C-m

tmux select-pane -t 2
tmux send-keys 'ssh root@freebsd rat.sh' C-m

tmux select-pane -t 3
tmux send-keys 'ssh root@openbsd rat.sh' C-m

tmux a


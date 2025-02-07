#! env bash

[ -z "$BUILD_TYPE" ] && BUILD_TYPE="debug"
if [ -n "$1" ]; then
  REMOTE_HOSTS="$1"
else
  REMOTE_HOSTS="deb-portsentry netbsd freebsd openbsd"
fi

# Build on all remote hosts in parallel
for host in $REMOTE_HOSTS; do
  ssh $host "rm -rf /tmp/portsentry"
  rsync -az -e ssh ../portsentry $host:/tmp/
  ssh $host "cd /tmp/portsentry && ./build.sh clean && ./build.sh $BUILD_TYPE"
done

# Run tests
tmux new -s rat -d
sleep 1
tmux split-window -h
sleep 1
tmux split-window -v -t 0
sleep 1
tmux split-window -v -t 2
sleep 1

tmux select-pane -t 0
sleep 1
tmux send-keys 'ssh root@deb-portsentry rat.sh' C-m
sleep 1

tmux select-pane -t 1
sleep 1
tmux send-keys 'ssh root@netbsd /usr/sbin/rat.sh' C-m
sleep 1

tmux select-pane -t 2
sleep 1
tmux send-keys 'ssh root@freebsd rat.sh' C-m
sleep 1

tmux select-pane -t 3
sleep 1
tmux send-keys 'ssh root@openbsd rat.sh' C-m
sleep 1

tmux a

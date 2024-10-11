#! env bash

BUILD_TYPE="debug"

# Build on all remote hosts in parallel
for host in $(cat remotes.txt); do
  ssh $host "rm -rf /tmp/portsentry"
  rsync -az -e ssh ../portsentry $host:/tmp/
  ssh $host "cd /tmp/portsentry && ./build.sh clean && ./build.sh $BUILD_TYPE" &
done

# Wait for all builds to finish
build_count=$(cat remotes.txt | wc -l)
success_count=0
while [ $success_count -lt $build_count ]; do
  sleep 1
  rm -r /tmp/build_status.txt
  echo "Waiting for builds to finish..."
  for host in $(cat remotes.txt); do
    echo "Checking $host"
    if ssh $host "file /tmp/portsentry/debug/portsentry" | grep -q "^/tmp/portsentry/debug/portsentry: ELF"; then
      echo "$host 1" >> /tmp/build_status.txt
    else
      echo "$host 0" >> /tmp/build_status.txt
    fi
  done

  success_count=0
  for host in $(cat remotes.txt); do
    if grep -q "$host 1" /tmp/build_status.txt; then
      success_count=$((success_count + 1))
    fi
  done

  echo "Success count: $success_count"
done

# Run tests
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

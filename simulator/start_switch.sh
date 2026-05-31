#!/bin/bash

PROGRAM=$1
if [ -z $1 ]; then
    echo "PROGRAM is missing";
    echo "Usage: ./start_switch.sh PROGRAM";
    exit 1
fi

ARCH=tofino

# Kill previous switch instace
tmux kill-session -t switch

# Sets up 128 virtual ethernet interfaces named veth0 up to veth127
sudo ${SDE_INSTALL}/bin/veth_setup.sh 128

# Creates new tmux session
tmux new-session -d -s switch
tmux split-window -t 0 -h

# Starts switch control plane (Barefoot Runtime)
tmux send-keys -t 0 "cd $SDE" C-m
tmux send-keys -t 0 "./run_switchd.sh --arch $ARCH -c $SDE_INSTALL/share/p4/targets/$ARCH/$PROGRAM/$PROGRAM.conf -p $PROGRAM" C-m

mkdir -p $SDE/logs

# Starts Tofino simulator
tmux send-keys -t 1 "cd $SDE" C-m
tmux send-keys -t 1 "./run_tofino_model.sh --arch $ARCH --log-dir $SDE/logs \
    -c $SDE_INSTALL/share/p4/targets/$ARCH/$PROGRAM/$PROGRAM.conf \
    -p $PROGRAM" C-m

sleep 3

# Runs a setup routine on control plane to setup the tables
$SDE/run_bfshell.sh -b $PROJECT_SRC/src/$PROGRAM/setup.py

tmux attach-session -t switch


#!/bin/bash
echo Starting demo session

byobu new-session \; \
  split-window -h \; \
  send-keys '/app/vershitifier -interface eth0 -command ping -drop 25' C-m \; \
  select-pane -L \; \
  send-keys 'sleep 2 && ping -c 20 google.com' C-m

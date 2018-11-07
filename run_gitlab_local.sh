#!/bin/bash -e

echo "Run a gitlab build step on the local machine"

gitlab-ci-multi-runner exec docker \
  --docker-volumes /sys/kernel/debug:/sys/kernel/debug \
  --docker-privileged \
  $@


#!/bin/sh
# Dispatches the container's single argument to the right anton binary.
set -e

case "$1" in
  api)
    exec anton_api
    ;;
  cli)
    shift
    exec anton "$@"
    ;;
  demo)
    shift
    exec demo_ransomware "$@"
    ;;
  *)
    echo "Usage: docker run <image> {api|cli <args...>|demo [path] [logpath]}" >&2
    exit 1
    ;;
esac

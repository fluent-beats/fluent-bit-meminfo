#!/bin/sh

set -e
cd $(dirname $0)/..

docker run --rm \
      -v /var/run/docker.sock:/var/run/docker.sock:ro \
      -v $(pwd)/code/build:/my_plugin \
      fluent/fluent-bit:1.8.4 /fluent-bit/bin/fluent-bit -e /my_plugin/flb-in_meminfo.so -i meminfo -o stdout

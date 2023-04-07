# Description

[Fluent Bit](https://fluentbit.io) input plugin that collects memory information from Linux hosts.

This plugin **will only work** on hosts running Linux, because it relies on `/proc/meminfo` file from [Procfs](https://en.wikipedia.org/wiki/Procfs).

# Requirements

- Docker
- Docker image `fluent-beats/fluent-bit-plugin-dev`

# Build
```bash
./build.sh
```

# Test
```bash
./test.sh
 ```

# Design

This plugin was desined to collect data from any mounted Linux `meminfo` proc file.

It can be used to collect host memory info, even if Fluent Bit is running inside a container, which is not achiavable using **native** Fluent Bit `mem` plugin.

> Potentially [LXCFS](https://linuxcontainers.org/lxcfs/) could bypass that without requiring a custom plugin
## Configurations

This input plugin can be configured using the following parameters:

 Key                    | Description                                   | Default
------------------------|-----------------------------------------------|------------------
 interval_sec           | Interval in seconds to collect data           | 1
 proc_path              | Path to look for meminfo file                 | /proc


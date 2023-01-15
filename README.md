# Description

[Fluent Bit](https://fluentbit.io) input plugin that collects memory info from Linux `meminfo device file`

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

This plugin was desined to collect memory from any mounted `meminfo` file.

It can be used to collect host memory info, even if Fluent Bit is running inside a cotainer, which is not achiavable using **native** Fluent Bit `mem` plugin.

## Configurations

This input plugin can be configured using the following parameters:

| Key  | Description | Default |
| ---- | ----------- | ------ |
| interval_sec | Interval in seconds to collect data  | 1 |
| proc_path | Path to look for meminfo file  | /proc |


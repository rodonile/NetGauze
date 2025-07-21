#!/bin/bash
set -e

# Run the collector and tee stdout/stderr to external log files if mounted
/usr/local/bin/netgauze-collector "$@" 2>&1 | tee /logs/netgauze-collector.log

#!/bin/bash
set -e

# Save JSON messages (stdout) to one file, logs (stderr) to another
/usr/local/bin/print-bmp > /logs/netgauze-messages.json 2> /logs/netgauze-collector.log

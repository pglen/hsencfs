#!/bin/bash
# This file is executed by the editor to cycle test
MYDIR=$(dirname $0)
xfce4-terminal -e "$MYDIR/cycle2.sh pause"

# EOF
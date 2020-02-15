#!/bin/bash
./umount.sh
rm -rf ~/.secrets
./hsencfs -v -f -l 4 -p 1234 ~/secrets ~/.secrets




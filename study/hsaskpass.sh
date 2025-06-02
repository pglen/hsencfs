#!/bin/bash

read -p "Enter pass for $1: " -s AA

echo -n $AA | base64

# EOF

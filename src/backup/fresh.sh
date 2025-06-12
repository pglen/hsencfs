#!/bin/bash
TTT=test_secrets

chmod u+rw ~/$TTT   >/dev/null 2>&1
chmod u+rw ~/.$TTT  >/dev/null 2>&1

rm -rf ~/$TTT       >/dev/null 2>&1
umount ~/$TTT       >/dev/null 2>&1

rm -rf ~/.$TTT      >/dev/null 2>&1
mkdir -m 700 ~/$TTT        >/dev/null 2>&1
mkdir -m 700 ~/.$TTT        >/dev/null 2>&1
chmod ug-w ~/$TTT  >/dev/null 2>&1
chmod ug-w ~/.$TTT  >/dev/null 2>&1

# EOF

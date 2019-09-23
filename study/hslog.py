#!/usr/bin/python
# -*- coding: UTF-8 -*-

import syslog, os, sys

if __name__ == '__main__':

    syslog.openlog("HSENCFS Tray")
    xstr = ""
    for aa in sys.argv[1:]:
        xstr += aa + " "
    syslog.syslog(xstr)




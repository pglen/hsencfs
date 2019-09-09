#!/usr/bin/python
# -*- coding: UTF-8 -*-

import syslog, os, sys, string

def respath(fname):
    #print os.environ['PATH']
    ppp = string.split(os.environ['PATH'], os.pathsep)
    for aa in ppp:
        ttt = aa + os.sep + fname
        print ttt
        if os.path.isfile(ttt):
            return ttt
    
if __name__ == '__main__':

    if len(sys.argv) == 2:
        pp = respath(sys.argv[1])
    else: 
        pp = respath("which")

    print "Found: '%s'" % pp





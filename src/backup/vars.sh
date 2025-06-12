#!/bin/bash

PASS=1234
DROOT=~/secrets

TESTFILE=aa5000.txt
TESTFILE2=aaa5000.txt
TESTFILE5=aaaaaa5000.txt

BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
# No Color
NC='\033[0m'

pgdiff()
{
    S1=`ls -l $2 |  awk {'print $5'}`
    S2=`ls -l $3 |  awk {'print $5'}`

    if [ "$S1" != "$S2" ] ; then
        echo -e $RED " File sizes differ " $NC
        return 1
    fi

    diff  $2 $3
    RET=$?

    if [ "$RET" != "0" ] ; then
        echo -e $RED " Files differ " $NC
        return 1
    fi
       echo Files \'`basename $2`\' and \'`basename $3`\' are identical
       return 0
}

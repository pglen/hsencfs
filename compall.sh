#!/bin/bash

# Compile project. Cycle through config/make/install.

aa=`pwd`; bb=`basename $aa`; err=0
#echo  $1 $bb
pushd `pwd` >/dev/null

if [ -z $1 ] ; then
    #echo "Assuming current dir: '$bb'"
    FF=$bb
 else
    FF=`basename $1`
    echo $FF
    cd $1 >/dev/null 2>&1
    
    if [ $? != 0 ] ; then
        echo Cannot change dir to $1
        popd >/dev/null
        exit
    fi
fi

CMAKEX=0

# Execute a command $1 with args $2; Return 1 if error

xmake()
{
    echo "cmake:" $FF
    $1 $2  >$1.out 2>$1.err
    err=$?
    if [ $err != 0 ] ; then
        echo "Error on $1" $FF
        tail $1.err
        return 1
    fi
    return 0
}

# ------------------------------------------------------------------------
# Cycle on make-config-autoconf

while [ 1 = 1 ] ;  do

    if [ -f Makefile ] ; then
        echo "make:" $FF
        make -k  >make.out 2>make.err
        err=$?
        if [ $err != 0 ] ; then
            echo "Error on make" $FF
            tail make.err
        fi
        echo "make install:" $FF
        sudo make install
        err=$?
        if [ $err != 0 ] ; then
            echo "Error on make install" $FF
        fi
        break
     fi
    
    # Configure if not conf-ed
     if [ -x configure ] ; then
        echo "configure:" $FF
        if [ -f confcom ] ; then
            cc=`cat confcom`
        else 
            cc=""
        fi
        ./configure $cc >config.out 2>config.err
        err=$?
        if [ $err != 0 ] ; then
            echo "Error on configure" $FF
            tail config.out
            break
        fi
        continue
     fi
     
     # Automake if needed
     if [ -x autoconf.sh ] ; then
        ./autoconf.sh >auto.out 2>auto.err
        err=$?
        if [ $err != 0 ] ; then
            echo "Error on autoconf" $FF
            tail auto.err
            break
        fi
     continue
     fi
     # Empty dir
     break
done
    
popd >/dev/null

exit $err

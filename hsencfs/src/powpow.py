# calc the range of   x pow (x ^ 2)
#

from math import *

xx = 3.45
dd = 0.0002

lastup = 0; lastdn = 0
for aa in range(0, 150):

    yy = pow(xx, sqrt(xx))
    #print(" %8f=%8f" % (xx, yy),end="     ")
    print(xx, yy, end="   ")

    if yy > 10:
        if xx == lastup:
            #print ("cy")
            dd /= 2
        lastup = xx
        xx -= dd
    else:
        xx += dd

    if yy == 10:
        print("Arrived")
        break
#                        README

How to generate these files.

 Example:

  dd if /dev/zero bs=1 count=4500 | tr \\0 a > aa4500.txt

 The batch file gendata will take care of this; execute it after clean
and before test.

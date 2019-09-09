# Do not do as I do, do as I say :-)
make -k distclean >/dev/null 2>&1
rm Makefile  >/dev/null 2>&1
echo "Executing automake ..."
automake
echo "Executing autoreconf ..."
autoreconf
echo "Executing configure ..."
./configure >/dev/null
echo "Executing make ..."
make








#!/usr/bin/env sh

LIBNAME="hooker"
CC="gcc"
LD="ld"
# fno-stack-protector -> `getProcessNameByPID': undefined reference to `__stack_chk_fail_local'
# Wno-format-zero-length -> for empty fields (C standard specifies that zero-length formats are allowed)
C_FLAGS="-Wall -fPIC -DPIC -fno-stack-protector -Wno-format-zero-length"
INSTALL_PATH="/usr/local/lib"

clean()
{
echo "Cleaning..."
rm -f *.o *.so *~ ./UI/*.tmp ./UI/*~ > /dev/null 2>&1
}

build()
{
echo "Building..."
$CC $C_FLAGS -c $LIBNAME.c
$LD -shared -o $LIBNAME.so $LIBNAME.o -ldl
}

testUID()
{
if [ "$(id -u)" != "$1" ]; then
	echo "Error: request UID $1 for this operation."
	exit 1
fi
}

install()
{
testUID "0"
if grep "$LIBNAME" "/etc/ld.so.preload" > /dev/null; then
	echo "Error: $LIBNAME appears to be installed already."
	echo "Please uninstall and reboot the computer before re-installing."
	exit 1
fi
echo > "/etc/ld.so.preload"
echo "Installing to "$INSTALL_PATH"/"$LIBNAME".so"
cp $LIBNAME".so" $INSTALL_PATH
chmod a+r $INSTALL_PATH"/"$LIBNAME".so"
echo $INSTALL_PATH"/"$LIBNAME".so" > "/etc/ld.so.preload"
echo "You must reboot your computer for changes to take effect."
}

uninstall()
{
testUID "0"
echo > "/etc/ld.so.preload"
ldconfig
echo $INSTALL_PATH"/"$LIBNAME".so will have to be removed manually next boot."
echo "You must reboot your computer for changes to take effect."
}

case "$1" in
  "clean")
		clean
		;;
  "build")
		build
		;;
  "install")
		install
		;;
  "uninstall")
		uninstall
		;;
  "help")	echo "Options: clean, build, install, uninstall."
		;;
  "")		clean
		build
		;;
esac

echo "Done."
exit 0

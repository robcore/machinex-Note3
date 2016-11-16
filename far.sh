#!/bin/bash
echo 'beginning driver conversions'
cd drivers
find . -type f \( -iname \*.h \
				-o -iname \*.c \) \
					| parallel sed -i '/SUSPEND_LEVEL/d' {} \;
echo 'halfway'
find . -type f \( -iname \*.h \
				-o -iname \*.c \) \
					| parallel sed -i '/suspend.level/d' {} \;
echo 'drivers done'
cd ../include
find . -type f \( -iname \*.h \
				-o -iname \*.c \) \
					| parallel sed -i '/SUSPEND_LEVEL/d' {} \;
echo 'halfway'
find . -type f \( -iname \*.h \
				-o -iname \*.c \) \
					| parallel sed -i '/suspend.level/d' {} \;
echo 'include done'
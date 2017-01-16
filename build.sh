#!/usr/bin/bash
#
# Quick build script for the Windows uTox updater

if [ ! -d build ]; then
    mkdir build
fi

i686-w64-mingw32-windres resource.rc -O coff -o build/resource.res

clang -s -Ofast -static -o build/utox-update.exe \
      -target i686-w64-mingw32 \
      -fno-exceptions \
      -isystem /usr/x86-64_w64_mingw32/include \
      -L lib/ \
      build/resource.res \
      main.c \
      utils.c \
      xz/*.c \
      -lcomctl32 -luuid -lole32 -lgdi32 -lws2_32 -lshlwapi -lsodium -mwindows

      # -isystem /opt/compiler/mingw-w64/i686-w64-mingw32/include \
      # -isystem /opt/compiler/mingw-w64/i686-w64-mingw32/include/c++/4.9.2 \
      # -isystem /opt/compiler/mingw-w64/i686-w64-mingw32/include/c++/4.9.2/backward \
      # -isystem /opt/compiler/mingw-w64/i686-w64-mingw32/include/c++/4.9.2/i686-w64-mingw32

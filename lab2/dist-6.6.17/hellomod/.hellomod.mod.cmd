savedcmd_/build/hellomod/hellomod.mod := printf '%s\n'   hellomod.o | awk '!x[$$0]++ { print("/build/hellomod/"$$0) }' > /build/hellomod/hellomod.mod

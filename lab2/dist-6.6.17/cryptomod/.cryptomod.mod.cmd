savedcmd_/build/cryptomod/cryptomod.mod := printf '%s\n'   cryptomod.o | awk '!x[$$0]++ { print("/build/cryptomod/"$$0) }' > /build/cryptomod/cryptomod.mod

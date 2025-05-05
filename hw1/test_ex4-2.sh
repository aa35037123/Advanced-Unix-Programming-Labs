#!/bin/bash

LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so cat /etc/hosts

#!/bin/bash

LD_PRELOAD=./libzpoline.so LIBZPHOOK=./logger.so touch main.c

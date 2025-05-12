#!/bin/bash

socat TCP-LISTEN:8888,reuseaddr,fork EXEC:"./serv_chal3 .",pty,raw,echo=0


#!/bin/sh

if NOT EXIST ./configure (
    autogen.sh
)

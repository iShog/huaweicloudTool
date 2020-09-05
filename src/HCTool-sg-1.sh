#!/bin/bash

if [ $# == 0 ];then
    echo "useage xxx.sh [cred file] [key] (ip addr)"
    echo "(ip addr) is optional."
elif [ $# == 2 ];then
    if [ -f "$1" ];then
        if [ 0"$EN_CRED_JSON_STR" = "0" ];then
            export EN_CRED_JSON_STR="$(cat $1)"
        else
            echo "cred env is exist."
        fi
        python ./HCTool-sg-1.py -k $2
    else
        echo "cred file is not exist!"
    fi
elif [ $# == 3 ];then
    if [ -f "$1" ];then
        if [ 0"$EN_CRED_JSON_STR" = "0" ];then
            export EN_CRED_JSON_STR="$(cat $1)"
        else
            echo "cred env is exist."
        fi
        python ./HCTool-sg-1.py -k $2 -i $3
    else
        echo "cred file is not exist!"
    fi
else
    echo "invaild parameters!"
    echo "useage xxx.sh [cred file] [key] (ip addr)\n"
    echo "(ip addr) is optional."
fi

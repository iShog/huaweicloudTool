#!/bin/bash

export EN_CRED_JSON_STR="$(cat $1)"
##echo $EN_CRED_JSON_STR

python ./HCTool-sg-1.py -k $2

#!/bin/sh

# FROM https://stackoverflow.com/a/32877921/1771845

cmp --silent $1 $2 && echo '### SUCCESS: Files Are Identical! ###' || echo '### WARNING: Files Are Different! ###'

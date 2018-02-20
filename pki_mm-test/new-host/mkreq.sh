#!/bin/bash

openssl genrsa 2048 > $1.key
openssl req -new -sha256 -key $1.key -out $1.csr

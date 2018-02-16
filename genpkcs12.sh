#!/bin/bash
HOST=$1
openssl pkcs12 -export -in <(PASSWORD_STORE_DIR=$HOME/.pass-team/ pass show "system/pki/safedc-external/${HOST}.pem") -inkey <(PASSWORD_STORE_DIR=$HOME/.pass-team/ pass show "system/pki/safedc-external/${HOST}.key") -out $1.p12 -name "CA signed"

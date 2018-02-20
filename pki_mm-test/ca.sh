#!/bin/bash

set -x

if [ ! -s ca.conf ]; then
	echo "ERROR: CA configuration file not found"
	exit 1
fi

if [ ! -s openssl.conf ]; then
	echo "ERROR: OpenSSL configuration file not found"
	exit 1
fi

. ./ca.conf

usage() {
	echo "USAGE: $0 bootstrap (root|sub)"
	echo "USAGE: $0 issue CSR (generic|subca|host|client) [hostname]"
	echo "USAGE: $0 revoke CERT"
	echo "USAGE: $0 crl"
	exit 1
}

ca_bootstrap_root() {
	rm -f $CA_CERT
	rm -fr $CA_ISSUED
	rm -f $CA_SERIAL
	rm -f $CA_DATABASE
	rm -f *.old

	if [ ! -n "$OPENSSL_ENGINE" ]; then
		if [ ! -f $CA_KEY ]; then
			touch $CA_KEY
			chmod go= $CA_KEY
			openssl genrsa 2048 > $CA_KEY
		fi
	fi

	$OPENSSL_BIN req -verbose -config $OPENSSL_CONF \
		-new -x509 -sha256 \
		-set_serial 0 -days $CA_DAYS \
		$OPENSSL_ENGINE \
		-key $CA_KEY \
		-out $CA_CERT

	$OPENSSL_BIN x509 -text -noout -in $CA_CERT

	mkdir $CA_ISSUED
	echo 01 > $CA_SERIAL
	touch $CA_DATABASE
}

ca_bootstrap_sub() {
	rm -f $CA_CERT
	rm -fr $CA_ISSUED
	rm -f $CA_SERIAL
	rm -f $CA_DATABASE
	rm -f *.old

	if [ ! -n "$OPENSSL_ENGINE" ]; then
		if [ ! -f $CA_KEY ]; then
			touch $CA_KEY
			chmod go= $CA_KEY
			openssl genrsa 2048 > $CA_KEY
		fi
	fi

	CA_CSR=$CA_PREFIX.csr

	$OPENSSL_BIN req -config $OPENSSL_CONF \
		-new -sha256 \
		$OPENSSL_ENGINE \
		-key $CA_KEY \
		-out $CA_CSR

	$OPENSSL_BIN req -text -noout -in $CA_CSR

	mkdir $CA_ISSUED
	echo 01 > $CA_SERIAL
	touch $CA_DATABASE
}

ca_revoke_certificate() {
	INPUT_CRT=$1

	if [ ! -s $INPUT_CRT ]; then
		echo "ERROR: Certificate file not found, revocation failed"
		exit 1
	fi

	[ -n "$CMD_BEFORE" ] && $CMD_BEFORE

	$OPENSSL_BIN ca -config $OPENSSL_CONF $OPENSSL_ENGINE \
		-name $CA_SECTION -revoke $INPUT_CRT

	[ -n "$CMD_AFTER" ] && $CMD_AFTER
}

ca_generate_crl() {
	[ -n "$CMD_BEFORE" ] && $CMD_BEFORE

	$OPENSSL_BIN ca -config $OPENSSL_CONF $OPENSSL_ENGINE \
		-name $CA_SECTION \
		-gencrl -crldays $CA_CRL_DAYS -out $CA_CRL.pem

	[ -n "$CMD_AFTER" ] && $CMD_AFTER

	$OPENSSL_BIN crl -in $CA_CRL.pem -out $CA_CRL -outform der
	$OPENSSL_BIN crl -in $CA_CRL -inform der -noout -text
	rm -f $CA_CRL.pem
}

ca_issue_certificate() {
	INPUT_CSR=$1
	TYPE=$2
	HOSTNAME=$3

	OUTPUT_CRT=`basename $1 .csr`.crt

	OPENSSL_CONF_TMP=openssl.conf.tmp

	cp $OPENSSL_CONF $OPENSSL_CONF_TMP

	cat <<CONFIG >>$OPENSSL_CONF_TMP

[ ext ]
subjectKeyIdentifier=	hash
authorityKeyIdentifier=	keyid:always,issuer:always
crlDistributionPoints=	$CA_CRL_DP
CONFIG

	case $TYPE in
	generic)
		cat <<CONFIG >>$OPENSSL_CONF_TMP
basicConstraints=	critical,CA:FALSE
keyUsage=		critical,keyEncipherment,digitalSignature
CONFIG
		;;
	subca)
		cat <<CONFIG >>$OPENSSL_CONF_TMP
basicConstraints=	critical,CA:TRUE,pathlen:0
keyUsage=		critical,keyCertSign,digitalSignature,cRLSign
CONFIG
		;;
	host)	
		cat <<CONFIG >>$OPENSSL_CONF_TMP
basicConstraints=	critical,CA:FALSE
keyUsage=		critical,keyEncipherment,digitalSignature
extendedKeyUsage=	serverAuth,clientAuth
subjectAltName=		DNS:$HOSTNAME
CONFIG
		;;
	client)
		cat <<CONFIG >>$OPENSSL_CONF_TMP
basicConstraints=	critical,CA:FALSE
keyUsage=               critical,keyEncipherment,digitalSignature,keyAgreement
extendedKeyUsage=       clientAuth,emailProtection
subjectAltName=         email:copy
CONFIG
		;;
	*)
		usage
	esac

	echo "Signing a $TYPE certificate"

	[ -n "$CMD_BEFORE" ] && $CMD_BEFORE

	$OPENSSL_BIN ca -config $OPENSSL_CONF_TMP $OPENSSL_ENGINE \
		-name $CA_SECTION \
		-extensions ext -in $INPUT_CSR -out $OUTPUT_CRT

	[ -n "$CMD_AFTER" ] && $CMD_AFTER

	rm $OPENSSL_CONF_TMP
	
	if [ -s $OUTPUT_CRT ]; then
		git add $CA_PREFIX-issued/*.pem $CA_PREFIX.db $CA_PREFIX.serial
		echo "Do not forget to commit changes using 'git commit' and 'git push'"
	else
		echo "ERROR: Failed to issue certificate"
		exit 1
	fi
}

case $1 in
	bootstrap)
		case $2 in
			root)
				ca_bootstrap_root
				;;
			sub)
				ca_bootstrap_sub
				;;
			*)
				usage
		esac
		;;
	issue)
		ca_issue_certificate $2 $3 $4
		;;
	revoke)
		ca_revoke_certificate $2 $3 $4
		;;
	crl)
		ca_generate_crl
		;;
	*)
		usage
esac

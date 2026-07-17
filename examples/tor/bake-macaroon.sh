#!/usr/bin/env bash
set -euo pipefail

LND_DIR=/lnd
NETWORK=signet
ADMIN_MACAROON="$LND_DIR/data/chain/bitcoin/$NETWORK/admin.macaroon"
MACAROON_TMP=/credentials/.lnproxy.macaroon.tmp
CERT_TMP=/credentials/.tls.cert.tmp

cleanup() {
	rm -f "$MACAROON_TMP" "$CERT_TMP"
}
trap cleanup EXIT

lncli_cmd() {
	lncli --network="$NETWORK" --rpcserver=lnd:10009 \
		--tlscertpath="$LND_DIR/tls.cert" \
		--macaroonpath="$ADMIN_MACAROON" "$@"
}

for _ in $(seq 1 120); do
	if lncli_cmd getinfo >/dev/null 2>&1; then
		break
	fi
	sleep 2
done
lncli_cmd getinfo >/dev/null

rm -f "$MACAROON_TMP" "$CERT_TMP"
lncli_cmd bakemacaroon --save_to "$MACAROON_TMP" \
	uri:/lnrpc.Lightning/DecodePayReq \
	uri:/lnrpc.Lightning/LookupInvoice \
	uri:/lnrpc.Lightning/SignMessage \
	uri:/lnrpc.Lightning/GetInfo \
	uri:/invoicesrpc.Invoices/AddHoldInvoice \
	uri:/invoicesrpc.Invoices/SubscribeSingleInvoice \
	uri:/invoicesrpc.Invoices/CancelInvoice \
	uri:/invoicesrpc.Invoices/SettleInvoice \
	uri:/routerrpc.Router/SendPaymentV2 \
	uri:/routerrpc.Router/EstimateRouteFee \
	uri:/chainrpc.ChainKit/GetBestBlock

cp "$LND_DIR/tls.cert" "$CERT_TMP"
chmod 0440 "$MACAROON_TMP" "$CERT_TMP"
chown 1000:1000 "$MACAROON_TMP" "$CERT_TMP"
mv -f "$MACAROON_TMP" /credentials/lnproxy.macaroon
mv -f "$CERT_TMP" /credentials/tls.cert
chmod 0750 /credentials

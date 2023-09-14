# lnproxy-relay

## Running a relay

This program uses the lnd REST API to handle lightning things so you'll need an lnd.conf with,
for example:

	restlisten=localhost:8080

To configure the relay follow the usage instructions:

	usage: ./lnproxy [flags] lnproxy.macaroon
	lnproxy.macaroon
		Path to lnproxy macaroon. Generate it with:
			lncli bakemacaroon --save_to lnproxy.macaroon
				uri:/lnrpc.Lightning/DecodePayReq \
				uri:/lnrpc.Lightning/LookupInvoice \
				uri:/invoicesrpc.Invoices/AddHoldInvoice \
				uri:/invoicesrpc.Invoices/SubscribeSingleInvoice \
				uri:/invoicesrpc.Invoices/CancelInvoice \
				uri:/invoicesrpc.Invoices/SettleInvoice \
				uri:/routerrpc.Router/SendPaymentV2 \
				uri:/routerrpc.Router/EstimateRouteFee \
				uri:/chainrpc.ChainKit/GetBestBlock
	-lnd string
		host for lnd's REST api (default "https://127.0.0.1:8080")
	-lnd-cert string
		lnd's self-signed cert (set to empty string for no-rest-tls=true) (default ".lnd/tls.cert")
	-port string
		http port over which to expose api (default "4747")

Run the binary:

	$ ./lnproxy-http-relay-openbsd-amd64-00000000 lnproxy.macaroon
	1970/01/01 00:00:00 HTTP server listening on: localhost:4747

and on a separate terminal, test with:

	curl -s --header "Content-Type: application/json" \
		--request POST \
		--data '{"invoice":"<bolt11 invoice>"}' \
		http://localhost:4747/spec

## Expose your relay over tor

If you know how to run a server you can put your relay behind a reverse proxy and and expose it to the internet.
A simpler route is to use tor.

Install tor, then edit `/etc/tor/torrc` to add:

	HiddenServiceDir /var/tor/lnproxy/
	HiddenServicePort 80 127.0.0.1:4747

and run:

	cat /var/tor/lnproxy.org/hostname

to get the onion url and try:

	torify curl -s --header "Content-Type: application/json" \
		--request POST \
		--data '{"invoice":"<bolt11 invoice>"}' \
		http://<your .onion url>/spec

Once you're happy with it, make a PR to add your url to: https://github.com/lnproxy/lnproxy-webui2/blob/main/assets/relays.json

## Operating your relay

Sending `SIGINT` (with Ctrl-C) to the running relay will cause it to shutdown the http server
and stop accepting new invoices, it will wait for the last open invoice to expire, before fully shutting itself down.
A second `SIGINT` will cancel all open invoices and cause the relay to shutdown immediately.

When upgrading to the latest binaries, simply send one `SIGINT`
and allow the program to shut itself down gracefully.
It is safe to start the new binary immediately since the http server
from the first binary will already have shut itself down.
This way your relay can continue to proxy payments even while upgrading.

### Recovering from errors

If an unexpected error occurs when a payment to an original invoice is settled
but the accepted proxy invoice payment is not yet settled,
funds will be at risk.
This lnproxy relay tries, wherever possible, to completely shutdown in this situation:
if a single circuit does not complete as expected, the executable will
shutdown and stop accepting new invoices or sending out new payments to settle
active invoices.
This ensures that at most `MaxAmountMsat` Bitcoin will be in a "limbo" state
at any one time (the default value is 1,000,000 satoshis).

Even if such an error occurs, and an lnproxy relay circuit ends up in a limbo state,
it will almost certainly be possible to recover from the error manually.
If you notice that your relay excutable has terminated
(it's easy to set up an alert from this on *NIX systems by just adding
another command to follow the lnproxy relay command in whatever script invokes it),
you will have `CltvDeltaAlpha` blocks (by default about one day) to
manually settle the proxy payment.
To do this, simply use `lncli listinvoices` to find any invoices in the `ACCEPTED` state,
and then lookup their associated payments using the payment hash (`r_hash`).
If the payment was completed you should have a preimage you can use to
settle the `ACCEPTED` invoice.

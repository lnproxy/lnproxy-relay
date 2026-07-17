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

## Expose the HTTP relay with a static Tor service

If you know how to run a server you can put the HTTP relay behind a reverse
proxy and expose it to the Internet. A simpler route for the standalone HTTP
binary is a static Tor onion service. Nostr providers should normally use the
integrated ephemeral service documented below instead.

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

HTTP clients can configure this endpoint explicitly. Nostr providers can also
advertise direct endpoints so clients discover them without an HTTP directory.

## Configuring your fees and limits

By default the relay charges a small base fee plus a proportional fee and
accepts invoices between 10 sats and 1,000,000 sats. Operators can set their own
fees and amount limits without recompiling, via flags or environment variables
(the flag wins when set, otherwise the environment variable, otherwise the
built-in default):

| flag | env var | meaning |
|---|---|---|
| `-min-msat` | `LNPROXY_MIN_MSAT` | minimum invoice amount (msat) |
| `-max-msat` | `LNPROXY_MAX_MSAT` | maximum invoice amount (msat) |
| `-base-fee-msat` | `LNPROXY_BASE_FEE_MSAT` | relay base fee (msat) |
| `-fee-ppm` | `LNPROXY_FEE_PPM` | relay proportional fee (ppm) |
| `-max-expiry` | `LNPROXY_MAX_EXPIRY` | maximum proxy invoice expiry (seconds, default 3600) |
| `-max-active-circuits` | `LNPROXY_MAX_ACTIVE_CIRCUITS` | maximum concurrent hold-invoice circuits (default 128) |

For example, to cap proxied amounts at 500,000 sats and charge 0.2%:

	./lnproxy-http-relay ... -max-msat 500000000 -fee-ppm 2000

## Advertising over nostr (decentralized discovery)

The `nostr-relay` binary advertises your relay on
[nostr](https://github.com/nostr-protocol/nips) so clients can discover it
without you having to get your URL added to a list, and serves wrap requests
over encrypted nostr messages. See the protocol in
[the spec](https://github.com/lnproxy/spec/blob/main/nostr.md).

It uses the same lnd setup as the HTTP relay, plus two extra macaroon
permissions for node attestation (omit them if you pass `-disable-ln-signing`):

	lncli bakemacaroon --save_to lnproxy.macaroon \
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

Run it:

	./nostr-relay -nostr-relays wss://nos.lol,wss://relay.damus.io lnproxy.macaroon

Or build the container image directly from this repository (no sibling `lnc`
checkout or parent-directory build context is required):

	docker build -t lnproxy-nostr-relay .

Useful flags (all fee/limit flags above also apply):

| flag | meaning |
|---|---|
| `-nostr-relays` (env `LNPROXY_NOSTR_RELAYS`) | comma-separated relay URLs (working defaults built in) |
| `-advertised-nostr-relays` (env `LNPROXY_ADVERTISED_NOSTR_RELAYS`) | optional client-reachable aliases when provider relay URLs are internal |
| `-nostr-key` | path to the persistent identity key (created if absent) |
| `-network` (env `LNPROXY_NETWORK`) | `mainnet`/`testnet`/`signet`/`regtest`; validated at startup, offers are tagged with it so clients on other networks never see them |
| `-features` | advertised feature flags, e.g. `pay_bolt11,wrap_bolt11` |
| `-min-request-pow` | NIP-13 difficulty required from clients (DoS protection) |
| `-announce-pow` | NIP-13 difficulty mined into each offer |
| `-disable-ln-signing` | do not attest the nostr identity with your node key |
| `-identity-pow` | anonymous identity proof of work bits (used with `-disable-ln-signing`) |
| `-urls` (env `LNPROXY_URLS`) | direct HTTP/onion `/spec` endpoints to advertise, in preference order |
| `-http-listen` (env `LNPROXY_HTTP_LISTEN`) | optional direct HTTP listen address, for example `127.0.0.1:4747` |
| `-http-max-concurrent` (env `LNPROXY_HTTP_MAX_CONCURRENT`) | concurrent direct handlers (default 8) |
| `-http-request-interval` (env `LNPROXY_HTTP_REQUEST_INTERVAL`) | global direct request interval (default 5s) |
| `-http-request-burst` (env `LNPROXY_HTTP_REQUEST_BURST`) | direct request burst capacity (default 3) |
| `-tor` (env `LNPROXY_TOR`) | enable Tor using the default local addresses; off by default |
| `-tor-proxy` (env `LNPROXY_TOR_PROXY`) | proxy Nostr WebSockets through Tor when enabled (default true) |
| `-tor-hidden-service` (env `LNPROXY_TOR_HIDDEN_SERVICE`) | create and advertise an ephemeral v3 onion endpoint (default true) |
| `-tor-socks` (env `LNPROXY_TOR_SOCKS`) | Tor SOCKS5 address (default `127.0.0.1:9050`) |
| `-tor-socks-username` (env `LNPROXY_TOR_SOCKS_USERNAME`) | optional SOCKS5 username for Tor circuit isolation |
| `-tor-socks-password` (env `LNPROXY_TOR_SOCKS_PASSWORD`) | optional SOCKS5 password for Tor circuit isolation |
| `-tor-control` (env `LNPROXY_TOR_CONTROL`) | Tor control address (default `127.0.0.1:9051`) |
| `-tor-control-password` (env `LNPROXY_TOR_CONTROL_PASSWORD`) | optional control password (default uses SAFECOOKIE) |
| `-tor-control-cookie` (env `LNPROXY_TOR_CONTROL_COOKIE`) | local SAFECOOKIE path when it differs from the path reported by Tor |
| `-tor-target` (env `LNPROXY_TOR_TARGET`) | hidden-service target (defaults to the direct listener on loopback) |
| `-tor-virtual-port` (env `LNPROXY_TOR_VIRTUAL_PORT`) | onion-service virtual port (default 80) |

By default the relay attests its nostr identity with its lightning node key, so
clients can verify that the advertisement belongs to a real node. A standard
proxy invoice already reveals the relay's node id to the client, so this leaks
nothing new. If you only ever issue blinded or BOLT12 proxy invoices and want to
keep your node id private, run with `-disable-ln-signing` and optionally
`-identity-pow` instead.

To let discovered clients contact the provider directly before using nostr as a
fallback, run both transports in the same process:

	./nostr-relay \
		-nostr-relays wss://nos.lol,wss://relay.damus.io \
		-http-listen 127.0.0.1:4747 \
		-urls https://lnproxy.example.com/spec,http://<your-v3-address>.onion/spec \
		lnproxy.macaroon

When both `-http-listen` and `-urls` are set, the offer automatically advertises
`request_id_v1`. Direct and nostr retries then share one idempotency cache, so a
lost HTTP response cannot open a second hold invoice. Put clearnet listeners
behind an HTTPS reverse proxy. The direct HTTP endpoint does not have the Nostr
request proof-of-work gate, so the integrated listener defaults to eight active
handlers and a global burst of three requests followed by one request every five
seconds. Public deployments should additionally enforce per-client connection
and request limits at their reverse proxy. Onion services can forward to the
loopback listener directly. Both transports also share the default limit of 128
active hold-invoice circuits.

Note on privacy: as a relay operator you see the complete invoices you are asked
to pay, including their destination, amount and description/memo. A direct
clearnet client also exposes its IP unless it uses a proxy. Nostr transport hides
that IP from the provider only when the Nostr relay does not disclose or share
connection metadata. A direct onion endpoint over Tor avoids both third-party
relay metadata and disclosure of the client IP to the provider.

### Recommended anonymous deployment with Tor

Anonymous providers should enable both Tor functions: Nostr WebSocket
connections use SOCKS5, and an ephemeral v3 onion service forwards port 80 to
the integrated direct endpoint. The generated `http://...onion/spec` URL is
automatically added to the offer. Its key is discarded and its lifetime is
bound to the authenticated control connection, so the onion address changes
when the relay restarts. The persistent Nostr identity does not change.

With a system Tor installation, enable a local SOCKS listener and authenticated
control port in `torrc`:

	SocksPort 127.0.0.1:9050 IsolateSOCKSAuth
	DataDirectory /var/lib/tor
	ControlPort 127.0.0.1:9051
	CookieAuthentication 1
	CookieAuthFile /var/run/tor/control_auth_cookie
	CookieAuthFileGroupReadable 1

Then run:

	./nostr-relay \
		-tor \
		-http-listen 127.0.0.1:4747 \
		lnproxy.macaroon

This uses the relay's default Tor addresses (`127.0.0.1:9050` and
`127.0.0.1:9051`); Tor's control port is disabled until configured. The relay
process must be able to read the SAFECOOKIE at the path returned by Tor's
`PROTOCOLINFO`, or at the local override path documented below. On packaged
installations this normally means adding its user to the dedicated Tor control
group. Restrict that group's membership and protect the cookie as a secret
because it grants control over the Tor process.

`PROTOCOLINFO` reports an absolute `COOKIEFILE` path in Tor's filesystem
namespace. If Tor and the relay run in different containers, either mount the
shared cookie at that same absolute path in both containers or set
`LNPROXY_TOR_CONTROL_COOKIE` to the relay container's local path. The override
changes only where the relay reads the cookie; SAFECOOKIE still verifies that
its contents match the cookie held by Tor. Do not set the override together
with `LNPROXY_TOR_CONTROL_PASSWORD`. For example, if the cookie volume is
mounted at `/run/tor-control` in the relay container:

	LNPROXY_TOR_CONTROL_COOKIE=/run/tor-control/control_auth_cookie

If `DataDirectory` is omitted from a host-managed `torrc`, this image runs as a
user whose home is `/data`, so Tor defaults to `/data/.tor` and reports
`/data/.tor/control_auth_cookie`. Mounting `/var/run/tor` alone does not change
that default. Set both `DataDirectory` and `CookieAuthFile` explicitly as shown
above.

Tor control password authentication is also supported. Generate the hash with
`tor --hash-password`, configure the result as `HashedControlPassword`, and
pass the original password through `LNPROXY_TOR_CONTROL_PASSWORD`. Environment
variables are preferable to command-line secrets because process arguments may
be visible to other local users. Tor control authentication has no username.

Optional `LNPROXY_TOR_SOCKS_USERNAME` and `LNPROXY_TOR_SOCKS_PASSWORD` values
must be set together. Tor accepts these SOCKS5 values and, with
`IsolateSOCKSAuth`, uses them to isolate this application's circuits; they are
not an access-control replacement for firewalling the SOCKS port. Set
`LNPROXY_TOR_PROXY=false` or `LNPROXY_TOR_HIDDEN_SERVICE=false` only when one
half of the integration is intentionally not needed.

For a containerized signet example:

	cd examples/tor
	docker compose up -d --build
	docker compose logs -f tor lnproxy

At startup, the relay logs whether Tor is enabled, whether Nostr uses SOCKS,
the control authentication method, the generated onion endpoint, and the exact
direct URL list placed in the offer. For example:

	tor: enabled; Nostr proxy=true ephemeral hidden service=true
	tor: Nostr relay connections use SOCKS5 at tor:9050 (SOCKS credentials configured=true, direct fallback disabled)
	tor: control=tor:9051 authentication=SAFECOOKIE local-cookie=/run/tor-control/control_auth_cookie; ephemeral v3 port 80 targets lnproxy:4747
	tor: onion endpoint advertised in offer: http://<v3-address>.onion/spec
	offer: advertised direct URLs: [http://<v3-address>.onion/spec]

SOCKS credentials enable stream isolation only when Tor's listener also uses
`IsolateSOCKSAuth`, as the Compose example does. Values in `LNPROXY_URLS` are
published in the Nostr offer and logged at startup. Do not put credentials,
access tokens, or other secrets in those URLs.

Current binaries emit either `tor: enabled` or `tor: disabled` after validating
the relay and Tor configuration. If neither appears, inspect preceding logs:
the process exited before Tor setup or the image predates Tor support. If it
reports `tor: disabled` unexpectedly, check the rendered environment with
`docker compose config`, then recreate the container. Rebuild a local image
with `docker compose build --no-cache lnproxy` when its source changed.

The example uses the version-pinned
[`m0wer/docker-tor`](https://github.com/m0wer/docker-tor) image and named
volumes for node data, relay credentials, the Nostr identity, Tor state, and
the control cookie. The lnproxy container has no Internet-connected interface.
It reaches LND on one internal network and Tor on another; only the Tor
container bridges the Tor-internal network to its outbound network. Tor, LND,
and bitcoind use separate outbound networks to prevent lateral access between
them. Read-only root filesystems for Tor and lnproxy, minimized capabilities,
`no-new-privileges`, bounded process counts, safe Tor logging, and a separately
shared read-only control-cookie volume reduce the effect of a relay compromise.
LND and bitcoind require a small capability set for their image entrypoints and
outbound access for Bitcoin and Lightning peers, but they do not route traffic
for lnproxy.

The Tor image's unprivileged user has `/data` as its home, and Tor otherwise
defaults its data directory to `/data/.tor`. The example explicitly sets
`DataDirectory /var/lib/tor`, so `/data` can remain read-only and Tor state is
kept in a named volume. Operators who manage `torrc` on the host must likewise
set `DataDirectory /var/lib/tor`; they can mount `/etc/tor` read-only and mount
host-owned data and runtime directories at `/var/lib/tor` and `/var/run/tor`.
Those directories must be owned by UID/GID `1000:1000` and should not be shared
with any container except the relay's read-only access to the control-cookie
runtime directory.

Do not attach the lnproxy service to any of the Compose egress networks. The code
uses a SOCKS-only transport with remote hostname resolution and no direct
fallback, while the internal Docker network provides enforcement if a future
code path accidentally attempts direct egress. The onion endpoint uses HTTP
intentionally: onion services provide end-to-end authentication and encryption
inside Tor.

Providers that already advertise a clearnet domain or IP do not gain operator
anonymity by proxying their public Nostr connections. They should normally
leave `-tor` disabled and connect to Nostr relays directly for lower latency,
while putting any advertised clearnet `/spec` endpoint behind HTTPS and a
hardened reverse proxy.

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
settle the `ACCEPTED` invoice.  If the payment failed, no funds are at risk,
you can cancel the hodl invoice.

## Development

Unit tests use a mocked lightning node, so they need no external services:

	go test ./...

The nostr transport also has an integration test that runs against a real
nostr relay in Docker, exercising the publish/subscribe, NIP-44 encryption and
NIP-13 proof-of-work paths over the wire:

	docker compose -f docker-compose.test.yml up -d
	LNPROXY_TEST_NOSTR_RELAY=ws://127.0.0.1:7777 go test -tags=integration ./nostr/...
	docker compose -f docker-compose.test.yml down -v

The integration test is skipped when `LNPROXY_TEST_NOSTR_RELAY` is unset.

# lnproxy

## What

lnproxy takes a bolt 11 invoice and generates a “wrapped” invoice that can be settled *if and only if* the original invoice is settled. The “wrapped” invoice has the same payment hash, expiry, and description, as the invoice it wraps but adds a small routing fee to the amount. The “wrapped” invoice can be used anywhere the original invoice would be used to trustlessly obfuscate the destination of a payment.

## Why

Lightning network privacy will improve. In the meantime, users of custodial lightning wallets, like Wallet of Satoshi or the Bitcoin Beach Wallet, reveal the destination of every lightning payment they make to their custodian. With lnproxy, these users can instead generate and pay wrapped invoices to obfuscate the destination of the payment from their custodian.

Users that operate public lightning network nodes, reveal the identity of their node with every lightning invoice they generate. With lnproxy, users can instead generate and give out wrapped invoices to obfuscate the identity of their lightning network nodes from their transaction counterparties.

## How

lnproxy wrapped invoices are hodl invoices. When an lnproxy node accepts an htlc for the wrapped invoice, it immediately pays the original invoice and uses the revealed preimage to settle the wrapped invoice. This ensures that you don't need to trust lnproxy with your payments.

For additional privacy, using a vpn or the lnproxy node's tor hidden service prevents the lnproxy node from discovering your IP address. Onion routing on the lightning network protects the privacy for the source of payments to wrapped invoices.

Anyone running a lightning network nodecan run an lnproxy server. **Users should verify that wrapped invoices are, in fact, conditional by decoding them to ensure that the payment hash matches that of the original invoice.**

## Dev

This little binary uses the lnd REST API to handle lightning things so running it requires lnd.

## Run an lnproxy server

The more nodes run an api server, the more censorship resistant the project will be.
It's easy, just
- build the lnproxy binary (prebuilt releases coming soon), 
- generate a macaroon with minimal permissions for lnproxy to use:
  ```
    lncli bakemacaroon --save_to lnproxy.macaroon \
      uri:/lnrpc.Lightning/DecodePayReq \
      uri:/lnrpc.Lightning/LookupInvoice \
      uri:/invoicesrpc.Invoices/AddHoldInvoice \
      uri:/invoicesrpc.Invoices/SubscribeSingleInvoice \
      uri:/invoicesrpc.Invoices/CancelInvoice \
      uri:/invoicesrpc.Invoices/SettleInvoice \
      uri:/routerrpc.Router/SendPaymentV2
  ```
- run: `./lnproxy lnproxy.macaroon`
- on a separate terminal:
  ```
    curl https://localhost:4747/{your invoice}
  ```

Once you've played with it a bit and set up tls or a tor hidden service for your api server, send me a message so I can add you to the gateway at https://lnproxy.org.

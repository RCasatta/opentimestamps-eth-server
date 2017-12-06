# Copyright (C) 2016 The OpenTimestamps developers
#
# This file is part of the OpenTimestamps Server.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of the OpenTimestamps Server including this file, may be copied,
# modified, propagated, or distributed except according to the terms contained
# in the LICENSE file.

import binascii
import http.server
import socketserver
from web3 import Web3, KeepAliveRPCProvider
from opentimestamps.core.serialize import StreamSerializationContext


class RPCRequestHandler(http.server.BaseHTTPRequestHandler):
    MAX_DIGEST_LENGTH = 64
    """Largest digest that can be POSTed for timestamping"""

    NONCE_LENGTH = 16
    """Length of nonce added to submitted digests"""

    digest_queue = None

    def post_digest(self):
        content_length = int(self.headers['Content-Length'])

        if content_length > self.MAX_DIGEST_LENGTH:
            self.send_response(400)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'digest too long')
            return

        digest = self.rfile.read(content_length)

        timestamp = self.aggregator.submit(digest)

        self.send_response(200)
        self.send_header('Content-type', 'application/octet-stream')
        self.end_headers()

        ctx = StreamSerializationContext(self.wfile)
        timestamp.serialize(ctx)

    def get_timestamp(self):
        commitment = self.path[len('/timestamp/'):]

        try:
            commitment = binascii.unhexlify(commitment)
        except binascii.Error:
            self.send_response(400)
            self.send_header('Content-type', 'text/plain')
            self.send_header('Cache-Control', 'public, max-age=31536000') # this will never not be an error!
            self.end_headers()
            self.wfile.write(b'commitment must be hex-encoded bytes')
            return

        try:
            timestamp = self.calendar[commitment]
        except KeyError:
            self.send_response(404)
            self.send_header('Content-type', 'text/plain')

            # Pending?
            reason = self.calendar.stamper.is_pending(commitment)
            if reason:
                reason = reason.encode()

                # The commitment is pending, so its status will change soonish
                # as blocks are found.
                self.send_header('Cache-Control', 'public, max-age=60')

            else:
                # The commitment isn't in this calendar at all. Clients only
                # get specific commitments from servers, so in the current
                # implementation there's no reason why this response would ever
                # change.
                self.send_header('Cache-Control', 'public, max-age=3600')
                reason = b'Not found'

            self.end_headers()
            self.wfile.write(reason)
            return

        self.send_response(200)

        # Since only Bitcoin attestations are currently made, once a commitment
        # is timestamped by Bitcoin this response will never change.
        self.send_header('Cache-Control', 'public, max-age=3600')

        self.send_header('Content-type', 'application/octet-stream')
        self.end_headers()

        timestamp.serialize(StreamSerializationContext(self.wfile))

    def do_POST(self):
        if self.path == '/digest':
            self.post_digest()

        else:
            self.send_response(404)
            self.send_header('Content-type', 'text/plain')

            # a 404 is only going to become not a 404 if the server is upgraded
            self.send_header('Cache-Control', 'public, max-age=3600')

            self.end_headers()
            self.wfile.write(b'not found')

    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')

            # Humans are likely to be refreshing this, so keep it up-to-date
            self.send_header('Cache-Control', 'public, max-age=1')

            self.end_headers()

            web3 = Web3(KeepAliveRPCProvider(host=self.web3_address[0], port=self.web3_address[1]))

            # FIXME: Unfortunately getbalance() doesn't return the right thing;
            # need to investigate further, but this seems to work.
            account = web3.eth.accounts[0]
            str_wallet_balance = str(web3.eth.getBalance(account)/1000000000000000000)
            block_number = web3.eth.blockNumber


            welcome_page = """\
<html>
<head>
    <title>OpenTimestamps Calendar Server</title>
</head>
<body>
<p>This is an <a href="http://www.opentimestamps.org">OpenTimestamps</a> Calendar.</p>
<p>Experimental etherum support, use at your own risks</p>
<p>
Best-block height %d</br>
</br>
Wallet balance: %s ETH</br>
</p>

<p>
You can donate to the wallet by sending funds to %s</br>
</p>

</body>
</html>
""" % (
       block_number,
       str_wallet_balance,
       account)

            self.wfile.write(welcome_page.encode())

        elif self.path.startswith('/timestamp/'):
            self.get_timestamp()

        else:
            self.send_response(404)
            self.send_header('Content-type', 'text/plain')

            # a 404 is only going to become not a 404 if the server is upgraded
            self.send_header('Cache-Control', 'public, max-age=3600')

            self.end_headers()
            self.wfile.write(b'Not found')


class StampServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    def __init__(self, server_address, web3_address, aggregator, calendar):
        class rpc_request_handler(RPCRequestHandler):
            pass
        rpc_request_handler.aggregator = aggregator
        rpc_request_handler.calendar = calendar
        rpc_request_handler.web3_address = web3_address

        super().__init__(server_address, rpc_request_handler)

    def serve_forever(self):
        super().serve_forever()

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

import collections
import logging
import os
import queue
import struct
import threading
import time

from web3 import KeepAliveRPCProvider
from web3 import Web3

from opentimestamps.ethereum import make_timestamp_from_block
from opentimestamps.core.notary import PendingAttestation
from opentimestamps.core.serialize import StreamSerializationContext, StreamDeserializationContext
from opentimestamps.core.op import OpPrepend, OpAppend, OpSHA256
from opentimestamps.core.timestamp import Timestamp, make_merkle_tree
from opentimestamps.timestamp import nonce_timestamp

from otsserver.calendar import Journal
import time

TimestampTx = collections.namedtuple('TimestampTx', ['tx', 'tip_timestamp', 'commitment_timestamps'])
WAIT_CONFIRMATIONS = 6

class EthStamper:
    """Timestamping bot"""

    def __do_ethereum(self):
        if self.pending_commitments:
            # logging.info(self.pending_commitments)
            # Update the most recent timestamp transaction with new commitments
            commitment_timestamps = [Timestamp(commitment) for commitment in self.pending_commitments]

            # Remember that commitment_timestamps contains raw commitments,
            # which are longer than necessary, so we sha256 them before passing
            # them to make_merkle_tree, which concatenates whatever it gets (or
            # for the matter, returns what it gets if there's only one item for
            # the tree!)
            commitment_digest_timestamps = [stamp.ops.add(OpSHA256()) for stamp in commitment_timestamps]

            tip_timestamp = make_merkle_tree(commitment_digest_timestamps)

            eth_tx = {'from': self.account, 'to': self.account, 'value': 0, 'data': '0x' + bytes.hex(tip_timestamp.msg)}
            logging.info(eth_tx)
            tx_hash = self.web3.eth.sendTransaction(eth_tx)
            logging.info("tx_hash " + str(tx_hash))
            self.pending_commitments = []
            self.unconfirmed_txs.append(TimestampTx(tx_hash, tip_timestamp, commitment_timestamps))

    def new_block_callback(self, block_hash):

        block = self.web3.eth.getBlock(block_hash, full_transactions=True)
        block_number = block['number']
        print("New Block: {0} Height: {1}".format(block_hash, block_number))

        for tx in self.unconfirmed_txs:
            msg = tx.tip_timestamp.msg
            msg_hex = bytes.hex(msg)
            stamp = make_timestamp_from_block(msg_hex, block, block_number)
            if stamp is not None:
                print("digest FOUND!!! " + msg_hex)
                print(stamp.str_tree())
                self.txs_waiting_for_confirmation[block_number] = tx
                # Since all unconfirmed txs conflict with each other, we can clear the entire lot
                self.unconfirmed_txs.clear()

                # And finally, we can reset the last time a timestamp
                # transaction was mined to right now.
                self.last_timestamp_tx = time.time()

        to_pop = []
        for height, tx in self.txs_waiting_for_confirmation.items():
            msg_hex = bytes.hex(tx.tip_timestamp.msg)
            elapsed = block_number - height
            if elapsed >= WAIT_CONFIRMATIONS:
                print("CONFIRMED " + msg_hex)  # check reorg
                to_pop.append(height)
                self.calendar.add_commitment_timestamp(tx.tip_timestamp)
            else:
                print("not yet confirmed " + msg_hex + " elapsed " + str(elapsed))
        for p in to_pop:
            self.txs_waiting_for_confirmation.pop(p, None)

    def __loop(self):
        logging.info("Starting stamper loop")

        journal = Journal(self.calendar.path + '/journal')

        try:
            with open(self.calendar.path + '/journal.known-good', 'r') as known_good_fd:
                idx = int(known_good_fd.read().strip())
        except FileNotFoundError as exp:
            idx = 0


        startup = True
        while not self.exit_event.is_set():
            if not startup:
                self.__do_ethereum()

            try:
                commitment = journal[idx]
            except KeyError:
                startup = False
                self.exit_event.wait(1)
                continue

            # Is this commitment already stamped?
            if commitment in self.calendar:
                logging.debug('Commitment %s (idx %d) already stamped' % (bytes.hex(commitment), idx))
                idx += 1
                continue

            self.pending_commitments.add(commitment)
            logging.info('Added %s (idx %d) to pending commitments; %d total' % (bytes.hex(commitment), idx, len(self.pending_commitments)))

            idx += 1


    def is_pending(self, commitment):
        return

    def __init__(self, calendar, exit_event):
        self.calendar = calendar
        self.exit_event = exit_event
        self.pending_commitments = set()
        self.unconfirmed_txs = []
        self.txs_waiting_for_confirmation = {}
        self.last_timestamp_tx = 0
        self.web3 = Web3(KeepAliveRPCProvider(host="localhost", port=8545))
        self.account = self.web3.eth.accounts[0]
        new_block_filter = self.web3.eth.filter('latest')
        new_block_filter.watch(self.new_block_callback)
        self.thread = threading.Thread(target=self.__loop)
        self.thread.start()

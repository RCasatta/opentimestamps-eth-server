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

class EthStamper:
    """Timestamping bot"""

    def __do_ethereum(self):
        if self.pending_commitments:
            logging.debug(self.pending_commitments)



    def __loop(self):
        logging.info("Starting stamper loop")

        journal = Journal(self.calendar.path + '/journal')

        try:
            with open(self.calendar.path + '/journal.known-good', 'r') as known_good_fd:
                idx = int(known_good_fd.read().strip())
        except FileNotFoundError as exp:
            idx = 0

        while not self.exit_event.is_set():
            self.__do_ethereum()

            try:
                commitment = journal[idx]
            except KeyError:
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

        self.thread = threading.Thread(target=self.__loop)
        self.thread.start()

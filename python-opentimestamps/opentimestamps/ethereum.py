# Copyright (C) 2016 The OpenTimestamps developers
#
# This file is part of python-opentimestamps.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-opentimestamps including this file, may be copied,
# modified, propagated, or distributed except according to the terms contained
# in the LICENSE file.


from opentimestamps.core.timestamp import Timestamp, cat_sha256d
from opentimestamps.core.op import OpAppend, OpPrepend, OpKECCAK256
from opentimestamps.core.notary import EthereumBlockHeaderAttestation
import rlp
from ethereum import trie, db


def __make_btc_block_merkle_tree(blk_txids):
    assert len(blk_txids) > 0

    digests = blk_txids
    while len(digests) > 1:
        # The famously broken Satoshi algorithm: if the # of digests at this
        # level is odd, double the last one.
        if len(digests) % 2:
            digests.append(digests[-1].msg)

        next_level = []
        for i in range(0,len(digests), 2):
            next_level.append(cat_sha256d(digests[i], digests[i + 1]))

        digests = next_level

    return digests[0]


def make_trie(block):
    state = trie.Trie(db.DB(), trie.BLANK_ROOT)
    txs_root = bytes.fromhex(block['transactionsRoot'][2:])
    list_tx_hash = []
    list_tx_raw = []
    # print(block)
    # print("total transactions: " + str(len(block[u'transactions'])))
    for i, tx_rpc in enumerate(block['transactions']):
        list_tx_hash.append(tx_rpc['hash'])
        rlp_i = rlp.encode(i)
        tx_raw = tx_rpc['raw'][2:]  # Parity RPC have raw attribute
        list_tx_raw.append(tx_raw)
        state.update(rlp_i, bytes.fromhex(tx_raw))
    return state


def get_append_and_prepend(inside, total):
    idx = total.index(inside, 0, len(total))
    return [total[0:idx], total[idx + len(inside):]]


# def create_proof(block, state, tx_hash, j, tx_raw):
def found_tx(digest, block, max_tx_size):
    for i, tx_rpc in enumerate(block['transactions']):
        tx_hex = tx_rpc['raw'][2:]
        if len(tx_hex)/2 < max_tx_size:
            try:
                tx_hex.index(digest)
                # print("found tx_raw: " + tx_hex)
                prepend, append = get_append_and_prepend(digest, tx_hex)
                # print(prepend + " " + digest + " " + append)
                return i, prepend, append
            except ValueError:
                continue
    raise ValueError


def make_timestamp_from_block(digest, block, blockheight, *, max_tx_size=1000):
    state = make_trie(block)
    my_root = state.root_hash
    block_root = bytes.fromhex(block['transactionsRoot'][2:])
    assert my_root == block_root
    digest = digest.decode('utf-8')
    try:
        j, prepend_tx, append_tx = found_tx(digest, block, max_tx_size)
    except ValueError:
        return None
    tx_raw = prepend_tx + digest + append_tx
    # print("tx_raw: " + tx_raw)
    # print("tx_hash: " + sha3.keccak_256(bytes.fromhex(tx_raw)).hexdigest())

    rlp_encode = rlp.encode(j)
    # print("rlp_encode: " + bytes.hex(rlp_encode))
    nibbles = trie.bin_to_nibbles(rlp_encode)
    current_node = state.root_node
    ops_list = []
    nibble_iter = nibbles.__iter__()

    while True:
        node_type = state._get_node_type(current_node)
        # print("node type: " + str(node_type))
        # print([bytes.hex(cur_el) for cur_el in current_node])
        current_node_rlp = rlp.encode(current_node)
        current_node_encoded = bytes.hex(current_node_rlp)
        # print(current_node_encoded)
        try:
            index = next(nibble_iter)
        except:
            pass

        current_el = current_node[index if node_type == trie.NODE_TYPE_BRANCH else 1]
        current_el_hex = bytes.hex(current_el)
        # print(str(index) + ":" + current_el_hex)
        [prepend, append] = get_append_and_prepend(current_el_hex, current_node_encoded)

        ops_list.append(OpKECCAK256())
        if len(append) > 0:
            ops_list.append(OpAppend(bytes.fromhex(append)))
        if len(prepend) > 0:
            ops_list.append(OpPrepend(bytes.fromhex(prepend)))

        if node_type == trie.NODE_TYPE_LEAF:
            break
        else:
            current_node = state._decode_to_node(current_el)

    assert tx_raw == prepend_tx + digest + append_tx
    orig = Timestamp(bytes.fromhex(digest))
    current = orig
    if len(prepend_tx) > 0:
        current = current.ops.add(OpPrepend(bytes.fromhex(prepend_tx)))
    if len(append_tx) > 0:
        current = current.ops.add(OpAppend(bytes.fromhex(append_tx)))
    while len(ops_list) > 0:
        current = current.ops.add(ops_list.pop())
    attestation = EthereumBlockHeaderAttestation(blockheight)
    current.attestations.add(attestation)

    return orig

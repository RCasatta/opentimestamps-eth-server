from web3 import Web3, KeepAliveRPCProvider
from ethereum import trie, db
import rlp
from opentimestamps.core.timestamp import Timestamp
from opentimestamps.core.op import *

web3 = Web3(KeepAliveRPCProvider(host="localhost", port=8545))
# web3 = Web3(KeepAliveRPCProvider(host="192.168.1.218", port=8545))


def getRawTransaction(hash):
    return web3._requestManager.request_blocking(
        "eth_getRawTransactionByHash",
        [hash]
    )


def new_block_callback(block_hash):
    total = 0
    # print("New Block: {0}".format(block_hash))
    block = web3.eth.getBlock(block_hash, full_transactions=True)
    state = trie.Trie(db.DB(), trie.BLANK_ROOT)
    txs_root = bytes.fromhex(block[u'transactionsRoot'][2:])
    list_tx_hash = []
    list_tx_raw = []
    # print(block)
    # print("total transactions: " + str(len(block[u'transactions'])))
    for i, tx_rpc in enumerate(block[u'transactions']):
        list_tx_hash.append(tx_rpc[u'hash'])
        rlp_i = rlp.encode(i)
        try:
            tx_raw = tx_rpc[u'raw'][2:]  # Parity RPC have raw attribute
        except:
            tx_raw = getRawTransaction()[2:] # Geth haven't raw attribute
        list_tx_raw.append(tx_raw)
        state.update(rlp_i, bytes.fromhex(tx_raw))
        # print("RLP " + bytes.hex(rlp_i))

    for j, (tx_hash, tx_raw) in enumerate(zip(list_tx_hash, list_tx_raw)):
        if len(tx_raw) <= 4096:
            timestamp = create_proof(block, state, tx_hash, j, tx_raw)
            # print(tx_hash)
            # print(timestamp.str_tree())
            msg = last_timestamp_msg(timestamp)
            if msg != txs_root:
                print("ERROR " + tx_hash)
                print()
            total += 1

    return total


def last_timestamp_msg(timestamp):
    current = timestamp
    while len(current.ops) > 0:
        for op, ts in sorted(current.ops.items()):
            current = ts
    return current.msg


def get_append_and_prepend(inside, total):
    idx = total.index(inside, 0, len(total))
    return [total[0:idx], total[idx + len(inside):]]


def create_proof(block, state, tx_hash, j, tx_raw):
    # print("tx_raw: " + tx_raw)
    # print("tx_hash: " + tx_hash)
    my_root = state.root_hash
    block_root = bytes.fromhex(block[u'transactionsRoot'][2:])
    assert my_root == block_root
    rlp_encode = rlp.encode(j)
    # print("rlp_encode: " + bytes.hex(rlp_encode))
    nibbles = trie.bin_to_nibbles(rlp_encode)
    current_node = state.root_node
    ops_list = []
    nibble_iter = nibbles.__iter__();

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

    orig = Timestamp(bytes.fromhex(tx_raw))
    current = orig
    while len(ops_list) > 0:
        current = current.ops.add(ops_list.pop())

    return orig

# t = 0
# for c in range(0, 3000000):
#    if c % 100 == 0:
#        print(str(c) + " " + str(t))
#    t += new_block_callback(c)



# ERROR in tx 0x4a1ece0605e404a9ce3d2b1d964517d8a52dd76da3edf1cc3f93a37eb57652ca
new_block_callback(121667)
# new_block_callback('0xa684821fe21a67143973a517561619903fac659f2bef31290a5998fdd33a5e5a')

#new_block_filter = web3.eth.filter('latest')
#new_block_filter.watch(new_block_callback)
#time.sleep(100)

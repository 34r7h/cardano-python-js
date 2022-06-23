
# TODO encrypt signed tx to save on user's address
# Args = [signed_tx, blockfrost_key]
from pycardano import BlockFrostChainContext, Network
import sys

args = sys.argv[1:]
bf = args[1]
signed_tx = args[0]
network = Network.MAINNET
context = BlockFrostChainContext(bf, network)
context.submit_tx(signed_tx)
print(id)
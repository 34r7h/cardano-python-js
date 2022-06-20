from dataclasses import dataclass, field
from typing import Dict, List

from pycardano import *
network = Network.MAINNET
context = BlockFrostChainContext("mainnetqEZ4wDDoRdtWqh2SNVLNqfQbhlNmTbza", network)

address = Address.from_primitive('addr1qxeky720e3yx5vfszs4ssk6tdlnhvdnngevr0qgu6q39xw0z7wxgc8snm7m5ce69fdtkuddmugwl6z2zev29f85rk2wq0mmf0q')

builder = TransactionBuilder(context)
builder.add_input_address(address)
utxos = context.utxos(str(address))

# Force chain context to return only one utxo
context.utxos = lambda _: utxos[-1:]

builder.add_output(
    TransactionOutput(
        Address.from_primitive(
"addr1qxeky720e3yx5vfszs4ssk6tdlnhvdnngevr0qgu6q39xw0z7wxgc8snm7m5ce69fdtkuddmugwl6z2zev29f85rk2wq0mmf0q"
        ),
        Value.from_primitive(
            [
                1000000,
                
            ]
        ),
    )
)
tx = builder.build(change_address=address)

print(tx.inputs)

print(tx.outputs)
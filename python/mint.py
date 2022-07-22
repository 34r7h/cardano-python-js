"""
This is a complete walk through of minting a NFT on Cardano blockchain in pure Python code.
This example is inspired by https://developers.cardano.org/docs/native-tokens/minting-nfts#crafting-the-transaction
# Submitted transaction in this example could be found at
# https://testnet.cardanoscan.io/transaction/632898c831719e07ad74b952880c98e9b51a1f31b25ca99e5a6e753ecd5d5201
"""
import pathlib
import sys
import json
from datetime import datetime
from pycardano import *

now = datetime.now()
if len(sys.argv) > 1:
    ### args = [address, data, blockfrostid]
    args = list(sys.argv[1:])
    tokendata = json.loads(args[1])
    tokenmetadata = tokendata['metadata']
    # print(tokenmetadata)
    tokenmetadata['minted_on'] = now.strftime("%d/%m/%Y %H:%M:%S")

else:
    args = [
        "addr1qxvqw3xawj76533sf8dl4rkm9sn5t4vfzwgtc0mvmcjpmgee8dlsen8n464ucw69acfgdxgguscgfl5we3rwts4s57assqu5h5",
        {
            "artist": "Sharon",
            "description": "x your eyes",
            "ticker": "shrn1",
            "collection": "Sharon Experiments",
            "creator": "XMBA",
            "discord": "https://discord.gg/446844338538938378",
            "rarity": "Tier 1 (1 of 1)",
            "set": "XMBLs (1 of 1)",
            "twitter": "https://twitter/i34r7h",
            "copyright": "Copyright 2022 Sharon",
            "files": [
                {
                    "mediaType": "image/png",
                    "name": "screen_shot_2022-06-28_at_21.49.43.png",
                    "src": "ipfs://QmYD4xHe3noykXihefWEKPzv6NyTeMf6Mngdr7pPVenh8u",
                }
            ],
            "xymboltoken": "c995c28304094b787bdefaa0803ead590286b3d6be23ff9c3c8adde8ff007ce3",
            "imagehash": "81d0f728b9c482336654193cdd29cdb25d8c141ddca70ec606ac513b34a8b76b",
            "ipfs": "QmYD4xHe3noykXihefWEKPzv6NyTeMf6Mngdr7pPVenh8u",
            "filehash": "263b32bf6bd33e9c53787c12aefdbbbf3dd92345e48fe3367d68edfb40166bff",
            "id": "c995c28304094b787bdefaa0803ead590286b3d6be23ff9c3c8adde8ff007ce3",
            "image": "ipfs://QmYD4xHe3noykXihefWEKPzv6NyTeMf6Mngdr7pPVenh8u",
            "mediaType": "image/png",
            "name": "x your eyes",
            "supply": "1",
            "size": "284212",
        },
        "mainnetqEZ4wDDoRdtWqh2SNVLNqfQbhlNmTbza",
    ]
    # print("no args", sys.argv)
    tokenmetadata = args[1]

# sendaddress = Address.from_primitive(args[0])
bf = args[2]

# Copy your BlockFrost project ID below. Go to https://blockfrost.io/ for more information.
BLOCK_FROST_PROJECT_ID = bf
NETWORK = Network.MAINNET

chain_context = BlockFrostChainContext(
    project_id=BLOCK_FROST_PROJECT_ID, network=NETWORK
)
# print([sendaddress, tokenmetadata, bf])
# print(tokenmetadata, type(tokenmetadata) )
# """Preparation"""
# Define the root directory where images and keys will be stored.
PROJECT_ROOT = "nft"
root = pathlib.Path(PROJECT_ROOT)

# # Create the directory if it doesn't exist
root.mkdir(parents=True, exist_ok=True)

# """Generate keys"""
key_dir = root / "keys"
key_dir.mkdir(exist_ok=True)


# Load payment keys or create them if they don't exist
def load_or_create_key_pair(base_dir, base_name):
    skey_path = base_dir / f"{base_name}.skey"
    vkey_path = base_dir / f"{base_name}.vkey"

    if skey_path.exists():
        skey = PaymentSigningKey.load(str(skey_path))
        vkey = PaymentVerificationKey.from_signing_key(skey)
    else:
        key_pair = PaymentKeyPair.generate()
        key_pair.signing_key.save(str(skey_path))
        key_pair.verification_key.save(str(vkey_path))
        skey = key_pair.signing_key
        vkey = key_pair.verification_key
    return skey, vkey

secret = args[0]
# data = args[1]

jsonsecret = json.loads(secret)
# jsondata = json.loads(data)

pkey = jsonsecret["payment"]["signing"]["cborHex"]
vkey = jsonsecret["payment"]["verification"]["cborHex"]
sk = PaymentSigningKey.from_cbor(pkey)
vk = PaymentVerificationKey.from_signing_key(sk)
address = Address.from_primitive(tokendata["address"])


# pkey = PaymentVerificationKey.load("testpayment.vkey")
# skey = PaymentSigningKey.load("testpayment.skey")

# spkey = jsonsecret["stake"]["verification"]["cborHex"]

# print('payment keys', pkey, skey)

# address = Address(
#     payment_part=pkey.hash(), staking_part=spkey.hash(), network=Network.MAINNET
# )
# print(address)

# # Payment address. Send some ADA (~5 ADA is enough) to this address, so we can pay the minting fee later.

# payment_skey, payment_vkey = load_or_create_key_pair(key_dir, "payment")

# address = Address(payment_vkey.hash(), network=NETWORK)
# print(address)

# Generate policy keys, which will be used when minting NFT
policy_skey, policy_vkey = load_or_create_key_pair(key_dir, "policy")

"""Create policy"""
# A policy that requires a signature from the policy key we generated above
pub_key_policy = ScriptPubkey(policy_vkey.hash())

# A time policy that disallows token minting after 10000 seconds from last block
must_before_slot = InvalidHereAfter(chain_context.last_block_slot + 10000)

# Combine two policies using ScriptAll policy
policy = ScriptAll([pub_key_policy, must_before_slot])

# Calculate policy ID, which is the hash of the policy
policy_id = policy.hash()
# print(f"Policy ID: {policy_id}")
with open(root / "policy.id", "a+") as f:
    f.truncate(0)
    f.write(str(policy_id))

"""Define NFT"""
# Create an asset container
my_asset = Asset()
# print('tokenmetadata', type(tokenmetadata), tokenmetadata['name'])
# print('tokenmetadata', tokenmetadata['name'])
# Create names for our assets
nft1 = AssetName(bytes(tokenmetadata['name'], 'utf-8'))
# nft2 = AssetName(b"MY_NFT_2")
# Put assets into the asset container with a quantity of 1

# TODO add quantity from xmba for currencies
my_asset[nft1] = 1
# my_asset[nft2] = 1

# Create a MultiAsset container
my_nft = MultiAsset()
# Put assets into MultiAsset container. In this example, we only have one policy.
# However, MultiAsset container can hold multiple different policies.

my_nft[policy_id] = my_asset

# Create the final native script that will be attached to the transaction
native_scripts = [policy]

"""Define NFT (Alternative)"""
# The nft definition above is somewhat verbose.
# We can also directly create native assets from python primitives.
name = tokenmetadata['name']
my_nft_alternative = MultiAsset.from_primitive(
    {
        policy_id.payload: {  # Use policy ID created from above. We can't use policy_id here because policy_id's type  # is ScriptHash, which is not a primitive type. Instead, we use policy_id.payload (bytes)
            bytes(name, 'utf-8'): 1,  # Name of our NFT1  # Quantity of this NFT
            # b"MY_NFT_2": 1,  # Name of our NFT2  # Quantity of this NFT
        }
    }
)

# my_nft and my_nft_alternative are equivalent
#  assert my_nft == my_nft_alternative

"""Create metadata"""
# We need to create a metadata for our NFTs, so they could be displayed correctly by blockchain explorer
policyid = policy_id.payload.hex()
metadata = {721:{}}
metadata[721][policyid] = {}
metadata[721][policyid][name] = tokenmetadata
# {
#     721: {  # 721 refers to the metadata label registered for NFT standard here:
#         # https://github.com/cardano-foundation/CIPs/blob/master/CIP-0010/registry.json#L14-L17
#         [policyid]: {
#             [name]: tokenmetadata
#         }
#     }
# }

# Place metadata in AuxiliaryData, the format acceptable by a transaction.
auxiliary_data = AuxiliaryData(AlonzoMetadata(metadata=Metadata(metadata)))

"""Build transaction"""

# Create a transaction builder
builder = TransactionBuilder(chain_context)

# Add our own address as the input address
builder.add_input_address(address)

# Since an InvalidHereAfter rule is included in the policy, we must specify time to live (ttl) for this transaction
builder.ttl = must_before_slot.after

# Set nft we want to mint
builder.mint = my_nft

# Set native script
builder.native_scripts = native_scripts

# Set transaction metadata
builder.auxiliary_data = auxiliary_data

# Calculate the minimum amount of lovelace that need to hold the NFT we are going to mint
min_val = min_lovelace(Value(0, my_nft), chain_context)


# Send the NFT to our own address
builder.add_output(TransactionOutput(address, Value(min_val, my_nft)))
# print('builder', builder)
# Create final signed transaction
signed_tx = builder.build_and_sign([sk, policy_skey], change_address=address)
tx_id = str(signed_tx.id)
# print("############### Transaction created ###############")
# print(signed_tx)
# print(signed_tx.to_cbor())

# Submit signed transaction to the network
# print("############### Submitting transaction ###############")
chain_context.submit_tx(signed_tx.to_cbor())
print(policy_id,tx_id )

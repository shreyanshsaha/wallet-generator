import ecdsa
from ecdsa import VerifyingKey, SigningKey
from hashlib import sha256, sha1
from Crypto.Hash import keccak
import argparse

ETH_CUVE = ecdsa.SECP256k1
BTC_CUVE = ecdsa.SECP256k1

def generate(private_key):
  # private_key = ecdsa.SigningKey.generate(curve=ETH_CUVE)
  if private_key is not None:
    private_key = SigningKey.from_string(bytes.fromhex(private_key[2:]),ETH_CUVE)    
  else:
    private_key = SigningKey.generate(curve=ETH_CUVE)

  public_key = private_key.get_verifying_key()
  return private_key, public_key

def validate(signed_message, actual_message, public_key):
  public_key = public_key[2:]
  signed_message = signed_message[2:]
  
  vk = VerifyingKey.from_string(bytes.fromhex(public_key))
  return vk.verify(bytes.fromhex(signed_message.hex()), actual_message.encode('utf-8'))

def get_address(public_key):
  keccak_hash = keccak.new(digest_bits=256)
  keccak_hash.update(bytes.fromhex(public_key))
  keccak_digest = keccak_hash.hexdigest()
  # Take the last 20 bytes
  wallet_len = 40
  wallet = '0x' + keccak_digest[-wallet_len:]
  return wallet


def verify(private_key: SigningKey, public_key: VerifyingKey):
  test_message = b"hello world"
  signed_message = private_key.sign(test_message)
  return public_key.verify()


parser = argparse.ArgumentParser(
  prog="Crypto Key & Address Generator",
  description="Generate keys and wallets for bitcoin and etherium"
)

parser.add_argument("command", choices=["generate", "validate", "validate_message", "sign"], default="generate")
parser.add_argument("-k", "--key", help="Generate with given private key, example: 0xabc", dest='private_key', metavar="Private Key")
# parser.add_argument("-p", "--public", help="Generate with given private key, example: 0xabc", dest='public_key', metavar="Public Key")
# parser.add_argument("-m", "--message", help="Validate Signed Message, example: 0xabc", dest='signed_message', metavar="Message")


args = parser.parse_args()
arg_private_key = args.private_key
command = args.command

if command == 'generate':
  private_key, public_key = generate(private_key=arg_private_key)
  print("Private key: 0x"+private_key.to_string().hex())
  print("Public key: 0x"+public_key.to_string().hex())
  address = get_address(public_key.to_string().hex())
  print("Address: "+address)
else:
  print("Invalid commannd")
  argparse.ArgumentParser.print_help()

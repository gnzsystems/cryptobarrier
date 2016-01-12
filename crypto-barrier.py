import os
import sys
import json
import struct
import base64
import argparse
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


class FileCodec:

    def __init__(self, inputFile=None, outputFile=None, plaintextKey=None):
        self.pad = lambda s: s + (16 - len(s) % 16) * chr(16 - len(s) % 16)
        self.unpad = lambda s: s[0:-ord(s[-1])]
        self.inputFile = inputFile
        self.outputFile = outputFile
        if plaintextKey:
            self.plaintextKey = plaintextKey
            self.cipherKey = self.generate_aes_key(seed=self.plaintextKey)
        else:
            self.plaintextKey = None
            self.cipherKey = None

    def asymmetric_encode(self, keyfile):
        if not os.path.isfile(keyfile):
            print "RSA Encryption Error: No key provided."
            sys.exit(1)
        with open(keyfile, "rb") as infile:
            pk = RSA.importKey(infile.read())
        if pk.has_private():
            print "RSA Encryption Error: Private key provided.  Use a public key for encryption."
            sys.exit(1)
        aesKey = self.generate_aes_key()
        keyDict = {
            "key": base64.b64encode(aesKey),
        }
        header = base64.b64encode(pk.encrypt(json.dumps(keyDict), None)[0])
        headerLength = str(len(header))
        if not len(headerLength) == 6:
            headerLength = str("0" * (6 - len(headerLength))) + headerLength
        buff = headerLength + header
        buff += self.symmetric_encode(key=aesKey, returnValue=True)
        with open(self.outputFile, "wb") as outfile:
            outfile.write(buff)

    def asymmetric_decode(self, keyfile):
        if not os.path.isfile(keyfile):
            print "RSA Decryption Error: No key provided."
            sys.exit(1)
        with open(keyfile, "rb") as infile:
            pk = RSA.importKey(infile.read())
        if not pk.has_private():
            print "RSA Decryption Error: Public key provided.  Use a private key for decryption."
            sys.exit(1)
        if not os.path.isfile(self.inputFile):
            print "RSA Decryption Error: No input file provided."
            sys.exit(1)
        with open(self.inputFile, "rb") as infile:
            headerLength = int(infile.read(6))
            encodedHeader = infile.read(headerLength)
            fileData = base64.b64decode(infile.read())
        with open(self.inputFile, "wb") as outfile:
            outfile.write(fileData)
        header = json.loads(pk.decrypt(base64.b64decode(encodedHeader)))
        aesKey = base64.b64decode(header["key"])
        self.symmetric_decode(key=aesKey)

    def symmetric_encode(self, key=None, returnValue=False, chunksize=64*1024):
        buff = ''
        if not self.inputFile:
            print "No input file provided."
            sys.exit(1)
        elif not os.path.isfile(self.inputFile):
            print "Provided input file does not exist."
            sys.exit(1)
        if self.inputFile and (not self.outputFile):
            self.outputFile = self.inputFile
        if not key:
            if not self.cipherKey:
                if not self.plaintextKey:
                    print "AES Encryption Error: No key provided."
                    sys.exit(1)
                else:
                    self.cipherKey = self.generate_aes_key(seed=self.plaintextKey)
                    key = self.cipherKey
            else:
                key = self.cipherKey
        else:
            if not len(key) == 32:
                key = self.generate_aes_key(seed=key)
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        filesize = os.path.getsize(self.inputFile)
        with open(self.inputFile, "rb") as infile:
            buff += base64.b64encode(iv)
            buff += struct.pack("<Q", filesize)
            while 1:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                buff += cipher.encrypt(self.pad(chunk))
        if returnValue:
            return base64.b64encode(buff)
        else:
            with open(self.outputFile, "wb") as outfile:
                outfile.write(buff)

    def symmetric_decode(self, key=None, chunksize=24*1024):
        buff = ''
        if not self.inputFile:
            print "No input file provided."
            sys.exit(1)
        elif not os.path.isfile(self.inputFile):
            print "Provided input file does not exist."
            sys.exit(1)
        if self.inputFile and (not self.outputFile):
            self.outputFile = self.inputFile
        if not key:
            if not self.cipherKey:
                if not self.plaintextKey:
                    print "AES Decryption Error: No key provided."
                    sys.exit(1)
                else:
                    self.cipherKey = self.generate_aes_key(seed=self.plaintextKey)
                    key = self.cipherKey
            else:
                key = self.cipherKey
        else:
            if not len(key) == 32:
                key = self.generate_aes_key(seed=key)
        f = open(self.inputFile, "rb")
        iv = base64.b64decode(f.read(24))
        cipher = AES.new(key, AES.MODE_CBC, iv)
        origsize = struct.unpack("<Q", f.read(struct.calcsize("Q")))[0]
        while 1:
            chunk = f.read(chunksize)
            if len(chunk) == 0:
                break
            buff += self.unpad(cipher.decrypt(chunk))
        with open(self.outputFile, "wb") as outfile:
            outfile.write(buff)
            outfile.truncate(origsize)

    @staticmethod
    def rsa_key_factory(outputDir=None):
        if not outputDir:
            outputDir = os.path.dirname(os.path.realpath(__file__))
        print "Outputting to directory: %s" % outputDir
        print "Generating 4096-bit RSA key pair.  This will take some time."
        keypair = RSA.generate(4096)
        print "Done. Saving keys..."
        privateKey = keypair.exportKey()
        publicKey = keypair.publickey().exportKey()
        privateKeyFile = os.path.join(outputDir, "private")
        publicKeyFile = os.path.join(outputDir, "public")
        with open(privateKeyFile, "wb") as outfile:
            outfile.write(privateKey)
        with open(publicKeyFile, "wb") as outfile:
            outfile.write(publicKey)

    @staticmethod
    def generate_aes_key(seed=None, unicode=False):
        if not seed:
            seed = get_random_bytes(256)
        h = sha256()
        h.update(seed)
        for i in range(0, 10001):
            s = h.digest()
            h = sha256()
            h.update(s)
        if unicode:
            s = base64.b64encode(s)
        return s[:32]


class MainFunctions:

    @staticmethod
    def main(parser, args):
        if (args.function == "e") or (args.function == "encrypt"):
            if not args.file:
                parser.error("Encryption requires an input file! Use -i option.")
            if not args.password:
                if not args.key:
                    parser.error("Key or password must be provided for file encryption.")
                else:
                    cryptoDriver = FileCodec(inputFile=args.file)
                    cryptoDriver.asymmetric_encode(keyfile=args.key)
            else:
                cryptoDriver = FileCodec(inputFile=args.file, plaintextKey=args.password)
                cryptoDriver.symmetric_encode()
        elif (args.function == "d") or (args.function == "decrypt"):
            if not args.file:
                parser.error("Decryption requires an input file! Use -i option.")
            if not args.password:
                if not args.key:
                    parser.error("Key or password must be provided for file decryption.")
                else:
                    cryptoDriver = FileCodec(inputFile=args.file)
                    cryptoDriver.asymmetric_decode(keyfile=args.key)
            else:
                cryptoDriver = FileCodec(inputFile=args.file, plaintextKey=args.password)
                cryptoDriver.symmetric_decode()
        elif (args.function == "g") or (args.function == "generate"):
            if not args.output:
                FileCodec.rsa_key_factory()
            else:
                FileCodec.rsa_key_factory(outputDir=args.output)

    @staticmethod
    def is_valid_file(parser, arg):
        if not os.path.exists(arg):
            parser.error("The file %s does not exist!" % arg)
        else:
            return arg

    @staticmethod
    def is_valid_directory(arg):
        if not os.path.isdir(arg):
            print "Provided output directory is not a directory."
            print "Using file location..."
            return os.path.dirname(os.path.realpath(__file__))
        else:
            return arg

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Command line file encryption utility.")

    parser.add_argument("--function", "-f", choices=["e", "encrypt", "d", "decrypt", "g", "generate"],
                        required=True, help="Determines whether to encrypt or decrypt the file.")

    parser.add_argument("--file", "--input", "-i", metavar="FILE",
                        type=lambda x: MainFunctions.is_valid_file(parser, x),
                        help="Used for encryption/decryption. Input file name.")

    parser.add_argument("--output", "-o", metavar="DIRECTORY",
                        type=lambda x: MainFunctions.is_valid_directory(x),
                        help="Output directory.  Only used for key generation")

    parser.add_argument("--key", "-k", type=lambda x: MainFunctions.is_valid_file(parser, x),
                        help="Absolute file path to your keyfile.")
    parser.add_argument("--password", "-p", help="Encrypt/Decrypt using a password.")

    args = parser.parse_args()

    MainFunctions.main(parser, args)

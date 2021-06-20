import struct
class ChaCha20(object):
    def bytearray_to_words(self, data):
        """Convert a bytearray to array of word sized ints"""
        ret = []
        for i in range(0, len(data) // 4):
            ret.extend(struct.unpack("<L", data[i * 4 : (i + 1) * 4]))
        return ret

    def word_to_bytearray(self, state):
        """Convert state to little endian bytestream"""
        return bytearray(struct.pack("<LLLLLLLLLLLLLLLL", *state))

    def __init__(self, key, nonce, counter=0):
        """Set the initial state for the ChaCha cipher"""
        if len(key) != 32:
            raise ValueError("Key must be 256 bit long")
        if len(nonce) != 12:
            raise ValueError("Nonce must be 96 bit long")

        self.key = []
        self.nonce = []
        self.counter = counter
        self.constants = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]

        # convert bytearray key and nonce to little endian 32 bit unsigned ints
        self.key = self.bytearray_to_words(key)
        self.nonce = self.bytearray_to_words(nonce)

    def rotl32(self, v, c):
        """Rotate left a 32 bit integer v by c bits"""
        return (v << c) & 0xFFFFFFFF | (v >> (32 - c))

    def quarter_round(self, x, a, b, c, d):
        """Perform a ChaCha quarter round"""
        xa = x[a]
        xb = x[b]
        xc = x[c]
        xd = x[d]

        for c1, c2 in ((16, 12), (8, 7)):
            xa = (xa + xb) & 0xFFFFFFFF
            xd = xd ^ xa
            xd = self.rotl32(xd, c1)

            xc = (xc + xd) & 0xFFFFFFFF
            xb = xb ^ xc
            xb = self.rotl32(xb, c2)

            x[a] = xa
            x[b] = xb
            x[c] = xc
            x[d] = xd

        return x

    def double_round(self, x):
        """Perform two rounds of ChaCha cipher"""
        round_mixup_box = [
            (0, 4, 8, 12),
            (1, 5, 9, 13),
            (2, 6, 10, 14),
            (3, 7, 11, 15),
            (0, 5, 10, 15),
            (1, 6, 11, 12),
            (2, 7, 8, 13),
            (3, 4, 9, 14),
        ]

        for a, b, c, d in round_mixup_box:
            x = self.quarter_round(x, a, b, c, d)

        return x

    def chacha_block(self, key, counter, nonce):
        state = self.constants + key + [counter] + nonce
        
        working_state = state[:]
        for _ in range(0, 10):
            working_state = self.double_round(working_state)
        
        return [
            (st + wrkSt) & 0xFFFFFFFF
            for st, wrkSt in zip(state, working_state)
        ]

    def key_stream(self, counter):
        """receive the key stream for nth block"""
        key_stream = self.chacha_block(
            self.key, self.counter + counter, self.nonce
        )
        key_stream = self.word_to_bytearray(key_stream)

        return key_stream

    def encrypt(self, plaintext):
        """Encrypt the data"""
        encrypted_message = bytearray()
        for i, block in enumerate(
            plaintext[i : i + 64] for i in range(0, len(plaintext), 64)
        ):

            key_stream = self.key_stream(i)
            encrypted_message += bytearray(
                x ^ y for x, y in zip(block, key_stream)
            )

        return encrypted_message

    def decrypt(self, ciphertext):
        """Decrypt the data"""
        return self.encrypt(ciphertext)
    
class Poly1305(object):
    def le_bytes_to_num(self, data):
        """Convert a number from little endian byte format"""
        ret = 0
        for i in range(len(data) - 1, -1, -1):
            ret <<= 8
            ret += data[i]
        return ret

    def num_to_16_le_bytes(self, num):
        """Convert number to 16 bytes in little endian format"""
        ret = [0] * 16
        for i, _ in enumerate(ret):
            ret[i] = num & 0xFF
            num >>= 8
        return bytearray(ret)

    def divceil(self, divident, divisor):
        """Integer division with rounding up"""
        quot, r = divmod(divident, divisor)
        return quot + int(bool(r))

    def __init__(self, key):
        """Set the authenticator key"""
        if len(key) != 32:
            raise ValueError("Key must be 256 bit long")
        self.acc = 0
        self.r = self.le_bytes_to_num(key[0:16])
        self.r &= 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
        self.s = self.le_bytes_to_num(key[16:32])
        self.P = 0x3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFB

    def create_tag(self, data):
        """Calculate authentication tag for data"""
        for i in range(0, self.divceil(len(data), 16)):
            n = self.le_bytes_to_num(data[i * 16 : (i + 1) * 16] + b"\x01")
            self.acc += n
            self.acc = (self.r * self.acc) % self.P
        self.acc += self.s
        return self.num_to_16_le_bytes(self.acc)
    
class TagInvalidException(Exception):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)


class ChaCha20Poly1305(object):
    """Pure python implementation of ChaCha20/Poly1305 AEAD cipher"""

    def __init__(self, key):
        """Set the initial state for the ChaCha20 AEAD"""
        if len(key) != 32:
            raise ValueError("Key must be 256 bit long")

        self.nonceLength = 12
        self.tagLength = 16
        self.name = "chacha20-poly1305"
        self.key = key

    def poly1305_key_gen(self, key, nonce):
        """Generate the key for the Poly1305 authenticator"""
        poly = ChaCha20(key, nonce)
        return poly.encrypt(bytearray(32))

    def pad16(self, data):
        """Return padding for the Associated Authenticated Data"""
        if len(data) % 16 == 0:
            return bytearray(0)
        else:
            return bytearray(16 - (len(data) % 16))

    def ct_compare_digest(self, val_a, val_b):
        if len(val_a) != len(val_b):
            return False

        result = 0
        for x, y in zip(val_a, val_b):
            result |= x ^ y

        return result == 0

    def seal(self, nonce, plaintext, data):
        """
        Encrypts and authenticates plaintext using nonce and data. Returns the
        ciphertext, consisting of the encrypted plaintext and tag concatenated.
        """
        if len(nonce) != 12:
            raise ValueError("Nonce must be 96 bit large")

        otk = self.poly1305_key_gen(self.key, nonce)

        ciphertext = ChaCha20(self.key, nonce, counter=1).encrypt(plaintext)

        mac_data = data + self.pad16(data)
        mac_data += ciphertext + self.pad16(ciphertext)
        mac_data += struct.pack("<Q", len(data))
        mac_data += struct.pack("<Q", len(ciphertext))
        tag = Poly1305(otk).create_tag(mac_data)
        return ciphertext + tag

    def open(self, nonce, ciphertext, data):
        """
        Decrypts and authenticates ciphertext using nonce and data. If the
        tag is valid, the plaintext is returned. If the tag is invalid,
        returns None.
        """
        if len(nonce) != 12:
            raise ValueError("Nonce must be 96 bit long")

        if len(ciphertext) < 16:
            return None

        expected_tag = ciphertext[-16:]
        ciphertext = ciphertext[:-16]

        otk = self.poly1305_key_gen(self.key, nonce)

        mac_data = data + self.pad16(data)
        mac_data += ciphertext + self.pad16(ciphertext)
        mac_data += struct.pack("<Q", len(data))
        mac_data += struct.pack("<Q", len(ciphertext))
        tag = Poly1305(otk).create_tag(mac_data)

        if not self.ct_compare_digest(tag, expected_tag):
            raise TagInvalidException

        return ChaCha20(self.key, nonce, counter=1).decrypt(ciphertext)

    def encrypt(self, nonce, plaintext, associated_data=None):
        return self.seal(
            nonce,
            plaintext,
            associated_data if associated_data is not None else bytearray(0),
        )

    def decrypt(self, nonce, ciphertext, associated_data=None):
        return self.open(
            nonce,
            ciphertext,
            associated_data if associated_data is not None else bytearray(0),
        )
    
import paho.mqtt.client as mqtt
import time
from binascii import hexlify

def on_connect(client, userdata, flags, rc):

    if rc == 0:
        print("Connected to MQTT Broker!")
    else:
        print("Failed to connect, return code %d\n", rc)

def on_message(client, userdata, message):
    key = b'This is a key for the chapol enc'
    keyint= int.from_bytes(key[:12],'little')
    cip=ChaCha20Poly1305(key)
    
    nonceout=bytes(message.payload[-12:])
    nonce_xor = (int.from_bytes(nonceout,'little')&0xFFF)^keyint
    noncein= nonce_xor.to_bytes((nonce_xor.bit_length() + 7) // 8, byteorder='little')
    
    plaintext=cip.decrypt(noncein,message.payload[:-12], nonceout)
    print("Received cipher message: ", hexlify(message.payload))
    print("Received plain message: ", plaintext.decode("utf-8",'ignore'))

mqttBroker = "mqtt.eclipseprojects.io"
client = mqtt.Client("abc")
client.on_message = on_message
client.on_connect= on_connect
client.connect(mqttBroker)

client.subscribe("secret1")
client.loop_forever()
# Besseau Léonard
from Crypto.Random import get_random_bytes

from AE import AE, AE_AES_256_CTR_HMAC_SHA_512, AE_AES_256_CBC_CMAC_AES


def xor_first_bit(data):
    data = bytearray(data)
    data[0] ^= 0xFF
    data = bytes(data)
    return data


def test_encrypt_then_mac(cipher: AE):
    m = b"0123456789ABCDEF"

    # Normal behaviour
    c, t = cipher.Encrypt_then_MAC_encrypt(m)
    m1 = cipher.Encrypt_then_MAC_decrypt(c, t)
    assert m == m1

    # Integrity modification
    c = xor_first_bit(c)
    try:
        m1 = cipher.Encrypt_then_MAC_decrypt(c, t)
        raise Exception("Modification not detected")
    except ValueError:
        pass

    c, t = cipher.Encrypt_then_MAC_encrypt(m)
    t = xor_first_bit(t)
    try:
        m1 = cipher.Encrypt_then_MAC_decrypt(c, t)
        raise Exception("Modification not detected")
    except ValueError:
        pass

    # IV modification
    c, t = cipher.Encrypt_then_MAC_encrypt(m)
    cipher.iv_encryption = xor_first_bit(cipher.iv_encryption)
    try:
        m1 = cipher.Encrypt_then_MAC_decrypt(c, t)
        raise Exception("Modification not detected")
    except ValueError:
        pass


def test_encrypt_and_mac(cipher: AE):
    m = b"0123456789ABCDEF"

    # Normal behaviour
    c, t = cipher.Encrypt_and_MAC_encrypt(m)
    m1 = cipher.Encrypt_and_MAC_decrypt(c, t)
    assert m == m1

    # Integrity modification
    c = xor_first_bit(c)
    try:
        m1 = cipher.Encrypt_and_MAC_decrypt(c, t)
        raise Exception("Modification not detected")
    except ValueError:
        pass

    c, t = cipher.Encrypt_and_MAC_encrypt(m)
    t = xor_first_bit(t)
    try:
        m1 = cipher.Encrypt_and_MAC_decrypt(c, t)
        raise Exception("Modification not detected")
    except ValueError:
        pass

    # IV modification
    c, t = cipher.Encrypt_and_MAC_encrypt(m)
    cipher.iv_encryption = xor_first_bit(cipher.iv_encryption)
    try:
        m1 = cipher.Encrypt_and_MAC_decrypt(c, t)
        raise Exception("Modification not detected")
    except ValueError:
        pass


def test_mac_then_encrypt(cipher: AE):
    m = b"0123456789ABCDEF"

    # Normal behaviour
    c = cipher.MAC_then_encrypt_encrypt(m)
    m1 = cipher.MAC_then_encrypt_decrypt(c)
    assert m == m1

    # Integrity modification
    c = xor_first_bit(c)
    try:
        m1 = cipher.MAC_then_encrypt_decrypt(c)
        raise Exception("Modification not detected")
    except ValueError:
        pass

    # IV modification
    c = cipher.MAC_then_encrypt_encrypt(m)
    cipher.iv_encryption = xor_first_bit(cipher.iv_encryption)
    try:
        m1 = cipher.MAC_then_encrypt_decrypt(c)
        raise Exception("Modification not detected")
    except ValueError:
        pass


def test_ctr():
    encryption_key = get_random_bytes(32)
    hash_key = get_random_bytes(32)
    aead = AE_AES_256_CTR_HMAC_SHA_512(encryption_key, hash_key)

    test_encrypt_then_mac(aead)
    test_encrypt_and_mac(aead)
    test_mac_then_encrypt(aead)


def test_cbc():
    encryption_key = get_random_bytes(32)
    hash_key = get_random_bytes(32)
    aead = AE_AES_256_CBC_CMAC_AES(encryption_key, hash_key)

    test_encrypt_then_mac(aead)
    test_encrypt_and_mac(aead)
    test_mac_then_encrypt(aead)


def size_comparison(message):
    encryption_key = get_random_bytes(32)
    hash_key = get_random_bytes(32)
    cipherCBC = AE_AES_256_CBC_CMAC_AES(encryption_key, hash_key)
    cipherCTR = AE_AES_256_CTR_HMAC_SHA_512(encryption_key, hash_key)

    print("Orginal message size {}".format(len(message)))

    print("{:<20} {:<20} {:<10}".format('Construction', 'AES-CBC', 'AES-CTR'))

    c1a, t1a = cipherCBC.Encrypt_then_MAC_encrypt(message)
    c2a, t2a = cipherCTR.Encrypt_then_MAC_encrypt(message)
    print("{:<20} C:{:<}  T:{:<12} C:{} T:{}".format('Encrypt-then-MAC', len(c1a), len(t1a), len(c2a), len(t2a)))

    c1a, t1a = cipherCBC.Encrypt_and_MAC_encrypt(message)
    c2a, t2a = cipherCTR.Encrypt_and_MAC_encrypt(message)
    print("{:<20} C:{:<}  T:{:<12} C:{} T:{}".format('Encrypt-then-MAC', len(c1a), len(t1a), len(c2a), len(t2a)))

    c1a = cipherCBC.MAC_then_encrypt_encrypt(message)
    c2a = cipherCTR.MAC_then_encrypt_encrypt(message)
    print("{:<20} C:{:<17}  C:{}".format('Encrypt-then-MAC', len(c1a), len(c2a)))


if __name__ == '__main__':
    test_ctr()
    test_cbc()
    print("All test are passing")

    encryption_key = get_random_bytes(32)
    hash_key = get_random_bytes(32)
    aead1 = AE_AES_256_CBC_CMAC_AES(encryption_key, hash_key)
    m = b"crypto = rigolo"
    size_comparison(m)

    m = b"0123456789ABCDEF"
    size_comparison(m)

from Cryptodome.Hash import HMAC,SHA256,SHA1,MD5
msg ="Password1!"
h = MD5.new()
h.update(b'Password1!')
md5_hash = h.digest()
HMAC_SHA1_Salt = b"salt1"
HMAC_SHA256_Salt = b"salt2"

h = HMAC.new(HMAC_SHA1_Salt, digestmod=SHA1)
h.update(md5_hash)
SHA1_HMAC = h.digest()
h = HMAC.new(HMAC_SHA256_Salt, digestmod=SHA256)
h.update(SHA1_HMAC)
SHA256_HMAC = h.hexdigest()
print(SHA256_HMAC)
#h = SHA256.new()
#h.update(SHA256_HMAC.encode('utf-8'))
#print (h.hexdigest())


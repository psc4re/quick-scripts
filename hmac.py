import hashlib
import hmac
hash=raw_input("Hash>")
salt=raw_input("Salt>")
print "HMAC",hmac.new(salt,hash,hashlib.sha1).hexdigest().upper()

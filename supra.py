# !/usr/bin/python3
# Supra Version: 1.7.4
# BackTrack || Host1let || CryptoX


from os import system 

try:
    
    from colorama import Fore as f  
    import socket 
    import requests
    import time
    import builtwith
    import hashlib
    import base64
    import random
    
except ModuleNotFoundError:
    system("pip install colorama && pip install socket && pip install requests && pip install builtwith && pip install base64 && pip install hashlib")

# Show Colors in CMD

system("")    

# Need Functions

tokens = []
chat_ids = []
messages = []

def telegram(text:str):
    if text.startswith("set token"):
        token = text.replace("set token ", "")
        tokens.append(str(token))
        print(f"\n{f.RED}token {f.YELLOW}> {f.CYAN}{token}\n")

    elif text.startswith("set chat id"):
        chat = text.replace("set chat id ", "")
        chat_ids.append(str(chat))
        print(f"\n{f.RED}chat id {f.YELLOW}> {f.CYAN}{chat}\n")
    
    elif text.startswith("set msg"):
        msg = text.replace("set msg ", "")
        messages.append(str(msg))
        print(f"\n{f.RED}message {f.YELLOW}> {f.CYAN}{msg}\n")
        
    elif text == "show-lists":
        print(f.MAGENTA+f"\nTokens List > {str(tokens)}\nChat id Lists > {str(chat_ids)}\nMessages > {str(messages)}\n")
    
    elif text == "clear-all-lists":
        tokens.clear()
        chat_ids.clear()
        messages.clear()
        print(f"{f.WHITE}All Lists Was {f.RED}Clear\n")
    
    elif text == "clear-token":
        tokens.clear()
        print(f"{f.WHITE}Token Lists Was {f.RED}Clear\n")
    
    elif text == "clear-chat-id":
        chat_ids.clear()
        print(f"{f.WHITE}Chat ID Lists Was {f.RED}Clear\n")
    
    elif text == "clear-msg":
        messages.clear()
        print(f"{f.WHITE}Message Lists Was {f.RED}Clear\n")
        
    elif text == "start-bot":
        try:
            _token = "".join(tokens)
            _chat = "".join(chat_ids)
            _msg = "".join(messages)
            
            url = (f"https://api.telegram.org/bot{_token}/sendMessage?chat_id={_chat}&text={_msg}")
            payload = {
                "UrlBox" : url,
                "AgentList" : "Google Chrome",
                "MethodList" : "GET",
                "VersionList" : "HTTP/1.1"
            }
            start = time.time()
            req = requests.post("https://www.httpdebugger.com/tools/ViewHttpHeaders.aspx", payload)
            end = time.time()
            print(f"\n{f.RED}Send {f.YELLOW}: {f.WHITE}True\n{f.RED}Mission end in {f.YELLOW}: {f.WHITE}{end-start:.2f}\n")
        except:
            print(f"{f.RED}Faild ! Please Try Again\n")
        
    
    elif text == "cls" or text == "clear":
        system("cls || clear")
        
    elif text == "time" or text == "date" or text == "t" or text == "d":
        times = time.strftime(f"{f.YELLOW}%H{f.BLUE}:{f.YELLOW}%M{f.BLUE}:{f.YELLOW}%S {f.RED}|| {f.YELLOW}%y{f.BLUE}-{f.YELLOW}%m{f.BLUE}-{f.YELLOW}%d")
        print(f"\n{times}\n")

    elif text == "help" or text == "?":
        print("")
        help_file = open("telegram_help.txt", "r")
        print(help_file.read()) 
        print("")
    
    elif text == "cd .." or text == "cd .. ":
        main()
        
    elif text == "exit" or text == "exit ":
        exit()
        
    else:
        print(f"\n{f.RED}faild\n")
        pass
        
        
def network(text: str):
    if text.startswith("get site -html"):
        site = text.replace("get site -html ", "")
        try:
            start = time.time()
            html = requests.get(site).text
            end = time.time()
            print(f.WHITE,html+"\n\n"+f"{f.RED}mission end in {f.YELLOW}: {f.WHITE}{end-start:.2f}")

        except:
            print(f"{f.RED}Faild ! Please Try Again")

    elif text.startswith("get site -ip"):
        site = text.replace("get site -ip ", "")
        try:
            start = time.time()
            s = socket.gethostbyname(site)
            end = time.time()
            print(f"\n{f.RED}site {f.YELLOW}: {f.WHITE}{site}\n{f.RED}host {f.YELLOW}: {f.WHITE}{s}\n{f.RED}mission end in {f.YELLOW}: {f.WHITE}{end-start:.2f}\n")

        except:
            print(f"\n{f.RED}Faild ! Please Try Again")

    elif text.startswith("get site -s"):
            site = text.replace("get site -s ", "")
            try:
                start = time.time()
                req = requests.get(site).status_code
                end = time.time()
                print("\n"+str(req)+f"{f.RED}\nmission end in {f.YELLOW}: {f.WHITE}{end-start:.2f}\n")

            except:
                print(f"{f.RED}Faild ! Please Try Again")

    elif text.startswith("font"):
        string = text.replace("font ", "")
        def font(txt : str):
            txt = txt.lower()
            t_1 = txt.translate(txt.maketrans("qwertyuiopasdfghjklzxcvbnm", "Qᴡᴇʀᴛʏᴜɪᴏᴘᴀꜱᴅꜰɢʜᴊᴋʟᴢxᴄᴠʙɴᴍ"))
            t_2 = txt.translate(txt.maketrans("qwertyuiopasdfghjklzxcvbnm", "𝖖𝖜𝖊𝖗𝖙𝖞𝖚𝖎𝖔𝖕𝖆𝖘𝖉𝖋𝖌𝖍𝖏𝖐𝖑𝖟𝖝𝖈𝖛𝖇𝖓𝖒"))
            t_3 = txt.translate(txt.maketrans("qwertyuiopasdfghjklzxcvbnm", "𝔮𝔴𝔢𝔯𝔱𝔶𝔲𝔦𝔬𝔭𝔞𝔰𝔡𝔣𝔤𝔥𝔧𝔨𝔩𝔷𝔵𝔠𝔳𝔟𝔫𝔪"))
            t_4 = txt.translate(txt.maketrans("qwertyuiopasdfghjklzxcvbnm", "𝓺𝔀𝓮𝓻𝓽𝔂𝓾𝓲𝓸𝓹𝓪𝓼𝓭𝓯𝓰𝓱𝓳𝓴𝓵𝔃𝔁𝓬𝓿𝓫𝓷𝓶"))
            t_5 = txt.translate(txt.maketrans("qwertyuiopasdfghjklzxcvbnm", "🅀🅆🄴🅁🅃🅈🅄🄸🄾🄿🄰🅂🄳🄵🄶🄷🄹🄺🄻🅉🅇🄲🅅🄱🄽🄼"))
            t_6 = txt.translate(txt.maketrans("qwertyuiopasdfghjklzxcvbnm", "𝐪𝐰𝐞𝐫𝐭𝐲𝐮𝐢𝐨𝐩𝐚𝐬𝐝𝐟𝐠𝐡𝐣𝐤𝐥𝐳𝐱𝐜𝐯𝐛𝐧𝐦"))
            t_7 = txt.translate(txt.maketrans("qwertyuiopasdfghjklzxcvbnm", "𝗾𝘄𝗲𝗿𝘁𝘆𝘂𝗶𝗼𝗽𝗮𝘀𝗱𝗳𝗴𝗵𝗷𝗸𝗹𝘇𝘅𝗰𝘃𝗯𝗻𝗺"))
            t_8 = txt.translate(txt.maketrans("qwertyuiopasdfghjklzxcvbnm", "𝚚𝚠𝚎𝚛𝚝𝚢𝚞𝚒𝚘𝚙𝚊𝚜𝚍𝚏𝚐𝚑𝚓𝚔𝚕𝚣𝚡𝚌𝚟𝚋𝚗𝚖"))
            t_9 = txt.translate(txt.maketrans("qwertyuiopasdfghjklzxcvbnm", "QЩΣЯƬYЦIӨPΛƧDFGΉJKᄂZXᄃVBПM"))
            print(t_1, t_2, t_3, t_4, t_5, t_6, t_7, t_8, t_9)
        print("")
        font(txt=string)
        print("")
        
    elif text.startswith("scan port"):
        _port = text.replace("scan port ", "")
        def open_port(host, port):
            s = socket.socket()
            try:
                s.connect((host, port))
                s.settimeout(0.2)
            except:
                return False
            
            else:
                return True
                
        for port in range(1,1023):
            if open_port(_port, port):
                print(f'{f.BLUE}[{f.RED}+{f.BLUE}] {f.YELLOW}{_port}{f.GREEN}:{f.YELLOW}{port} is open {f.RESET}')
            else:
                print(f'{f.BLUE}[{f.RED}-{f.BLUE}] {f.RED}{_port}{f.GREEN}:{f.RED}{port} is closed {f.RESET}')
                
    
    elif text.startswith("get site full scan"):
        site_Scan = text.replace("get site full scan ", "")
        try:
            start = time.time()
            _info = builtwith.builtwith(site_Scan)
            end = time.time()
            print(_info)
            print("\n"+str(req)+f"{f.RED}\nmission end in {f.YELLOW}: {f.WHITE}{end-start:.2f}\n")
        except:
            print("")
    
    elif text == "time" or text == "date" or text == "t" or text == "d":
        times = time.strftime(f"{f.YELLOW}%H{f.BLUE}:{f.YELLOW}%M{f.BLUE}:{f.YELLOW}%S {f.RED}|| {f.YELLOW}%y{f.BLUE}-{f.YELLOW}%m{f.BLUE}-{f.YELLOW}%d")
        print(f"\n{times}\n")

    elif text == "cls" or text == "clear":
        system("cls || clear")
        
    elif text == "help" or text == "?":
        print("")
        help_file = open("network_help.txt", "r")
        print(help_file.read()) 
        print("")

    
    elif text == "cd .." or text == "cd .. ":
        main()
    
    elif text == "exit" or text == "exit ":
        exit()
    
    else:
        print(f"\n{f.RED}faild\n")
        pass
    

def encrypt(text : str):
    
    if text.startswith("-b64"):
        new_text = text.replace("-b64 ", "")
        print("")
        print(base64.b64encode(new_text.encode("ascii")))
        print("")
        
    elif text.startswith("-b32"):
        new_text = text.replace("-b32 ", "")
        print("")
        print(base64.b32encode(new_text.encode("ascii")))
        print("")
        
    elif text.startswith("-b16"):
        new_text = text.replace("-b16 ", "")
        print("")
        print(base64.b16encode(new_text.encode("ascii")))
        print("")
        
    elif text.startswith("-b85"):
        new_text = text.replace("-b85 ", "")
        print("")
        print(base64.b85encode(new_text.encode("ascii")))
        print("")
        
    elif text.startswith("-md5"):
        new_text = text.replace("-md5 ", "")
        strTomd5 = hashlib.md5()
        strTomd5.update(new_text.encode("utf-8"))
        print("")
        print(strTomd5.hexdigest())
        print("")
        
    elif text.startswith("-sha256"):
        new_text = text.replace("-sha256 ", "")
        strTo256 = hashlib.sha256()
        strTo256.update(new_text.encode("utf-8"))
        print("")
        print(strTo256.hexdigest())
        print("")
        
    elif text.startswith("-sha224"):
        new_text = text.replace("-sha224 ", "")
        strTo224 = hashlib.sha224()
        strTo224.update(new_text.encode('utf-8'))
        print("")
        print(strTo224.hexdigest())
        print("")
        
    elif text.startswith("-sha1"):
        new_text = text.replace("-sha1 ","")
        strTo1 = hashlib.sha1()
        strTo1.update(new_text.encode('utf-8'))
        print("")
        print(strTo1.hexdigest())
        print("")
        
    elif text.startswith("-sha512"):
        new_text = text.replace("-sha512 ", "")
        strTo512 = hashlib.sha512()
        strTo512.update(new_text.encode("utf-8"))
        print("")
        print(strTo512.hexdigest())
        print("")
        
    elif text.startswith("-sha384"):
        new_text = text.replace("-sha384 ", "")
        strTo384 = hashlib.sha384()
        strTo384.update(new_text.encode("utf-8"))
        print("")
        print(strTo384.hexdigest())
        print("")
    
    elif text.startswith("-sha3_256"):
        new_text = text.replace("-sha3_256 ", "")
        strTo3286 = hashlib.sha3_256()
        strTo3286.update(new_text.encode('utf-8'))
        print("")
        print(strTo3286.hexdigest())
        print("")
    
    elif text.startswith("font"):
        string = text.replace("font ", "")
        def font(txt : str):
            txt = txt.lower()
            t_1 = txt.translate(txt.maketrans("qwertyuiopasdfghjklzxcvbnm", "Qᴡᴇʀᴛʏᴜɪᴏᴘᴀꜱᴅꜰɢʜᴊᴋʟᴢxᴄᴠʙɴᴍ"))
            t_2 = txt.translate(txt.maketrans("qwertyuiopasdfghjklzxcvbnm", "𝖖𝖜𝖊𝖗𝖙𝖞𝖚𝖎𝖔𝖕𝖆𝖘𝖉𝖋𝖌𝖍𝖏𝖐𝖑𝖟𝖝𝖈𝖛𝖇𝖓𝖒"))
            t_3 = txt.translate(txt.maketrans("qwertyuiopasdfghjklzxcvbnm", "𝔮𝔴𝔢𝔯𝔱𝔶𝔲𝔦𝔬𝔭𝔞𝔰𝔡𝔣𝔤𝔥𝔧𝔨𝔩𝔷𝔵𝔠𝔳𝔟𝔫𝔪"))
            t_4 = txt.translate(txt.maketrans("qwertyuiopasdfghjklzxcvbnm", "𝓺𝔀𝓮𝓻𝓽𝔂𝓾𝓲𝓸𝓹𝓪𝓼𝓭𝓯𝓰𝓱𝓳𝓴𝓵𝔃𝔁𝓬𝓿𝓫𝓷𝓶"))
            t_5 = txt.translate(txt.maketrans("qwertyuiopasdfghjklzxcvbnm", "🅀🅆🄴🅁🅃🅈🅄🄸🄾🄿🄰🅂🄳🄵🄶🄷🄹🄺🄻🅉🅇🄲🅅🄱🄽🄼"))
            t_6 = txt.translate(txt.maketrans("qwertyuiopasdfghjklzxcvbnm", "𝐪𝐰𝐞𝐫𝐭𝐲𝐮𝐢𝐨𝐩𝐚𝐬𝐝𝐟𝐠𝐡𝐣𝐤𝐥𝐳𝐱𝐜𝐯𝐛𝐧𝐦"))
            t_7 = txt.translate(txt.maketrans("qwertyuiopasdfghjklzxcvbnm", "𝗾𝘄𝗲𝗿𝘁𝘆𝘂𝗶𝗼𝗽𝗮𝘀𝗱𝗳𝗴𝗵𝗷𝗸𝗹𝘇𝘅𝗰𝘃𝗯𝗻𝗺"))
            t_8 = txt.translate(txt.maketrans("qwertyuiopasdfghjklzxcvbnm", "𝚚𝚠𝚎𝚛𝚝𝚢𝚞𝚒𝚘𝚙𝚊𝚜𝚍𝚏𝚐𝚑𝚓𝚔𝚕𝚣𝚡𝚌𝚟𝚋𝚗𝚖"))
            t_9 = txt.translate(txt.maketrans("qwertyuiopasdfghjklzxcvbnm", "QЩΣЯƬYЦIӨPΛƧDFGΉJKᄂZXᄃVBПM"))
            print(t_1, t_2, t_3, t_4, t_5, t_6, t_7, t_8, t_9)
        print("")
        font(txt=string)
        print("")
    
    elif text == "time" or text == "date" or text == "t" or text == "d":
        times = time.strftime(f"{f.YELLOW}%H{f.BLUE}:{f.YELLOW}%M{f.BLUE}:{f.YELLOW}%S {f.RED}|| {f.YELLOW}%y{f.BLUE}-{f.YELLOW}%m{f.BLUE}-{f.YELLOW}%d")
        print(f"\n{times}\n")

    elif text == "cls" or text == "clear":
        system("cls || clear")
        
    elif text == "help" or text == "?":
        print("")
        help_file = open("encrypt_help.txt", "r")
        print(help_file.read()) 
        print("")

    
    elif text == "cd .." or text == "cd .. ":
        main()
        
    elif text == "exit" or text == "exit ":
        exit()
    
    else:
        print(f"\n{f.RED}faild\n")
        pass

def decrypt(text : str):
    if text.startswith("-b64"):
        m = text.replace("-b64 ", "")
        print("")
        print(base64.b64decode(m.encode("utf-8")))
        print("")
    
    elif text.startswith("-b32"):
        m = text.replace("-b32 ", "")
        print("")
        print(base64.b32decode(m.encode("utf-8")))
        print("")
    
    elif text.startswith("-b16"):
        m = text.replace("-b16 ", "")
        print("")
        print(base64.b16decode(m.encode("utf-8")))
        print("")
    
    elif text.startswith("-b85"):
        m = text.replace("-b85 ", "")
        print("")
        print(base64.b85decode(m.encode("utf-8")))
        print("")
        
    elif text.startswith("-utf-8"):
        m = text.replace("-b85 ", "")
        print("")
        print(m.encode("utf-8"))
        print("")
    
    elif text.startswith("font"):
        string = text.replace("font ", "")
        def font(txt : str):
            txt = txt.lower()
            t_1 = txt.translate(txt.maketrans("qwertyuiopasdfghjklzxcvbnm", "Qᴡᴇʀᴛʏᴜɪᴏᴘᴀꜱᴅꜰɢʜᴊᴋʟᴢxᴄᴠʙɴᴍ"))
            t_2 = txt.translate(txt.maketrans("qwertyuiopasdfghjklzxcvbnm", "𝖖𝖜𝖊𝖗𝖙𝖞𝖚𝖎𝖔𝖕𝖆𝖘𝖉𝖋𝖌𝖍𝖏𝖐𝖑𝖟𝖝𝖈𝖛𝖇𝖓𝖒"))
            t_3 = txt.translate(txt.maketrans("qwertyuiopasdfghjklzxcvbnm", "𝔮𝔴𝔢𝔯𝔱𝔶𝔲𝔦𝔬𝔭𝔞𝔰𝔡𝔣𝔤𝔥𝔧𝔨𝔩𝔷𝔵𝔠𝔳𝔟𝔫𝔪"))
            t_4 = txt.translate(txt.maketrans("qwertyuiopasdfghjklzxcvbnm", "𝓺𝔀𝓮𝓻𝓽𝔂𝓾𝓲𝓸𝓹𝓪𝓼𝓭𝓯𝓰𝓱𝓳𝓴𝓵𝔃𝔁𝓬𝓿𝓫𝓷𝓶"))
            t_5 = txt.translate(txt.maketrans("qwertyuiopasdfghjklzxcvbnm", "🅀🅆🄴🅁🅃🅈🅄🄸🄾🄿🄰🅂🄳🄵🄶🄷🄹🄺🄻🅉🅇🄲🅅🄱🄽🄼"))
            t_6 = txt.translate(txt.maketrans("qwertyuiopasdfghjklzxcvbnm", "𝐪𝐰𝐞𝐫𝐭𝐲𝐮𝐢𝐨𝐩𝐚𝐬𝐝𝐟𝐠𝐡𝐣𝐤𝐥𝐳𝐱𝐜𝐯𝐛𝐧𝐦"))
            t_7 = txt.translate(txt.maketrans("qwertyuiopasdfghjklzxcvbnm", "𝗾𝘄𝗲𝗿𝘁𝘆𝘂𝗶𝗼𝗽𝗮𝘀𝗱𝗳𝗴𝗵𝗷𝗸𝗹𝘇𝘅𝗰𝘃𝗯𝗻𝗺"))
            t_8 = txt.translate(txt.maketrans("qwertyuiopasdfghjklzxcvbnm", "𝚚𝚠𝚎𝚛𝚝𝚢𝚞𝚒𝚘𝚙𝚊𝚜𝚍𝚏𝚐𝚑𝚓𝚔𝚕𝚣𝚡𝚌𝚟𝚋𝚗𝚖"))
            t_9 = txt.translate(txt.maketrans("qwertyuiopasdfghjklzxcvbnm", "QЩΣЯƬYЦIӨPΛƧDFGΉJKᄂZXᄃVBПM"))
            print(t_1, t_2, t_3, t_4, t_5, t_6, t_7, t_8, t_9)
        print("")
        font(txt=string)
        print("")
    
    elif text == "time" or text == "date" or text == "t" or text == "d":
        times = time.strftime(f"{f.YELLOW}%H{f.BLUE}:{f.YELLOW}%M{f.BLUE}:{f.YELLOW}%S {f.RED}|| {f.YELLOW}%y{f.BLUE}-{f.YELLOW}%m{f.BLUE}-{f.YELLOW}%d")
        print(f"\n{times}\n")

    elif text == "cls" or text == "clear":
        system("cls || clear")
        
    elif text == "help" or text == "?":
        print("")
        help_file = open("decrypt_help.txt", "r")
        print(help_file.read()) 
        print("")

    
    elif text == "cd .." or text == "cd .. ":
        main()
    
    elif text == "exit" or text == "exit ":
        exit()
    
    else:
        print(f"\n{f.RED}faild\n")
        pass


def gen(text : str):
    if text in ("-p", "--password"):
        lower_case = "abcdefghijklmnopqrstuvwxyz"
        upper_case = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        number = "0123456789"
        symbols = "@#$%&/\?"
        User_for = lower_case + upper_case + number + symbols
        nums = [7, 8, 9, 10 ,11, 12, 13, 14, 15, 16, 17, 18, 19, 20]
        password = "".join(random.sample(User_for, random.choice(nums)))
        print(password)
        
    elif text in ("-w", "--word"):
        lower_case = "abcdefghijklmnopqrstuvwxyz"
        upper_case = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        user_for = lower_case + upper_case 
        nums = [7, 8, 9, 10 ,11, 12, 13, 14, 15, 16, 17, 18, 19, 20]
        password = "".join(random.sample(user_for, random.choice(nums)))
        print(password)
        
    elif text in ("-uw", "--upper-word"):
        upper_case = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        nums = [7, 8, 9, 10 ,11, 12, 13, 14, 15, 16, 17, 18, 19, 20]
        password = "".join(random.sample(upper_case, random.choice(nums)))
        print(password)
        
    elif text in ("-lw", "--lower-word"):
        lower_case = "abcdefghijklmnopqrstuvwxyz"
        nums = [7, 8, 9, 10 ,11, 12, 13, 14, 15, 16, 17, 18, 19, 20]
        password = "".join(random.sample(lower_case, random.choice(nums)))
        print(password)
        
    elif text in ("-i", "--integer"):
        number = "0123456789"
        nums = [7, 8, 9, 10 ,11, 12, 13, 14, 15, 16, 17, 18, 19, 20]
        password = "".join(random.sample(number, random.choice(nums)))
        print(password)
        
    elif text in ("-is", "--integer-symbol"):
        number = "0123456789"
        symbols = "@#$%&/\?"
        se = number + symbols
        nums = [7, 8, 9, 10 ,11, 12, 13, 14, 15, 16, 17, 18, 19, 20]
        password = "".join(random.sample(se, random.choice(nums)))
        print(password)
        
    elif text in ("-s", "--symbol"):
        symbols = "@#$%&/\?"
        nums = [7, 8, 9, 10 ,11, 12, 13, 14, 15, 16, 17, 18, 19, 20]
        password = "".join(random.sample(symbols, random.choice(nums)))
        print(password)
        
    elif text in ("-ws", "--word-symbol"):
        symbols = "@#$%&/\?"
        upper_case = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        lower_case = "abcdefghijklmnopqrstuvwxyz"
        User_for = lower_case + upper_case + symbols
        nums = [7, 8, 9, 10 ,11, 12, 13, 14, 15, 16, 17, 18, 19, 20]
        password = "".join(random.sample(User_for, random.choice(nums)))
        print(password)
        
    elif text in ("-lws", "--lower-word-symbol"):
        lower_case = "abcdefghijklmnopqrstuvwxyz"
        symbols = "@#$%&/\?"
        se = lower_case + symbols
        nums = [7, 8, 9, 10 ,11, 12, 13, 14, 15, 16, 17, 18, 19, 20]
        password = "".join(random.sample(se, random.choice(nums)))
        print(password)
        
    elif text in ("-uws", "--upper-word-symbol"):
        upper_case = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        symbols = "@#$%&/\?"
        se = upper_case + symbols
        nums = [7, 8, 9, 10 ,11, 12, 13, 14, 15, 16, 17, 18, 19, 20]
        password = "".join(random.sample(se, random.choice(nums)))
        print(password)
        
    elif text in ("-iw", "--integer-word"):
        upper_case = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        lower_case = "abcdefghijklmnopqrstuvwxyz"
        number = "0123456789"
        se = upper_case + lower_case + number
        nums = [7, 8, 9, 10 ,11, 12, 13, 14, 15, 16, 17, 18, 19, 20]
        password = "".join(random.sample(se, random.choice(nums)))
        print(password)
    
    elif text in ("-lwi", "--lower-word-integer"):
        lower_case = "abcdefghijklmnopqrstuvwxyz"
        number = "0123456789"
        se = lower_case + number
        nums = [7, 8, 9, 10 ,11, 12, 13, 14, 15, 16, 17, 18, 19, 20]
        password = "".join(random.sample(se, random.choice(nums)))
        print(password)
        
    elif text in ("-uwi", "--upper-word-integer"):
        upper_case = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        number = "0123456789"
        se = upper_case + number
        nums = [7, 8, 9, 10 ,11, 12, 13, 14, 15, 16, 17, 18, 19, 20]
        password = "".join(random.sample(se, random.choice(nums)))
        print(password)
    
    elif text.startswith("font"):
        string = text.replace("font ", "")
        def font(txt : str):
            txt = txt.lower()
            t_1 = txt.translate(txt.maketrans("qwertyuiopasdfghjklzxcvbnm", "Qᴡᴇʀᴛʏᴜɪᴏᴘᴀꜱᴅꜰɢʜᴊᴋʟᴢxᴄᴠʙɴᴍ"))
            t_2 = txt.translate(txt.maketrans("qwertyuiopasdfghjklzxcvbnm", "𝖖𝖜𝖊𝖗𝖙𝖞𝖚𝖎𝖔𝖕𝖆𝖘𝖉𝖋𝖌𝖍𝖏𝖐𝖑𝖟𝖝𝖈𝖛𝖇𝖓𝖒"))
            t_3 = txt.translate(txt.maketrans("qwertyuiopasdfghjklzxcvbnm", "𝔮𝔴𝔢𝔯𝔱𝔶𝔲𝔦𝔬𝔭𝔞𝔰𝔡𝔣𝔤𝔥𝔧𝔨𝔩𝔷𝔵𝔠𝔳𝔟𝔫𝔪"))
            t_4 = txt.translate(txt.maketrans("qwertyuiopasdfghjklzxcvbnm", "𝓺𝔀𝓮𝓻𝓽𝔂𝓾𝓲𝓸𝓹𝓪𝓼𝓭𝓯𝓰𝓱𝓳𝓴𝓵𝔃𝔁𝓬𝓿𝓫𝓷𝓶"))
            t_5 = txt.translate(txt.maketrans("qwertyuiopasdfghjklzxcvbnm", "🅀🅆🄴🅁🅃🅈🅄🄸🄾🄿🄰🅂🄳🄵🄶🄷🄹🄺🄻🅉🅇🄲🅅🄱🄽🄼"))
            t_6 = txt.translate(txt.maketrans("qwertyuiopasdfghjklzxcvbnm", "𝐪𝐰𝐞𝐫𝐭𝐲𝐮𝐢𝐨𝐩𝐚𝐬𝐝𝐟𝐠𝐡𝐣𝐤𝐥𝐳𝐱𝐜𝐯𝐛𝐧𝐦"))
            t_7 = txt.translate(txt.maketrans("qwertyuiopasdfghjklzxcvbnm", "𝗾𝘄𝗲𝗿𝘁𝘆𝘂𝗶𝗼𝗽𝗮𝘀𝗱𝗳𝗴𝗵𝗷𝗸𝗹𝘇𝘅𝗰𝘃𝗯𝗻𝗺"))
            t_8 = txt.translate(txt.maketrans("qwertyuiopasdfghjklzxcvbnm", "𝚚𝚠𝚎𝚛𝚝𝚢𝚞𝚒𝚘𝚙𝚊𝚜𝚍𝚏𝚐𝚑𝚓𝚔𝚕𝚣𝚡𝚌𝚟𝚋𝚗𝚖"))
            t_9 = txt.translate(txt.maketrans("qwertyuiopasdfghjklzxcvbnm", "QЩΣЯƬYЦIӨPΛƧDFGΉJKᄂZXᄃVBПM"))
            print(t_1, t_2, t_3, t_4, t_5, t_6, t_7, t_8, t_9)
        print("")
        font(txt=string)
        print("")
    
    elif text == "time" or text == "date" or text == "t" or text == "d":
        times = time.strftime(f"{f.YELLOW}%H{f.BLUE}:{f.YELLOW}%M{f.BLUE}:{f.YELLOW}%S {f.RED}|| {f.YELLOW}%y{f.BLUE}-{f.YELLOW}%m{f.BLUE}-{f.YELLOW}%d")
        print(f"\n{times}\n")

    elif text == "cls" or text == "clear":
        system("cls || clear")
        
    elif text == "help" or text == "?":
        print("")
        help_file = open("generator_help.txt", "r")
        print(help_file.read()) 
        print("")

    
    elif text == "cd .." or text == "cd .. ":
        main()
    
    elif text == "exit" or text == "exit ":
        exit()
    
    else:
        print(f"\n{f.RED}faild\n")
        pass



# Banner
red = '\033[31m'
print(f"""{f.RED}
 ___ _   _ _ __  _ __ __ _
/ __| | | | '_ \| '__/ _` |
\__ \ |_| | |_) | | | (_| |
|___/\__,_| .__/|_|  \__,_|
          |_|
          
    {f.RED}+----------------------+
{f.RED}    |   {f.YELLOW}Supra {f.CYAN}FrameWork{f.RED}    |   
{f.RED}    +----------------------+

""")

# Main Function
def main():
    app = str(input(f"{f.WHITE}home{f.YELLOW}/{f.WHITE}terminal{f.YELLOW}/{f.WHITE}Supra {f.YELLOW}> {f.WHITE}"))

    
    if app == "help" or app == "?":
        print("")
        help_file = open("help.txt", "r")
        print(help_file.read()) 
        main() 
    
    
    elif app == "cls" or app == "clear":
        system("cls || clear")
        main()
    
    elif app == "cd network" or app == "cd net":
        while 1:
            net_app = str(input(f"{f.WHITE}home{f.YELLOW}/{f.WHITE}terminal{f.YELLOW}/{f.WHITE}Supra{f.YELLOW}/{f.WHITE}network {f.YELLOW}> {f.WHITE}"))    
            network(text=net_app)

        
        

        
            
    elif app.startswith("font"):
        text = app.replace("font ", "")
        def font(text : str):
            text = text.lower()
            t_1 = text.translate(text.maketrans("qwertyuiopasdfghjklzxcvbnm", "Qᴡᴇʀᴛʏᴜɪᴏᴘᴀꜱᴅꜰɢʜᴊᴋʟᴢxᴄᴠʙɴᴍ"))
            t_2 = text.translate(text.maketrans("qwertyuiopasdfghjklzxcvbnm", "𝖖𝖜𝖊𝖗𝖙𝖞𝖚𝖎𝖔𝖕𝖆𝖘𝖉𝖋𝖌𝖍𝖏𝖐𝖑𝖟𝖝𝖈𝖛𝖇𝖓𝖒"))
            t_3 = text.translate(text.maketrans("qwertyuiopasdfghjklzxcvbnm", "𝔮𝔴𝔢𝔯𝔱𝔶𝔲𝔦𝔬𝔭𝔞𝔰𝔡𝔣𝔤𝔥𝔧𝔨𝔩𝔷𝔵𝔠𝔳𝔟𝔫𝔪"))
            t_4 = text.translate(text.maketrans("qwertyuiopasdfghjklzxcvbnm", "𝓺𝔀𝓮𝓻𝓽𝔂𝓾𝓲𝓸𝓹𝓪𝓼𝓭𝓯𝓰𝓱𝓳𝓴𝓵𝔃𝔁𝓬𝓿𝓫𝓷𝓶"))
            t_5 = text.translate(text.maketrans("qwertyuiopasdfghjklzxcvbnm", "🅀🅆🄴🅁🅃🅈🅄🄸🄾🄿🄰🅂🄳🄵🄶🄷🄹🄺🄻🅉🅇🄲🅅🄱🄽🄼"))
            t_6 = text.translate(text.maketrans("qwertyuiopasdfghjklzxcvbnm", "𝐪𝐰𝐞𝐫𝐭𝐲𝐮𝐢𝐨𝐩𝐚𝐬𝐝𝐟𝐠𝐡𝐣𝐤𝐥𝐳𝐱𝐜𝐯𝐛𝐧𝐦"))
            t_7 = text.translate(text.maketrans("qwertyuiopasdfghjklzxcvbnm", "𝗾𝘄𝗲𝗿𝘁𝘆𝘂𝗶𝗼𝗽𝗮𝘀𝗱𝗳𝗴𝗵𝗷𝗸𝗹𝘇𝘅𝗰𝘃𝗯𝗻𝗺"))
            t_8 = text.translate(text.maketrans("qwertyuiopasdfghjklzxcvbnm", "𝚚𝚠𝚎𝚛𝚝𝚢𝚞𝚒𝚘𝚙𝚊𝚜𝚍𝚏𝚐𝚑𝚓𝚔𝚕𝚣𝚡𝚌𝚟𝚋𝚗𝚖"))
            t_9 = text.translate(text.maketrans("qwertyuiopasdfghjklzxcvbnm", "QЩΣЯƬYЦIӨPΛƧDFGΉJKᄂZXᄃVBПM"))
            print(t_1, t_2, t_3, t_4, t_5, t_6, t_7, t_8, t_9)
        print("")
        font(text=text)
        print("")
        main()
        
    elif app == "time" or app == "date" or app == "t" or app == "d":
        times = time.strftime(f"{f.YELLOW}%H{f.BLUE}:{f.YELLOW}%M{f.BLUE}:{f.YELLOW}%S {f.RED}|| {f.YELLOW}%y{f.BLUE}-{f.YELLOW}%m{f.BLUE}-{f.YELLOW}%d")
        print(f"\n{times}\n")
        main()
        
    elif app == "cd telegram" or app == "cd tel":
        while 1:
            tel_app = str(input(f"{f.WHITE}home{f.YELLOW}/{f.WHITE}terminal{f.YELLOW}/{f.WHITE}Supra{f.YELLOW}/{f.WHITE}telegram {f.YELLOW}> {f.WHITE}"))
            telegram(text=tel_app)
            
    
    elif app == "cd encrypt" or app == "cd enc":
        while 1:
            en_app = str(input(f"{f.WHITE}home{f.YELLOW}/{f.WHITE}terminal{f.YELLOW}/{f.WHITE}Supra{f.YELLOW}/{f.WHITE}encrypt {f.YELLOW}> {f.WHITE}"))
            encrypt(text=en_app)
            
    elif app == "cd decrypt" or app == "cd dec":
        while 1:
            de_app = str(input(f"{f.WHITE}home{f.YELLOW}/{f.WHITE}terminal{f.YELLOW}/{f.WHITE}Supra{f.YELLOW}/{f.WHITE}decrypt {f.YELLOW}> {f.WHITE}"))
            decrypt(text=de_app)
            
    elif app == "cd generator" or app == "cd gen":
        while 1:
            rand_app = str(input(f"{f.WHITE}home{f.YELLOW}/{f.WHITE}terminal{f.YELLOW}/{f.WHITE}Supra{f.YELLOW}/{f.WHITE}generator {f.YELLOW}> {f.WHITE}"))
            gen(text=rand_app)
            
    elif app.startswith("send post"):
        site = app.replace("send post ", "")
        try:
            site_payload = {
                "UrlBox" : site,
                "AgentList" : "Google Chrome",
                "VersionList" : "HTTP/1.1",
                "MethodList" : "GET"
            }
            start = time.time()
            req = requests.post("https://www.httpdebugger.com/tools/ViewHttpHeaders.aspx", site_payload)
            end = time.time()
            print(f"\n{f.RED}Url {f.YELLOW}: {f.WHITE}{site}\n{f.RED}Send {f.YELLOW}: {f.WHITE}True\n{f.RED}Mission end in {f.YELLOW}: {f.WHITE}{end-start:.2f}\n")
            main()
        except:
            print(f"{f.RED}Faild ! Please Try Again")
            main()
    
    elif app == "exit" or app == "exit ":
        exit()
    
    else:
        print(f"\n{f.RED}faild\n")
        main()


# Start Main Function

main()

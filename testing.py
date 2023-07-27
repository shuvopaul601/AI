import speech_recognition as sr
import pyttsx3
import datetime
import wikipedia
import webbrowser
import os
import socket
import dns.resolver
from urllib.parse import urlparse
import threading
import ipaddress
import time
import subprocess
from ecapture import ecapture as ec
import wolframalpha
import json
import hashlib
import requests
import argparse
from unittest import result
import phonenumbers
from opencage.geocoder import OpenCageGeocode
from phonenumbers import carrier, geocoder, timezone
from AppOpener import open

# Initialize the text-to-speech engine
engine = pyttsx3.init('sapi5')
voices = engine.getProperty('voices')
engine.setProperty('voice', voices[1].id)  # id = 0 for male, id = 1 for female.


def speak(text):
    """
    Use the text-to-speech engine to speak the given text.
    """
    engine.say(text)
    engine.runAndWait()


def wishMe():
    """
    Greet the user based on the current time.
    """
    hour = datetime.datetime.now().hour
    if 0 <= hour < 12:
        speak("Hello, good morning.")
        print("Hello, good morning.")
    elif 12 <= hour < 18:
        speak("Hello, good afternoon.")
        print("Hello, good afternoon.")
    else:
        speak("Hello, good evening.")
        print("Hello, good evening.")


def takeCommand():
    """
    Use speech recognition to listen for a command from the user.
    """
    r = sr.Recognizer()
    with sr.Microphone() as source:
        print("Listening...")
        audio = r.listen(source)

        try:
            statement = r.recognize_google(audio, language='en-in')
            print(f"User said: {statement}\n")

        except Exception as e:
            speak("Pardon me, please say that again.")
            return "None"
        return statement.lower()


print("Loading your AI personal assistant G-One.")
speak("Loading your AI personal assistant G-One.")
wishMe()

if __name__ == '__main__':

    while True:
        speak("Tell me, how can I help you now?")
        statement = takeCommand()
        if statement == 0:
            continue

        if 'open camera' in statement or 'camera' in statement:
            open('CAMERA')
            speak('camera opened sir')

        if 'open calculator' in statement or 'calculator' in statement:
            open('CALCULATOR')
            speak('calculator opened sir')

        if 'open command prompt' in statement or 'command prompt' in statement:
            open('COMMAND PROMPT')
            speak('command prompt opened sir')

        if 'show Wi-Fi networks' in statement or 'Wi-Fi networks' in statement:
            def get_available_networks():
                output = subprocess.check_output(['netsh', 'wlan', 'show', 'networks'])
                networks = []
                lines = output.decode().split('\r\n')
                for i in range(len(lines)):
                    if 'SSID' in lines[i]:
                        ssid = lines[i].split(':')[1].strip()
                        networks.append(ssid)
                return networks


            networks = get_available_networks()
            print(f"Found {len(networks)} networks:")
            for network in networks:
                print(network)


        if 'wikipedia' in statement:
            speak('Searching Wikipedia...')
            statement = statement.replace("wikipedia", "")
            results = wikipedia.summary(statement, sentences=3)
            speak("According to Wikipedia,")
            print(results)
            speak(results)

        elif 'open youtube' in statement:
            webbrowser.open_new_tab("https://www.youtube.com")
            speak("YouTube is open now.")
            time.sleep(5)

        elif 'open google' in statement or 'google' in statement:
            webbrowser.open_new_tab("https://www.google.com")
            speak("Google Chrome is open now.")
            time.sleep(5)

        elif 'open gmail' in statement or 'gmail' in statement or 'gmail open' in statement:
            webbrowser.open_new_tab("https://www.gmail.com")
            speak("Google Mail is open now.")
            time.sleep(5)

        elif 'open whatsapp' in statement or 'whatsapp' in statement:
            open("whatsapp")
            speak('whatsapp opened')

        elif 'open telegram' in statement or 'telegram' in statement:
            open('telegram desktop')
            speak('telegram opened')


        elif 'time' in statement:
            strTime = datetime.datetime.now().strftime("%H:%M:%S")
            speak(f"The time is {strTime}")

        elif 'search' in statement:
            statement = statement.replace("search", "")
            webbrowser.open_new_tab(statement)
            time.sleep(5)

        elif 'find my ip' in statement or 'my ip' in statement:
            def get_ip():
                response = requests.get('https://api64.ipify.org?format=json').json()
                return response["ip"]


            def get_location():
                ip_address = get_ip()
                response = requests.get(f'https://ipapi.co/{ip_address}/json/').json()
                location_data = {
                    "ip": ip_address,
                    "city": response.get("city"),
                    "region": response.get("region"),
                    "country": response.get("country_name")
                }
                return location_data


            print(get_location())

        elif 'ip lookup' in statement or 'open ip lookup' in statement or 'iplookup' in statement:
            def get_ip_addresses(url):
                # Extract domain from URL
                parsed_url = urlparse(url)
                domain = parsed_url.netloc

                ip_addresses = []

                # Lookup domain
                try:
                    domain_ips = socket.gethostbyname_ex(domain)[-1]
                    ip_addresses.extend(domain_ips)
                except socket.gaierror:
                    pass

                # Lookup subdomains
                try:
                    answers = dns.resolver.resolve(domain, 'A')
                    subdomain_ips = [str(answer) for answer in answers]
                    ip_addresses.extend(subdomain_ips)
                except dns.resolver.NoAnswer:
                    pass

                return ip_addresses


            # Prompt for user input
            website_url = input("Enter the URL or domain name: ")
            ip_addresses = get_ip_addresses(website_url)

            if ip_addresses:
                print(f"The IP addresses of {website_url} and its subdomains are:")
                for ip_address in ip_addresses:
                    print(ip_address)
            else:
                print(f"Failed to retrieve the IP addresses of {website_url} and its subdomains")


        elif 'phone number trace' in statement or 'number trace' in statement or 'trace number' in statement:
            def main():
                parser = argparse.ArgumentParser()
                parser.add_argument('-i', '--input', required=True, type=str,
                                    help='path to the input file')
                parser.add_argument('-o', '--output', required=True, type=str,
                                    help='path to the output file')
                args = parser.parse_args()

                # MAIN WORK


            speak("Enter the target number with country code")
            target = input("ENTER THE TARGET NUMBER WITH COUNTRY COD :")
            c_h = phonenumbers.parse(target, "CH")
            locations = (geocoder.description_for_number(c_h, 'en'))
            print("THIS IS YOUR TARGET COUNTRY:" + locations)
            LO = timezone.time_zones_for_number(c_h)
            print("THIS IS YOUR TARGET TIME ZONE:" + str(LO))
            service_provider = phonenumbers.parse(target, "RO")
            print("THIS IS YOUR TARGET SIM PROVIDER :" + carrier.name_for_number(service_provider, "en"))
            key = 'bbbafb3514fd43229acc391a2b5477e1'
            geocoder = OpenCageGeocode(key)
            qeari = str(locations)
            result_s = geocoder.geocode(qeari)
            lat = result_s[0]["geometry"]["lat"]
            lng = result_s[0]["geometry"]["lng"]
            print("THIS IS YOUR TARGET LATITUDE AND LONGITUD:" + str(lat), lng)


        elif 'angry ip scanner' in statement or 'open ip scanner' in statement:
            def scan(ip, port):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.5)
                    s.connect((ip, port))
                    print(f"{ip}:{port} is open")
                    s.close()
                except:
                    pass


            def get_network(ip):
                # Get the network address and mask from the IP address
                ip_net = ipaddress.IPv4Network(ip, strict=False)
                return ip_net


            def get_all_ips_in_network(network):
                # Get a list of all IP addresses in the network
                all_ips = []
                for ip in network.hosts():
                    all_ips.append(str(ip))
                return all_ips


            def angry_ip_scanner(ip):
                # Get the network and all IP addresses in the network
                network = get_network(ip)
                all_ips = get_all_ips_in_network(network)

                # Display the number of IP addresses in the network
                print(f"Total number of IP addresses in the network: {len(all_ips)}")

                # Scan all IP addresses in the network
                for ip in all_ips:
                    for port in range(1, 65536):
                        t = threading.Thread(target=scan, args=(ip, port))
                        t.start()


            if __name__ == '__main__':
                speak('Please enter the Ip address sir')
                ip = input("Enter an IP address to scan: ")
                angry_ip_scanner(ip)


        # elif 'nmap open' in statement or 'nmap' in statement or 'open nmap' in statement or 'open in map' in statement or 'in map' in statement:

        elif 'check hash' in statement or 'hash check' in statement or 'hash type' in statement or 'hash' in statement or 'algorithm check' in statement:
            def identify_hash_type(hash_str):
                # List of common hash algorithms and their digest sizes in bytes
                hash_algos = {
                    ('md5', hashlib.md5().digest_size),
                    ('sha1', hashlib.sha1().digest_size),
                    ('sha224', hashlib.sha224().digest_size),
                    ('sha256', hashlib.sha256().digest_size),
                    ('sha384', hashlib.sha384().digest_size),
                    ('sha512', hashlib.sha512().digest_size),
                    ('blake2b', hashlib.blake2b().digest_size),
                    ('blake2s', hashlib.blake2s().digest_size),
                    ('shake_256', hashlib.shake_256().digest_size),
                    ('md5', hashlib.md5().digest_size),
                    ('md4', hashlib.new('md4').digest_size),
                    ('mdc2', hashlib.new('mdc2').digest_size),
                    ('ripemd160', hashlib.new('ripemd160').digest_size),
                    ('whirlpool', hashlib.new('whirlpool').digest_size),
                    ('blake2s256', hashlib.blake2s(digest_size=32).digest_size),
                    ('blake2b160', hashlib.blake2b(digest_size=20).digest_size),
                    ('blake2b256', hashlib.blake2b(digest_size=32).digest_size),
                    ('blake2b384', hashlib.blake2b(digest_size=48).digest_size),
                    ('blake2b512', hashlib.blake2b(digest_size=64).digest_size),
                    ('sha3_384t', hashlib.sha3_384().digest_size),
                    ('sha3_512t', hashlib.sha3_512().digest_size),
                    ('sha3_224t', hashlib.sha3_224().digest_size),
                    ('sha3_256t', hashlib.sha3_256().digest_size),
                    ('sha3_384t', hashlib.sha3_384().digest_size),
                    ('sha3_512t', hashlib.sha3_512().digest_size),
                    ('md5t', hashlib.md5().digest_size),
                    ('sha1t', hashlib.sha1().digest_size),
                    ('sha224t', hashlib.sha224().digest_size),
                    ('sha256t', hashlib.sha256().digest_size),
                    ('sha384t', hashlib.sha384().digest_size),
                    ('sha512t', hashlib.sha512().digest_size),
                    ('sha3_224t', hashlib.sha3_224().digest_size),
                    ('sha3_256t', hashlib.sha3_256().digest_size),
                }

                # Iterate over each hash algorithm and check if the input hash matches the expected digest size
                for algo, size in hash_algos:
                    if len(hash_str) == size * 2:  # Input hash is in hexadecimal format
                        return algo

                # If the input hash does not match any expected digest size, return None
                return None


            # Get user input for the hash string
            speak('Please enter the hash')
            hash_str = input('Enter the hash string: ')

            # Identify the hash type
            hash_algo = identify_hash_type(hash_str)

            # Print the results
            if hash_algo is not None:
                print(f'The hash {hash_str} was identified as {hash_algo}')


            else:
                print(f'Could not identify the hash type for {hash_str}')


        elif 'temparature converter' in statement:
            def celsius_to_fahrenheit(celsius):
                fahrenheit = (celsius * 1.8) + 32
                return fahrenheit


            def fahrenheit_to_celsius(fahrenheit):
                celsius = (fahrenheit - 32) / 1.8
                return celsius


            def celsius_to_kelvin(celsius):
                kelvin = celsius + 273.15
                return kelvin


            def kelvin_to_celsius(kelvin):
                celsius = kelvin - 273.15
                return celsius


            def fahrenheit_to_kelvin(fahrenheit):
                kelvin = (fahrenheit + 459.67) * 5 / 9
                return kelvin


            def kelvin_to_fahrenheit(kelvin):
                fahrenheit = (kelvin * 1.8) - 459.67
                return fahrenheit


            # Prompt user for input
            temperature = float(input("Enter temperature value: "))
            unit = input("Enter temperature unit (C/F/K): ")

            # Convert temperature to Celsius
            if unit.upper() == 'C':
                celsius = temperature
            elif unit.upper() == 'F':
                celsius = fahrenheit_to_celsius(temperature)
            elif unit.upper() == 'K':
                celsius = kelvin_to_celsius(temperature)
            else:
                print("Invalid temperature unit.")
                exit()

            # Convert Celsius to other units
            fahrenheit = celsius_to_fahrenheit(celsius)
            kelvin = celsius_to_kelvin(celsius)

            # Print the converted temperatures
            print("Celsius: ", celsius)
            print("Fahrenheit: ", fahrenheit)
            print("Kelvin: ", kelvin)

        elif 'shut down my laptop' in statement:
            os.system("shutdown /s /t 1")

        elif 'restart my laptop' in statement:
            os.system("shutdown /r /t 1")

        elif 'sleep my laptop' in statement:
            os.system("rundll32.exe powrprof.dll,SetSuspendState 0,1,0")

        if "good bye" in statement or "ok bye" in statement or "stop" in statement or 'exit' in statement or 'exit yourself' in statement:
            speak('your personal assistant G-one is shutting down,Good bye')
            print('your personal assistant G-one is shutting down,Good bye')
            break

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
import hashlib
import requests
import phonenumbers
from opencage.geocoder import OpenCageGeocode
from phonenumbers import carrier, geocoder, timezone
from AppOpener import open, close

# Initialize the text-to-speech engine
engine = pyttsx3.init('sapi5')
voices = engine.getProperty('voices')
engine.setProperty('voice', voices[1].id)  # Female voice

def speak(text):
    engine.say(text)
    engine.runAndWait()

def wish_me():
    hour = datetime.datetime.now().hour
    if 0 <= hour < 12:
        speak("Hello, good morning.")
    elif 12 <= hour < 18:
        speak("Hello, good afternoon.")
    else:
        speak("Hello, good evening.")

def take_command():
    r = sr.Recognizer()
    with sr.Microphone() as source:
        print("Listening...")
        audio = r.listen(source)
        try:
            statement = r.recognize_google(audio, language='en-in')
            print(f"User said: {statement}\n")
        except Exception:
            speak("Pardon me, please say that again.")
            return "None"
        return statement.lower()

def get_available_networks():
    output = subprocess.check_output(['netsh', 'wlan', 'show', 'networks'])
    lines = output.decode().split('\r\n')
    return [line.split(':')[1].strip() for line in lines if 'SSID' in line]

def get_ip():
    return requests.get('https://api64.ipify.org?format=json').json()["ip"]

def get_location():
    ip_address = get_ip()
    response = requests.get(f'https://ipapi.co/{ip_address}/json/').json()
    return {
        "ip": ip_address,
        "city": response.get("city"),
        "region": response.get("region"),
        "country": response.get("country_name")
    }

def get_ip_addresses(url):
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    ip_addresses = []
    try:
        ip_addresses.extend(socket.gethostbyname_ex(domain)[-1])
        answers = dns.resolver.resolve(domain, 'A')
        ip_addresses.extend(str(answer) for answer in answers)
    except Exception:
        pass
    return ip_addresses

def identify_hash_type(hash_str):
    hash_algos = {
        'md5': 32, 'sha1': 40, 'sha224': 56, 'sha256': 64,
        'sha384': 96, 'sha512': 128, 'blake2b': 128, 'blake2s': 64
    }
    for algo, size in hash_algos.items():
        if len(hash_str) == size:
            return algo
    return None

def convert_temperature():
    temperature = float(input("Enter temperature value: "))
    unit = input("Enter unit (C/F/K): ").upper()
    if unit == 'C':
        celsius = temperature
    elif unit == 'F':
        celsius = (temperature - 32) / 1.8
    elif unit == 'K':
        celsius = temperature - 273.15
    else:
        print("Invalid unit.")
        return
    print(f"Celsius: {celsius}")
    print(f"Fahrenheit: {(celsius * 1.8) + 32}")
    print(f"Kelvin: {celsius + 273.15}")

print("Loading G-One AI assistant...")
speak("Loading your AI personal assistant G-One.")
wish_me()

if __name__ == '__main__':
    while True:
        speak("Tell me, how can I help you now?")
        statement = take_command()
        if statement == "none":
            continue

        if 'open camera' in statement:
            open('CAMERA')
            speak('Camera opened')

        elif 'close camera' in statement:
            close('CAMERA')
            speak('Camera closed')

        elif 'open calculator' in statement:
            open('CALCULATOR')
            speak('Calculator opened')

        elif 'close calculator' in statement:
            close('CALCULATOR')
            speak('Calculator closed')

        elif 'open command prompt' in statement:
            open('COMMAND PROMPT')
            speak('Command Prompt opened')

        elif 'close command prompt' in statement:
            close('COMMAND PROMPT')
            speak('Command Prompt closed')

        elif 'show wi-fi networks' in statement:
            networks = get_available_networks()
            for net in networks:
                print(net)

        elif 'wikipedia' in statement:
            speak('Searching Wikipedia...')
            query = statement.replace("wikipedia", "")
            results = wikipedia.summary(query, sentences=3)
            speak("According to Wikipedia")
            print(results)
            speak(results)

        elif 'open youtube' in statement:
            webbrowser.open("https://www.youtube.com")
            speak("YouTube is open now")

        elif 'open google' in statement:
            webbrowser.open("https://www.google.com")
            speak("Google is open now")

        elif 'open gmail' in statement:
            webbrowser.open("https://www.gmail.com")
            speak("Gmail is open now")

        elif 'open whatsapp' in statement:
            open('whatsapp')
            speak("WhatsApp opened")

        elif 'close whatsapp' in statement:
            close('whatsapp')
            speak("WhatsApp closed")

        elif 'open telegram' in statement:
            open('telegram desktop')
            speak("Telegram opened")

        elif 'close telegram' in statement:
            close('telegram desktop')
            speak("Telegram closed")

        elif 'time' in statement:
            speak(datetime.datetime.now().strftime("%H:%M:%S"))

        elif 'search' in statement:
            query = statement.replace("search", "")
            webbrowser.open(query)

        elif 'find my ip' in statement:
            print(get_location())

        elif 'ip lookup' in statement:
            url = input("Enter URL: ")
            print(get_ip_addresses(url))

        elif 'phone number trace' in statement:
            number = input("Enter number with country code: ")
            ch = phonenumbers.parse(number, "CH")
            print("Country:", geocoder.description_for_number(ch, 'en'))
            print("Time zone:", timezone.time_zones_for_number(ch))
            ro = phonenumbers.parse(number, "RO")
            print("Provider:", carrier.name_for_number(ro, "en"))

        elif 'check hash' in statement:
            hash_str = input("Enter hash string: ")
            print("Hash type:", identify_hash_type(hash_str))

        elif 'temperature converter' in statement:
            convert_temperature()

        elif 'shut down my laptop' in statement:
            os.system("shutdown /s /t 1")

        elif 'restart my laptop' in statement:
            os.system("shutdown /r /t 1")

        elif 'sleep my laptop' in statement:
            os.system("rundll32.exe powrprof.dll,SetSuspendState 0,1,0")

        elif any(exit_command in statement for exit_command in ["good bye", "ok bye", "stop", "exit", "exit yourself"]):
            speak('Your personal assistant G-One is shutting down. Goodbye!')
            print('Your personal assistant G-One is shutting down. Goodbye!')
            break

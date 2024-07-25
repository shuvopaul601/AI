# G-One: Your AI Personal Assistant

G-One is an AI personal assistant that can perform a variety of tasks using voice commands. It utilizes speech recognition, text-to-speech, and various other Python libraries to provide functionalities like opening applications, searching the web, checking the time, and more.

## Features

- **Voice Interaction**: Uses speech recognition to take commands and text-to-speech to respond.
- **Application Control**: Can open applications like Camera, Calculator, Command Prompt, WhatsApp, Telegram, etc.
- **Web Interaction**: Opens websites like YouTube, Google, Gmail and performs Wikipedia searches.
- **Networking Tools**: Shows Wi-Fi networks, performs IP lookups, scans IP addresses, and more.
- **Phone Number Tracing**: Provides details about a phone number including location, carrier, and timezone.
- **Temperature Conversion**: Converts temperatures between Celsius, Fahrenheit, and Kelvin.
- **System Control**: Can shut down, restart, or put the system to sleep.

## Requirements

**To run this project, you need to have Python installed along with the following libraries. You can install them using the `requirements.txt` file.


pip install -r requirements.txt

Command Examples:

Open Camera: "open camera"
Open Calculator: "open calculator"
Search Wikipedia: "wikipedia [search term]"
Open YouTube: "open youtube"
Open Google: "open google"
Find IP: "find my ip"
Trace Phone Number: "phone number trace"

System Commands:
Shut Down: "shut down my laptop"
Restart: "restart my laptop"
Sleep: "sleep my laptop"
Exit: "good bye", "ok bye", "stop", "exit"
Functions
speak(text): Uses the text-to-speech engine to speak the given text.
wishMe(): Greets the user based on the current time.
takeCommand(): Uses speech recognition to listen for a command from the user.
get_available_networks(): Retrieves available Wi-Fi networks.
get_ip(): Gets the current IP address.
get_location(): Gets the geographical location based on IP.
get_ip_addresses(url): Retrieves IP addresses for a given URL.
identify_hash_type(hash_str**): Identifies the hash type of a given hash string.
Temperature Conversion Functions: Converts temperatures between different units.

Contributing
If you would like to contribute to this project, please fork the repository and submit a pull request.

License
This project is licensed under the MIT License.

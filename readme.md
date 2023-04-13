# DuoBreak

DuoBreak is a Python-based solution for handling Duo authentication on any computer that can run Python. It eliminates the need for a dedicated security key for your computer by emulating your phone's Duo push notifications and HOTP codes.

This tool is perfect for those who want to have a more flexible authentication method without being tied to a specific device or security key.

## Features

- Emulates Duo push notifications and HOTP codes
- Compatible with any computer that can run Python
- Secure storage of your authentication keys

## Video Tutorial

[![DuoBreak Video Tutorial](https://img.youtube.com/vi/PLACEHOLDER_VIDEO_ID/0.jpg)](https://www.youtube.com/watch?v=PLACEHOLDER_VIDEO_ID)

## Step-by-Step Tutorial

1. Clone this repository and install the required Python packages:

    ```
    git clone https://github.com/JesseNaser/DuoBreak.git
    cd DuoBreak
    pip install -r requirements.txt
    ```

2. Run the `duobreak.py` script:

    ```
    python duobreak.py
    ```

3. Follow the on-screen instructions to create a new password-protected vault for storing your authentication keys. (Notice your password is hidden from being displayed in the console while typing).

4. On your computer, go to the Duo webpage and add a new device. Choose "Tablet" and then "Android" as your device type, and click "I have Duo Mobile installed".

5. Save the QR code image given by the webpage.

6. In the DuoBreak script, choose "Add a new key" from the main menu. Enter a nickname for the new key and provide the file path to the saved QR code image.

7. The script will automatically activate the new key and store it securely in your vault.

8. To authenticate, choose "Authenticate" from the main menu and enter the nickname of the key you want to use. You can choose to authenticate using Duo push notifications or HOTP codes.

9. Congratulations! You can now use your Python-based Duo Authenticator on any compatible device!

## License

This project is licensed under the AGPL 3.0 or later license. Please see the [LICENSE](LICENSE) file for more information.

## Disclaimer

This tool is provided "as is" and without any warranty. Use it at your own risk. The author(s) are not responsible for any damage or loss that may occur as a result of using this tool. Always follow the best security practices and consider the risks before using any authentication method.

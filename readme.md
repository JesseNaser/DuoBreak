# DuoBreak

DuoBreak is a Python-based solution for handling Duo Push and HOTP authentication. Traditionally, Duo authentication is device-specific, meaning you will be locked out of your account if you lose your Phone (or reset to factory defaults) or lose your security key. However, after reverse-engineering the Duo app, DuoBreak emulates the functionality of a Duo Phone device while making it possible to export your keys to any device or backup service by saving the ".duo" archive to your place of liking, allowing you to authenticate into Duo-protected accounts using only your computer or embedded device (Raspberry Pi) where your Phone or security key is unavailable.

## Video Tutorial

[![DuoBreak Video Tutorial](https://img.youtube.com/vi/PLACEHOLDER_VIDEO_ID/0.jpg)](https://www.youtube.com/watch?v=PLACEHOLDER_VIDEO_ID)

## Step-by-Step Tutorial

### Initial Key Setup


1. Clone this repository and install the required Python packages:

    ```
    git clone https://github.com/JesseNaser/DuoBreak.git
    cd DuoBreak
    pip install -r requirements.txt
    ```

2. (for macOS only!) Install dependencies:

    ```
    brew install zbar
    sudo ln -s $(brew --prefix zbar)/lib/libzbar.dylib /usr/local/lib/libzbar.dylib
    ```

3. Run the `duobreak.py` script:

    ```
    python duobreak.py
    ```

4. Follow the on-screen instructions to create a new password-protected vault for storing your authentication keys. *Notice your password is hidden from being displayed in the console while typing*.

5. On your computer, go to the Duo webpage and add a new device. Choose "Tablet" and then "Android" as your device type, and click "I have Duo Mobile installed".

6. Save the QR code image given by the webpage as a PNG file.

7. In the DuoBreak script, choose "Add a new key" from the main menu. Enter a nickname for the new key and provide the file path to the saved QR code image.

8. The script will automatically activate the new key and store it securely in your vault.

### Authentication

To authenticate, choose "Authenticate" from the main menu and enter the nickname of the key you want to use. You can choose to authenticate using Duo push notifications or HOTP codes.

## License

This project is licensed under the AGPL 3.0 or later license. Please see the [LICENSE](LICENSE) file for more information.

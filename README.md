Chrome-Password-Extractor
=========================

Library for extracting saved credentials from the Chrome/Chromium webbrowser

This library provides the 'CredentialExtractor' class used to decrypt saved passwords from the Google Chrome/Chromium webbrowser. Sqlite 3 source and the Crypt32 library (available in the windows SDK) are required to build the library.

# CredentialExtractor

## Constructor
Creates an instance of CredentialExtractor. The specified database file is copied to a specified location and opened.

## CountCredentials
returns an integer indicating the number of credentials stored in the database

## DecryptPassword
Returns the decrypted password as a c-style string from the specified row on successful decryption, otherwise returns a null pointer. Usually the password can only be successfully decrypted by the user that encrypted it.

## GetCredential
returns a Credential struct containing:
* OriginUrl: Url of the website the credentials are used for
* username
* password

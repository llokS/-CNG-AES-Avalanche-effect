#include <windows.h>
#include <stdio.h>
#include <math.h>
#include <locale.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

#pragma warning(disable:4996)

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)

#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)


void Cleanup(BCRYPT_ALG_HANDLE* hAesAlg, BCRYPT_KEY_HANDLE* hKey, PBYTE* pbCipherText, PBYTE* pbPlainText, PBYTE* pbKeyObject, PBYTE* pbIV)
{
    if (*hAesAlg)
    {
        BCryptCloseAlgorithmProvider(*hAesAlg, 0);
    }

    if (*hKey)
    {
        BCryptDestroyKey(*hKey);
    }

    if (*pbCipherText)
    {
        HeapFree(GetProcessHeap(), 0, *pbCipherText);
    }

    if (*pbPlainText)
    {
        HeapFree(GetProcessHeap(), 0, *pbPlainText);
    }

    if (*pbKeyObject)
    {
        HeapFree(GetProcessHeap(), 0, *pbKeyObject);
    }

    if (*pbIV)
    {
        HeapFree(GetProcessHeap(), 0, *pbIV);
    }
}


DWORD getLenFile(char* nameFile)
{
    FILE* file;
    DWORD len = 0;

    file = fopen(nameFile, "r");

    fseek(file, 0, SEEK_END);
    len = ftell(file);
    fseek(file, 0, SEEK_SET);

    return len;
}


DWORD ReadTextFileToHex(char* nameFile, BYTE* text)
{
    FILE* file;
    char ch;

    file = fopen(nameFile, "r");

    ch = getc(file);
    int i = 0;
    while (ch != EOF) {
        text[i] = (BYTE)ch;
        ch = getc(file);
        i++;
    }
}


DWORD ReadBitFileToHex(char* nameFile, BYTE* text)
{
    FILE* file;

    char ch;

    unsigned char bitFile[128] = { 0 };

    file = fopen(nameFile, "r");

    ch = getc(file);
    int i = 0;
    while (ch != EOF) {
        bitFile[i] = ch;
        ch = getc(file);
        i++;
    }

    for (i = 0; i < 128 / 8; i++)
    {
        if (bitFile[8 * i] == '1')
            text[i] ^= 0b10000000;
        if (bitFile[8 * i + 1] == '1')
            text[i] ^= 0b01000000;
        if (bitFile[8 * i + 2] == '1')
            text[i] ^= 0b00100000;
        if (bitFile[8 * i + 3] == '1')
            text[i] ^= 0b00010000;
        if (bitFile[8 * i + 4] == '1')
            text[i] ^= 0b00001000;
        if (bitFile[8 * i + 5] == '1')
            text[i] ^= 0b00000100;
        if (bitFile[8 * i + 6] == '1')
            text[i] ^= 0b00000010;
        if (bitFile[8 * i + 7] == '1')
            text[i] ^= 0b00000001;
    }
}


void PrintBytes(
    IN BYTE* pbPrintData,
    IN DWORD    cbDataLen)
{
    DWORD dwCount = 0;

    for (dwCount = 0; dwCount < cbDataLen; dwCount++)
    {
        printf("0x%02x, ", pbPrintData[dwCount]);

        if (0 == (dwCount + 1) % 16) putchar('\n');
    }
}


void PrintText(
    IN BYTE* pbPrintData,
    IN DWORD    cbDataLen)
{
    DWORD dwCount = 0;

    for (dwCount = 0; dwCount < cbDataLen; dwCount++)
    {
        printf("%c", pbPrintData[dwCount]);

    }
    printf("\n\n");
}


void EncryptAES(
    BYTE* rgbPlainText,
    DWORD cbText,
    BYTE* rgbCiphertext,
    DWORD cbCiph,
    BYTE* rgbIV,
    DWORD cbIV,
    BYTE* rgbAES128Key,
    PBYTE chainMode)
{
    BCRYPT_ALG_HANDLE       hAesAlg = NULL;
    BCRYPT_KEY_HANDLE       hKey = NULL;

    NTSTATUS                status = STATUS_UNSUCCESSFUL;

    DWORD   cbCipherText = cbCiph,
            cbPlainText = cbText,
            cbData = 0,
            cbKeyObject = 0,
            cbBlockLen = 0,
            cbBlob = 0;

    PBYTE   pbCipherText = NULL,
            pbPlainText = NULL,
            pbKeyObject = NULL,
            pbIV = NULL,
            pbBlob = NULL;


    // Открытие поставщика алгоритмов. Тип шифрования AES
    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(
        &hAesAlg,
        BCRYPT_AES_ALGORITHM,
        NULL,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
        Cleanup(&hAesAlg, &hKey, &pbCipherText, &pbPlainText, &pbKeyObject, &pbIV);
    }


    //Вычисляем размер буфера для хранения объекта KeyObject
    if (!NT_SUCCESS(status = BCryptGetProperty(
        hAesAlg,
        BCRYPT_OBJECT_LENGTH,
        (PBYTE)&cbKeyObject,
        sizeof(DWORD),
        &cbData,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
        Cleanup(&hAesAlg, &hKey, &pbCipherText, &pbPlainText, &pbKeyObject, &pbIV);
    }

    // Выделяем место в памяти для хранения объекта KeyObject
    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (NULL == pbKeyObject)
    {
        wprintf(L"**** memory allocation failed\n");
        Cleanup(&hAesAlg, &hKey, &pbCipherText, &pbPlainText, &pbKeyObject, &pbIV);
    }


    if (chainMode != (PBYTE)L"ChainingModeECB")
    {
        // Рассчитайте длину блока для IV.
        if (!NT_SUCCESS(status = BCryptGetProperty(
            hAesAlg,
            BCRYPT_BLOCK_LENGTH,
            (PBYTE)&cbBlockLen,
            sizeof(DWORD),
            &cbData,
            0)))
        {
            wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
            Cleanup(&hAesAlg, &hKey, &pbCipherText, &pbPlainText, &pbKeyObject, &pbIV);
        }

        // Определяем, не превышает ли cbBlockLen длину IV.
        if (cbBlockLen > cbIV)
        {
            wprintf(L"**** block length is longer than the provided IV length\n");
            Cleanup(&hAesAlg, &hKey, &pbCipherText, &pbPlainText, &pbKeyObject, &pbIV);
        }

        // Выделите буфер для IV. Буфер расходуется во время процесса 
        // шифрования/дешифрования.
        pbIV = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbBlockLen);
        if (NULL == pbIV)
        {
            wprintf(L"**** memory allocation failed\n");
            Cleanup(&hAesAlg, &hKey, &pbCipherText, &pbPlainText, &pbKeyObject, &pbIV);
        }

        memcpy(pbIV, rgbIV, cbBlockLen);
    }
    else
    {
        pbIV = NULL;
        cbBlockLen = NULL;
    }

    if (!NT_SUCCESS(status = BCryptSetProperty(
        hAesAlg,
        BCRYPT_CHAINING_MODE,
        chainMode,
        sizeof(chainMode),
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptSetProperty\n", status);
        Cleanup(&hAesAlg, &hKey, &pbCipherText, &pbPlainText, &pbKeyObject, &pbIV);
    }


    // Генерируем ключ из предоставленных входных ключевых байтов.
    if (!NT_SUCCESS(status = BCryptGenerateSymmetricKey(
        hAesAlg,
        &hKey,
        pbKeyObject,
        cbKeyObject,
        (PBYTE)rgbAES128Key,
        16,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptGenerateSymmetricKey\n", status);
        Cleanup(&hAesAlg, &hKey, &pbCipherText, &pbPlainText, &pbKeyObject, &pbIV);
    }

    pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
    if (NULL == pbPlainText)
    {
        wprintf(L"**** memory allocation failed\n");
        Cleanup(&hAesAlg, &hKey, &pbCipherText, &pbPlainText, &pbKeyObject, &pbIV);
    }

    memcpy(pbPlainText, rgbPlainText, cbPlainText);


    // Получение размера выходного буфера
    if (!NT_SUCCESS(status = BCryptEncrypt(
        hKey,
        pbPlainText,
        cbPlainText,
        NULL,
        pbIV,
        cbBlockLen,
        NULL,
        0,
        &cbCipherText,
        BCRYPT_BLOCK_PADDING)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptEncrypt\n", status);
        Cleanup(&hAesAlg, &hKey, &pbCipherText, &pbPlainText, &pbKeyObject, &pbIV);
    }

    pbCipherText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbCipherText);
    if (NULL == pbCipherText)
    {
        wprintf(L"**** memory allocation failed\n");
        Cleanup(&hAesAlg, &hKey, &pbCipherText, &pbPlainText, &pbKeyObject, &pbIV);
    }

    // Используйте ключ для шифрования буфера открытого текста.
    // Для сообщений размером в блок, IV добавит дополнительный блок.
    if (!NT_SUCCESS(status = BCryptEncrypt(
        hKey,
        pbPlainText,
        cbPlainText,
        NULL,
        pbIV,
        cbBlockLen,
        pbCipherText,
        cbCipherText,
        &cbData,
        BCRYPT_BLOCK_PADDING)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptEncrypt\n", status);
        Cleanup(&hAesAlg, &hKey, &pbCipherText, &pbPlainText, &pbKeyObject, &pbIV);
    }

    memcpy(rgbCiphertext, pbCipherText, cbCipherText);

    Cleanup(&hAesAlg, &hKey, &pbCipherText, &pbPlainText, &pbKeyObject, &pbIV);
}


void DecryptAES(
    BYTE* rgbCiphertext,
    DWORD cbCiph,
    BYTE* rgbPlainText,
    DWORD cbText,
    BYTE* rgbIV,
    DWORD cbIV,
    BYTE* rgbAES128Key,
    PBYTE chainMode)
{
    BCRYPT_ALG_HANDLE       hAesAlg = NULL;
    BCRYPT_KEY_HANDLE       hKey = NULL;

    NTSTATUS                status = STATUS_UNSUCCESSFUL;

    DWORD   cbCipherText = cbCiph,
            cbPlainText = cbText,
            cbData = 0,
            cbKeyObject = 0,
            cbBlockLen = 0,
            cbBlob = 0;

    PBYTE   pbCipherText = NULL,
            pbPlainText = NULL,
            pbKeyObject = NULL,
            pbIV = NULL,
            pbBlob = NULL;


    // Открытие поставщика алгоритмов. Тип шифрования AES
    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(
        &hAesAlg,
        BCRYPT_AES_ALGORITHM,
        NULL,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
        Cleanup(&hAesAlg, &hKey, &pbCipherText, &pbPlainText, &pbKeyObject, &pbIV);
    }


    //Вычисляем размер буфера для хранения объекта KeyObject
    if (!NT_SUCCESS(status = BCryptGetProperty(
        hAesAlg,
        BCRYPT_OBJECT_LENGTH,
        (PBYTE)&cbKeyObject,
        sizeof(DWORD),
        &cbData,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
        Cleanup(&hAesAlg, &hKey, &pbCipherText, &pbPlainText, &pbKeyObject, &pbIV);
    }

    // Выделяем место в памяти для хранения объекта KeyObject
    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (NULL == pbKeyObject)
    {
        wprintf(L"**** memory allocation failed\n");
        Cleanup(&hAesAlg, &hKey, &pbCipherText, &pbPlainText, &pbKeyObject, &pbIV);
    }


    if (chainMode != (PBYTE)L"ChainingModeECB")
    {
        // Рассчитайте длину блока для IV.
        if (!NT_SUCCESS(status = BCryptGetProperty(
            hAesAlg,
            BCRYPT_BLOCK_LENGTH,
            (PBYTE)&cbBlockLen,
            sizeof(DWORD),
            &cbData,
            0)))
        {
            wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
            Cleanup(&hAesAlg, &hKey, &pbCipherText, &pbPlainText, &pbKeyObject, &pbIV);
        }

        // Определяем, не превышает ли cbBlockLen длину IV.
        if (cbBlockLen > cbIV)
        {
            wprintf(L"**** block length is longer than the provided IV length\n");
            Cleanup(&hAesAlg, &hKey, &pbCipherText, &pbPlainText, &pbKeyObject, &pbIV);
        }

        // Выделите буфер для IV. Буфер расходуется во время процесса 
        // шифрования/дешифрования.
        pbIV = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbBlockLen);
        if (NULL == pbIV)
        {
            wprintf(L"**** memory allocation failed\n");
            Cleanup(&hAesAlg, &hKey, &pbCipherText, &pbPlainText, &pbKeyObject, &pbIV);
        }

        memcpy(pbIV, rgbIV, cbBlockLen);
    }
    else
    {
        pbIV = NULL;
        cbBlockLen = NULL;
    }

    if (!NT_SUCCESS(status = BCryptSetProperty(
        hAesAlg,
        BCRYPT_CHAINING_MODE,
        chainMode,
        sizeof(chainMode),
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptSetProperty\n", status);
        Cleanup(&hAesAlg, &hKey, &pbCipherText, &pbPlainText, &pbKeyObject, &pbIV);
    }


    // Генерируем ключ из предоставленных входных ключевых байтов.
    if (!NT_SUCCESS(status = BCryptGenerateSymmetricKey(
        hAesAlg,
        &hKey,
        pbKeyObject,
        cbKeyObject,
        (PBYTE)rgbAES128Key,
        16,
        0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptGenerateSymmetricKey\n", status);
        Cleanup(&hAesAlg, &hKey, &pbCipherText, &pbPlainText, &pbKeyObject, &pbIV);
    }

    pbCipherText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbCiph);
    if (NULL == pbCipherText)
    {
        wprintf(L"**** memory allocation failed\n");
        Cleanup(&hAesAlg, &hKey, &pbCipherText, &pbPlainText, &pbKeyObject, &pbIV);
    }
    memcpy(pbCipherText, rgbCiphertext, cbCiph);

    // Получение размера выходного буфера.
    if (!NT_SUCCESS(status = BCryptDecrypt(
        hKey,
        pbCipherText,
        cbCipherText,
        NULL,
        pbIV,
        cbBlockLen,
        NULL,
        0,
        &cbPlainText,
        BCRYPT_BLOCK_PADDING)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptDecrypt\n", status);
        Cleanup(&hAesAlg, &hKey, &pbCipherText, &pbPlainText, &pbKeyObject, &pbIV);
    }

    pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
    if (NULL == pbPlainText)
    {
        wprintf(L"**** memory allocation failed\n");
        Cleanup(&hAesAlg, &hKey, &pbCipherText, &pbPlainText, &pbKeyObject, &pbIV);
    }

    if (!NT_SUCCESS(status = BCryptDecrypt(
        hKey,
        pbCipherText,
        cbCipherText,
        NULL,
        pbIV,
        cbBlockLen,
        pbPlainText,
        cbPlainText,
        &cbPlainText,
        BCRYPT_BLOCK_PADDING)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptDecrypt\n", status);
        Cleanup(&hAesAlg, &hKey, &pbCipherText, &pbPlainText, &pbKeyObject, &pbIV);
    }
   
    memcpy(rgbPlainText, pbPlainText, cbPlainText);

    Cleanup(&hAesAlg, &hKey, &pbCipherText, &pbPlainText, &pbKeyObject, &pbIV);
}

DWORD compareBits(BYTE* oneBlock, BYTE* twoBlock, DWORD len)
{
    DWORD num = 0;

    for (int i = 0; i < len; i++)
    {
        for (int j = 0; j < 8; j++)
        {
            if (((oneBlock[i] >> j) & 1) != ((twoBlock[i] >> j) & 1))
                num++;
        }
    }
    return num;
}

void main()
{
    setlocale(LC_ALL, "");

    DWORD   cbText = 0,
            cbKey = 0,
            cbIV = 0,
            cbCiph;

    DWORD num = 0;

    BYTE* rgbPlaintext;
    BYTE* tempPlaintext;
    BYTE* rgbCiphertext;
    BYTE* tempCiphertext;
    BYTE* rgbIV;
    BYTE* rgbAES128Key;

    PBYTE chainMode = (PBYTE)L"ChainingModeCFB";

    cbText = getLenFile("plainText.txt");
    cbKey = getLenFile("key.txt");
    cbIV = getLenFile("IV.txt");
    cbCiph = (int)ceil((float)cbText / 16) * 16;

    if (cbKey != 128 || cbIV != 128)
        exit(25);

    rgbPlaintext = (BYTE*)malloc(cbText);
    memset(rgbPlaintext, 0, cbText);

    tempPlaintext = (BYTE*)malloc(cbText);

    rgbIV = (BYTE*)malloc(cbIV / 8);
    memset(rgbIV, 0, cbIV / 8);

    rgbAES128Key = (BYTE*)malloc(cbKey / 8);
    memset(rgbAES128Key, 0, cbKey / 8);

    rgbCiphertext = (BYTE*)malloc(cbCiph);
    memset(rgbCiphertext, 0, cbCiph);

    tempCiphertext = (BYTE*)malloc(cbCiph);
    memset(tempCiphertext, 0, cbCiph);

    ReadTextFileToHex("plainText.txt", rgbPlaintext);
    memcpy(tempPlaintext, rgbPlaintext, cbText);

    ReadBitFileToHex("key.txt", rgbAES128Key);
    ReadBitFileToHex("IV.txt", rgbIV);

    EncryptAES(rgbPlaintext, cbText, rgbCiphertext, cbCiph, rgbIV, cbIV, rgbAES128Key, chainMode);
    PrintBytes(rgbCiphertext, cbIV);

    //DecryptAES(rgbCiphertext, cbCiph, rgbPlaintext, cbText, rgbIV, cbIV, rgbAES128Key, chainMode);
    //PrintText(rgbPlaintext, cbText);



    FILE* file;
    file = fopen("exp.txt", "w");

    int i = 0;
    int j = 0;
    for (i = 0; i < cbText; i++)
    {   
        for (j = 0; j < 8; j++)
        {
            tempPlaintext[i] = (tempPlaintext[i] >> j) ^ 1;

            EncryptAES(tempPlaintext, cbText, tempCiphertext, cbCiph, rgbIV, cbIV, rgbAES128Key, chainMode);

            memcpy(tempPlaintext, rgbPlaintext, cbText);

            num = compareBits(rgbCiphertext, tempCiphertext, cbCiph);
            memset(tempCiphertext, 0, cbCiph);

            fprintf(file, "%d_%d \n", 8 * i + j, num);
        }

    }
}
#include "GostEngine.h"
#include <iostream>
#include <fstream>
#include <random>
#include <cstring>
#include <vector>

using namespace std;

const uint8_t GostEngine::DefaultSBox[8][16] = {
    {4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3},
    {14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9},
    {5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11},
    {7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3},
    {6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2},
    {4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14},
    {13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12},
    {1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12}
};

GostEngine::GostEngine() {
    for (int i = 0; i < 8; i++)
        for (int j = 0; j < 16; j++)
            SBox[i][j] = DefaultSBox[i][j];
    memset(Key, 0, sizeof(Key));
}

// математика

uint32_t GostEngine::f_function(uint32_t part, uint32_t key_part) {
    uint32_t temp = part + key_part;
    uint32_t substituted = 0;
    for (int i = 0; i < 8; i++) {
        int s_row = (temp >> (4 * i)) & 0x0F;
        substituted |= ((uint32_t)SBox[i][s_row] << (4 * i));
    }
    return (substituted << 11) | (substituted >> 21);
}

void GostEngine::encryptBlock(uint32_t& N1, uint32_t& N2) {
    for (int i = 0; i < 32; i++) {
        int keyIndex = (i < 24) ? (i % 8) : (7 - (i % 8));
        uint32_t stepResult = f_function(N1, Key[keyIndex]);
        uint32_t temp = N2 ^ stepResult;

        if (i < 31) { N2 = N1; N1 = temp; }
        else { N2 = temp; }
    }
}

void GostEngine::decryptBlock(uint32_t& N1, uint32_t& N2) {
    for (int i = 0; i < 32; i++) {
        int keyIndex = (i < 8) ? i : (7 - (i % 8));
        uint32_t stepResult = f_function(N1, Key[keyIndex]);
        uint32_t temp = N2 ^ stepResult;

        if (i < 31) { N2 = N1; N1 = temp; }
        else { N2 = temp; }
    }
}

// ключи

void GostEngine::generateAndSaveKey(const string& filename) {
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<unsigned int> dis(0, 255);
    uint8_t tempKeyBuf[32];
    for (int i = 0; i < 32; i++) tempKeyBuf[i] = (uint8_t)dis(gen);

    ofstream outFile(filename, ios::binary);
    outFile.write((char*)tempKeyBuf, 32);
    outFile.close();
    cout << "Случайный ключ сохранен в " << filename << endl;
}

void GostEngine::createKeyFromPassword(const string& password, const string& filename) {
    uint8_t tempKeyBuf[32];
    memset(tempKeyBuf, 0, 32);
    size_t len = password.length();
    if (len > 32) len = 32;
    for (size_t i = 0; i < len; i++) tempKeyBuf[i] = (uint8_t)password[i];

    ofstream outFile(filename, ios::binary);
    outFile.write((char*)tempKeyBuf, 32);
    outFile.close();
    cout << "Ключ из пароля сохранен в " << filename << endl;
}

bool GostEngine::loadKey(const string& filename) {
    ifstream inFile(filename, ios::binary);
    if (!inFile) return false;
    inFile.read((char*)Key, 32);
    return inFile.gcount() == 32;
}

// режимы
 
bool GostEngine::processFileECB(const string& inputFile, const string& outputFile, bool encrypt) {
    ifstream inFile(inputFile, ios::binary);
    ofstream outFile(outputFile, ios::binary);
    if (!inFile || !outFile) {
        cerr << "Ошибка открытия файлов!" << endl;
        return false;
    }

    uint32_t block[2];

    while (inFile.peek() != EOF) {
        block[0] = 0; block[1] = 0;

        inFile.read((char*)block, 8);
        int bytesRead = (int)inFile.gcount();

        if (encrypt) {
            encryptBlock(block[0], block[1]);
        }
        else {
            decryptBlock(block[0], block[1]);
        }

        outFile.write((char*)block, 8);
    }

    cout << (encrypt ? "Зашифровано" : "Расшифровано") << " в режиме ECB." << endl;
    return true;
}

bool GostEngine::processFileGamming(const string& inputFile, const string& outputFile, bool encrypt, const string& customIV) {
    ifstream inFile(inputFile, ios::binary);
    ofstream outFile(outputFile, ios::binary);
    if (!inFile || !outFile) {
        cerr << "Ошибка: Не удалось открыть файлы! Проверьте, существуют ли папки files_plain и files_encrypted." << endl;
        return false;
    }

    uint32_t IV[2];

    if (encrypt) {
        if (customIV.empty()) {
            random_device rd;
            mt19937 gen(rd());
            IV[0] = gen();
            IV[1] = gen();
            cout << "Использован случайный IV.\n";
        }
        else {
            uint8_t tempBuf[8];
            memset(tempBuf, 0, 8); 
            size_t len = customIV.length();
            if (len > 8) len = 8;

            for (size_t i = 0; i < len; i++) {
                tempBuf[i] = (uint8_t)customIV[i];
            }
            memcpy(IV, tempBuf, 8);
            cout << "Использован пользовательский IV: " << customIV.substr(0, len) << "\n";
        }

        outFile.write((char*)IV, 8);
    }
    else {
        inFile.read((char*)IV, 8);
        if (inFile.gcount() != 8) {
            cerr << "Ошибка: Файл слишком короткий, нет IV." << endl;
            return false;
        }
    }

    uint32_t Counter[2];
    Counter[0] = IV[0];
    Counter[1] = IV[1];

    uint32_t dataBlock[2];
    uint32_t gammaBlock[2];

    while (inFile.peek() != EOF) {
        gammaBlock[0] = Counter[0];
        gammaBlock[1] = Counter[1];
        encryptBlock(gammaBlock[0], gammaBlock[1]);

        dataBlock[0] = 0; dataBlock[1] = 0;
        inFile.read((char*)dataBlock, 8);
        int bytesRead = (int)inFile.gcount();

        dataBlock[0] ^= gammaBlock[0];
        dataBlock[1] ^= gammaBlock[1];

        outFile.write((char*)dataBlock, bytesRead);

        Counter[0]++;
        if (Counter[0] == 0) Counter[1]++;
    }

    cout << (encrypt ? "Зашифровано" : "Расшифровано") << " успешно." << endl;
    return true;
}

void GostEngine::processFileCFB(const string& inputFile, const string& outputFile, bool encrypt, const string& customIV) {
    ifstream inFile(inputFile, ios::binary);
    ofstream outFile(outputFile, ios::binary);
    if (!inFile || !outFile) {
        cerr << "Ошибка: Не удалось открыть файлы." << endl;
        return;
    }

    uint32_t IV[2]; 

    if (encrypt) {

        if (customIV.empty()) {
            random_device rd;
            mt19937 gen(rd());
            IV[0] = gen();
            IV[1] = gen();
            cout << "Сгенерирован случайный IV для CFB.\n";
        }
        else {
            uint8_t tempBuf[8];
            memset(tempBuf, 0, 8);
            size_t len = customIV.length();
            if (len > 8) len = 8;
            for (size_t i = 0; i < len; i++) {
                tempBuf[i] = (uint8_t)customIV[i];
            }
            memcpy(IV, tempBuf, 8);
            cout << "Использован пользовательский IV для CFB.\n";
        }

        outFile.write((char*)IV, 8);
    }
    else {
        inFile.read((char*)IV, 8);
        if (inFile.gcount() != 8) {
            cerr << "Ошибка: файл слишком короткий, нет IV." << endl;
            return;
        }
    }

    uint32_t Register[2];
    Register[0] = IV[0];
    Register[1] = IV[1];

    uint32_t dataBlock[2];
    uint32_t gammaBlock[2];

    //проверка не закончился ли файл
    while (inFile.peek() != EOF) {
        gammaBlock[0] = Register[0];
        gammaBlock[1] = Register[1];
        encryptBlock(gammaBlock[0], gammaBlock[1]);

        dataBlock[0] = 0; dataBlock[1] = 0;
        inFile.read((char*)dataBlock, 8);
        int bytesRead = (int)inFile.gcount();

        if (encrypt) {
            dataBlock[0] ^= gammaBlock[0];
            dataBlock[1] ^= gammaBlock[1];

            outFile.write((char*)dataBlock, bytesRead);

            Register[0] = dataBlock[0];
            Register[1] = dataBlock[1];
        }
        else {
            uint32_t saveCipher[2];
            saveCipher[0] = dataBlock[0];
            saveCipher[1] = dataBlock[1];

            dataBlock[0] ^= gammaBlock[0];
            dataBlock[1] ^= gammaBlock[1];

            outFile.write((char*)dataBlock, bytesRead);

            Register[0] = saveCipher[0];
            Register[1] = saveCipher[1];
        }
    }
    cout << (encrypt ? "Зашифровано" : "Расшифровано") << " в режиме CFB." << endl;
}

void GostEngine::calculateMAC(const string& inputFile) {
    ifstream inFile(inputFile, ios::binary);
    if (!inFile) {
        cerr << "Ошибка: Не удалось открыть файл для MAC." << endl;
        return;
    }

    uint32_t MAC[2] = { 0, 0 };
    uint32_t block[2];

    while (inFile.peek() != EOF) {
        block[0] = 0; block[1] = 0;
        inFile.read((char*)block, 8);

        MAC[0] ^= block[0];
        MAC[1] ^= block[1];

        for (int i = 0; i < 16; i++) {
            int keyIndex = i % 8;
            uint32_t stepResult = f_function(MAC[0], Key[keyIndex]);

            uint32_t temp = MAC[1] ^ stepResult;
            MAC[1] = MAC[0];
            MAC[0] = temp;
        }
    }
    cout << "--- РЕЗУЛЬТАТ ИМИТОВСТАВКИ (MAC) ---\n";
    cout << "HEX: " << hex << MAC[0] << " " << MAC[1] << dec << endl;
    cout << "------------------------------------\n";
}
//удаление ключа из оперативки
GostEngine::~GostEngine() {
    volatile uint32_t* pKey = Key;
    for (int i = 0; i < 8; i++) pKey[i] = 0;

}
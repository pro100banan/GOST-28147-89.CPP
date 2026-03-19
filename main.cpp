#include <iostream>
#include <clocale>
#include <string>
#include <limits>
#include "GostEngine.h"
#include <fstream>
#include <vector>

using namespace std;

void cleanInputBuffer() {
    cin.clear();
    cin.ignore(numeric_limits<streamsize>::max(), '\n');
}

void printMainMenu() {
    cout << "\n=== ГОСТ 28147-89 Главное меню ===\n";
    cout << "1. Сгенерировать СЛУЧАЙНЫЙ Ключ\n";
    cout << "2. Создать Ключ из ПАРОЛЯ\n";
    cout << "3. ЗАШИФРОВАТЬ файл (из files_plain -> в files_encrypted)\n";
    cout << "4. РАСШИФРОВАТЬ файл (из files_encrypted -> в files_plain)\n";
    cout << "0. Выход\n";
    cout << "Ваш выбор: ";
}

void printCryptoModesMenu(bool encrypting) {
    cout << "\n--- Выберите режим ---\n";
    cout << "1. Простая замена (ECB)\n";
    cout << "2. Гаммирование (Counter Mode)\n";
    cout << "3. Гаммирование с обратной связью (CFB)\n";
    cout << "4. Имитовставка (MAC)\n";
    cout << "0. Назад\n";
    cout << "Ваш выбор: ";
}


void Test() {
    ofstream f("files_plain/input.txt", ios::binary);
    f << "12345678";
    f.close();

    char zeros[24] = { 0 };
    ofstream f2("files_plain/zeros.bin", ios::binary);
    f2.write(zeros, 8);
    f2.close();

    char zeros16[16] = { 0 };
    ofstream f3("files_plain/zeros_16.bin", ios::binary);
    f3.write(zeros16, 16);
    f3.close();
}

int main() {
    setlocale(LC_ALL, "Russian");
    //Test();

    GostEngine engine;
    string keyFile = "key.bin";
    
    string dirPlain = "files_plain/";     
    string dirEncrypted = "files_encrypted/"; 

    int mainChoice;
    do {
        printMainMenu();
        if (!(cin >> mainChoice)) { cleanInputBuffer(); mainChoice = -1; }
        cleanInputBuffer(); 

        if (mainChoice == 1) {
            engine.generateAndSaveKey(keyFile);
        }
        else if (mainChoice == 2) {
            string userPass;
            cout << "Введите пароль для ключа: ";
            getline(cin, userPass);
            engine.createKeyFromPassword(userPass, keyFile);
        }
        else if (mainChoice == 3 || mainChoice == 4) {
            bool isEncrypt = (mainChoice == 3);
            
            if (!engine.loadKey(keyFile)) {
                cout << "ОШИБКА: Ключ не найден!\n";
                continue;
            }

            int modeChoice;
            printCryptoModesMenu(isEncrypt);
            if (!(cin >> modeChoice)) { cleanInputBuffer(); modeChoice = -1; }
            cleanInputBuffer();
            if (modeChoice == 0) continue;

            string inFile, outFile;
            
            if (isEncrypt) {
                // шифруем
                cout << "Введите имя файла в папке " << dirPlain << " (например, photo.jpg): ";
                getline(cin, inFile);
                
                string outName = inFile + ".bin"; 
                
                string fullInPath = dirPlain + inFile;
                string fullOutPath = dirEncrypted + outName;

                string customIV = "";
                if (modeChoice == 2 || modeChoice == 3) {
                    cout << "Хотите задать свой IV (Синхропосылку)? (y - да, n - нет): ";
                    char ans; cin >> ans; cleanInputBuffer();
                    if (ans == 'y' || ans == 'Y') {
                        cout << "Введите IV (макс 8 символов): ";
                        getline(cin, customIV);
                    }
                }

                if (modeChoice == 1) engine.processFileECB(fullInPath, fullOutPath, true);
                else if (modeChoice == 2) engine.processFileGamming(fullInPath, fullOutPath, true, customIV);
                else if (modeChoice == 3) engine.processFileCFB(fullInPath, fullOutPath, true, customIV);
                else if (modeChoice == 4) engine.calculateMAC(fullInPath);
                
            } else {
                // дешифруем
                cout << "Введите имя файла в папке " << dirEncrypted << " (например, photo.jpg.bin): ";
                getline(cin, inFile);

                cout << "В какой формат расшифровать? (например .txt или .jpg): ";
                string ext;
                cin >> ext; cleanInputBuffer();
                
                if (ext.length() > 0 && ext[0] != '.') ext = "." + ext;

                // чистим формат
                string baseName = inFile;
                if (baseName.size() > 4 && baseName.substr(baseName.size() - 4) == ".bin") {
                    baseName = baseName.substr(0, baseName.size() - 4);
                }
                
                string outName = baseName + ext;

                string fullInPath = dirEncrypted + inFile;
                string fullOutPath = dirPlain + outName;

                if (modeChoice == 1) engine.processFileECB(fullInPath, fullOutPath, false);
                else if (modeChoice == 2) engine.processFileGamming(fullInPath, fullOutPath, false);
                else if (modeChoice == 3) engine.processFileCFB(fullInPath, fullOutPath, false);
            }
        }
    } while (mainChoice != 0);

    return 0;
}
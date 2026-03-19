#ifndef GOSTENGINE_H
#define GOSTENGINE_H

#include <vector>
#include <string>
#include <cstdint>
#include <fstream>


class GostEngine {
private:
    static const uint8_t DefaultSBox[8][16];
    uint8_t SBox[8][16];
    uint32_t Key[8];

    uint32_t f_function(uint32_t part, uint32_t key_part);

    void encryptBlock(uint32_t& N1, uint32_t& N2);
    void decryptBlock(uint32_t& N1, uint32_t& N2);

public:
    GostEngine();
    ~GostEngine();

    void generateAndSaveKey(const std::string& filename);
    void createKeyFromPassword(const std::string& password, const std::string& filename);
    bool loadKey(const std::string& filename);

    bool processFileECB(const std::string& inputFile, const std::string& outputFile, bool encrypt);

    bool processFileGamming(const std::string& inputFile, const std::string& outputFile, bool encrypt, const std::string& customIV = "");

    void processFileCFB(const std::string& inputFile, const std::string& outputFile, bool encrypt, const std::string& customIV = "");

    void calculateMAC(const std::string& inputFile);
};

#endif
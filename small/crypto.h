#ifndef CRYPTO_H
#define CRYPTO_H

#include <QObject>
#include <QString>
#include <botan/argon2.h>
#include <botan/hex.h>
#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <botan/rng.h>
#include <botan/kdf.h>
#include <botan/pwdhash.h>
#include <botan/system_rng.h>
#include <botan/mac.h>
#include <botan/aead.h>
#include <botan/block_cipher.h>
#include <iostream>
#include <fstream>
#include <argon2.h>

class Crypto : public QObject
{
    Q_OBJECT
public:
    explicit Crypto(QObject *parent = nullptr, std::string encryptToggle="", std::string cipher="",
std::string mode="", std::string password="", std::string inputFilePath="", std::string outputFilePath="",
std::string pbkdf="", size_t memcost=1, size_t timecost=1, size_t threads=1, std::string header="");

    void run();
    void deriveKey(std::vector<uint8_t> salt);
    void hmacProcess(std::ifstream& fileHandle);

signals:
    void finished();
    void progress(int percent);
    void sendMessage(QString);

private:
    std::string encryptToggle, cipher, mode, password, inputFilePath, outputFilePath, pbkdf, header;
    Botan::secure_vector<uint8_t> key;
    size_t memcost, timecost, threads;
};

#endif // CRYPTO_H

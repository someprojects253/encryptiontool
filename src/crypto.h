#ifndef CRYPTO_H
#define CRYPTO_H

#include <QDebug>
#include <filesystem>

#include <QObject>
#include <QString>
#include <QByteArray>
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

#include <fstream>
#include <stdio.h>
#include <iostream>

#include <argon2.h>


class Crypto : public QObject
{
    Q_OBJECT

public:
    explicit Crypto(QObject *parent = nullptr);

    void setParams(const QString& input, const QString& output, const QString& password, const QString& mode,
                   const QString& encryptToggle, const std::vector<std::vector<std::string>>& cipherList,
                    size_t memcost, size_t timecost, size_t threads, QString pbkdf, QString header);

public slots:
    void encrypt();
    void cipherLoop();
    std::vector<uint8_t> mac(Botan::secure_vector<uint8_t> key, int iv_and_salt_size);
    void deriveKey(const std::vector<uint8_t>& salt, size_t keysize);

    void setKeySizes();

signals:
    void finished();
    void progress(int percent);
    void sendMessage(QString);

private:
    std::string inputFile;
    std::string outputFile;
    std::string password;
    std::string mode;
    std::string cipher;
    std::string encryptToggle;
    std::string pbkdf;
    std::string intermediateMode, finalMode;
    std::string header;
    size_t memcost, timecost, threads;
    std::vector<std::vector<std::string>> cipherList;

    Botan::secure_vector<uint8_t> key;

    size_t initialCipherListSize;
    int mainKeySize;

    std::string initialOutputFile;

    std::vector<std::string> cleanupFiles;
    std::vector<uint8_t> salt;
    std::vector<uint8_t> iv;
};

#endif // CRYPTO_H

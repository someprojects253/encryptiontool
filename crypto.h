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

#include <fstream>
#include <stdio.h>
#include <iostream>


class Crypto : public QObject
{
    Q_OBJECT

public:
    explicit Crypto(QObject *parent = nullptr);

    void setParams(const QString& input, const QString& output, const QString& password, const QString& mode,
                   const QString& cipher, const QString& encryptToggle, std::vector<std::vector<std::string>> cipherList,
                    size_t memcost, size_t timecost, size_t threads, QString argon2);

public slots:
    void encrypt();
    void cipherLoop();
    std::vector<uint8_t> mac(Botan::secure_vector<uint8_t> key, int iv_and_salt_size);
    void deriveKey(const std::vector<uint8_t>& salt, size_t keysize);

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
    std::string argon2;
    std::string intermediateMode, finalMode;
    size_t iteration, memcost, timecost, threads;
    std::vector<std::vector<std::string>> cipherList;

    Botan::secure_vector<uint8_t> key;

    int initialCipherListSize;

    std::string initialOutputFile;

    std::vector<std::string> cleanupFiles;
};

#endif // CRYPTO_H

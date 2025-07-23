#include "crypto.h"

Crypto::Crypto(QObject *parent, std::string encryptToggle, std::string cipher, std::string mode, std::string password,
std::string inputFilePath, std::string outputFilePath, std::string pbkdf, size_t memcost, size_t timecost, size_t threads,
std::string header)
    : QObject{parent}
{
    this->encryptToggle = encryptToggle;
    this->cipher = cipher;
    this->mode = mode;
    this->password = password;
    this->inputFilePath = inputFilePath;
    this->outputFilePath = outputFilePath;

    this->pbkdf = pbkdf;
    this->memcost=memcost;
    this->timecost=timecost;
    this->threads=threads;
    this->header = header;
}

void Crypto::deriveKey(std::vector<uint8_t> salt)
{
    size_t MiB = 1024;
    std::unique_ptr<Botan::PasswordHash> pwd_fam;

    try {
        if(pbkdf == "Argon2i" || pbkdf == "Argon2id" || pbkdf == "Argon2d") {
            memcost = memcost * MiB;
            const void* pwd_data = this->password.data();
            size_t pwd_len = this->password.size();

            int result;
            //time, memory, threads, password, password length, salt, salt length, output buffer, output length
            if(pbkdf == "Argon2id")  result = argon2id_hash_raw(timecost, memcost, threads, pwd_data, pwd_len, salt.data(), salt.size(), key.data(), key.size());
            if(pbkdf == "Argon2d")  result = argon2d_hash_raw(timecost, memcost, threads, pwd_data, pwd_len, salt.data(), salt.size(), key.data(), key.size());
            if(pbkdf == "Argon2i")  result = argon2i_hash_raw(timecost, memcost, threads, pwd_data, pwd_len, salt.data(), salt.size(), key.data(), key.size());

            if (result != ARGON2_OK) {
                throw std::runtime_error(std::string("Argon2 error: ") + argon2_error_message(result));
            }
        }
        if(pbkdf == "Scrypt") {
            timecost = 1 << timecost;
            pwd_fam = Botan::PasswordHashFamily::create_or_throw(pbkdf)->from_params(timecost, memcost, threads);
        }
        if(pbkdf == "PBKDF2") {
            timecost = timecost * 1000;
            pwd_fam = Botan::PasswordHashFamily::create_or_throw(pbkdf)->from_params(timecost);
        }
    } catch(const std::exception& e) {
        emit sendMessage(QString::fromStdString(e.what()));
        emit finished();
        return;
    }

    if(pbkdf == "PBKDF2" || pbkdf == "Scrypt") pwd_fam->hash(key, password, salt);
    password = "";
}

void Crypto::run()
{
    Botan::AutoSeeded_RNG rng;
    std::vector<uint8_t> salt(32);
    std::vector<uint8_t> iv;

    if(mode == "GCM" || mode == "SIV") iv.resize(12);
    if(mode == "OCB") iv.resize(15);
    if(mode == "EAX") iv.resize(key.size()); // maybe needs adjusting for shacal2
    if(mode == "192-bit") iv.resize(24);
    if(mode == "96-bit") iv.resize(12);
    if(mode == "64-bit") iv.resize(8);
    std::unique_ptr<Botan::AEAD_Mode> enc;
    std::string algostr = cipher + "/" + mode;
    if(cipher == "ChaCha20") algostr = "ChaCha20Poly1305";
    std::string_view algostrview = algostr;


    std::ifstream inputFileHandle(inputFilePath, std::ios::binary);
    std::ofstream outputFileHandle(outputFilePath, std::ios::binary);
    if(encryptToggle == "Encrypt") {
        enc = Botan::AEAD_Mode::create_or_throw(algostrview, Botan::Cipher_Dir::Encryption);
        salt = rng.random_vec<std::vector<uint8_t>>(32);
        iv = rng.random_vec<std::vector<uint8_t>>(iv.size());
        if(header.size() > 0) outputFileHandle.write(reinterpret_cast<char*>(header.data()), header.size());
        outputFileHandle.write(reinterpret_cast<char*>(salt.data()), salt.size());
        if(mode != "SIV") outputFileHandle.write(reinterpret_cast<char*>(iv.data()), iv.size());
    }
    if(encryptToggle == "Decrypt") {
        enc = Botan::AEAD_Mode::create_or_throw(algostrview, Botan::Cipher_Dir::Decryption);
        inputFileHandle.seekg(header.size(), std::ios::beg);
        inputFileHandle.read(reinterpret_cast<char*>(salt.data()), salt.size());
        if(mode != "SIV") inputFileHandle.read(reinterpret_cast<char*>(iv.data()), iv.size());
    }

    key.resize(enc->maximum_keylength());
    deriveKey(salt);

    try {
        enc->set_key(key);
        std::span<uint8_t> associated_data(reinterpret_cast<uint8_t*>(header.data()), header.size());
        if(header.size() > 0) enc->set_associated_data(associated_data);
        if(mode != "SIV") enc->start(iv);
    } catch(const Botan::Exception& e) {
        emit sendMessage(QString(e.what()));
        emit finished();
        return;
    }


    size_t totalBytesRead = 0;
    int lastPercent = -1;
    std::vector<uint8_t> buffer(4096);
    std::streamsize bytesRead;
    bool isLastChunk;

    inputFileHandle.seekg(0, std::ios::end);
    size_t filesize = inputFileHandle.tellg();
    if(encryptToggle == "Encrypt") inputFileHandle.seekg(0, std::ios::beg);
    if(encryptToggle == "Decrypt") {
       if(mode != "SIV") inputFileHandle.seekg(salt.size() + iv.size() + header.size(), std::ios::beg);
       else inputFileHandle.seekg(salt.size() + header.size(), std::ios::beg);
    }

    if(mode == "SIV") {
        if(encryptToggle == "Decrypt")
            buffer.resize(filesize - salt.size() - header.size());
        else
            buffer.resize(filesize);
        inputFileHandle.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        enc->finish(buffer);
        outputFileHandle.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
        emit finished();
        return;
    }
    while(true)
    {
            inputFileHandle.read(reinterpret_cast<char*>(buffer.data()), buffer.size());

            bytesRead = inputFileHandle.gcount();
            totalBytesRead += bytesRead;
            if (bytesRead == 0)
                break; // EOF
            isLastChunk = inputFileHandle.eof();

            std::vector<uint8_t> chunk(buffer.begin(), buffer.begin() + bytesRead);

            try {
                if(!isLastChunk) enc->update(chunk);

                else enc->finish(chunk);

                outputFileHandle.write(reinterpret_cast<const char*>(chunk.data()), chunk.size());

            } catch(const Botan::Exception& e) {
                emit sendMessage(QString(e.what()));
                emit finished();
                return;
            }

            int percent = static_cast<int>((100.0 * totalBytesRead) / filesize);
            if (percent != lastPercent) {
                emit progress(percent);
                lastPercent = percent;
            }
    }
    inputFileHandle.close();
    outputFileHandle.close();

    emit sendMessage("Done");
    emit finished();
}

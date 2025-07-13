#include "crypto.h"

Crypto::Crypto(QObject *parent) : QObject(parent) {}

void Crypto::setParams(const QString& input, const QString& output, const QString& password, const QString& mode,
                        const QString& encryptToggle, const std::vector<std::vector<std::string>>& cipherList,
                        size_t memcost, size_t timecost, size_t threads, QString pbkdf, QString header)
{
    this->inputFile = input.toStdString();
    this->outputFile = output.toStdString();
    this->password = password.toStdString();
    this->mode = mode.toStdString();
    this->encryptToggle = encryptToggle.toStdString();
    this->cipherList = cipherList;
    this->header = header.toStdString();

    this->memcost = memcost;
    this->timecost = timecost;
    this->threads = threads;
    this->pbkdf = pbkdf.toStdString();

    initialCipherListSize = cipherList.size();

    initialOutputFile = outputFile;

    if(cipherList.size() > 1) outputFile = "temp7UXgmUZb";

    mainKeySize = 0;

    std::string algo = cipherList[0][0];
    std::string algomode = cipherList[0][1];

    if(encryptToggle == "Encrypt"){
        Botan::AutoSeeded_RNG rng;
        salt = rng.random_vec<std::vector<uint8_t>>(32);
    } else {
        std::ifstream file(inputFile, std::ios::binary);
        file.seekg(header.size(), std::ios::beg);
        salt.resize(32);
        file.read(reinterpret_cast<char*>(salt.data()), 32);
        file.close();
    }

}

std::vector<uint8_t> Crypto::mac(Botan::secure_vector<uint8_t> key, int iv_and_salt_size)
{
    emit sendMessage("Computing MAC");
    std::string file_to_mac;
    if(encryptToggle == "Encrypt") file_to_mac = outputFile;
    else file_to_mac = inputFile;

    std::ifstream fin(file_to_mac, std::ios::binary);
    std::vector<uint8_t> buffer (4096);

    std::vector<uint8_t> hash;

    auto hmac = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");
    hmac->set_key(key);

    // fin.seekg(iv_and_salt_size + header.size(), std::ios::beg);
    fin.seekg(0, std::ios::beg);
    while (true)
    {
        fin.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        std::streamsize bytesRead = fin.gcount();

        if (bytesRead == 0)
            break; // EOF

        std::vector<uint8_t> chunk(buffer.begin(), buffer.begin() + bytesRead);

        bool isLastChunk = fin.eof();
        if(isLastChunk && encryptToggle == "Decrypt"){  chunk.resize(chunk.size() - 32); } //sha-256 size
        hmac->update(chunk);
    }
    fin.close();

    hmac->final(hash);
    emit sendMessage("MAC computed.");
    return hash;
}

void Crypto::deriveKey(const std::vector<uint8_t>& salt, size_t keysize)
{
    emit sendMessage("Deriving key");

    uint32_t M = static_cast<uint32_t>(memcost);   // Memory in KiB
    uint32_t t = static_cast<uint32_t>(timecost);  // Iterations
    uint32_t p = static_cast<uint32_t>(threads);   // Parallelism

    key.resize(keysize);

    const void* pwd_data = this->password.data();
    size_t pwd_len = this->password.size();

    int result;
    //time, memory, threads, password, password length, salt, salt length, output buffer, output length
    if(pbkdf == "Argon2id")  result = argon2id_hash_raw(t, M, p, pwd_data, pwd_len, salt.data(), salt.size(), key.data(), key.size());
    if(pbkdf == "Argon2d")  result = argon2d_hash_raw(t, M, p, pwd_data, pwd_len, salt.data(), salt.size(), key.data(), key.size());
    if(pbkdf == "Argon2i")  result = argon2i_hash_raw(t, M, p, pwd_data, pwd_len, salt.data(), salt.size(), key.data(), key.size());

    if(pbkdf == "PBKDF2(HMAC(SHA-512))"){
        timecost *= 1000;
        auto pwd_fam = Botan::PasswordHashFamily::create_or_throw(pbkdf)->from_params(timecost);
        pwd_fam->hash(key, password, salt);
    }
    if(pbkdf == "Scrypt") {
        timecost = 1 << timecost;
        memcost /= 1024;
        auto pwd_fam = Botan::PasswordHashFamily::create_or_throw(pbkdf)->from_params(timecost, memcost, threads);
        pwd_fam->hash(key, password, salt);
    }

    // if (result != ARGON2_OK) {
    //     throw std::runtime_error(std::string("Argon2 error: ") + argon2_error_message(result));
    // }
}

void Crypto::setKeySizes()
{
    int keysize = 32;
    std::string algo, mode;
    for(size_t i = 0; i < cipherList.size(); i++)
    {
        algo = cipherList[i][0];
        mode = cipherList[i][1];
        keysize = 32;
        if(algo == "SHACAL2" || algo == "Threefish-512") keysize = 64;

        if(algo == "SM4") keysize = 16;

        // 32 bytes for HMAC-SHA256 tag
        // If chaining and encrypting, only need MAC key for last encryption
        // If chaining and decrypting, only need MAC key for first decryption
        if((mode == "CBC/PKCS7" || mode == "CTR-BE")){
            if(encryptToggle == "Encrypt" && i == initialCipherListSize-1)
                keysize += 32;
            if(encryptToggle == "Decrypt" && i == 0)
                keysize += 32;
        }

        if(mode == "SIV") keysize += 32;
        cipherList[i].push_back(std::to_string(keysize));
        mainKeySize += keysize;
    }
}

void Crypto::encrypt()
{
    //Renaming files for cascade
    if(cipherList.size() == 1) outputFile = initialOutputFile;
    else cleanupFiles.push_back(outputFile); // these will be deleted after crypto operations are complete

    std::ifstream fin(inputFile, std::ios::binary);
    std::ofstream fout(outputFile, std::ios::binary);
    std::vector<uint8_t> buffer (4096);


    //Setup crypto variables
    std::unique_ptr<Botan::Cipher_Mode> enc;
     std::unique_ptr<Botan::AEAD_Mode> encAEAD;
    Botan::AutoSeeded_RNG rng;

    Botan::secure_vector<uint8_t> cipher_key;
    Botan::secure_vector<uint8_t> mac_key;
    std::vector<uint8_t> hash_output;


    std::string combined;
    std::string_view algo;

    algo = this->cipherList[0][0];
    mode = this->cipherList[0][1];



    if(algo != "ChaCha20Poly1305" && algo != "ChaCha20") {
        combined = algo + "/" + mode;
    }
    if(algo == "ChaCha20Poly1305" || algo == "ChaCha20") combined = algo;

    size_t keysize = std::stoi(cipherList[0][2]);
    Botan::secure_vector<uint8_t> subkey;

    if(encryptToggle == "Encrypt") {
        subkey.assign(key.begin(), key.begin() + keysize);
        key.erase(key.begin(), key.begin() + keysize);
    } else { // Decrypt
        subkey.assign(key.end() - keysize, key.end());
        key.resize(key.size() - keysize);
    }

    //Resize IVs
    //Overview: IV size default 16. 64 for Threefish-512, 32 for SHACAL2. 24 for XChaCha20
    iv.resize(16);
    if(algo == "ChaCha20Poly1305" || algo == "ChaCha20") iv.resize(24);
    if(algo == "SHACAL2") iv.resize(32);
    if(algo == "Threefish-512") iv.resize(64);
    if(mode == "GCM") iv.resize(12);
    if(mode == "OCB") iv.resize(15);

    std::vector<uint8_t> associated_data(header.begin(), header.end());

    bool isAEAD = false;
    if(mode != "CBC/PKCS7" && mode != "CTR-BE" && header.size() > 0)
        isAEAD = true;

    if(encryptToggle == "Encrypt")
    {
        try{
            if(isAEAD)
                encAEAD = Botan::AEAD_Mode::create_or_throw(combined, Botan::Cipher_Dir::Encryption);
            else
                enc = Botan::Cipher_Mode::create_or_throw(combined, Botan::Cipher_Dir::Encryption);
        }
        catch (const Botan::Exception& e){
            cipherList.clear();
            QString errormsg = QString(e.what());
            emit sendMessage(errormsg);
            emit finished();
            return;
        }

        if(cipherList.size() == 1){
            fout.write(header.c_str(), header.size());
            fout.write(reinterpret_cast<const char*>(salt.data()), salt.size());
        }

       if(mode != "SIV") {
        iv = rng.random_vec<std::vector<uint8_t>>(iv.size());
        fout.write(reinterpret_cast<const char*>(iv.data()), iv.size());
        }
    }

    else if(encryptToggle == "Decrypt")
    {
        if(cipherList.size() == initialCipherListSize)
            fin.seekg(header.size(), std::ios::beg);
        fin.read(reinterpret_cast<char*>(buffer.data()), iv.size()+salt.size());
        std::copy(buffer.begin(), buffer.begin() + salt.size(), salt.begin());
        if(mode != "SIV")
            std::copy(buffer.begin() + salt.size(), buffer.begin() + salt.size() + iv.size(), iv.begin());

        try{
            if(isAEAD)
                encAEAD = Botan::AEAD_Mode::create_or_throw(combined, Botan::Cipher_Dir::Decryption);
            else
                enc = Botan::Cipher_Mode::create_or_throw(combined, Botan::Cipher_Dir::Decryption);
        }
        catch (const Botan::Exception& e){
            QString errormsg = QString(e.what());
            emit sendMessage(errormsg);
            emit finished();
            cipherList.clear();
            return;
        }
    }

    if(mode != "CBC/PKCS7" && mode != "CTR-BE") {
        cipher_key.resize(keysize);
        std::copy(subkey.begin(), subkey.begin()+keysize, cipher_key.begin());
    }

    //Split key into cipher and MAC keys if needed
    if((mode == "CBC/PKCS7" || mode == "CTR-BE")) {
        if((encryptToggle == "Encrypt" && cipherList.size() == 1) || (encryptToggle == "Decrypt" && cipherList.size() == initialCipherListSize)) {
            cipher_key.resize(keysize-32);
            mac_key.resize(32);
            std::copy(subkey.begin(), subkey.begin()+keysize-32, cipher_key.begin());
            std::copy(subkey.begin()+keysize-32, subkey.end(), mac_key.begin());
        } else{
            cipher_key.resize(keysize);
            std::copy(subkey.begin(), subkey.begin()+keysize, cipher_key.begin());
        }
    }


    //Verify MAC before decrypting if applicable
    if(encryptToggle == "Decrypt" && (mode == "CBC/PKCS7" || mode == "CTR-BE") && cipherList.size() == initialCipherListSize) {
        fin.seekg(0, std::ios::end);
        std::streamoff fileSize = fin.tellg();
        fin.seekg(fileSize - 32, std::ios::beg);
        std::vector<uint8_t> mactag(32);
        fin.read(reinterpret_cast<char*>(mactag.data()), 32);

        fin.close();
        fout.close();
        hash_output = mac(mac_key, iv.size() + salt.size());
        fout.open(outputFile, std::ios::binary);
        fin.open(inputFile, std::ios::binary);
        fin.seekg(header.size() + iv.size() + salt.size(), std::ios::beg);

        if(mactag == hash_output) emit sendMessage("Authentication successful");
        else {
                emit sendMessage("Authentication failed. Stopping operations.");
                cipherList.clear();
                return;
            }
    }

    //Setup
    try{
        if(isAEAD) { // for authenticatd modes
            encAEAD->set_key(cipher_key);
            encAEAD->set_associated_data(associated_data);

            if(encryptToggle == "Encrypt"){
                if(mode != "SIV") encAEAD->start(iv);
                else encAEAD->start();
            }
            if(encryptToggle == "Decrypt") {
                if(mode == "SIV")
                {
                    fin.seekg(header.size() + salt.size(), std::ios::beg);
                    encAEAD->start();
                } else encAEAD->start(iv);
            }
        } else { // unauthenticated modes
            enc->set_key(cipher_key);

            if(encryptToggle == "Encrypt"){
                if(mode != "SIV") enc->start(iv);
                else enc->start();
            }
            if(encryptToggle == "Decrypt") {
                if(mode == "SIV")
                {
                    fin.seekg(header.size() + salt.size(), std::ios::beg);
                    enc->start();
                } else enc->start(iv);
            }
        }
    }catch(const Botan::Exception& e) {
        QString errormsg = QString(e.what());
        emit sendMessage(errormsg);
        emit finished();
        cipherList.clear();
        return;
    }


    //Encryption/decryption code
    size_t totalBytesRead = 0;
    const auto fileSize = std::filesystem::file_size(inputFile);
    int lastPercent = -1;

    while (true)
    {
        fin.read(reinterpret_cast<char*>(buffer.data()), buffer.size());

        std::streamsize bytesRead = fin.gcount();
        totalBytesRead += bytesRead;
        if (bytesRead == 0)
            break; // EOF

        bool isLastChunk = fin.eof();

        std::vector<uint8_t> chunk(buffer.begin(), buffer.begin() + bytesRead);

        try{
            if (isLastChunk) {
                // Removing HMAC tag from Encrypt-then-MAC, if applicable
                if((mode == "CBC/PKCS7" || mode == "CTR-BE") && encryptToggle == "Decrypt" && cipherList.size() == initialCipherListSize)
                    chunk.resize((chunk.size() - 32)); // 32 is hmac sha256 size
                if(isAEAD){
                    encAEAD->finish(chunk);
                } else{ //unauthenticated
                    enc->finish(chunk);
                }
                fout.write(reinterpret_cast<const char*>(chunk.data()), chunk.size());
            }
            else { // not last chunk

                if(isAEAD){
                    encAEAD->update(chunk);
                } else { //unauthenticated
                    enc->update(chunk);
                }
                if(mode != "SIV") fout.write(reinterpret_cast<const char*>(chunk.data()), chunk.size());
            }

        } catch(const Botan::Exception& e) {
            QString errormsg = QString(e.what());
            emit sendMessage(errormsg);
            emit finished();
            cipherList.clear();
            return;
        }

        //Updating progress bar
        int percent = static_cast<int>((100.0 * totalBytesRead) / fileSize);
        if (percent != lastPercent) {
            emit progress(percent);
            lastPercent = percent;
        }
    }

    //Generating and writing MAC tag if applicable
    fin.close();
    if(encryptToggle == "Encrypt" && (mode == "CBC/PKCS7" || mode == "CTR-BE") && cipherList.size() == 1) {
        fout.close();
        hash_output = mac(mac_key, iv.size() + salt.size());
        fout.open(outputFile, std::ios::app | std::ios::binary);
        fout.write(reinterpret_cast<const char*>(hash_output.data()), hash_output.size());
    }
    fout.close();

    //Crypto operations complete. Removing item from list.
    if(encryptToggle == "Decrypt" && cipherList.size() == initialCipherListSize) salt.resize(0);
    cipherList.erase(cipherList.begin());
    emit sendMessage("Round complete" + QString::fromStdString(" ") + QString::fromStdString(combined));
    inputFile = outputFile;
    outputFile = "temp" + std::to_string(initialCipherListSize - cipherList.size());
}

void Crypto::cipherLoop()
{
    setKeySizes();
    try {
        deriveKey(salt, mainKeySize);
    } catch (const std::exception& e) {
        emit sendMessage(QString("Key derivation failed: ") + e.what());
        emit finished();
        return;
    }

    for(size_t i = 0; i < initialCipherListSize; i++){
        if(cipherList.size() > 0) encrypt();
    }

    emit sendMessage("Done");

    for( const std::string& file : cleanupFiles) {
        std::filesystem::remove(file);
    }

    password = "";
    emit progress(100);
    emit finished();
}

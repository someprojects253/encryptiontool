#include "crypto.h"

Crypto::Crypto(QObject *parent) : QObject(parent) {}

void Crypto::setParams(const QString& input, const QString& output, const QString& password, const QString& mode,
                       const QString& cipher, const QString& encryptToggle, std::vector<std::vector<std::string>> cipherList,
                        size_t memcost, size_t timecost, size_t threads, QString argon2)
{
    this->inputFile = input.toStdString();
    this->outputFile = output.toStdString();
    this->password = password.toStdString();
    this->mode = mode.toStdString();
    this->cipher = cipher.toStdString(); // unused
    this->encryptToggle = encryptToggle.toStdString();
    this->cipherList = cipherList;

    this->memcost = memcost;
    this->timecost = timecost;
    this->threads = threads;
    this->argon2 = argon2.toStdString();

    initialCipherListSize = cipherList.size();

    initialOutputFile = outputFile;

    if(cipherList.size() > 1) outputFile = "temp7UXgmUZb";

    iteration = 0;
}

std::vector<uint8_t> Crypto::mac(Botan::secure_vector<uint8_t> key, int iv_and_salt_size)
{
    std::string file_to_mac;
    if(encryptToggle == "Encrypt") file_to_mac = outputFile;
    else file_to_mac = inputFile;

    std::ifstream fin(file_to_mac, std::ios::binary);
    std::vector<uint8_t> buffer (4096);

    std::vector<uint8_t> hash;

    auto hmac = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");
    hmac->set_key(key);

    fin.seekg(iv_and_salt_size, std::ios::beg);
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
    const std::string_view pbkdf_algo = argon2;

    // Argon2 parameters: memory, iterations, parallelism
    size_t M = memcost;      // memory
    size_t t = timecost;     // number of iterations
    size_t p = threads;     // threads


    auto pbkdf = Botan::PasswordHashFamily::create_or_throw(pbkdf_algo)->from_params(M, t, p);

    key.resize(keysize);

    pbkdf->hash(key, this->password, salt);
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
    Botan::AutoSeeded_RNG rng;

    auto iv = rng.random_vec<std::vector<uint8_t>>(16);
    auto salt = rng.random_vec<std::vector<uint8_t>>(32);
    // Botan::secure_vector<uint8_t> key;
    Botan::secure_vector<uint8_t> cipher_key;
    Botan::secure_vector<uint8_t> mac_key;
    std::vector<uint8_t> hash_output;
    size_t keysize;

    std::string combined;
    std::string_view algo;

    algo = cipherList[0][0];
    mode = cipherList[0][1];


    if(algo != "ChaCha20Poly1305" && algo != "ChaCha20") {
        combined = algo + "/" + mode;
    }
    if(algo == "ChaCha20Poly1305" || algo == "ChaCha20") combined = algo;


    //Overview: IV size default 16. 64 for Threefish-512, 32 for SHACAL2.
    //IV size remains same for all modes except: OCB (must be 15) and CCM (must be 12 or less)
    if(encryptToggle == "Encrypt")
    {
        try{
            enc = Botan::Cipher_Mode::create_or_throw(combined, Botan::Cipher_Dir::Encryption);
        }
        catch (Botan::Exception e){
            cipherList.clear();
            QString errormsg = QString(e.what());
            emit sendMessage(errormsg);
            emit finished();
            return;
        }
       if(algo == "ChaCha20Poly1305" || algo == "ChaCha20") {
           iv.resize(24);
           iv = rng.random_vec<std::vector<uint8_t>>(24);
       }
       if(mode == "OCB")
       {
           iv.resize(15);
           iv = rng.random_vec<std::vector<uint8_t>>(15);
       }
       if(algo == "SHACAL2" && mode == "CBC/PKCS7")
       {
           iv.resize(32);
           iv = rng.random_vec<std::vector<uint8_t>>(32);
       }
       if(algo == "Threefish-512" && mode == "CBC/PKCS7")
       {
           iv.resize(64);
           iv = rng.random_vec<std::vector<uint8_t>>(64);
       }
       if(mode == "CCM")
       {
           iv.resize(12);
           iv = rng.random_vec<std::vector<uint8_t>>(12);
       }
       fout.write(reinterpret_cast<const char*>(iv.data()), iv.size());
       fout.write(reinterpret_cast<const char*>(salt.data()), salt.size());
    }

    else if(encryptToggle == "Decrypt")
    {
        if(algo == "ChaCha20Poly1305" || algo == "ChaCha20") iv.resize(24);
        if(mode == "OCB") iv.resize(15);
        if(algo == "SHACAL2" && mode == "CBC/PKCS7") iv.resize(32);
        if(algo == "Threefish-512" && mode == "CBC/PKCS7") iv.resize(64);
        if(mode == "CCM") iv.resize(12);

        fin.read(reinterpret_cast<char*>(buffer.data()), iv.size()+salt.size());
        std::copy(buffer.begin(), buffer.begin() + iv.size(), iv.begin());
        std::copy(buffer.begin()+iv.size(), buffer.begin() + +iv.size()+ salt.size(), salt.begin());

        try{

            enc = Botan::Cipher_Mode::create_or_throw(combined, Botan::Cipher_Dir::Decryption);
        }
        catch (Botan::Exception e){
            QString errormsg = QString(e.what());
            emit sendMessage(errormsg);
            emit finished();
            cipherList.clear();
            return;
        }
    }

    //Adjust key size for algorithm
    keysize = 32;
    if(algo == "SHACAL2" || algo == "Threefish-512") {
        keysize = 64;
    }

    if((mode == "CBC/PKCS7" || mode == "CTR-BE")){
        if(encryptToggle == "Encrypt" && cipherList.size() == 1)
            keysize += 32;
        if(encryptToggle == "Decrypt" && cipherList.size() == initialCipherListSize)
            keysize += 32;
    }

    if(mode == "SIV") keysize += 32;


    //Derive key and split if needed
    // if(cipherList.size() == initialCipherListSize) // Implement key reuse logic later
    deriveKey(salt, keysize);

    if(mode != "CBC/PKCS7" && mode != "CTR-BE") {
        cipher_key.resize(keysize);
        std::copy(key.begin(), key.begin()+keysize, cipher_key.begin());
    }

    //Split key into cipher and MAC keys if needed
    if((mode == "CBC/PKCS7" || mode == "CTR-BE")) {
        if((encryptToggle == "Encrypt" && cipherList.size() == 1) || (encryptToggle == "Decrypt" && cipherList.size() == initialCipherListSize)) {
            cipher_key.resize(keysize-32);
            mac_key.resize(32);
            std::copy(key.begin(), key.begin()+keysize-32, cipher_key.begin());
            std::copy(key.begin()+keysize-32, key.end(), mac_key.begin());
        } else{
            cipher_key.resize(keysize);
            std::copy(key.begin(), key.begin()+keysize, cipher_key.begin());
        }
    }


    //Setup
    try{
    enc->set_key(cipher_key);
    enc->start(iv);
    }catch(Botan::Exception e) {
        QString errormsg = QString(e.what());
        emit sendMessage(errormsg);
        emit finished();
        cipherList.clear();
        return;
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
        fin.seekg(iv.size() + salt.size(), std::ios::beg);

        if(mactag == hash_output) emit sendMessage("Authentication successful");
        else emit sendMessage("Authentication failed.");
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
                enc->finish(chunk);
            }
            else enc->update(chunk);

        } catch(Botan::Exception e) {
            QString errormsg = QString(e.what());
            emit sendMessage(errormsg);
            emit finished();
            cipherList.clear();
            return;
        }

        fout.write(reinterpret_cast<const char*>(chunk.data()), chunk.size());

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
    cipherList.erase(cipherList.begin());
    emit sendMessage("Round complete" + QString::fromStdString(" ") + QString::fromStdString(combined));
    inputFile = outputFile;
    outputFile = "temp" + std::to_string(initialCipherListSize - cipherList.size());
}

void Crypto::cipherLoop()
{
    for(int i = 0; i < initialCipherListSize; i++){
        encrypt();
    }

    emit sendMessage("Done");

    for( const std::string& file : cleanupFiles) {
        std::filesystem::remove(file);
    }

    password = "";
    emit progress(100);
    emit finished();
}

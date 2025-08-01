#include "crypto.h"

Crypto::Crypto(QObject *parent, std::string encryptToggle, std::string password,
std::string inputFilePath, std::string outputFilePath, std::string pbkdf, size_t memcost, size_t timecost, size_t threads,
std::string header, std::vector<std::string> cipherList)
    : QObject{parent}
{
    this->encryptToggle = encryptToggle;
    this->password = password;
    this->inputFilePath = inputFilePath;
    this->outputFilePath = outputFilePath;
    this->pbkdf = pbkdf;
    this->memcost=memcost;
    this->timecost=timecost;
    this->threads=threads;
    this->header = header;
    this->cipherList = cipherList;
    this->initialOutputFile = outputFilePath;
    this->initialListSize = cipherList.size();
}

void Crypto::deriveKey(std::vector<uint8_t> salt)
{
    size_t MiB = 1024;
    std::unique_ptr<Botan::PasswordHash> pwd_fam;

    emit sendMessage("Deriving key.");

    //Botan for Scrypt and PBKDF2, libargon2 for Argon2
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
            pbkdf = "PBKDF2(HMAC(SHA-256))";
            pwd_fam = Botan::PasswordHashFamily::create_or_throw(pbkdf)->from_params(timecost);
        }
    } catch(const std::exception& e) {
        emit sendMessage(QString::fromStdString(e.what()));
        emit finished();
        return;
    }
    if(pbkdf == "PBKDF2(HMAC(SHA-256))" || pbkdf == "Scrypt") pwd_fam->hash(key, password, salt);
    password.clear(); // Probably should be cleared in a better way
}

void Crypto::run()
{
    Botan::AutoSeeded_RNG rng;
    std::vector<uint8_t> iv(0);
    std::unique_ptr<Botan::AEAD_Mode> encAEAD;
    std::unique_ptr<Botan::Cipher_Mode> enc;
    std::unique_ptr<Botan::MessageAuthenticationCode> hmac;
    std::vector<uint8_t> hmac_tag;
    Botan::secure_vector<uint8_t> cipher_key;
    Botan::secure_vector<uint8_t> hmac_key;
    std::ifstream inputFileHandle(inputFilePath, std::ios::binary);
    std::ofstream outputFileHandle(outputFilePath, std::ios::binary | std::ios::app);
    bool isOuter = (encryptToggle == "Encrypt" && cipherList.size() == 1) || (encryptToggle == "Decrypt" && cipherList.size() == initialListSize);
    // isOuter is an important variable. Refers to outermost cipher in a chain. For example, for AES(Serpent(Twofish)),
    // AES is the outermost cipher.

    // Resizing ivs, setting cipher string to pass to Botan
    if(mode == "GCM") iv.resize(12);
    if(mode == "OCB") iv.resize(15);
    if(mode == "EAX") iv.resize(Botan::BlockCipher::create(cipher)->block_size());
    if(mode == "CCM") {
        mode = "CCM(16,4)";
        iv.resize(11);
    }
    if(mode == "192-bit") iv.resize(24);
    if(mode == "96-bit") iv.resize(12);
    if(mode == "64-bit") iv.resize(8);
    if(mode == "CBC" || mode == "CTR" || mode == "CFB" || mode == "OFB") iv.resize(Botan::BlockCipher::create(cipher)->block_size());

    std::string algostr = cipher + "/" + mode;
    if(cipher == "ChaCha20") algostr = "ChaCha20";
    if(cipher == "ChaCha20Poly1305") algostr = "ChaCha20Poly1305";
    if(mode == "CTR") algostr = "CTR-BE(" + cipher + ",8)";
    if(mode == "OFB") algostr = "OFB(" + cipher + ")";

    bool isAEAD = (!(mode == "CBC" || mode == "CTR" || algostr == "ChaCha20" || mode == "CFB" || mode == "OFB"));
    if(!isAEAD) hmac = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");

    emit sendMessage(QString::fromStdString(algostr));

    // For encryption, write header and salt only for final encryption in chain.
    if(encryptToggle == "Encrypt") {
        dir = Botan::Cipher_Dir::Encryption;
        iv = rng.random_vec<std::vector<uint8_t>>(iv.size());
        if(isOuter) {
            outputFileHandle.write(reinterpret_cast<char*>(header.data()), header.size());
            outputFileHandle.write(reinterpret_cast<char*>(salt.data()), salt.size());
        }
        if(mode != "SIV") outputFileHandle.write(reinterpret_cast<char*>(iv.data()), iv.size());
    }
    if(encryptToggle == "Decrypt") {
        dir = Botan::Cipher_Dir::Decryption;
        if(isOuter) {
            inputFileHandle.seekg(header.size() + salt.size(), std::ios::beg);
        }
        if(mode != "SIV") inputFileHandle.read(reinterpret_cast<char*>(iv.data()), iv.size());
    }

    // Setting up mode object. AEAD modes need separate class from non-AEAD modes.
    // Getting key for cipher and MAC if applicable.
    try {
        if(isAEAD){
            encAEAD = Botan::AEAD_Mode::create_or_throw(algostr, dir);
            cipher_key.resize(encAEAD->maximum_keylength());

            if(encryptToggle == "Encrypt") {
                cipher_key.assign(key.begin(), key.begin() + cipher_key.size());
                key.erase(key.begin(), key.begin() + cipher_key.size());
            }else {
                cipher_key.assign(key.end() - cipher_key.size(), key.end());
                key.resize(key.size() - cipher_key.size());
            }

            encAEAD->set_key(cipher_key);
            std::span<uint8_t> associated_data(reinterpret_cast<uint8_t*>(header.data()), header.size());
            if(header.size() > 0) encAEAD->set_associated_data(associated_data);
            if(mode != "SIV") encAEAD->start(iv);
        } else {
            enc = Botan::Cipher_Mode::create_or_throw(algostr, dir);
            emit sendMessage(QString::number(enc->maximum_keylength()));
            cipher_key.resize(enc->maximum_keylength());

            if(isOuter) {
                if(encryptToggle == "Encrypt") {
                    cipher_key.assign(key.begin(), key.begin() + cipher_key.size());
                    hmac_key.assign(key.begin() + cipher_key.size(), key.begin() + cipher_key.size() + 32);
                    key.erase(key.begin(), key.begin() + cipher_key.size() + 32);
                }
                if(encryptToggle == "Decrypt") {
                    cipher_key.assign(key.end() - cipher_key.size() - 32, key.end() - 32);
                    hmac_key.assign(key.end()-32, key.end());
                    key.resize(key.size() - cipher_key.size()-32);
                }
                hmac->set_key(hmac_key);
                hmac->update(header);
            } else {
                if(encryptToggle == "Encrypt") {
                    cipher_key.assign(key.begin(), key.begin() + cipher_key.size());
                    key.erase(key.begin(), key.begin() + cipher_key.size());
                }
                if(encryptToggle == "Decrypt") {
                    cipher_key.assign(key.end() - cipher_key.size(), key.end());
                    key.resize(key.size() - cipher_key.size());
                }
            }
            enc->set_key(cipher_key);
            enc->start(iv);
        }
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

    //If encrypting, read file from start. If decrypting in mode other than SIV, start after header, salt and IV.
    //If decrypting in SIV mode, start after header and salt (Cipher class handles IV in this case).
    if(encryptToggle == "Encrypt") inputFileHandle.seekg(0, std::ios::beg);
    if(encryptToggle == "Decrypt") {
       if(mode != "SIV") {
            if(isOuter) inputFileHandle.seekg(salt.size() + iv.size() + header.size(), std::ios::beg);
            else inputFileHandle.seekg(iv.size(), std::ios::beg);
       }
       else inputFileHandle.seekg(salt.size() + header.size(), std::ios::beg);
    }

    //Load entire file into memory for SIV mode.
    try {
        if(mode == "SIV" || mode == "CCM(16,4)") {
            if(encryptToggle == "Decrypt")
            {
                if(mode == "SIV")
                    buffer.resize(filesize - salt.size() - header.size());
                if(mode == "CCM(16,4)")
                    buffer.resize(filesize - salt.size() - header.size() - iv.size());
            }
            else
                buffer.resize(filesize);

            inputFileHandle.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
            encAEAD->finish(buffer);
            outputFileHandle.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
            return;
        }
    }catch(const Botan::Exception& e) {
        emit sendMessage(QString(e.what()));
        emit finished();
        return;
    }


    //Process file in chunks for modes other than SIV
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
                if(!isLastChunk) {
                    if(isAEAD) encAEAD->update(chunk);
                    else {
                        if(encryptToggle == "Decrypt" && isOuter) hmac->update(chunk);
                        enc->update(chunk);
                        if(encryptToggle == "Encrypt" && isOuter) hmac->update(chunk);
                    }
                } else { // last chunk
                    if(isAEAD) encAEAD->finish(chunk);
                    else {
                        if(encryptToggle == "Decrypt" && isOuter){
                            std::vector<uint8_t> tagcheck(chunk.end() - 32, chunk.end());
                            chunk.resize(chunk.size()- 32);
                            hmac->update(chunk);
                            hmac->final(hmac_tag);

                            if(hmac_tag != tagcheck)
                                emit sendMessage("Authentication failed.");
                            else
                                emit sendMessage("Authentication successful.");
                        }
                        enc->finish(chunk);
                        if(encryptToggle == "Encrypt" && isOuter) {
                            hmac->update(chunk);
                            hmac->final(hmac_tag);
                        }
                    }
                }

                outputFileHandle.write(reinterpret_cast<const char*>(chunk.data()), chunk.size());

            } catch(const Botan::Exception& e) {
                emit sendMessage(QString(e.what()));
                // emit finished();
                return;
            }

            int percent = static_cast<int>((100.0 * totalBytesRead) / filesize);
            if (percent != lastPercent) {
                emit progress(percent);
                lastPercent = percent;
            }
    }
    //Awkward placement, but MAC tag must be written to end of file.
    if(!isAEAD) {
        if(encryptToggle == "Encrypt" && isOuter) outputFileHandle.write(reinterpret_cast<const char*>(hmac_tag.data()), hmac_tag.size());
    }
    inputFileHandle.close();
    outputFileHandle.close();
}

void Crypto::start()
{
    //Set salt. Generate randomly for encryption, read from file for decryption.
    salt.resize(32);
    Botan::AutoSeeded_RNG rng;
    std::ifstream inputFileHandle(inputFilePath, std::ios::binary);
    std::ofstream outputFileHandle(outputFilePath, std::ios::binary);
    if(encryptToggle == "Encrypt") {
        salt = rng.random_vec<std::vector<uint8_t>>(32);
    } else {
        inputFileHandle.seekg(header.size(), std::ios::beg);
        inputFileHandle.read(reinterpret_cast<char*>(salt.data()), salt.size());
    }
    inputFileHandle.close();
    outputFileHandle.close();

    //Generate intermediate file list for chained encryption.
    for(int i = 0; i < cipherList.size(); i++) {
        std::string filepath = "output" + std::to_string(i+1);
        fileList.push_back(filepath);
    }
    if(encryptToggle == "Encrypt") dir = Botan::Cipher_Dir::Encryption;
    else dir = Botan::Cipher_Dir::Decryption;

    //Get key sizes and derive main key
    int keysize = 0;

    for(size_t i = 0; i < cipherList.size(); i++){
        std::string item = cipherList[i];
        std::string algostr = item;
        size_t pos = item.find('/');

        if (pos != std::string::npos) {
            cipher = item.substr(0, pos);
            mode = item.substr(pos + 1);
        }
        bool isAEAD = (!(mode == "CBC" || mode == "CTR" || mode == "CFB" || mode == "OFB"));
        if(mode == "CTR") algostr = "CTR-BE(" + cipher + ",4)";
        if(cipher == "ChaCha20" || cipher == "ChaCha20Poly1305") algostr = "ChaCha20";
        keysize += Botan::Cipher_Mode::create_or_throw(algostr, dir)->maximum_keylength();
        bool isOuter = ((encryptToggle == "Encrypt" && i == cipherList.size()-1)) || (encryptToggle == "Decrypt" && i == 0);
        if(!isAEAD && isOuter) keysize += 32;
    }

    key.resize(keysize);
    deriveKey(salt);

    // Apply ciphers in cipherList
    for(int i = 0; i < initialListSize; i++) {
        std::string algostr = cipherList[0];
        size_t pos = algostr.find('/');

        if (pos != std::string::npos) {
            cipher = algostr.substr(0, pos);
            mode = algostr.substr(pos + 1);
        }
        if(cipherList.size() == 1) {
            outputFilePath = initialOutputFile;
        } else {
            outputFilePath = fileList[i];
        }
        run();
        inputFilePath = outputFilePath;
        cipherList.erase(cipherList.begin());
    }

    // Clean up files
    for (const std::string& item : fileList) {
        std::filesystem::remove(item);
    }

    emit finished();
    return;
}

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
    if(mode == "GCM" || mode == "SIV") iv.resize(12);
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

    bool isAEAD = (mode == "GCM" || mode == "SIV" || mode == "OCB" || mode == "CCM(16,4)" || mode == "EAX" || cipher == "ChaCha20Poly1305");
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
        outputFileHandle.write(reinterpret_cast<char*>(iv.data()), iv.size());
    }
    if(encryptToggle == "Decrypt") {
        dir = Botan::Cipher_Dir::Decryption;
        if(isOuter) {
            inputFileHandle.seekg(header.size() + salt.size(), std::ios::beg);
        }
        inputFileHandle.read(reinterpret_cast<char*>(iv.data()), iv.size());
    }

    // Setting up mode object. AEAD modes need separate class from non-AEAD modes.
    // Getting key for cipher and MAC if applicable.
    // std::cout << algostr;
    std::cout << mode << encryptToggle;
    try {
        if(isAEAD){

            encAEAD = Botan::AEAD_Mode::create_or_throw(algostr, dir);
            std::cout << " Maximum key length: " << encAEAD->maximum_keylength() << std::endl;
            cipher_key.resize(encAEAD->maximum_keylength());

            if(encryptToggle == "Encrypt") {
                cipher_key.assign(key.begin(), key.begin() + cipher_key.size());
                key.erase(key.begin(), key.begin() + cipher_key.size());
            }else {
                cipher_key.assign(key.end() - cipher_key.size(), key.end());
                key.resize(key.size() - cipher_key.size());
            }

            encAEAD->set_key(cipher_key);
            std::vector<uint8_t> associated_data(header.size()+salt.size()+iv.size());
            if(header.size() > 0) associated_data.insert(associated_data.end(), header.begin(), header.end());
            associated_data.insert(associated_data.end(), salt.begin(), salt.end());
            associated_data.insert(associated_data.end(), iv.begin(), iv.end());
            encAEAD->set_associated_data(associated_data);
            encAEAD->start(iv);
        } else {

            enc = Botan::Cipher_Mode::create_or_throw(algostr, dir);
            std::cout << " Maximum key length not AEAD: " << enc->maximum_keylength() << std::endl;
            // emit sendMessage(QString::number(enc->maximum_keylength()));
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

    // size_t totalBytesRead = 0;
    int lastPercent = -1;
    std::vector<uint8_t> buffer(4096);

    inputFileHandle.seekg(0, std::ios::end);
    size_t filesize = inputFileHandle.tellg();

    //If encrypting, read file from start. If decrypting in mode other than SIV, start after header, salt and IV.
    //If decrypting in SIV mode, start after header and salt (Cipher class handles IV in this case).
    if(encryptToggle == "Encrypt") inputFileHandle.seekg(0, std::ios::beg);
    if(encryptToggle == "Decrypt") {
        if(isOuter) inputFileHandle.seekg(salt.size() + iv.size() + header.size(), std::ios::beg);
        else inputFileHandle.seekg(iv.size(), std::ios::beg);
    }

    //Load entire file into memory for SIV mode.
    try {
        if(mode == "SIV" || mode == "CCM(16,4)" || filesize < 4096) {
            std::vector<uint8_t> buffer;

            if (encryptToggle == "Decrypt" && isOuter) buffer.resize(filesize - salt.size() - header.size() - iv.size());
            if (encryptToggle == "Decrypt" && !isOuter) buffer.resize(filesize - iv.size());
            if (encryptToggle == "Encrypt") buffer.resize(filesize);
            inputFileHandle.read(reinterpret_cast<char*>(buffer.data()), buffer.size());

            if(isAEAD) {
                encAEAD->finish(buffer);
            } else {
                if(encryptToggle == "Decrypt" && isOuter){
                    std::vector<uint8_t> checktag(buffer.end()-32, buffer.end());
                    buffer.resize(buffer.size()-32);
                    hmac->update(buffer);
                    hmac->final(hmac_tag);
                    if(checktag == hmac_tag)
                        emit sendMessage("Authentication successful.");
                    else
                        emit sendMessage("Authentication failed.");
                }
                enc->finish(buffer);
                if(encryptToggle == "Encrypt" && isOuter){
                    hmac->update(buffer);
                    hmac->final(hmac_tag);
                }
            }
            outputFileHandle.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
            if(!isAEAD && encryptToggle == "Encrypt" && isOuter) outputFileHandle.write(reinterpret_cast<const char*>(hmac_tag.data()), hmac_tag.size());

            emit finished();
            return;
        }
    } catch(const Botan::Exception& e) {
        emit sendMessage(QString(e.what()));
        emit finished();
        return;
    }
    size_t chunkSize = 4096;
    size_t ciphertext_size;
    size_t totalBytesRead = 0;
    size_t tagsize;
    if(isAEAD) tagsize = encAEAD->tag_size();
    else tagsize = 32;

    if(encryptToggle == "Encrypt"){
        ciphertext_size = filesize;
    } else  {
        ciphertext_size = filesize - header.size() - iv.size() - salt.size();
        size_t remainder = ciphertext_size % chunkSize;
        size_t blocksize = Botan::BlockCipher::create_or_throw(cipher)->block_size();
        if(mode == "CBC") remainder = blocksize;
        if(remainder > 0 && mode != "OCB"){ // OCB only allows multiple of block size for update calls
            inputFileHandle.read(reinterpret_cast<char*>(buffer.data()), remainder);
            std::vector<uint8_t> chunk(buffer.begin(), buffer.begin() + inputFileHandle.gcount());

            if(isAEAD) encAEAD->update(chunk);
            else {
                if(isOuter && encryptToggle == "Decrypt") hmac->update(chunk);
                enc->update(chunk);
                if(isOuter && encryptToggle == "Encrypt") {
                    if(header.size() > 0) hmac->update(header);
                    hmac->update(salt);
                    hmac->update(iv);
                    hmac->update(chunk);
                }
            }

            outputFileHandle.write(reinterpret_cast<const char*>(chunk.data()), chunk.size());
        }
    }

    while(true){
        inputFileHandle.read(reinterpret_cast<char*>(buffer.data()), buffer.size());

        size_t bytesRead = inputFileHandle.gcount();
        totalBytesRead += bytesRead;
        if (bytesRead == 0) break;

        std::vector<uint8_t> chunk(buffer.begin(), buffer.begin() + bytesRead);

        try {
            if(inputFileHandle.eof() || inputFileHandle.peek() == EOF){
                Botan::secure_vector<uint8_t> out(chunk.begin(), chunk.end());
                if(isAEAD) {
                    encAEAD->finish(out);
                } else {
                    if(isOuter && encryptToggle == "Decrypt"){
                        std::vector<uint8_t> checktag(out.end() - 32, out.end());
                        out.resize(out.size() - 32);
                        hmac->update(out);
                        hmac->final(hmac_tag);

                        if(checktag != hmac_tag){
                            emit sendMessage("Authenitcation failed.");
                        } else {
                            emit sendMessage("Authentication successful.");
                        }
                    }
                    enc->finish(out);
                    if(isOuter && encryptToggle == "Encrypt"){
                        hmac->update(out);
                        hmac->final(hmac_tag);
                    }
                }
                outputFileHandle.write(reinterpret_cast<const char*>(out.data()), out.size());
            } else {
                if(isAEAD) encAEAD->update(chunk);
                else {
                    if(isOuter && encryptToggle == "Decrypt") hmac->update(chunk);
                    enc->update(chunk);
                    if(isOuter && encryptToggle == "Encrypt") hmac->update(chunk);
                }
                outputFileHandle.write(reinterpret_cast<const char*>(chunk.data()), chunk.size());
            }

        } catch(const Botan::Exception& e) {
            emit sendMessage(QString::fromStdString(e.what()));
            return;
        }

        int percent = static_cast<int>((100.0 * totalBytesRead) / filesize);
        if (percent != lastPercent) {
            emit progress(percent);
            lastPercent = percent;
        }
    }
    if(!isAEAD && encryptToggle == "Encrypt") outputFileHandle.write(reinterpret_cast<const char*>(hmac_tag.data()), hmac_tag.size());
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
        if(mode == "CTR") algostr = "CTR-BE(" + cipher + ",8)";
        if(mode == "OFB") algostr = "OFB(" + cipher + ")";
        if(cipher == "ChaCha20" || cipher == "ChaCha20Poly1305") algostr = cipher;
        keysize += Botan::Cipher_Mode::create_or_throw(algostr, dir)->maximum_keylength();
        bool isOuter = ((encryptToggle == "Encrypt" && i == cipherList.size()-1)) || (encryptToggle == "Decrypt" && i == 0);
        if(!isAEAD && isOuter) keysize += 32;
    }

    key.resize(keysize);
    deriveKey(salt);

    std::string header_store = header;
    if(encryptToggle == "Encrypt") header.clear();

    // Apply ciphers in cipherList
    for(int i = 0; i < initialListSize; i++) {
        if(cipherList.size() == 1 && encryptToggle == "Encrypt")
            header = header_store;
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
        if(cipherList.size() == initialListSize && encryptToggle == "Decrypt")
            header.clear();
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

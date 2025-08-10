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
            pbkdf = "PBKDF2(HMAC(SHA-256))";
            pwd_fam = Botan::PasswordHashFamily::create_or_throw(pbkdf)->from_params(timecost);
        }
    } catch(const std::exception& e) {
        emit sendMessage(QString::fromStdString(e.what()));
        emit finished();
        return;
    }

    if(pbkdf == "PBKDF2(HMAC(SHA-256))" || pbkdf == "Scrypt") pwd_fam->hash(key, password, salt);
    password = "";
}

void Crypto::run()
{
    Botan::AutoSeeded_RNG rng;
    std::vector<uint8_t> salt(32);
    std::vector<uint8_t> iv;

    if(mode == "GCM" || mode == "SIV") iv.resize(12);
    if(mode == "CCM"){
        iv.resize(11);
        mode = "CCM(16,4)";
    }
    if(mode == "OCB") iv.resize(12); // changed from 15. change back if encountering errors. maybe should include iv size in header
    if(mode == "CBC" || mode == "CTR" || mode == "CFB" || mode == "OFB") iv.resize(Botan::BlockCipher::create_or_throw(cipher)->block_size());
    if(mode == "EAX") iv.resize(key.size()); // maybe needs adjusting for shacal2
    if(mode == "192-bit") iv.resize(24);
    if(mode == "96-bit") iv.resize(12);
    if(mode == "64-bit") iv.resize(8);
    std::unique_ptr<Botan::AEAD_Mode> encAEAD;
    std::unique_ptr<Botan::Cipher_Mode> enc;
    std::unique_ptr<Botan::MessageAuthenticationCode> hmac;
    Botan::Cipher_Dir dir;
    std::vector<uint8_t> hmac_tag(32);
    std::string algostr = cipher + "/" + mode;

    if(cipher == "ChaCha20") algostr = "ChaCha20Poly1305";
    if(mode == "CTR") algostr = "CTR-BE(" + cipher +",8)";
    if(mode == "OFB") algostr = "OFB(" + cipher + ")";
    std::string_view algostrview = algostr;

    bool isAEAD = (mode == "GCM" || mode == "SIV" || mode == "OCB" || mode == "CCM(16,4)" || mode == "EAX" || cipher == "ChaCha20Poly1305");


    std::ifstream inputFileHandle(inputFilePath, std::ios::binary);
    std::ofstream outputFileHandle(outputFilePath, std::ios::binary);
    if(encryptToggle == "Encrypt") {
        dir = Botan::Cipher_Dir::Encryption;
        salt = rng.random_vec<std::vector<uint8_t>>(32);
        iv = rng.random_vec<std::vector<uint8_t>>(iv.size());
        if(header.size() > 0) outputFileHandle.write(reinterpret_cast<char*>(header.data()), header.size());
        outputFileHandle.write(reinterpret_cast<char*>(salt.data()), salt.size());
        outputFileHandle.write(reinterpret_cast<char*>(iv.data()), iv.size());
    }
    if(encryptToggle == "Decrypt") {
        dir = Botan::Cipher_Dir::Decryption;
        inputFileHandle.seekg(header.size(), std::ios::beg);
        inputFileHandle.read(reinterpret_cast<char*>(salt.data()), salt.size());
        inputFileHandle.read(reinterpret_cast<char*>(iv.data()), iv.size());
    }

    if(isAEAD) {
        encAEAD = Botan::AEAD_Mode::create_or_throw(algostrview, dir);
        key.resize(encAEAD->maximum_keylength());
    }
    else {
        enc = Botan::Cipher_Mode::create_or_throw(algostrview, dir);
        key.resize(enc->maximum_keylength());
    }

    deriveKey(salt);

    try {
        if(isAEAD) {
            encAEAD->set_key(key);
            std::vector<uint8_t> associated_data(header.size()+salt.size()+iv.size());
            if(header.size() > 0) associated_data.insert(associated_data.end(), header.begin(), header.end());
            associated_data.insert(associated_data.end(), salt.begin(), salt.end());
            associated_data.insert(associated_data.end(), iv.begin(), iv.end());
            encAEAD->set_associated_data(associated_data);
            encAEAD->start(iv);
        } else {
            Botan::secure_vector<uint8_t> mac_key;
            hmac = Botan::MessageAuthenticationCode::create_or_throw("HMAC(SHA-256)");
            auto kdf = Botan::KDF::create_or_throw("HKDF(SHA-256)");
            mac_key = kdf->derive_key(32, key);
            enc->set_key(key);
            enc->start(iv);
            hmac->set_key(mac_key);
            if(header.size() > 0) hmac->update(header);
            hmac->update(salt);
            hmac->update(iv);
        }
    } catch(const Botan::Exception& e) {
        emit sendMessage(QString(e.what()));
        emit finished();
        return;
    }

    int lastPercent = -1;
    inputFileHandle.seekg(0, std::ios::end);
    size_t filesize = inputFileHandle.tellg();
    size_t ciphertext_size;
    if(encryptToggle == "Encrypt") {
        ciphertext_size = filesize;
        inputFileHandle.seekg(0, std::ios::beg);
    }
    if(encryptToggle == "Decrypt") {
        ciphertext_size = filesize - header.size() - salt.size() - iv.size();
        inputFileHandle.seekg(salt.size() + iv.size() + header.size(), std::ios::beg);
    }

    size_t chunkSize = 1024 * 1024;

    std::vector<uint8_t> buffer(chunkSize);
    size_t totalBytesRead = 0;
    size_t remainder = ciphertext_size % chunkSize;
    size_t numchunks = (ciphertext_size - remainder - chunkSize) / chunkSize; // case when ciphertext is multiple of chunksize?

    // Encrypt in chunks if applicable
    if(!(mode == "SIV" || mode == "CCM(16,4)" || ciphertext_size < (1 << 20))){
        for(size_t i = 0; i < numchunks; i++){
            inputFileHandle.read(reinterpret_cast<char*>(buffer.data()), chunkSize);
            size_t read = inputFileHandle.gcount();
            buffer.resize(read);  // resize to actual data read


            if(isAEAD) {
                encAEAD->update(buffer);
            } else {
                if(encryptToggle == "Decrypt") hmac->update(buffer);
                enc->update(buffer);
                if(encryptToggle == "Encrypt") hmac->update(buffer);
            }

            outputFileHandle.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());

            totalBytesRead += read;
            int percent = static_cast<int>((100.0 * totalBytesRead) / ciphertext_size);
            if (percent != lastPercent) {
                emit progress(percent);
                lastPercent = percent;
            }
        }
    }

    // Load entire file into memory for some modes, otherwise finish last chunk
    if(mode == "SIV" || mode == "CCM(16,4)" || ciphertext_size < (1 << 20)) buffer.resize(ciphertext_size);
    else buffer.resize(chunkSize * 2);
    inputFileHandle.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
    buffer.resize(inputFileHandle.gcount());

    if(isAEAD){
        encAEAD->finish(buffer);
    } else {
        if(encryptToggle == "Decrypt"){
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
        if(encryptToggle == "Encrypt"){
            hmac->update(buffer);
            hmac->final(hmac_tag);
        }
    }

    outputFileHandle.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());

    if(!isAEAD && encryptToggle == "Encrypt") outputFileHandle.write(reinterpret_cast<const char*>(hmac_tag.data()), hmac_tag.size());

    inputFileHandle.close();
    outputFileHandle.close();

    emit sendMessage("Done");
    emit finished();
}

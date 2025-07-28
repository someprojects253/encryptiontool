#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    // Encrypt/Decrypt buttons
    ui->pushButton_addCipher->setEnabled(false);
    ui->pushButton_removeCipher->setEnabled(false);
    connect(ui->pushButton_Encrypt, &QPushButton::clicked, this, [this]() {
        run("Encrypt");
    });
    connect(ui->pushButton_Decrypt, &QPushButton::clicked, this, [this]() {
        run("Decrypt");
    });

    // UI elements for chained encryption
    connect(ui->pushButton_addCipher, &QPushButton::clicked, this, [this] () {
        updateCipherList("Add");
    });
    connect(ui->pushButton_removeCipher, &QPushButton::clicked, this, [this] () {
        updateCipherList("Remove");
    });
    connect(ui->checkBox_chain, &QCheckBox::checkStateChanged, this, [this] (Qt::CheckState state) {
        cipherList.clear();
        ui->lineEdit_cipherList->clear();
        if(state == Qt::Checked) {
            ui->pushButton_addCipher->setEnabled(true);
            ui->pushButton_removeCipher->setEnabled(true);
        } else {
            ui->pushButton_addCipher->setEnabled(false);
            ui->pushButton_removeCipher->setEnabled(false);
        }
        updateButtons();
    });

    // Password UI elements
    connect(ui->lineEdit_Password, &QLineEdit::textEdited, this, &MainWindow::updateButtons);
    connect(ui->lineEdit_confirmPassword, &QLineEdit::textEdited, this, &MainWindow::updateButtons);
    connect(ui->checkBox_showPassword, &QCheckBox::checkStateChanged, this, [this](const Qt::CheckState& checkState) {
        if(checkState == Qt::Checked){
            ui->lineEdit_Password->setEchoMode(QLineEdit::Normal);
            ui->lineEdit_confirmPassword->setEchoMode(QLineEdit::Normal);
        } else {
            ui->lineEdit_Password->setEchoMode(QLineEdit::Password);
            ui->lineEdit_confirmPassword->setEchoMode(QLineEdit::Password);
        }
    });

    // Handle file dropped
    connect(this, &MainWindow::fileDropped, this, [this]() {
        ui->lineEdit_inputFile->setText(QString::fromStdString(inputFilePath));
        getHeader();
        if(header.size() > 0) setParams("header");
        else setParams("");
        updateButtons();
    });

    // Information about ciphers and modes. Add and remove modes based on ciphers.
    connect(ui->comboBox_cipher, &QComboBox::currentTextChanged, this, [this] (QString item){
        ui->comboBox_mode->clear();
        ui->comboBox_mode->setToolTip("");
        if(item == "AES")
            ui->comboBox_mode->addItems({"GCM", "CBC", "CTR", "OCB", "EAX", "SIV", "CCM", "CFB", "OFB"});
        else if (item == "SHACAL2" || item == "Threefish-512")
            ui->comboBox_mode->addItems({"CBC", "CTR", "OCB", "EAX", "CFB", "OFB"});
        else if (item == "Blowfish" || item == "IDEA" || item == "3DES") {
            ui->comboBox_mode->addItems({"CBC", "CTR", "CFB", "OFB", "EAX"});
            ui->textBrowser->append(item + ": This is a 64-bit block cipher. Recommended not to encrypt more than "
                                    "4GB with this cipher.\n");
        }
        else if (item == "ChaCha20"){
            ui->comboBox_mode->addItems({"192-bit", "96-bit", "64-bit"});
            ui->textBrowser->append("ChaCha20 will be used with Poly1305 if it is the only cipher used or if it is the last cipher used in a chain. "
                                    "The number of bits refers to the nonce size. 64-bit has a higher proabability of nonce reuse but "
                                    "a higher file size limit (exabytes). 96-bit and 192-bit nonces have a lower probability of nonce reuse "
                                    "but a lower file size limit (256GB). ChaCha20 with a 192-bit nonce is XChaCha20.\n");
        }
        else
            ui->comboBox_mode->addItems({"CBC", "CTR", "OCB", "EAX", "SIV", "CCM", "CFB", "OFB"});

    });

    connect(ui->comboBox_mode, &QComboBox::currentTextChanged, this, [this] (QString item) {
        if(item == "CCM")
            ui->textBrowser->append("Warning: CCM mode has max file size of 4GB. Entire file is loaded into memory. Ensure you have enough memory available.\n");
        if(item == "SIV")
            ui->textBrowser->append("Warning: SIV mode loads entire file into memory. Ensure you have enough memory available.");
        if(item == "CTR" || item == "CBC" || item == "CFB" || item == "OFB")
            ui->textBrowser->append(item+ ": This is an unauthenticated mode. If a cipher is used in this mode, and if it is the only cipher "
                                    "used, or if it is the last cipher used in a chain, authentication will be added with HMAC-SHA256. "
                                    "The authentication tag is 32 bytes and will be added to the end of the file.\n");
    });

    // Update labels for different PBKDFs
    connect (ui->comboBox_PBKDF, &QComboBox::currentTextChanged, this, [this](){
        updateLabels();
        setParams("");
    });
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::updateButtons()
{
    QString password = ui->lineEdit_Password->text();
    QString confirm = ui->lineEdit_confirmPassword->text();

    if(password.length() > 0 && inputFilePath.length() > 0 && (cipherList.size() > 0 || !ui->checkBox_chain->isChecked())){
        ui->pushButton_Decrypt->setEnabled(true);
        if(password == confirm) ui->pushButton_Encrypt->setEnabled(true);
        else ui->pushButton_Encrypt->setEnabled(false);
    } else {
        ui->pushButton_Encrypt->setEnabled(false);
        ui->pushButton_Decrypt->setEnabled(false);
    }
}

void MainWindow::run(std::string encryptToggle)
{
    ui->textBrowser->clear();

    std::string cipher = ui->comboBox_cipher->currentText().toStdString();
    std::string mode = ui->comboBox_mode->currentText().toStdString();
    std::string password = ui->lineEdit_Password->text().toStdString();
    std::string pbkdf = ui->comboBox_PBKDF->currentText().toStdString();
    size_t memcost = ui->lineEdit_memcost->text().toUInt();
    size_t timecost = ui->lineEdit_timecost->text().toUInt();
    size_t threads = ui->lineEdit_threads->text().toUInt();

    if(cipher == "AES") cipher = "AES-256";
    if(cipher == "Camellia") cipher = "Camellia-256";

    std::string cipherChain = cipher + "/" + mode;
    if(ui->checkBox_chain->isChecked()) {
        cipherChain = ui->lineEdit_cipherList->text().toStdString();
    }

    if(encryptToggle == "Encrypt") {
        outputFilePath = inputFilePath + ".bin";
        if(ui->checkBox_header->isChecked()){
            this->header = "cryptoheader\n"
                            "pbkdf=" + pbkdf + "\n"
                            "cipher=" + cipherChain + "\n"
                            "memcost=" + std::to_string(memcost) + "\n"
                            "timecost=" + std::to_string(timecost) + "\n"
                            "threads=" + std::to_string(threads) + "\nendheader";

            std::string from, to;
            if(pbkdf != "Scrypt" && pbkdf != "PBKDF2"){
                from = "memcost";
                to = "memcost(MiB)";
            }
            if(pbkdf == "PBKDF2"){
                from = "timecost";
                to = "timecost(1000s)";
            }
            if(pbkdf == "Scrypt") {
                from = "timecost";
                to = "timecost(2^x)";
            }
            if (auto pos = header.find(from); pos != std::string::npos)
                header.replace(pos, from.length(), to);
        } else {
            this->header="";
        }
    }
    if(encryptToggle == "Decrypt"){
        std::string to_remove = ".bin";
        std::string edited = inputFilePath;
        size_t pos = edited.find(to_remove);
        if (pos != std::string::npos) {
            edited.erase(pos, to_remove.length());
            edited += "_decrypted";
        } else {
            edited += "_decrypted";
        }
        outputFilePath = edited;
    }

    if(ui->checkBox_chain->isChecked() == false) {
        std::string algostr = cipher + "/" + mode;
        cipherList.push_back(algostr);
    }
    if(encryptToggle == "Encrypt") std::reverse(cipherList.begin(), cipherList.end());

    Crypto* worker = new Crypto(nullptr, encryptToggle, password, inputFilePath, outputFilePath,
                                pbkdf, memcost, timecost, threads, header, cipherList);
    QThread* thread = new QThread;

    worker->moveToThread(thread);

    connect(thread, &QThread::started, worker, &Crypto::start);
    connect(worker, &Crypto::finished, this, [this]{
        updateButtons();
        ui->progressBar->setValue(100);
        this->header.clear();
        cipherList.clear();
        ui->lineEdit_cipherList->clear();
    });
    connect(worker, &Crypto::finished, thread, &QThread::quit);
    connect(worker, &Crypto::finished, worker, &QObject::deleteLater);
    connect(thread, &QThread::finished, thread, &QObject::deleteLater);
    connect(worker, &Crypto::progress, this, [this](int percent){
        ui->progressBar->setValue(percent);
    });

    connect(worker, &Crypto::sendMessage, this, [this](QString message){
        ui->textBrowser->append(message);
        ui->textBrowser->moveCursor(QTextCursor::End);
    });

    ui->pushButton_Encrypt->setEnabled(false);
    ui->pushButton_Decrypt->setEnabled(false);

    ui->lineEdit_Password->clear();
    ui->lineEdit_confirmPassword->clear();
    password.clear();
    header.clear();
    thread->start();
}

void MainWindow::getHeader()
{
    std::ifstream inputFileHandle(inputFilePath, std::ios::binary);
    if (!inputFileHandle)
        return;  // Handle file open failure gracefully

    const std::string headerStart = "cryptoheader";
    const std::string headerEnd = "endheader";

    // Read only the first N bytes to check for "cryptoheader"
    std::vector<char> buffer(headerStart.size());
    inputFileHandle.read(buffer.data(), buffer.size());

    std::string startCheck(buffer.begin(), buffer.end());

    if (startCheck != headerStart){
        ui->textBrowser->append("No header found.");
        return;  // No header — do nothing
    }

    // If we made it here, we found the header prefix — now read until "endheader"
    std::ostringstream headerStream;
    headerStream << startCheck;

    char ch;
    std::string rollingBuffer;
    while (inputFileHandle.get(ch))
    {
        headerStream.put(ch);
        rollingBuffer += ch;

        // Keep rolling buffer the same length as "endheader"
        if (rollingBuffer.size() > headerEnd.size())
            rollingBuffer.erase(0, 1);

        if (rollingBuffer == headerEnd)
            break;  // End of header reached
    }

    std::string fullHeader = headerStream.str();
    ui->textBrowser->append("Header found: \n" + QString::fromStdString(fullHeader));
    this->header = fullHeader;  // Assuming `header` is a member variable
}

void MainWindow::setParams(std::string preset)
{
    if(preset != "header") {
        QString pbkdf = ui->comboBox_PBKDF->currentText();
        if(pbkdf == "PBKDF2") {
            ui->lineEdit_memcost->setText("0");
            ui->lineEdit_threads->setText("0");
            ui->lineEdit_timecost->setText("600");
        } else if (pbkdf == "Scrypt") {
            ui->lineEdit_threads->setText("1");
            ui->lineEdit_memcost->setText("8");
            ui->lineEdit_timecost->setText("20");
        } else { // Argon2
            ui->lineEdit_threads->setText("4");
            ui->lineEdit_memcost->setText("2048");
            ui->lineEdit_timecost->setText("1");
        }
        return;
    }

    cipherList.clear();
    std::istringstream stream(header);
    std::string line;

    while (std::getline(stream, line)) {
        size_t pos = line.find('=');
        if (pos != std::string::npos) {
            std::string key = line.substr(0, pos);
            std::string value = line.substr(pos + 1);

            if(key == "memcost" || key == "memcost(MiB)")  ui->lineEdit_memcost->setText(QString::fromStdString(value));
            if(key == "timecost" || key == "timecost(2^x)" || key == "timecost(1000s)") ui->lineEdit_timecost->setText(QString::fromStdString(value));
            if(key == "threads") ui->lineEdit_threads->setText(QString::fromStdString(value));

            if(key == "pbkdf") {
                int index = ui->comboBox_PBKDF->findText(QString::fromStdString(value));
                ui->comboBox_PBKDF->setCurrentIndex(index);
            }
            if(key == "cipher") {
                std::string algostr = value;
                std::string cipherstr, modestr;

                QString algoQStr = QString::fromStdString(algostr);
                if(algoQStr.contains("(")) {
                    ui->checkBox_chain->setCheckState(Qt::Checked);
                    ui->lineEdit_cipherList->setText(algoQStr);
                    algoQStr.remove(")");
                    QStringList cipherListQStr = algoQStr.split("(");
                    for(const QString& item : cipherListQStr) {
                        cipherList.push_back(item.toStdString());
                    }
                } else {
                    ui->checkBox_chain->setCheckState(Qt::Unchecked);
                    ui->lineEdit_cipherList->clear();

                    size_t pos = algostr.find('/');
                    if (pos != std::string::npos) {
                        cipherstr = algostr.substr(0, pos);
                        modestr = algostr.substr(pos + 1);
                    }
                    if(cipherstr == "AES-256") cipherstr = "AES";
                    if(cipherstr == "Camellia-256") cipherstr = "Camellia";

                    int index = ui->comboBox_cipher->findText(QString::fromStdString(cipherstr));
                    ui->comboBox_cipher->setCurrentIndex(index);
                    index = ui->comboBox_mode->findText(QString::fromStdString(modestr));
                    ui->comboBox_mode->setCurrentIndex(index);

                }
            }
        }
    }
}

void MainWindow::updateLabels()
{
    QString current_pbkdf = ui->comboBox_PBKDF->currentText();

    if(current_pbkdf == "PBKDF2"){
        ui->lineEdit_memcost->setEnabled(false);
        ui->lineEdit_threads->setEnabled(false);
        ui->label_iterations->setText("Iterations (1000s)");
    }
    if(current_pbkdf == "Argon2id" || current_pbkdf == "Argon2i" || current_pbkdf == "Argon2d") {
        ui->lineEdit_memcost->setEnabled(true);
        ui->lineEdit_threads->setEnabled(true);
        ui->label_iterations->setText("Iterations");
    }
    if(current_pbkdf == "Scrypt"){
        ui->lineEdit_memcost->setEnabled(true);
        ui->lineEdit_threads->setEnabled(true);
        ui->label_iterations->setText("Iterations (2^x)");
    }
}

void MainWindow::updateCipherList(QString addToggle)
{
    std::string cipher = ui->comboBox_cipher->currentText().toStdString();
    std::string mode = ui->comboBox_mode->currentText().toStdString();
    if(cipher == "AES") cipher = "AES-256";
    if(cipher == "Camellia") cipher = "Camellia-256";
    if(cipher == "ChaCha20" && cipherList.size() == 0) cipher = "ChaCha20Poly1305";
    if(addToggle == "Add"){
        cipherList.push_back(cipher + "/" + mode);
    } else {
        if(cipherList.size() > 0) cipherList.pop_back();
        else return;
    }

    QString cipherChain = "";

    for(const std::string& item : cipherList) {
        cipherChain += QString::fromStdString(item) + "(";
    }
    for(int i = 0; i < cipherList.size(); i++) {
        cipherChain += ")";
    }
    cipherChain.replace("()", "");
    ui->lineEdit_cipherList->setText(cipherChain);
    updateButtons();
}


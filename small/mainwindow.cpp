#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    connect(ui->pushButton_Encrypt, &QPushButton::clicked, this, [this]() {
        run("Encrypt");
    });
    connect(ui->pushButton_Decrypt, &QPushButton::clicked, this, [this]() {
        run("Decrypt");
    });

    connect(ui->lineEdit_Password, &QLineEdit::textEdited, this, &MainWindow::updateButtons);
    connect(ui->lineEdit_confirmPassword, &QLineEdit::textEdited, this, &MainWindow::updateButtons);

    connect(this, &MainWindow::fileDropped, this, [this]() {
        ui->lineEdit_inputFile->setText(QString::fromStdString(inputFilePath));
        getHeader();
        updateButtons();
        setParams("header");
    });

    connect(ui->comboBox_cipher, &QComboBox::currentTextChanged, this, [this] (QString item){
        ui->textBrowser->clear();
        ui->comboBox_mode->clear();
        // 128-bit block ciphers
        if(item == "AES" || item == "Serpent" || item == "Twofish" || item == "Camellia" || item == "Kuznyechik" || item == "SM4")
            ui->comboBox_mode->addItems({"GCM", "OCB", "EAX", "SIV"});
        // Wide block ciphers
        if (item == "SHACAL2" || item == "Threefish-512")
            ui->comboBox_mode->addItems({"OCB", "EAX"});
        // 64-bit block ciphers
        if (item == "Blowfish" || item == "IDEA" || item == "3DES") {
            ui->comboBox_mode->addItems({"EAX"});
            ui->textBrowser->append(item + ": This is a 64-bit block cipher. Recommended not to encrypt more than "
                                           "4GB with this cipher.\n");
        }
        if (item == "ChaCha20"){
            ui->comboBox_mode->addItems({"192-bit", "96-bit", "64-bit"});
            ui->textBrowser->append("ChaCha20 will be used with Poly1305. "
                                    "The number of bits refers to the nonce size. 64-bit has a higher proabability of nonce reuse but "
                                    "a higher file size limit (exabytes). 96-bit and 192-bit nonces have a lower probability of nonce reuse "
                                    "but a lower file size limit (256GB). ChaCha20 with a 192-bit nonce is XChaCha20.\n");
        }
    });

    connect(ui->comboBox_mode, &QComboBox::currentTextChanged, this, [this] (QString item) {
        if(item == "GCM")
            ui->textBrowser->append("Max file size in GCM mode is ~64GB before security failure.");
        if(item == "SIV")
            ui->textBrowser->append("Warning: SIV mode loads entire file into memory. Ensure you have enough memory available.");
    });
    
    connect (ui->comboBox_PBKDF, &QComboBox::currentTextChanged, this, [this]() {
        updateLabels();
        setParams();
    });

    connect(ui->checkBox_showPassword, &QCheckBox::checkStateChanged, this, [this](const Qt::CheckState& checkState) {
        if(checkState == Qt::Checked){
            ui->lineEdit_Password->setEchoMode(QLineEdit::Normal);
            ui->lineEdit_confirmPassword->setEchoMode(QLineEdit::Normal);
        } else {
            ui->lineEdit_Password->setEchoMode(QLineEdit::Password);
            ui->lineEdit_confirmPassword->setEchoMode(QLineEdit::Password);
        }
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
    if(password.length() > 0 && inputFilePath.length() > 0){
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
    std::string cipher = ui->comboBox_cipher->currentText().toStdString();
    std::string mode = ui->comboBox_mode->currentText().toStdString();
    std::string password = ui->lineEdit_Password->text().toStdString();
    std::string pbkdf = ui->comboBox_PBKDF->currentText().toStdString();
    size_t memcost = ui->lineEdit_memcost->text().toUInt();
    size_t timecost = ui->lineEdit_timecost->text().toUInt();
    size_t threads = ui->lineEdit_threads->text().toUInt();

    if(cipher == "AES") cipher = "AES-256";
    if(cipher == "Camellia") cipher = "Camellia-256";

    if(encryptToggle == "Encrypt") {
        outputFilePath = inputFilePath + ".enc";
        if(ui->checkBox_header->isChecked()){
            this->header = "cryptoheader\n"
                            "pbkdf=" + pbkdf + "\n"
                            "cipher=" + cipher + "/" + mode+ "\n"
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
        std::string to_remove = ".enc";
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

    Crypto* worker = new Crypto(nullptr, encryptToggle, cipher, mode, password, inputFilePath, outputFilePath,
                                pbkdf, memcost, timecost, threads, header);
    QThread* thread = new QThread;

    worker->moveToThread(thread);

    connect(thread, &QThread::started, worker, &Crypto::run);
    connect(worker, &Crypto::finished, this, [this]{
        updateButtons();
        ui->progressBar->setValue(100);
        this->header.clear();
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

void MainWindow::setParams(QString preset)
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
            ui->lineEdit_threads->setText("1");
            ui->lineEdit_memcost->setText("2048");
            ui->lineEdit_timecost->setText("1");
        }
        return;
    }


    std::istringstream stream(header);
    std::string line;

    while (std::getline(stream, line)) {
        size_t pos = line.find('=');
        if (pos != std::string::npos) {
            std::string key = line.substr(0, pos);
            std::string value = line.substr(pos + 1);

            if(key == "pbkdf") {
                int index = ui->comboBox_PBKDF->findText(QString::fromStdString(value));
                ui->comboBox_PBKDF->setCurrentIndex(index);
            }
            if(key == "cipher") {
                std::string algostr = value;
                std::string cipherstr, modestr;

                size_t pos = algostr.find('/');
                if (pos != std::string::npos) {
                    cipherstr = algostr.substr(0, pos);
                    modestr = algostr.substr(pos + 1);
                }
                if(cipherstr == "AES-256") cipherstr = "AES";

                int index = ui->comboBox_cipher->findText(QString::fromStdString(cipherstr));
                ui->comboBox_cipher->setCurrentIndex(index);
                index = ui->comboBox_mode->findText(QString::fromStdString(modestr));
                ui->comboBox_mode->setCurrentIndex(index);
            }
            if(key == "memcost" || key == "memcost(MiB)")  ui->lineEdit_memcost->setText(QString::fromStdString(value));
            if(key == "timecost" || key == "timecost(2^x)" || key == "timecost(1000s)") ui->lineEdit_timecost->setText(QString::fromStdString(value));
            if(key == "threads") ui->lineEdit_threads->setText(QString::fromStdString(value));
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


#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QFile>
#include <QTextStream>
#include <QByteArray>
#include <QDebug>
#include <QIntValidator>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    header = "";
    ui->setupUi(this);
    ui->pushButton->setDisabled(true);

    ui->lineEdit_memcost->setValidator(new QIntValidator(ui->lineEdit_memcost));
    ui->lineEdit_timecost->setValidator(new QIntValidator(ui->lineEdit_timecost));
    ui->lineEdit_threads->setValidator(new QIntValidator(ui->lineEdit_threads));

    // Start button enable conditions
    connect(ui->lineEdit_Password, &QLineEdit::textChanged, this, &MainWindow::updateButtonState);
    connect(ui->lineEdit_confirm, &QLineEdit::textChanged, this, &MainWindow::updateButtonState);
    connect(ui->lineEdit_inputFile, &QLineEdit::textChanged, this, &MainWindow::updateButtonState);
    connect(ui->lineEdit_outputFile, &QLineEdit::textChanged, this, &MainWindow::updateButtonState);
    connect(ui->comboBox_EncryptDecrypt, &QComboBox::currentIndexChanged, this, &MainWindow::updateButtonState);
    connect(ui->checkBox_chainToggle, &QCheckBox::checkStateChanged, this, &MainWindow::updateButtonState);
    connect(ui->pushButton_Add, &QPushButton::clicked, this, &MainWindow::updateButtonState);
    connect(ui->pushButton_Remove, &QPushButton::clicked, this, &MainWindow::updateButtonState);

    connect(ui->comboBox_Algorithm, &QComboBox::currentIndexChanged, this, [this]{
        QString cipher = ui->comboBox_Algorithm->currentText();
        if(cipher == "SHACAL2" || cipher == "Threefish-512"){
            ui->comboBox_cipherMode->setItemData(2, false, Qt::UserRole -1);
         ui->comboBox_cipherMode->setItemData(3, false, Qt::UserRole -1);
        } else {
            ui->comboBox_cipherMode->setItemData(2, QVariant(), Qt::UserRole -1);
            ui->comboBox_cipherMode->setItemData(3, QVariant(), Qt::UserRole -1);
        }
    });

    connect(ui->lineEdit_timecost, &QLineEdit::textChanged, this, [this]{
        int iterations = ui->lineEdit_timecost->text().toInt();
        if(ui->comboBox_Argon2->currentText() == "Scrypt"){
            iterations = 1 << iterations;
            ui->lineEdit_timecost->setToolTip(QString::number(iterations));
        }
    });
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_pushButton_inputFile_clicked()
{
    // Open a file picker dialog to select a file
    QString filePath = QFileDialog::getOpenFileName(this, "Select a File");

    // If the user cancels or doesn't select a file, return early
    if (filePath.isEmpty()) {
        return;
    }

    // Set the selected file path to the input field
    ui->lineEdit_inputFile->setText(filePath);

    // Extract file components
    QFileInfo fileInfo(filePath);
    QString baseName = fileInfo.completeBaseName();  // name without extension
    QString dir = fileInfo.absolutePath();           // file's directory

    // Determine if we are encrypting or decrypting
    QString mode = ui->comboBox_EncryptDecrypt->currentText().toLower();  // "encrypt" or "decrypt"
    QString outputName;

    if (mode == "encrypt") {
        outputName = baseName + "_encrypted";
    } else if (mode == "decrypt") {
        if (baseName.endsWith("_encrypted")) {
            outputName = baseName.left(baseName.length() - QString("_encrypted").length()) + "_decrypted";
        } else {
            outputName = baseName + "_decrypted";
        }
    } else {
        // Default to "_processed" if mode is unrecognized
        outputName = baseName + "_processed";
    }

    // Combine directory and output name
    QString outputPath = QString("%1/%2").arg(dir, outputName);

    // Set the generated output path to the output field
    ui->lineEdit_outputFile->setText(outputPath);


    // Get header
    std::ifstream file(filePath.toStdString(), std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Failed to open file.\n";
        ui->textBrowser->append("Failed to open file.");
        return;
    }

    const std::string start_marker = "cryptoheader";
    const std::string end_marker = "endheader";
    std::string buffer;
    std::string header;

    char ch;

    // Step 1: Read initial bytes to check for "cryptoheader"
    for (size_t i = 0; i < start_marker.size(); ++i) {
        if (!file.get(ch)) {
            std::cerr << "File too short to contain full start marker.\n";
            ui->textBrowser->append("File too short to contain header.");
            return;
        }
        buffer += ch;
    }

    if (buffer != start_marker) {
        std::cerr << "Start marker mismatch.\n";
        ui->textBrowser->append("No header found.");
        return;
    }

    header = buffer;

    // Step 2: Continue reading until "endheader" is found
    while (file.get(ch)) {
        header += ch;

        if (header.size() >= end_marker.size()) {
            if (header.substr(header.size() - end_marker.size()) == end_marker) {
                this->header = QString::fromStdString(header);
                ui->textBrowser->append(this->header);
                setInputFields();
                return;
            }
        }
    }

    // If we get here, end marker was not found
    std::cerr << "End marker not found.\n";
    ui->textBrowser->append("Header delimiter not found.");
}

void MainWindow::setInputFields()
{
    std::istringstream stream(header.toStdString());  // header is a std::string containing the full header
    std::string line;
    std::map<std::string, std::string> headerVars;

    while (std::getline(stream, line)) {
        // Skip start and end markers
        if (line == "cryptoheader" || line == "endheader") continue;

        // Find the first '=' character
        size_t eqPos = line.find('=');
        if (eqPos != std::string::npos) {
            std::string key = line.substr(0, eqPos);
            std::string value = line.substr(eqPos + 1);
            headerVars[key] = value;
        }
    }

    // Optional: print the extracted variables
    for (const auto& [key, value] : headerVars) {
        std::cout << key << " = " << value << '\n';
    }

    auto it = headerVars.find("memcost(MiB)");
    if (it != headerVars.end()) {
        ui->lineEdit_memcost->setText(QString::fromStdString(it->second));
    }

    it = headerVars.find("timecost");
    if (it != headerVars.end()) {
        ui->lineEdit_timecost->setText(QString::fromStdString(it->second));
    }

    it = headerVars.find("threads");
    if (it != headerVars.end()) {
        ui->lineEdit_threads->setText(QString::fromStdString(it->second));
    }

    it = headerVars.find("pbkdf");
    if (it != headerVars.end()) {
        if(it->second.starts_with("PBKDF2")) it->second = "PBKDF2";
        int index = ui->comboBox_Argon2->findText(QString::fromStdString(it->second));
        ui->comboBox_Argon2->setCurrentIndex(index);
    }

    ui->comboBox_EncryptDecrypt->setCurrentIndex(1);

    it = headerVars.find("cipher");
    if (it != headerVars.end()) {
        std::string cipherstr = it->second;

        ui->lineEdit_cipherChain->setText(QString::fromStdString(cipherstr));
        cipherList.clear();  // Ensure no leftover entries

        if (cipherstr.find('(') != std::string::npos) {
            ui->checkBox_chainToggle->setCheckState(Qt::Checked);

            // Remove all closing parentheses
            cipherstr.erase(std::remove(cipherstr.begin(), cipherstr.end(), ')'), cipherstr.end());

            // Split the string by '('
            std::stringstream ss(cipherstr);
            std::string item;
            while (std::getline(ss, item, '(')) {
                // Trim whitespace
                item.erase(0, item.find_first_not_of(" \t\r\n"));
                item.erase(item.find_last_not_of(" \t\r\n") + 1);

                if (item.empty()) continue;

                size_t slash = item.find('/');
                if (slash != std::string::npos) {
                    std::string cipher = item.substr(0, slash);
                    std::string mode = item.substr(slash + 1);
                    cipherList.push_back({cipher, mode});
                } else {
                    cipherList.push_back({item, ""});
                }
            }
        } else {
            ui->checkBox_chainToggle->setCheckState(Qt::Unchecked);

            size_t slash = cipherstr.find('/');
            if (slash != std::string::npos) {
                std::string cipher = cipherstr.substr(0, slash);
                std::string mode = cipherstr.substr(slash + 1);

                ui->comboBox_Algorithm->setCurrentText(QString::fromStdString(cipher));
                ui->comboBox_cipherMode->setCurrentText(QString::fromStdString(mode));
            } else {
                ui->comboBox_Algorithm->setCurrentText(QString::fromStdString(cipherstr));
            }
        }
    }
    updateButtonState();
}

void MainWindow::on_pushButton_4_clicked()
{
    // Open a save file dialog to select a file (can be a non-existent file)
    QString outputFilePath = QFileDialog::getSaveFileName(this, "Select Output File");

    // If the user cancels or doesn't select a file, return early
    if (outputFilePath.isEmpty()) {
        return;
    }

    // Check if the file already exists
    QFile file(outputFilePath);
    if (file.exists()) {
        // Show a warning message if the file exists
        QMessageBox::warning(this, "File Exists", "The file already exists. Please choose a different file.");
        return;
    }

    ui->lineEdit_outputFile->setText(outputFilePath);
}

void MainWindow::on_pushButton_clicked()
{
    //UI setup
    ui->pushButton->setEnabled(false);
    ui->progressBar->setValue(0);
    ui->textBrowser->clear();

    //Get crypto parameters
    size_t memcost = ui->lineEdit_memcost->text().toInt() * 1024;
    size_t timecost = ui->lineEdit_timecost->text().toInt();
    size_t threads = ui->lineEdit_threads->text().toInt();

    QString mode = ui->comboBox_cipherMode->currentText();
    QString pbkdf = ui->comboBox_Argon2->currentText();
    if(pbkdf == "PBKDF2") pbkdf = "PBKDF2(HMAC(SHA-512))";
    if(mode == "CTR") mode = "CTR-BE";
    if(mode == "CBC") mode = "CBC/PKCS7";
    QString algorithm = ui->comboBox_Algorithm->currentText();
    QString encryptToggle = ui->comboBox_EncryptDecrypt->currentText();

    if (encryptToggle == "Encrypt") {
        header += "cryptoheader\n";
        header += "pbkdf=" + pbkdf + "\n";
        header += "memcost(MiB)=" + QString::number(memcost / 1024) + "\n";
        header += "timecost=" + QString::number(timecost) + "\n";
        header += "threads=" + QString::number(threads) + "\n";

        if (ui->checkBox_chainToggle->isChecked()) {
            header += "cipher=" + ui->lineEdit_cipherChain->text() + "\n";
        } else {
            if (algorithm == "XChaCha20")
                header += "cipher=" + algorithm + "\n";  // e.g. XChaCha20
            else
                header += "cipher=" + algorithm + "/" + mode + "\n";
        }

        header += "endheader";
    }
    if(!ui->checkBox_header->isChecked()){
        ui->textBrowser->append(header);
        ui->textBrowser->append("Warning: Header will not be written to file. If you forget your encryption settings, you will not be able to decrypt your file. Recommended to write settings down somewhere.");
        header = "";
    }

    //Change cipher labels for Botan functions. Add cipher + mode to cipherList
    // if(algorithm == "AES") algorithm.replace("AES","AES-256");
    if(algorithm == "XChaCha20") { algorithm.replace("XChaCha20", "ChaCha20Poly1305"); mode = "";}

    if(!ui->checkBox_chainToggle->isChecked())
        cipherList.push_back({algorithm.toStdString(), mode.toStdString()});

    // if(ui->checkBox_chainToggle->isChecked()) {
    for(size_t i = 0; i < cipherList.size(); i++) {
        if(cipherList[i][0] == "AES") cipherList[i][0] = "AES-256";
        if(cipherList[i][0] == "Camellia") cipherList[i][0] = "Camellia-256";
        if(cipherList[i][0] == "XChaCha20") cipherList[i][0] = "ChaCha20";
        if(cipherList[i][1] == "CBC") cipherList[i][1] = "CBC/PKCS7";
        if(cipherList[i][1] == "CTR") cipherList[i][1] = "CTR-BE";
    }
    if(cipherList[0][0] == "ChaCha20") cipherList[0][0] = "ChaCha20Poly1305";
    // }

    //Reverse list if encrypting
    if(encryptToggle == "Encrypt") std::reverse(cipherList.begin(), cipherList.end());

    //Setup new thread, signals and slots.
    Crypto* worker = new Crypto;
    QThread* thread = new QThread;

    // Set the parameters
    worker->setParams(
        ui->lineEdit_inputFile->text(),
        ui->lineEdit_outputFile->text(),
        ui->lineEdit_Password->text(),
        mode,
        encryptToggle,
        cipherList,
        memcost,
        timecost,
        threads,
        pbkdf,
        header
    );


    worker->moveToThread(thread);

    connect(thread, &QThread::started, worker, &Crypto::cipherLoop);

    connect(worker, &Crypto::finished, this, [this]{
        ui->pushButton->setEnabled(true);
        cipherList.clear();
        header.clear();
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


    //Show user parameters in text browser
    // if(encryptToggle == "Encrypt") {
    //     QString message = "Header: \n";
    //     message += header;
    //     ui->textBrowser->append(message + "\n");
    // }

    thread->start();

    //Clear list for next encryption or decryption
    ui->lineEdit_cipherChain->clear();
}

void MainWindow::on_checkBox_checkStateChanged(const Qt::CheckState &arg1)
{
    if (arg1 == Qt::Checked) {
        ui->lineEdit_Password->setEchoMode(QLineEdit::Normal);
        ui->lineEdit_confirm->setEchoMode(QLineEdit::Normal);        // Show password
    } else {
        ui->lineEdit_Password->setEchoMode(QLineEdit::Password);
        ui->lineEdit_confirm->setEchoMode(QLineEdit::Password);        // Hide password
    }
}


void MainWindow::on_lineEdit_Password_textEdited(const QString &arg1)
{
    if(arg1.length() > 0)
    {
        ui->pushButton->setEnabled(true);
    }
    else
    {
        ui->pushButton->setEnabled(false);
    }
}


void MainWindow::on_comboBox_EncryptDecrypt_currentIndexChanged(int index)
{
    if(index == 1){
        ui->lineEdit_confirm->setEnabled(false);
    }
    else {
        ui->lineEdit_confirm->setEnabled(true);
    }

}

void MainWindow::updateButtonState()
{
    QString encryptToggle = ui->comboBox_EncryptDecrypt->currentText();
    bool isChain = ui->checkBox_chainToggle->isChecked();
    bool buttonActive;

    bool linesFull = !ui->lineEdit_Password->text().trimmed().isEmpty() &&
                     !ui->lineEdit_inputFile->text().trimmed().isEmpty() &&
                     !ui->lineEdit_outputFile->text().trimmed().isEmpty() &&
                     !ui->lineEdit_memcost->text().trimmed().isEmpty() &&
                     !ui->lineEdit_timecost->text().trimmed().isEmpty() &&
                     !ui->lineEdit_threads->text().trimmed().isEmpty();

    if(encryptToggle == "Encrypt")
    {
        if(isChain)
            buttonActive = (ui->lineEdit_Password->text() == ui->lineEdit_confirm->text()
                            && linesFull && (cipherList.size() > 0));
        if(!isChain)
            buttonActive = (ui->lineEdit_Password->text() == ui->lineEdit_confirm->text() && linesFull);
    }
    if(encryptToggle == "Decrypt")
    {
        if(isChain)
            buttonActive = (linesFull && (cipherList.size() > 0));
        if(!isChain)
            buttonActive = linesFull;
    }

    ui->pushButton->setEnabled(buttonActive);
}

void MainWindow::on_comboBox_Algorithm_currentTextChanged(const QString &arg1)
{
    if(arg1 == "XChaCha20") ui->comboBox_cipherMode->setEnabled(false);
    else ui->comboBox_cipherMode->setEnabled(true);
}

void MainWindow::on_pushButton_Add_clicked()
{
    // Extract cipher and mode
    QString algo = ui->comboBox_Algorithm->currentText();
    QString algomode = ui->comboBox_cipherMode->currentText();

    if (algo == "XChaCha20")
        algomode = "";

    // Add to cipherList
    std::vector<std::string> cipherInfo;
    cipherInfo.push_back(algo.toStdString());
    cipherInfo.push_back(algomode.toStdString());
    cipherList.push_back(cipherInfo);

    // Update lineEdit to display current chain
    QString chainText;
    for (size_t i = 0; i < cipherList.size(); ++i) {
        QString cipher = QString::fromStdString(cipherList[i][0]);
        QString mode = QString::fromStdString(cipherList[i][1]);

        chainText += cipher;
        if (!mode.isEmpty())
            chainText += "/" + mode;

        // Add '(' after every cipher except the last one
        if (i < cipherList.size() - 1) {
            chainText += "(";
        }
    }

    // Close parentheses for nested chains (number of ciphers - 1)
    for (size_t i = 1; i < cipherList.size(); ++i) {
        chainText += ")";
    }

    ui->lineEdit_cipherChain->setText(chainText);
}

void MainWindow::on_pushButton_Remove_clicked()
{
    if (cipherList.empty()) return;

    // Remove the last cipher from the chain
    cipherList.pop_back();

    // Build the new nested chain string
    QString chainText;
    for (size_t i = 0; i < cipherList.size(); ++i) {
        QString cipher = QString::fromStdString(cipherList[i][0]);
        QString mode   = QString::fromStdString(cipherList[i][1]);

        // Add cipher and mode if mode exists
        chainText += cipher;
        if (!mode.isEmpty()) {
            chainText += "/" + mode;
        }

        if (i < cipherList.size() - 1) {
            chainText += "(";
        }
    }

    // Close parentheses for nested chains
    for (size_t i = 1; i < cipherList.size(); ++i) {
        chainText += ")";
    }

    ui->lineEdit_cipherChain->setText(chainText);
}

void MainWindow::on_checkBox_chainToggle_stateChanged(int arg1)
{
    ui->pushButton_Add->setEnabled(arg1);
    ui->pushButton_Remove->setEnabled(arg1);
    ui->lineEdit_cipherChain->setEnabled(arg1);

    if(!arg1) {
        cipherList.clear();
        ui->lineEdit_cipherChain->setText("");
    }
}


void MainWindow::on_comboBox_Argon2_currentTextChanged(const QString &arg1)
{
    // if decrying parameters should be from header or manually entered
    bool encrypt = (ui->comboBox_EncryptDecrypt->currentText() == "Encrypt");

    if(arg1 == "PBKDF2"){
        ui->lineEdit_timecost->setMaxLength(4);
        ui->lineEdit_threads->setText("0");
        ui->lineEdit_memcost->setText("0");
        ui->lineEdit_memcost->setEnabled(false);
        ui->lineEdit_threads->setEnabled(false);
        ui->label_timecost->setText("Passes (1000s)");

        if(encrypt) {
        ui->lineEdit_timecost->setText("600");
        }
    }
    if(arg1.contains("Argon")) {
        ui->lineEdit_timecost->setMaxLength(3);
        ui->lineEdit_memcost->setEnabled(true);
        ui->lineEdit_threads->setEnabled(true);
        ui->label_timecost->setText("Passes");
        ui->label_memcost->setText("Memcost (MiB)");

        if(encrypt) {
        ui->lineEdit_threads->setText("4");
        ui->lineEdit_memcost->setText("2048");
        ui->lineEdit_timecost->setText("1");
        }
    }
    if(arg1.contains("Scrypt")){
        ui->lineEdit_timecost->setMaxLength(2);
        ui->lineEdit_memcost->setEnabled(true);
        ui->lineEdit_threads->setEnabled(true);
        ui->label_timecost->setText("Passes (2^x)");
        ui->label_memcost->setText("Memcost");

        if(encrypt) {
        ui->lineEdit_threads->setText("1");
        ui->lineEdit_memcost->setText("8");
        ui->lineEdit_timecost->setText("20");
        }
    }
}


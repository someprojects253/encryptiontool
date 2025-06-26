#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QFile>
#include <QTextStream>
#include <QByteArray>
#include <QDebug>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->comboBox_MAC->hide();
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

    //Get crypto parameters
    size_t memcost = ui->lineEdit_memcost->text().toInt() * 1024;
    size_t timecost = ui->lineEdit_timecost->text().toInt();
    size_t threads = ui->lineEdit_threads->text().toInt();

    QString mode = ui->comboBox_cipherMode->currentText();
    QString argon2 = ui->comboBox_Argon2->currentText();
    if(mode == "CTR") mode = "CTR-BE";
    if(mode == "CBC") mode = "CBC/PKCS7";
    QString algorithm = ui->comboBox_Algorithm->currentText();
    QString encryptToggle = ui->comboBox_EncryptDecrypt->currentText();


    //Change cipher labels for Botan functions. Add cipher + mode to cipherList
    if(algorithm == "AES") algorithm.replace("AES","AES-256");
    if(algorithm == "XChaCha20") { algorithm.replace("XChaCha20", "ChaCha20Poly1305"); mode = "";}

    if(!ui->checkBox_chainToggle->isChecked())
        cipherList.push_back({algorithm.toStdString(), mode.toStdString()});

    if(ui->checkBox_chainToggle->isChecked()) {
        for(size_t i = 0; i < cipherList.size(); i++) {
            if(cipherList[i][0] == "AES") cipherList[i][0] = "AES-256";
            if(cipherList[i][0] == "Camellia") cipherList[i][0] = "Camellia-256";
            if(cipherList[i][0] == "XChaCha20") cipherList[i][0] = "ChaCha20";
            if(cipherList[i][1] == "CBC") cipherList[i][1] = "CBC/PKCS7";
            if(cipherList[i][1] == "CTR") cipherList[i][1] = "CTR-BE";

        }
        if(cipherList[0][0] == "ChaCha20") cipherList[0][0] = "ChaCha20Poly1305";
    }

    //Setup new thread, signals and slots.

    Crypto* worker = new Crypto;
    QThread* thread = new QThread;


    // Set the parameters
    worker->setParams(
        ui->lineEdit_inputFile->text(),
        ui->lineEdit_outputFile->text(),
        ui->lineEdit_Password->text(),
        mode,
        algorithm,
        encryptToggle,
        cipherList,
        memcost,
        timecost,
        threads,
        argon2
    );


    worker->moveToThread(thread);

    connect(thread, &QThread::started, worker, &Crypto::cipherLoop);

    connect(worker, &Crypto::finished, this, [this]{
        ui->pushButton->setEnabled(true);
    });
    connect(worker, &Crypto::finished, thread, &QThread::quit);
    connect(worker, &Crypto::finished, worker, &QObject::deleteLater);
    connect(thread, &QThread::finished, thread, &QObject::deleteLater);
    connect(worker, &Crypto::progress, this, [this](int percent){
        ui->progressBar->setValue(percent);
    });

    connect(worker, &Crypto::sendMessage, this, [this](QString message){
        ui->textBrowser->append(message);
    });


    //Show user parameters in text browser
    if(encryptToggle == "Encrypt") {
        QString message = "Parameters used. If you forget these, you will not be able to decrypt your data. Recommended to store somewhere accessible.\n\nArgon2 version=" + argon2 + "\nMemory (MiB)=" + QString::number(memcost/1024)
        + "\nPasses="
            + QString::number(timecost)
            + "\nThreads=" + QString::number(threads);
        if(!ui->checkBox_chainToggle->isChecked()){
            message += "\nChain: no\nCipher=" + QString::fromStdString(cipherList[0][0]) +
                       "\nMode=" += QString::fromStdString(cipherList[0][1]);
        } else {
            message += "\nChain: yes\nChain order: " + ui->lineEdit_cipherChain->text();
        }
        ui->textBrowser->append(message + "\n");
    }

    thread->start();

    //Clear list for next encryption or decryption
    ui->lineEdit_cipherChain->clear();
    cipherList.clear();
}

void MainWindow::on_checkBox_checkStateChanged(const Qt::CheckState &arg1)
{
    if (arg1 == Qt::Checked) {
        ui->lineEdit_Password->setEchoMode(QLineEdit::Normal);  // Show password
    } else {
        ui->lineEdit_Password->setEchoMode(QLineEdit::Password);  // Hide password
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
}

void MainWindow::on_comboBox_cipherMode_currentTextChanged(const QString &arg1)
{
}


void MainWindow::on_comboBox_Algorithm_currentTextChanged(const QString &arg1)
{
    if(arg1 == "XChaCha20") ui->comboBox_cipherMode->setHidden(true);
    else ui->comboBox_cipherMode->setHidden(false);
}


void MainWindow::on_pushButton_Add_clicked()
{
    //Extract cipher and mode
    QString algo = ui->comboBox_Algorithm->currentText();
    QString algomode = ui->comboBox_cipherMode->currentText();
    if(algo == "XChaCha20") algomode = "";
    QString chainText = "";

    //Add to cipherList
    std::vector<std::string> cipherInfo;
    cipherInfo.push_back(algo.toStdString());
    cipherInfo.push_back(algomode.toStdString());
    cipherList.push_back(cipherInfo);

    // Update lineEdit to display current chain
    for(size_t i = 0; i < cipherList.size(); i++){
        chainText += cipherList[i][0] + "/" + cipherList[i][1] + "(";
        if(i == cipherList.size()-1) {
            for(size_t i2 = 0; i2 <cipherList.size(); i2++) {
                chainText += ")";
            }
        }
    }
    chainText.remove("()");
    ui->lineEdit_cipherChain->setText(chainText);
}


void MainWindow::on_pushButton_Remove_clicked()
{
    // Code for removing cipher from chain, updating display
    if(cipherList.size() > 0)
    {
        QString chainText = "";

        cipherList.erase(cipherList.begin()+cipherList.size()-1);
        for(size_t i = 0; i < cipherList.size(); i++){
            chainText += cipherList[i][0] + "(";
            if(i == cipherList.size()-1) {
                for(size_t i2 = 0; i2 <cipherList.size(); i2++) {
                    chainText += ")";
                }
            }
        }
        chainText.remove("()");
        ui->lineEdit_cipherChain->setText(chainText);
    }
}


void MainWindow::on_checkBox_chainToggle_stateChanged(int arg1)
{
    ui->pushButton_Add->setEnabled(arg1);
    ui->pushButton_Remove->setEnabled(arg1);
    ui->lineEdit_cipherChain->setEnabled(arg1);
}


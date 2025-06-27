#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "crypto.h"

#include <QMainWindow>
#include <botan/system_rng.h>
#include <QThread>

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);

    void updateButtonState();
    ~MainWindow();

private slots:
    void on_pushButton_inputFile_clicked();

    void on_pushButton_4_clicked();

    void on_pushButton_clicked();

    void on_checkBox_checkStateChanged(const Qt::CheckState &arg1);

    void on_lineEdit_Password_textEdited(const QString &arg1);

    void on_comboBox_EncryptDecrypt_currentIndexChanged(int index);

    void on_comboBox_cipherMode_currentTextChanged(const QString &arg1);

    void on_comboBox_Algorithm_currentTextChanged(const QString &arg1);

    void on_pushButton_Add_clicked();

    void on_pushButton_Remove_clicked();

    void on_checkBox_chainToggle_stateChanged(int arg1);

private:
    Ui::MainWindow *ui;
    std::vector<std::vector<std::string>> cipherList;
};
#endif // MAINWINDOW_H

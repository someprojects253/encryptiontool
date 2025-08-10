#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "crypto.h"
#include <QMainWindow>
#include <QThread>
#include <QDropEvent>
#include <QMimeData>

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
    ~MainWindow();

    void run(std::string encryptToggle);
    void updateButtons();
    void getHeader();
    void setParams(QString preset="");
    void updateLabels();

signals:
    void fileDropped();
protected:
    void dragEnterEvent(QDragEnterEvent* event) override {
        if (event->mimeData()->hasUrls())
            event->acceptProposedAction();
    }

    void dropEvent(QDropEvent* event) override {
        const QList<QUrl> urls = event->mimeData()->urls();
        if (!urls.isEmpty()) {
            inputFilePath = urls.first().toLocalFile().toStdString(); // Only the first file
            emit fileDropped();
        }
    }

private:
    Ui::MainWindow *ui;
    QString localFilePath;
    std::string inputFilePath, outputFilePath, header;
};
#endif // MAINWINDOW_H

// doge_wif_converter.cpp
#include <QtWidgets>
#include <QCryptographicHash>

static const QString BASE58_ALPHABET = "0123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

QString base58Encode(const QByteArray &input) {
    // Copy input and remove leading zeros
    QByteArray b = input;
    int zeros = 0;
    while (zeros < b.size() && static_cast<unsigned char>(b[zeros]) == 0)
        ++zeros;

    QByteArray result;

    // Process bytes
    while (!b.isEmpty() && b != QByteArray(b.size(), '\0')) {
        int remainder = 0;
        QByteArray newB;
        for (int i = 0; i < b.size(); ++i) {
            int val = (remainder << 8) + static_cast<unsigned char>(b[i]);
            int q = val / 58;
            remainder = val % 58;
            if (!newB.isEmpty() || q != 0)
                newB.append(static_cast<char>(q));
        }
        result.prepend(BASE58_ALPHABET[remainder].toLatin1());
        b = newB;
    }

    // Add leading '1's
    if (zeros > 0)
        result.prepend(QByteArray(zeros, '1'));

    return QString::fromUtf8(result);
}




static QByteArray doubleSHA256(const QByteArray &data) {
    return QCryptographicHash::hash(QCryptographicHash::hash(data, QCryptographicHash::Sha256), QCryptographicHash::Sha256);
}

// Convert 32-byte key to WIF
static QString keyToWIF(const QByteArray &key32, quint8 version = 0x9E, bool compressed = false) {
    QByteArray payload;
    payload.append(static_cast<char>(version));
    payload.append(key32);
    if (compressed) payload.append('\x01');
    QByteArray checksum = doubleSHA256(payload).left(4);
    QByteArray full = payload + checksum;

    QString wif = base58Encode(full);
    qDebug() << "WIF (uncompressed):" << wif;


    // Base58 encode
    QByteArray result;
    int zeros = 0;
    for (char c : full) if (c==0) zeros++; else break;
    quint64 acc = 0;
    for (char b : full) acc = (acc << 8) | static_cast<unsigned char>(b);

    QByteArray b58;
    while (acc > 0) {
        int mod = acc % 58;
        b58.prepend(BASE58_ALPHABET[mod].toLatin1());
        acc /= 58;
    }
    b58.prepend(QByteArray(zeros, '1'));
    return wif;
}

// Qt GUI
class MainWindow : public QWidget {
    Q_OBJECT
public:
    MainWindow() {
        setWindowTitle("Dogecoin Hex → WIF Converter");
        auto *layout = new QVBoxLayout(this);
        layout->addWidget(new QLabel("Enter hex blob (≥32 bytes):"));
        hexEdit = new QLineEdit;
        layout->addWidget(hexEdit);
        auto *btn = new QPushButton("Convert to WIF");
        layout->addWidget(btn);
        out = new QTextEdit;
        out->setReadOnly(true);
        layout->addWidget(out);

        connect(btn, &QPushButton::clicked, this, &MainWindow::onConvert);
        connect(hexEdit, &QLineEdit::returnPressed, btn, &QPushButton::click);


        QByteArray privKey32 = QByteArray::fromHex("78789e1b82c793fef0bb9861e80ea4f344b34e34ce980ea4a7a35bde83f3b0e1");
        QByteArray payload;
        payload.append(char(0x9E));     // Dogecoin version byte
        payload.append(privKey32);
        QByteArray checksum = QCryptographicHash::hash(QCryptographicHash::hash(payload, QCryptographicHash::Sha256), QCryptographicHash::Sha256).left(4);
        payload.append(checksum);

        QString wif = base58Encode(payload);
        qDebug() << "WIF (uncompressed):" << wif;


    }
private slots:
    void onConvert() {
        QString hex = hexEdit->text().trimmed();
        if (hex.length() < 64) { out->setPlainText("Hex must be at least 32 bytes (64 hex chars)"); return; }
        QByteArray key32 = QByteArray::fromHex(hex.left(64).toUtf8());
        if (key32.size() != 32) { out->setPlainText("Failed to decode 32 bytes"); return; }

        QString wifUncompressed = keyToWIF(key32, 0x9E, false);
        QString wifCompressed   = keyToWIF(key32, 0x9E, true);

        out->setPlainText(QString("Private key (hex):\n%1\n\nWIF (uncompressed): %2\nWIF (compressed): %3")
                          .arg(QString(key32.toHex()))
                          .arg(wifUncompressed)
                          .arg(wifCompressed));
    }
private:
    QLineEdit *hexEdit;
    QTextEdit *out;
};

int main(int argc, char **argv) {
    QApplication app(argc, argv);
    MainWindow w;
    w.resize(540, 360);
    w.show();
    return app.exec();
}

#include "main.moc"

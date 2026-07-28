// doge_wif_converter.cpp
#include <QtWidgets>
#include <QCryptographicHash>

static const QString BASE58_ALPHABET =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

QString base58Encode(const QByteArray &input)
{
    if (input.isEmpty())
        return QString();

    // Count leading zero bytes.
    int zeros = 0;
    while (zeros < input.size() &&
           static_cast<unsigned char>(input.at(zeros)) == 0)
    {
        ++zeros;
    }

    // Copy the significant bytes.
    QByteArray num = input.mid(zeros);
    QByteArray encoded;

    while (!num.isEmpty()) {
        int remainder = 0;
        QByteArray quotient;
        quotient.reserve(num.size());

        for (int i = 0; i < num.size(); ++i) {
            int value = (remainder << 8) |
                        static_cast<unsigned char>(num.at(i));

            int digit = value / 58;
            remainder = value % 58;

            // Skip leading zeroes in the quotient.
            if (!quotient.isEmpty() || digit != 0)
                quotient.append(static_cast<char>(digit));
        }

        encoded.prepend(BASE58_ALPHABET[remainder].toLatin1());
        num = quotient;
    }

    // One leading zero byte becomes one '1'.
    while (zeros-- > 0)
        encoded.prepend('1');

    return QString::fromLatin1(encoded.constData(), encoded.size());
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


        QByteArray privKey32 = QByteArray::fromHex("49396dce3b65ce0fade0488184de797ba8a960fd48f3b4578f5268d5c524949b");
        QByteArray payload;
        payload.append(char(0x9E));     // Dogecoin version byte
        payload.append(privKey32);
        QByteArray checksum = QCryptographicHash::hash(QCryptographicHash::hash(payload, QCryptographicHash::Sha256), QCryptographicHash::Sha256).left(4);
        payload.append(checksum);
qDebug() << "testc " << checksum.toHex();
        qDebug() << "test " << payload.toHex();

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

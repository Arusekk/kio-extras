/*
 * SPDX-FileCopyrightText: 2024 Arkadiusz Kozdra <floss@arusekk.pl>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#ifndef __kio_9p_h__
#define __kio_9p_h__

#include <KIO/Global>
#include <KIO/WorkerBase>

#include <QByteArray>
#include <QUrl>

class QTcpSocket;

using Result = KIO::WorkerResult;

class P9Worker : public QObject, public KIO::WorkerBase
{
    Q_OBJECT
public:
    explicit P9Worker(const QByteArray &poolSocket, const QByteArray &appSocket);
    Q_DISABLE_COPY_MOVE(P9Worker)

    void setHost(const QString &h, quint16 port, const QString &user, const QString &pass) override;
    Q_REQUIRED_RESULT Result get(const QUrl &url) override;
    Q_REQUIRED_RESULT Result listDir(const QUrl &url) override;
    Q_REQUIRED_RESULT Result stat(const QUrl &url) override;
    Q_REQUIRED_RESULT Result put(const QUrl &url, int permissions, KIO::JobFlags flags) override;
    void closeConnection() override;
    void worker_status() override;
    Q_REQUIRED_RESULT Result del(const QUrl &url, bool isfile) override;
    Q_REQUIRED_RESULT Result chmod(const QUrl &url, int permissions) override;
    Q_REQUIRED_RESULT Result rename(const QUrl &src, const QUrl &dest, KIO::JobFlags flags) override;
    Q_REQUIRED_RESULT Result mkdir(const QUrl &url, int permissions) override;
    Q_REQUIRED_RESULT Result openConnection() override;

    // KIO::FileJob interface
    Q_REQUIRED_RESULT Result open(const QUrl &url, QIODevice::OpenMode mode = QIODevice::ReadOnly) override;
    Q_REQUIRED_RESULT Result read(KIO::filesize_t size) override;
    Q_REQUIRED_RESULT Result write(const QByteArray &data) override;
    Q_REQUIRED_RESULT Result seek(KIO::filesize_t offset) override;
    Q_REQUIRED_RESULT Result truncate(KIO::filesize_t length) override;
    Q_REQUIRED_RESULT Result close() override;
    // Q_REQUIRED_RESULT Result special(const QByteArray &data) override;

    // Must call after construction!
    // Bit rubbish, but we need to return something on init.
    Q_REQUIRED_RESULT Result init();
    Q_REQUIRED_RESULT Result negotiateVersion();
    Q_REQUIRED_RESULT Result authenticate(quint32 afid, QString uname, QString aname);
    Q_REQUIRED_RESULT Result attach(quint32 afid, quint32 fid, QString uname, QString aname);
    Q_REQUIRED_RESULT Result walk(quint32 fid, quint32 nfid, QStringList walks);
    Q_REQUIRED_RESULT Result read(quint32 fid, quint64 offset, quint32 count);
    Q_REQUIRED_RESULT Result write(quint32 fid, quint64 offset, QByteArray data);
    Q_REQUIRED_RESULT Result open(quint32 fid, quint8 mode);
    Q_REQUIRED_RESULT Result create(quint32 fid, QString name, quint32 perm, quint8 mode);
    Q_REQUIRED_RESULT Result stat(quint32 fid);
    Q_REQUIRED_RESULT Result clunk(quint32 fid);
    Q_REQUIRED_RESULT Result remove(quint32 fid);

private: // Private variables
    enum p9cmd {
        Tversion = 100,
        Rversion = 101,
        Tauth = 102,
        Rauth = 103,
        Tattach = 104,
        Rattach = 105,
        Rerror = 107,
        Twalk = 110,
        Rwalk = 111,
        Topen = 112,
        Ropen = 113,
        Tcreate = 114,
        Rcreate = 115,
        Tread = 116,
        Rread = 117,
        Twrite = 118,
        Rwrite = 119,
        Tclunk = 120,
        Rclunk = 121,
        Tremove = 122,
        Rremove = 123,
        Tstat = 124,
        Rstat = 125,
        Twstat = 126,
        Rwstat = 127,
    };
    enum omode {
        OREAD = 0,
        OWRITE = 1,
        ORDWR = 2,
        OEXEC = 3,
        OTRUNC = 0x10,
        ORCLOSE = 0x40,
    };
    enum dmmode {
        DMDIR = 0x80000000,
        DMAPPEND = 0x40000000,
        DMEXCL = 0x20000000,
        DMTMP = 0x04000000,
    };
    struct p9qid {
        quint8 qid_type;
        quint32 qid_version;
        quint64 qid_path;
    };
    struct p9statbuf {
        quint16 type;
        quint32 dev;
        p9qid qid;
        quint32 mode;
        quint32 atime;
        quint32 mtime;
        quint64 length;
        QString name;
        QString uid;
        QString gid;
        QString muid;
    };
    /** True if worker is connected to 9p server. */
    bool mConnected = false;

    /** Host we are connected to. */
    QString mHost;

    /** Port we are connected to. */
    int mPort = -1;

    /** Current user. */
    QString mUser;

    /** The tcp session for the connection */
    QTcpSocket *mSession = nullptr;

    /** Maximum message size. */
    quint32 mMax = 0x20018;

    /** Current top file id. */
    quint32 mMaxFid = 0;

    /** Current file id. */
    quint32 mLastFid = 0;

    /** If open URL is dir */
    bool mIsDir;

    /** The open URL */
    QUrl mOpenUrl;

    // KIO::FileJob interface
    KIO::filesize_t openOffset = 0;

    Q_REQUIRED_RESULT Result sendCmd(enum p9cmd cmd, quint16 tag, const QByteArray &payload);
    Q_REQUIRED_RESULT Result recvCmd(enum p9cmd cmd, quint16 tag);
    Q_REQUIRED_RESULT QByteArray recvExact(qsizetype size);

    friend class P9DataStream;
};

#endif

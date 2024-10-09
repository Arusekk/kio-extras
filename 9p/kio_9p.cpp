/*
 * SPDX-FileCopyrightText: 2024 Arkadiusz Kozdra <floss@arusekk.pl>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "kio_9p.h"

#include <QCoreApplication>
#include <QTcpSocket>

#include "kio_9p_debug.h"
#include "kio_9p_trace_debug.h"

// Pseudo plugin class to embed meta data
class KIOPluginForMetaData : public QObject
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID "org.kde.kio.worker.9p" FILE "9p.json")
};

using namespace KIO;

extern "C" Q_DECL_EXPORT int kdemain(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("kio_9p"));

    qCDebug(KIO_9P_LOG) << "Starting";

    if (argc != 4) {
        fprintf(stderr, "Usage: kio_9p protocol domain-socket1 domain-socket2\n");
        exit(-1);
    }

    P9Worker worker(argv[2], argv[3]);
    worker.dispatchLoop();

    qCDebug(KIO_9P_LOG) << "Done";
    return 0;
}

class P9DataStream : public QDataStream
{
public:
    P9DataStream(const QByteArray &inp)
        : QDataStream(inp)
    {
        setByteOrder(QDataStream::LittleEndian);
    }
    P9DataStream(QByteArray *outp)
        : QDataStream(outp, QIODevice::WriteOnly)
    {
        setByteOrder(QDataStream::LittleEndian);
    }
    P9DataStream &operator<<(quint8 i)
    {
        *static_cast<QDataStream *>(this) << i;
        return *this;
    }
    P9DataStream &operator>>(quint8 &i)
    {
        *static_cast<QDataStream *>(this) >> i;
        return *this;
    }
    P9DataStream &operator<<(quint16 i)
    {
        *static_cast<QDataStream *>(this) << i;
        return *this;
    }
    P9DataStream &operator>>(quint16 &i)
    {
        *static_cast<QDataStream *>(this) >> i;
        return *this;
    }
    P9DataStream &operator<<(quint32 i)
    {
        *static_cast<QDataStream *>(this) << i;
        return *this;
    }
    P9DataStream &operator>>(quint32 &i)
    {
        *static_cast<QDataStream *>(this) >> i;
        return *this;
    }
    P9DataStream &operator<<(quint64 i)
    {
        *static_cast<QDataStream *>(this) << i;
        return *this;
    }
    P9DataStream &operator>>(quint64 &i)
    {
        *static_cast<QDataStream *>(this) >> i;
        return *this;
    }
    P9DataStream &operator<<(QString s)
    {
        QByteArray b = s.toUtf8();
        *this << (quint16)b.size();
        return *this << b;
    }
    P9DataStream &operator>>(QString &s)
    {
        quint16 n;
        *this >> n;
        QByteArray b(n, Qt::Initialization());
        *this >> b;
        s = QString::fromUtf8(b);
        return *this;
    }
    P9DataStream &operator<<(const QByteArray &b)
    {
        writeRawData(b.data(), b.size());
        return *this;
    }
    P9DataStream &operator>>(QByteArray &b)
    {
        readRawData(b.data(), b.size());
        return *this;
    }
    P9DataStream &operator>>(P9Worker::p9qid &qid)
    {
        *this >> qid.qid_type >> qid.qid_version >> qid.qid_path;
        return *this;
    }
    P9DataStream &operator>>(P9Worker::p9statbuf &buf)
    {
        quint16 n;
        *this >> n;
        QByteArray b(n, Qt::Initialization());
        *this >> b;

        P9DataStream sub(b);
        sub >> buf.type >> buf.dev;
        sub >> buf.qid;
        sub >> buf.mode;
        sub >> buf.atime >> buf.mtime;
        sub >> buf.length;
        sub >> buf.name;
        sub >> buf.uid >> buf.gid >> buf.muid;
        return *this;
    }
    P9DataStream &operator>>(UDSEntry &entry)
    {
        P9Worker::p9statbuf buf;
        *this >> buf;
        entry.clear();
        entry.reserve(10);
        entry.fastInsert(KIO::UDSEntry::UDS_NAME, buf.name);
        entry.fastInsert(KIO::UDSEntry::UDS_FILE_TYPE, (buf.mode & P9Worker::DMDIR) ? QT_STAT_DIR : QT_STAT_REG);
        entry.fastInsert(KIO::UDSEntry::UDS_ACCESS, buf.mode & 0777);
        entry.fastInsert(KIO::UDSEntry::UDS_ACCESS_TIME, buf.atime);
        entry.fastInsert(KIO::UDSEntry::UDS_MODIFICATION_TIME, buf.mtime);
        entry.fastInsert(KIO::UDSEntry::UDS_SIZE, buf.length);
        entry.fastInsert(KIO::UDSEntry::UDS_USER, buf.uid);
        entry.fastInsert(KIO::UDSEntry::UDS_GROUP, buf.gid);
        return *this;
    }
};

//===============================================================================
// P9Worker
//===============================================================================

P9Worker::P9Worker(const QByteArray &pool, const QByteArray &app)
    : WorkerBase(QByteArrayLiteral("9p"), pool, app)
{
}

void P9Worker::setHost(const QString &host, quint16 port, const QString &user, const QString &pass)
{
    if (host != mHost || port != mPort || user != mUser) {
        mHost = host;
        mPort = port;
        mUser = user;
        if (mSession)
            closeConnection();
    }
}

KIO::WorkerResult P9Worker::openConnection()
{
    if (mSession)
        return Result::pass();
    mSession = new QTcpSocket;
    mSession->connectToHost(mHost, mPort ? mPort : 564);
    qCDebug(KIO_9P_LOG) << "connecting! " << mHost << mPort;
    mSession->waitForConnected(30 * 1000);
    qCDebug(KIO_9P_LOG) << "connected!";
    Result res = negotiateVersion();
    if (!res.success())
        return res;
    // authenticate(142, mUser, QByteArrayLiteral(""));
    mMaxFid = 0;
    return attach(0, 0xffffffff, mUser.isEmpty() ? "nobody" : mUser, QByteArrayLiteral(""));
}

KIO::WorkerResult P9Worker::negotiateVersion()
{
    QString proto = "9P2000";
    QByteArray payload;
    {
        P9DataStream ds(&payload);
        ds << mMax;
        ds << proto;
    }
    Result res = sendCmd(Tversion, 0xffff, payload);
    if (!res.success())
        return res;
    return recvCmd(Rversion, 0xffff);
}

KIO::WorkerResult P9Worker::authenticate(quint32 afid, QString uname, QString aname)
{
    QByteArray payload;
    {
        P9DataStream ds(&payload);
        ds << afid;
        ds << uname << aname;
    }
    Result res = sendCmd(Tauth, 0, payload);
    if (!res.success())
        return res;
    return recvCmd(Rauth, 0);
}

KIO::WorkerResult P9Worker::attach(quint32 fid, quint32 afid, QString uname, QString aname)
{
    QByteArray payload;
    {
        P9DataStream ds(&payload);
        ds << fid << afid;
        ds << uname << aname;
    }
    Result res = sendCmd(Tattach, 0, payload);
    if (!res.success())
        return res;
    return recvCmd(Rattach, 0);
}

KIO::WorkerResult P9Worker::walk(quint32 fid, quint32 nfid, QStringList walks)
{
    QByteArray payload;
    {
        P9DataStream ds(&payload);
        ds << fid << nfid << (quint16)walks.size();
        for (QString s : walks)
            ds << s;
    }
    Result res = sendCmd(Twalk, 0, payload);
    if (!res.success())
        return res;
    return recvCmd(Rwalk, 0);
}

KIO::WorkerResult P9Worker::read(quint32 fid, quint64 offset, quint32 count)
{
    QByteArray payload;
    {
        P9DataStream ds(&payload);
        ds << fid << offset << count;
    }
    Result res = sendCmd(Tread, 0, payload);
    if (!res.success())
        return res;
    return recvCmd(Rread, 0);
}

KIO::WorkerResult P9Worker::open(quint32 fid, quint8 mode)
{
    QByteArray payload;
    {
        P9DataStream ds(&payload);
        ds << fid << mode;
    }
    Result res = sendCmd(Topen, 0, payload);
    if (!res.success())
        return res;
    return recvCmd(Ropen, 0);
}

KIO::WorkerResult P9Worker::stat(quint32 fid)
{
    QByteArray payload;
    {
        P9DataStream ds(&payload);
        ds << fid;
    }
    Result res = sendCmd(Tstat, 0, payload);
    if (!res.success())
        return res;
    return recvCmd(Rstat, 0);
}

void P9Worker::closeConnection()
{
    delete mSession;
    mSession = nullptr;
}

KIO::WorkerResult P9Worker::sendCmd(enum p9cmd type, quint16 tag, const QByteArray &cmd)
{
    QByteArray payload;
    {
        P9DataStream ds(&payload);
        ds << (quint32)cmd.size() + 7;
        ds << (quint8)type;
        ds << tag;
        ds << cmd;
    }
    qCDebug(KIO_9P_TRACE_LOG) << "sending " << payload;
    qint64 n = mSession->write(payload);
    if (n == -1)
        return Result::fail(ERR_WORKER_DEFINED, tr("write: %1").arg(mSession->errorString()));
    if (n != payload.size())
        return Result::fail(ERR_WORKER_DEFINED, tr("Short write"));
    qCDebug(KIO_9P_TRACE_LOG) << "sent";
    return Result::pass();
}

KIO::WorkerResult P9Worker::recvCmd(enum p9cmd type, quint16 tag)
{
    qCDebug(KIO_9P_TRACE_LOG) << "recving";
    mSession->waitForReadyRead(30 * 1000);
    QByteArray head = recvExact(4);
    if (head.size() == 0)
        return Result::fail(ERR_WORKER_DEFINED, tr("read: %1").arg(mSession->errorString()));
    if (head.size() != 4)
        return Result::fail(ERR_WORKER_DEFINED, tr("Short read"));
    quint32 n = head[0] | head[1] << 8 | head[2] << 16 | head[3] << 24;
    if (n < 7)
        return Result::fail(ERR_WORKER_DEFINED, tr("Malformed packet"));
    QByteArray payload = recvExact(n - 4);
    qCDebug(KIO_9P_TRACE_LOG) << "recvd " << payload;
    P9DataStream ds(payload);

    quint8 cmd;
    quint16 theirtag;

    ds >> cmd;
    ds >> theirtag;

    if (theirtag != tag)
        return Result::fail(ERR_WORKER_DEFINED, tr("Unexpected response: %1 (expected %2)").arg(theirtag, tag));

    if (cmd == Rerror) {
        QString ename;
        ds >> ename;
        return Result::fail(ERR_WORKER_DEFINED, ename);
    }
    if (cmd != type)
        return Result::fail(ERR_WORKER_DEFINED, tr("Unexpected response: %1 (expected %2)").arg(type, cmd));

    switch (cmd) {
    case Rversion: {
        ds >> mMax;
        QString ver;
        ds >> ver;
        if (ver != "9P2000")
            return Result::fail(ERR_CANNOT_CONNECT, "9P version not implemented: " + ver);
        break;
    }
    case Rattach: {
        p9qid qid;
        ds >> qid;
        break;
    }
    case Rstat: {
        UDSEntry entry;
        ds >> entry;
        statEntry(entry);
        break;
    }
    case Ropen: {
        p9qid qid;
        quint32 iounit;
        ds >> qid >> iounit;
        if (qid.qid_type & 0x80)
            mimeType("inode/directory");
        else
            mimeType("application/octet-stream");
        mIsDir = qid.qid_type & 0x80;
        break;
    }
    case Rwalk: {
        quint16 nqids;
        ds >> nqids;
        // nqids < nwalks indicates partial success
        // need to walk to returned depth and walk the offending component again to get error cause
        for (quint16 i = 0; i < nqids; i++) {
            p9qid qid;
            ds >> qid;
        }
        break;
    }
    case Rread: {
        quint32 count;
        ds >> count;
        QByteArray filedata(count, Qt::Initialization());
        ds >> filedata;
        if (mIsDir) {
            P9DataStream ds2(filedata);
            UDSEntry entry;
            while (!ds2.atEnd()) {
                ds2 >> entry;
                listEntry(entry);
            }
        } else
            data(filedata);
        break;
    }
    }
    return Result::pass();
}

QByteArray P9Worker::recvExact(qsizetype size)
{
    QByteArray payload = mSession->read(size);
    if (payload.isEmpty())
        return payload;
    while (payload.size() < size) {
        mSession->waitForReadyRead(3 * 1000);
        // suboptimal: could fill the bytearray in place
        QByteArray nxt = mSession->read(size - payload.size());
        if (nxt.isEmpty())
            break;
        payload += nxt;
    }
    return payload;
}

KIO::WorkerResult P9Worker::stat(const QUrl &url)
{
    Result res = openConnection();
    if (!res.success())
        return res;
    quint32 fid = ++mMaxFid;
    res = walk(0, fid, url.path().mid(1).split('/'));
    if (!res.success())
        return res;

    return stat(fid);
}

KIO::WorkerResult P9Worker::listDir(const QUrl &url)
{
    Result res = openConnection();
    if (!res.success())
        return res;
    quint32 fid = 0;
    if (url.path() != "/") {
        fid = ++mMaxFid;
        res = walk(0, fid, url.path().mid(1).split('/'));
        if (!res.success())
            return res;
    }

    res = open(fid, OREAD);
    if (!res.success())
        return res;

    return read(fid, 0, 8192);
}

KIO::WorkerResult P9Worker::mkdir(const QUrl &url, int permissions)
{
    return Result::pass();
}

KIO::WorkerResult P9Worker::rename(const QUrl &src, const QUrl &dst, JobFlags flags)
{
    return Result::pass();
}

KIO::WorkerResult P9Worker::del(const QUrl &url, bool isfile)
{
    return Result::pass();
}

KIO::WorkerResult P9Worker::chmod(const QUrl &url, int permissions)
{
    return Result::pass();
}

KIO::WorkerResult P9Worker::get(const QUrl &url)
{
    Result res = openConnection();
    if (!res.success())
        return res;
    quint32 fid = ++mMaxFid;
    res = walk(0, fid, url.path().mid(1).split('/'));
    if (!res.success())
        return res;

    res = open(fid, OREAD);
    if (!res.success())
        return res;

    return read(fid, 0, 8192);
}

KIO::WorkerResult P9Worker::put(const QUrl &url, int permissions, JobFlags flags)
{
    return Result::pass();
}

void P9Worker::worker_status()
{
}

KIO::WorkerResult P9Worker::copy(const QUrl &src, const QUrl &dest, int permissions, JobFlags flags)
{
    return Result::pass();
}

QDebug operator<<(QDebug dbg, const Result &r)

{
    QDebugStateSaver saver(dbg);
    dbg.nospace() << "Result("
                  << "success=" << r.success() << ", err=" << r.error() << ", str=" << r.errorString() << ')';
    return dbg;
}

// needed for JSON file embedding
#include "kio_9p.moc"

#include "moc_kio_9p.cpp"

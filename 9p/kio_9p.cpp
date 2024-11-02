/*
 * SPDX-FileCopyrightText: 2024 Arkadiusz Kozdra <floss@arusekk.pl>
 *
 * SPDX-License-Identifier: LGPL-2.0-or-later
 */

#include "kio_9p.h"

#include <QCoreApplication>
#include <QTcpSocket>
#include <kio/global.h>
#include <kio/job_base.h>

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
    P9DataStream &operator<<(const P9Worker::p9qid &qid)
    {
        *this << qid.qid_type << qid.qid_version << qid.qid_path;
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
    P9DataStream &operator<<(const P9Worker::p9statbuf &buf)
    {
        QByteArray b;
        P9DataStream sub(&b);
        sub << buf.type << buf.dev;
        sub << buf.qid;
        sub << buf.mode;
        sub << buf.atime << buf.mtime;
        sub << buf.length;
        sub << buf.name;
        sub << buf.uid << buf.gid << buf.muid;

        *this << (quint16)(b.size() + 2) << (quint16)b.size() << b;

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
    return recvCmd(Rversion, 0xffff, [&](P9DataStream &ds) {
        ds >> mMax;
        QString ver;
        ds >> ver;
        if (ver != proto)
            return Result::fail(ERR_CANNOT_CONNECT, tr("9P version not implemented: %1").arg(ver));
        return Result::pass();
    });
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
    return recvCmd(Rauth, 0, [&](P9DataStream &) {
        return Result::pass();
    });
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
    return recvCmd(Rattach, 0, [&](P9DataStream &ds) {
        p9qid qid;
        ds >> qid;
        return Result::pass();
    });
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
    return recvCmd(Rwalk, 0, [&](P9DataStream &ds) {
        quint16 nqids;
        ds >> nqids;
        // nqids < nwalks indicates partial success
        // need to walk to returned depth and walk the offending component again to get error cause
        for (quint16 i = 0; i < nqids; i++) {
            p9qid qid;
            ds >> qid;
        }
        if (nqids < walks.size()) {
            if (nqids == 0)
                return Result::fail(ERR_WORKER_DEFINED, tr("zero partial walk"));
            int fidx = ++mMaxFid;
            res = walk(fid, fidx, walks.mid(0, nqids));
            if (!res.success())
                return res;
            return walk(fidx, nfid, walks.mid(nqids));
        }
        return Result::pass();
    });
}

KIO::WorkerResult P9Worker::read(quint32 fid, quint64 offset, quint32 count, std::function<Result(QByteArray &)> callback)
{
    QByteArray payload;
    {
        P9DataStream ds(&payload);
        ds << fid << offset << count;
    }
    Result res = sendCmd(Tread, 0, payload);
    if (!res.success())
        return res;
    return recvCmd(Rread, 0, [&](P9DataStream &ds) {
        quint32 count;
        ds >> count;
        if (!count)
            return Result::fail(ERR_WORKER_DEFINED, "EOF");
        openOffset += count;
        QByteArray filedata(count, Qt::Initialization());
        ds >> filedata;
        return callback(filedata);
    });
}

KIO::WorkerResult P9Worker::write(quint32 fid, quint64 offset, QByteArray data)
{
    QByteArray payload;
    {
        P9DataStream ds(&payload);
        ds << fid << offset << (quint32)data.size() << data;
    }
    Result res = sendCmd(Twrite, 0, payload);
    if (!res.success())
        return res;
    return recvCmd(Rwrite, 0, [&](P9DataStream &ds) {
        quint32 count;
        ds >> count;
        openOffset += count;
        return Result::pass();
    });
}

KIO::WorkerResult P9Worker::clunk(quint32 fid)
{
    QByteArray payload;
    {
        P9DataStream ds(&payload);
        ds << fid;
    }
    Result res = sendCmd(Tclunk, 0, payload);
    if (!res.success())
        return res;
    if (fid == mMaxFid)
        mMaxFid--;
    return recvCmd(Rclunk, 0, [&](P9DataStream &) {
        return Result::pass();
    });
}

KIO::WorkerResult P9Worker::remove(quint32 fid)
{
    QByteArray payload;
    {
        P9DataStream ds(&payload);
        ds << fid;
    }
    Result res = sendCmd(Tremove, 0, payload);
    if (!res.success())
        return res;
    if (fid == mMaxFid)
        mMaxFid--;
    return recvCmd(Rremove, 0, [&](P9DataStream &) {
        return Result::pass();
    });
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
    return recvCmd(Ropen, 0, [&](P9DataStream &ds) {
        p9qid qid;
        quint32 iounit;
        ds >> qid >> iounit;
        if (qid.qid_type & 0x80)
            mimeType("inode/directory");
        else
            mimeType("application/octet-stream");
        return Result::pass();
    });
}

KIO::WorkerResult P9Worker::create(quint32 fid, QString name, quint32 perm, quint8 mode)
{
    QByteArray payload;
    {
        P9DataStream ds(&payload);
        ds << fid << name << perm << mode;
    }
    Result res = sendCmd(Tcreate, 0, payload);
    if (!res.success())
        return res;
    return recvCmd(Rcreate, 0, [&](P9DataStream &ds) {
        p9qid qid;
        quint32 iounit;
        ds >> qid >> iounit;
        return Result::pass();
    });
}

KIO::WorkerResult P9Worker::stat(quint32 fid, std::function<void(UDSEntry &)> callback)
{
    QByteArray payload;
    {
        P9DataStream ds(&payload);
        ds << fid;
    }
    Result res = sendCmd(Tstat, 0, payload);
    if (!res.success())
        return res;

    return recvCmd(Rstat, 0, [&](P9DataStream &ds) {
        quint16 ign; // ignore; must be len(entry) + 2
        UDSEntry entry;
        ds >> ign >> entry;
        callback(entry);
        return Result::pass();
    });
}

KIO::WorkerResult P9Worker::wstat(quint32 fid, const p9statbuf &buf)
{
    QByteArray payload;
    {
        P9DataStream ds(&payload);
        ds << fid;
        ds << buf;
    }
    Result res = sendCmd(Twstat, 0, payload);
    if (!res.success())
        return res;

    return recvCmd(Rwstat, 0, [&](P9DataStream &) {
        return Result::pass();
    });
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

KIO::WorkerResult P9Worker::recvCmd(enum p9cmd type, quint16 tag, std::function<Result(P9DataStream &)> callback)
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

    return callback(ds);
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
    quint32 fid = 0;
    if (url.path() != "/") {
        fid = ++mMaxFid;
        res = walk(0, fid, url.path().split('/', Qt::SkipEmptyParts));
        if (!res.success())
            return res;
    }

    return stat(fid, [&](UDSEntry &entry) {
        statEntry(entry);
    });
}

KIO::WorkerResult P9Worker::listDir(const QUrl &url)
{
    Result res = open(url);
    if (!res.success())
        return res;

    res = stat(mLastFid, [&](UDSEntry &entry) {
        qCDebug(KIO_9P_LOG) << "UDS " << entry;
        entry.replace(KIO::UDSEntry::UDS_NAME, ".");
        listEntry(entry);
    });
    if (!res.success())
        return res;
    while (true) {
        res = read(mLastFid, openOffset, 8192, [&](QByteArray &filedata) {
            P9DataStream ds2(filedata);
            UDSEntry entry;
            while (!ds2.atEnd()) {
                ds2 >> entry;
                listEntry(entry);
            }
            return Result::pass();
        });
        if (!res.success())
            break;
    }
    if (res.errorString() == "EOF")
        res = Result::pass();
    return res;
}

KIO::WorkerResult P9Worker::mkdir(const QUrl &url, int permissions)
{
    Result res = openConnection();
    if (!res.success())
        return res;

    QStringList components = url.path().split('/', Qt::SkipEmptyParts);
    if (components.empty())
        return Result::fail(ERR_WORKER_DEFINED, "mkdir root dir");
    QString newName = components.takeLast();

    quint32 fid = ++mMaxFid;
    res = walk(0, fid, components);
    if (!res.success())
        return res;

    res = create(fid, newName, permissions | DMDIR, OREAD);
    if (!res.success())
        return res;

    // (void)clunk(fid);
    return res;
}

KIO::WorkerResult P9Worker::rename(const QUrl &src, const QUrl &dst, JobFlags flags)
{
    Result res = openConnection();
    if (!res.success())
        return res;

    quint32 fid = ++mMaxFid;
    QStringList srcList = src.path().split('/', Qt::SkipEmptyParts);
    res = walk(0, fid, srcList);
    if (!res.success())
        return res;

    QStringList dstList = dst.path().split('/', Qt::SkipEmptyParts);
    p9statbuf buf;
    buf.name = dstList.last();

    res = wstat(fid, buf);
    if (res.success())
        return res;
    if (!(flags & KIO::Overwrite))
        return res;
    res = del(dst, true);
    if (!res.success())
        return res;
    return wstat(fid, buf);
}

KIO::WorkerResult P9Worker::del(const QUrl &url, bool isfile)
{
    Result res = openConnection();
    if (!res.success())
        return res;

    quint32 fid = ++mMaxFid;
    res = walk(0, fid, url.path().split('/', Qt::SkipEmptyParts));
    if (!res.success())
        return res;

    Q_UNUSED(isfile);
    res = remove(fid);
    return res;
}

KIO::WorkerResult P9Worker::chmod(const QUrl &url, int permissions)
{
    Result res = openConnection();
    if (!res.success())
        return res;

    quint32 fid = ++mMaxFid;
    res = walk(0, fid, url.path().split('/', Qt::SkipEmptyParts));
    if (!res.success())
        return res;

    p9statbuf buf;
    buf.mode = permissions; // TODO: DMDIR from last qid from walk
    return wstat(fid, buf);
}

KIO::WorkerResult P9Worker::get(const QUrl &url)
{
    Result res = open(url);
    if (!res.success())
        return res;

    while (true) {
        res = read(8192);
        if (!res.success())
            break;
    }
    if (res.errorString() == "EOF")
        res = Result::pass();
    return res;
}

KIO::WorkerResult P9Worker::put(const QUrl &url, int permissions, JobFlags flags)
{
    Result res = openConnection();
    if (!res.success())
        return res;

    QStringList components = url.path().split('/', Qt::SkipEmptyParts);
    if (components.empty())
        return Result::fail(ERR_WORKER_DEFINED, "put root dir");
    QString newName = components.takeLast();

    quint32 fid = ++mMaxFid;
    res = walk(0, fid, components);
    if (!res.success())
        return res;

    res = create(fid, newName, permissions & 0777, OWRITE);
    if (!res.success()) {
        if (res.error() != KIO::ERR_FILE_ALREADY_EXIST)
            return res;
        if (flags & (KIO::Overwrite | KIO::Resume))
            return res;
        int dfid = fid;
        fid = ++mMaxFid;
        res = walk(dfid, fid, {newName});
        if (!res.success())
            return res;
        quint8 p9mode = OWRITE;
        if (flags & KIO::Overwrite)
            p9mode |= OTRUNC;
        res = open(fid, p9mode);
        if (!res.success())
            return res;
    }
    mLastFid = fid;

    dataReq();
    QByteArray arr;
    readData(arr);

    res = write(arr);

    (void)clunk(fid);
    return res;
}

void P9Worker::worker_status()
{
}

Result P9Worker::open(const QUrl &url, QIODevice::OpenMode mode)
{
    Result res = openConnection();
    if (!res.success())
        return res;

    quint32 fid = ++mMaxFid;
    res = walk(0, fid, url.path().split('/', Qt::SkipEmptyParts));
    if (!res.success())
        return res;
    mLastFid = fid;

    quint8 p9mode = (mode & QIODevice::ReadWrite) == QIODevice::ReadWrite ? ORDWR : (mode & QIODevice::WriteOnly) ? OWRITE : OREAD;
    if (mode & QIODevice::Truncate)
        p9mode |= OTRUNC;
    // TODO: NewOnly, ExistingOnly: see open(5)
    openOffset = 0;
    return open(fid, p9mode);
}
Result P9Worker::read(KIO::filesize_t size)
{
    return read(mLastFid, openOffset, size, [&](QByteArray &filedata) {
        processedSize(openOffset);
        data(filedata);
        return Result::pass();
    });
}
Result P9Worker::write(const QByteArray &data)
{
    return write(mLastFid, openOffset, data);
}
Result P9Worker::seek(KIO::filesize_t offset)
{
    openOffset = offset;
    return Result::pass();
}
Result P9Worker::truncate(KIO::filesize_t length)
{
    p9statbuf buf;
    buf.length = length;
    return wstat(mLastFid, buf);
}

Result P9Worker::close()
{
    if (!mLastFid)
        return Result::pass();
    return clunk(mLastFid);
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

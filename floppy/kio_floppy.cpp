/*  This file is part of the KDE project

    Copyright (C) 2000 Alexander Neundorf <neundorf@kde.org>

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Library General Public
    License as published by the Free Software Foundation; either
    version 2 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Library General Public License for more details.

    You should have received a copy of the GNU Library General Public License
    along with this library; see the file COPYING.LIB.  If not, write to
    the Free Software Foundation, Inc., 51 Franklin Steet, Fifth Floor,
    Boston, MA 02110-1301, USA.
*/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>

#include <qtextstream.h>
#include <qcstring.h>
#include <qfile.h>

#include "kio_floppy.h"

#include <kinstance.h>
#include <kdebug.h>
#include <kio/global.h>
#include <klocale.h>

using namespace KIO;

extern "C" { KDE_EXPORT int kdemain(int argc, char **argv); }

int kdemain( int argc, char **argv )
{
  KInstance instance( "kio_floppy" );

  if (argc != 4)
  {
     fprintf(stderr, "Usage: kio_floppy protocol domain-socket1 domain-socket2\n");
     exit(-1);
  }
  kdDebug(7101) << "Floppy: kdemain: starting" << endl;

  FloppyProtocol slave(argv[2], argv[3]);
  slave.dispatchLoop();
  return 0;
}

void getDriveAndPath(const QString& path, QString& drive, QString& rest)
{
   drive=QString::null;
   rest=QString::null;
   QStringList list=QStringList::split("/",path);
   for (QStringList::Iterator it=list.begin(); it!=list.end(); it++)
   {
      if (it==list.begin())
         drive=(*it)+":";
      else
         rest=rest+"/"+(*it);
   }
}

FloppyProtocol::FloppyProtocol (const QCString &pool, const QCString &app )
:SlaveBase( "floppy", pool, app )
,m_mtool(0)
,m_stdoutBuffer(0)
,m_stderrBuffer(0)
,m_stdoutSize(0)
,m_stderrSize(0)
{
   kdDebug(7101)<<"Floppy::Floppy: -"<<pool<<"-"<<endl;
}

FloppyProtocol::~FloppyProtocol()
{
   delete [] m_stdoutBuffer;
   delete [] m_stderrBuffer;
   delete m_mtool;
   m_mtool=0;
   m_stdoutBuffer=0;
   m_stderrBuffer=0;
}

int FloppyProtocol::readStdout()
{
   //kdDebug(7101)<<"Floppy::readStdout"<<endl;
   if (m_mtool==0) return 0;

   char buffer[16*1024];
   int length=::read(m_mtool->stdoutFD(),buffer,16*1024);
   if (length<=0) return 0;

   //+1 gives us room for a terminating 0
   char *newBuffer=new char[length+m_stdoutSize+1];
   kdDebug(7101)<<"Floppy::readStdout(): length: "<<length<<" m_tsdoutSize: "<<m_stdoutSize<<" +1="<<length+m_stdoutSize+1<<endl;
   if (m_stdoutBuffer!=0)
   {
      memcpy(newBuffer, m_stdoutBuffer, m_stdoutSize);
   }
   memcpy(newBuffer+m_stdoutSize, buffer, length);
   m_stdoutSize+=length;
   newBuffer[m_stdoutSize]='\0';

   delete [] m_stdoutBuffer;
   m_stdoutBuffer=newBuffer;
   //kdDebug(7101)<<"Floppy::readStdout(): -"<<m_stdoutBuffer<<"-"<<endl;

   //kdDebug(7101)<<"Floppy::readStdout ends"<<endl;
   return length;
}

int FloppyProtocol::readStderr()
{
   //kdDebug(7101)<<"Floppy::readStderr"<<endl;
   if (m_mtool==0) return 0;

   /*struct timeval tv;
   tv.tv_sec=0;
   tv.tv_usec=1000*300;
   ::select(0,0,0,0,&tv);*/

   char buffer[16*1024];
   int length=::read(m_mtool->stderrFD(),buffer,16*1024);
   kdDebug(7101)<<"Floppy::readStderr(): read "<<length<<" bytes"<<endl;
   if (length==0) return 0;

   //+1 gives us room for a terminating 0
   char *newBuffer=new char[length+m_stderrSize+1];
   memcpy(newBuffer, m_stderrBuffer, m_stderrSize);
   memcpy(newBuffer+m_stderrSize, buffer, length);
   m_stderrSize+=length;
   newBuffer[m_stderrSize]='\0';
   delete [] m_stderrBuffer;
   m_stderrBuffer=newBuffer;
   kdDebug(7101)<<"Floppy::readStderr(): -"<<m_stderrBuffer<<"-"<<endl;

   return length;
}

void FloppyProtocol::clearBuffers()
{
   kdDebug(7101)<<"Floppy::clearBuffers()"<<endl;
   m_stdoutSize=0;
   m_stderrSize=0;
   delete [] m_stdoutBuffer;
   m_stdoutBuffer=0;
   delete [] m_stderrBuffer;
   m_stderrBuffer=0;
   //kdDebug(7101)<<"Floppy::clearBuffers() ends"<<endl;
}

void FloppyProtocol::terminateBuffers()
{
   //kdDebug(7101)<<"Floppy::terminateBuffers()"<<endl;
   //append a terminating 0 to be sure
   if (m_stdoutBuffer!=0)
   {
      m_stdoutBuffer[m_stdoutSize]='\0';
   }
   if (m_stderrBuffer!=0)
   {
      m_stderrBuffer[m_stderrSize]='\0';
   }
   //kdDebug(7101)<<"Floppy::terminateBuffers() ends"<<endl;
}

bool FloppyProtocol::stopAfterError(const KURL& url, const QString& drive)
{
   if (m_stderrSize==0)
      return true;
   //m_stderrBuffer[m_stderrSize]='\0';

   QString outputString(m_stderrBuffer);
   QTextIStream output(&outputString);
   QString line=output.readLine();
   kdDebug(7101)<<"line: -"<<line<<"-"<<endl;
   if (line.find("resource busy") > -1)
   {
      error( KIO::ERR_SLAVE_DEFINED, i18n("Could not access drive %1.\nThe drive is still busy.\nWait until it is inactive and then try again.").arg(drive));
   }
   else if ((line.find("Disk full") > -1) || (line.find("No free cluster") > -1))
   {
      error( KIO::ERR_SLAVE_DEFINED, i18n("Could not write to file %1.\nThe disk in drive %2 is probably full.").arg(url.prettyURL(),drive));
   }
   //file not found
   else if (line.find("not found") > -1)
   {
      error( KIO::ERR_DOES_NOT_EXIST, url.prettyURL());
   }
   //no disk
   else if (line.find("not configured") > -1)
   {
      error( KIO::ERR_SLAVE_DEFINED, i18n("Could not access %1.\nThere is probably no disk in the drive %2").arg(url.prettyURL(),drive));
   }
   else if (line.find("No such device") > -1)
   {
      error( KIO::ERR_SLAVE_DEFINED, i18n("Could not access %1.\nThere is probably no disk in the drive %2 or you do not have enough permissions to access the drive.").arg(url.prettyURL(),drive));
   }
   else if (line.find("not supported") > -1)
   {
      error( KIO::ERR_SLAVE_DEFINED, i18n("Could not access %1.\nThe drive %2 is not supported.").arg(url.prettyURL(),drive));
   }
   //not supported or no such drive
   else if (line.find("Permission denied") > -1)
   {
      error( KIO::ERR_SLAVE_DEFINED, i18n("Could not access %1.\nMake sure the floppy in drive %2 is a DOS-formatted floppy disk \nand that the permissions of the device file (e.g. /dev/fd0) are set correctly (e.g. rwxrwxrwx).").arg(url.prettyURL(),drive));
   }
   else if (line.find("non DOS media") > -1)
   {
      error( KIO::ERR_SLAVE_DEFINED, i18n("Could not access %1.\nThe disk in drive %2 is probably not a DOS-formatted floppy disk.").arg(url.prettyURL(),drive));
   }
   else if (line.find("Read-only") > -1)
   {
      error( KIO::ERR_SLAVE_DEFINED, i18n("Access denied.\nCould not write to %1.\nThe disk in drive %2 is probably write-protected.").arg(url.prettyURL(),drive));
   }
   else if ((outputString.find("already exists") > -1) || (outputString.find("Skipping ") > -1))
   {
      error( KIO::ERR_FILE_ALREADY_EXIST,url.prettyURL());
      //return false;
   }
   else if (outputString.find("could not read boot sector") > -1)
   {
      error( KIO::ERR_SLAVE_DEFINED, i18n("Could not read boot sector for %1.\nThere is probably not any disk in drive %2.").arg(url.prettyURL(),drive));
      //return false;
   }
   else
   {
      error( KIO::ERR_UNKNOWN, outputString);
   }
   return true;
}

void FloppyProtocol::listDir( const KURL& _url)
{
   kdDebug(7101)<<"Floppy::listDir() "<<_url.path()<<endl;
   KURL url(_url);
   QString path(url.path());

   if ((path.isEmpty()) || (path=="/"))
   {
      url.setPath("/a/");
      redirection(url);
      finished();
      return;
   }
   QString drive;
   QString floppyPath;
   getDriveAndPath(path,drive,floppyPath);

   QStringList args;

   args<<"mdir"<<"-a"<<(drive+floppyPath);
   if (m_mtool!=0)
      delete m_mtool;
   m_mtool=new Program(args);

   clearBuffers();

   if (!m_mtool->start())
   {
      delete m_mtool;
      m_mtool=0;
      errorMissingMToolsProgram("mdir");
      return;
   }

   int result;
   bool loopFinished(false);
   bool errorOccured(false);
   do
   {
      bool stdoutEvent;
      bool stderrEvent;
      result=m_mtool->select(1,0,stdoutEvent, stderrEvent);
      if (stdoutEvent)
         if (readStdout()==0)
            loopFinished=true;
      if (stderrEvent)
      {
         if (readStderr()==0)
            loopFinished=true;
         else
            if (stopAfterError(url,drive))
            {
               loopFinished=true;
               errorOccured=true;
            }
      }
   } while (!loopFinished);

   delete m_mtool;
   m_mtool=0;
   //now mdir has finished
   //let's parse the output
   terminateBuffers();

   if (errorOccured)
      return;

   QString outputString(m_stdoutBuffer);
   QTextIStream output(&outputString);
   QString line;

   int totalNumber(0);
   int mode(0);
   UDSEntry entry;

   while (!output.atEnd())
   {
      line=output.readLine();
      kdDebug(7101)<<"Floppy::listDir(): line: -"<<line<<"- length: "<<line.length()<<endl;

      if (mode==0)
      {
         if (line.isEmpty())
         {
            kdDebug(7101)<<"Floppy::listDir(): switching to mode 1"<<endl;
            mode=1;
         }
      }
      else if (mode==1)
      {
         if (line[0]==' ')
         {
            kdDebug(7101)<<"Floppy::listDir(): ende"<<endl;
            totalSize(totalNumber);
            break;
         }
         entry.clear();
         StatInfo info=createStatInfo(line);
         if (info.isValid)
         {
            createUDSEntry(info,entry);
            //kdDebug(7101)<<"Floppy::listDir(): creating UDSEntry"<<endl;
            listEntry( entry, false);
            totalNumber++;
         }
      }
   }
   listEntry( entry, true ); // ready
   finished();
   //kdDebug(7101)<<"Floppy::listDir() ends"<<endl;
}

void FloppyProtocol::errorMissingMToolsProgram(const QString& name)
{
     error(KIO::ERR_SLAVE_DEFINED,i18n("Could not start program \"%1\".\nEnsure that the mtools package is installed correctly on your system.").arg(name));
 }

void FloppyProtocol::createUDSEntry(const StatInfo& info, UDSEntry& entry)
{
   UDSAtom atom;
   atom.m_uds = KIO::UDS_NAME;
   atom.m_str = info.name;
   entry.append( atom );

   atom.m_uds = KIO::UDS_SIZE;
   atom.m_long = info.size;
   entry.append(atom);

   atom.m_uds = KIO::UDS_MODIFICATION_TIME;
   atom.m_long = info.time;
   entry.append( atom );

   atom.m_uds = KIO::UDS_ACCESS;
   atom.m_long=info.mode;
   entry.append( atom );

   atom.m_uds = KIO::UDS_FILE_TYPE;
   atom.m_long =(info.isDir?S_IFDIR:S_IFREG);
   entry.append( atom );
}

StatInfo FloppyProtocol::createStatInfo(const QString line, bool makeStat, const QString& dirName)
{
   //kdDebug(7101)<<"Floppy::createUDSEntry()"<<endl;
   QString name;
   QString size;
   bool isDir(false);
   QString day,month, year;
   QString hour, minute;
   StatInfo info;

   static QDateTime beginningOfTimes(QDate(1970,1,1),QTime(1,0));

   if (line.length()==41)
   {
      int nameLength=line.find(' ');
      kdDebug(7101)<<"Floppy::createStatInfo: line find: "<<nameLength <<"= -"<<line<<"-"<<endl;
      if (nameLength>0)
      {
         name=line.mid(0,nameLength);
         QString ext=line.mid(9,3);
         ext=ext.stripWhiteSpace();
         if (!ext.isEmpty())
            name+="."+ext;
      }
      kdDebug(7101)<<"Floppy::createStatInfo() name 8.3= -"<<name<<"-"<<endl;
   }
   else if (line.length()>41)
   {
      name=line.mid(42);
      kdDebug(7101)<<"Floppy::createStatInfo() name vfat: -"<<name<<"-"<<endl;
   }
   if ((name==".") || (name==".."))
   {
      if (makeStat)
         name=dirName;
      else
      {
         info.isValid=false;
         return info;
      }
   }

   if (line.mid(13,5)=="<DIR>")
   {
      //kdDebug(7101)<<"Floppy::createUDSEntry() isDir"<<endl;
      size="1024";
      isDir=true;
   }
   else
   {
      size=line.mid(13,9);
      //kdDebug(7101)<<"Floppy::createUDSEntry() size: -"<<size<<"-"<<endl;
   }

        //TEEKANNE JPG     70796 01-02-2003  17:47  Teekanne.jpg
   if (line[25]=='-')
   {
      month=line.mid(23,2);
      day=line.mid(26,2);
      year=line.mid(29,4);
   }
   else //SETUP    PKG      1019 1997-09-25  10:31  setup.pkg
   {
      year=line.mid(23,4);
      month=line.mid(28,2);
      day=line.mid(31,2);
   }
   hour=line.mid(35,2);
   minute=line.mid(38,2);
   //kdDebug(7101)<<"Floppy::createUDSEntry() day: -"<<day<<"-"<<month<<"-"<<year<<"- -"<<hour<<"-"<<minute<<"-"<<endl;

   if (name.isEmpty())
   {
      info.isValid=false;
      return info;
   }

   info.name=name;
   info.size=size.toInt();

   QDateTime date(QDate(year.toInt(),month.toInt(),day.toInt()),QTime(hour.toInt(),minute.toInt()));
   info.time=beginningOfTimes.secsTo(date);

   if (isDir)
      info.mode = S_IRUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH| S_IWOTH|S_IWGRP|S_IWUSR  ;
   else
      info.mode = S_IRUSR | S_IRGRP | S_IROTH| S_IWOTH|S_IWGRP|S_IWUSR;

   info.isDir=isDir;

   info.isValid=true;
   //kdDebug(7101)<<"Floppy::createUDSEntry() ends"<<endl;
   return info;
}

StatInfo FloppyProtocol::_stat(const KURL& url)
{
   StatInfo info;

   QString path(url.path());
   QString drive;
   QString floppyPath;
   getDriveAndPath(path,drive,floppyPath);

   if (floppyPath.isEmpty())
   {
      kdDebug(7101)<<"Floppy::_stat(): floppyPath.isEmpty()"<<endl;
      info.name=path;
      info.size=1024;
      info.time=0;
      info.mode=S_IRUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH| S_IWOTH|S_IWGRP|S_IWUSR;
      info.isDir=true;
      info.isValid=true;

      return info;
   }

   //kdDebug(7101)<<"Floppy::_stat(): delete m_mtool"<<endl;
   if (m_mtool!=0)
      delete m_mtool;

   QStringList args;
   args<<"mdir"<<"-a"<<(drive+floppyPath);

   //kdDebug(7101)<<"Floppy::_stat(): create m_mtool"<<endl;
   m_mtool=new Program(args);

   if (!m_mtool->start())
   {
      delete m_mtool;
      m_mtool=0;
      errorMissingMToolsProgram("mdir");
      return info;
   }


   clearBuffers();

   int result;
   bool loopFinished(false);
   bool errorOccured(false);
   do
   {
      bool stdoutEvent;
      bool stderrEvent;
      result=m_mtool->select(1,0,stdoutEvent, stderrEvent);
      if (stdoutEvent)
         if (readStdout()==0)
            loopFinished=true;
      if (stderrEvent)
      {
         if (readStderr()==0)
            loopFinished=true;
         else
            if (stopAfterError(url,drive))
            {
               loopFinished=true;
               errorOccured=true;
            }
      }
   } while (!loopFinished);

   //kdDebug(7101)<<"Floppy::_stat(): delete m_mtool"<<endl;
   delete m_mtool;
   m_mtool=0;
   //now mdir has finished
   //let's parse the output
   terminateBuffers();

   if (errorOccured)
   {
      info.isValid=false;
      return info;
   }

   if (m_stdoutSize==0)
   {
      info.isValid=false;
      error( KIO::ERR_COULD_NOT_STAT, url.prettyURL());
      return info;
   }

   kdDebug(7101)<<"Floppy::_stat(): parse stuff"<<endl;
   QString outputString(m_stdoutBuffer);
   QTextIStream output(&outputString);
   QString line;
   for (int lineNumber=0; !output.atEnd(); lineNumber++)
   {
      line=output.readLine();
      if ( (lineNumber<3) || (line.isEmpty()) )
         continue;
      StatInfo info=createStatInfo(line,true,url.fileName());
      if (info.isValid==false)
         error( KIO::ERR_COULD_NOT_STAT, url.prettyURL());
      return info;
   }
   if (info.isValid==false)
      error( KIO::ERR_COULD_NOT_STAT, url.prettyURL());
   return info;
}

int FloppyProtocol::freeSpace(const KURL& url)
{
   QString path(url.path());
   QString drive;
   QString floppyPath;
   getDriveAndPath(path,drive,floppyPath);

   //kdDebug(7101)<<"Floppy::freeSpace(): delete m_mtool"<<endl;
   if (m_mtool!=0)
      delete m_mtool;

   QStringList args;
   args<<"mdir"<<"-a"<<drive;

   //kdDebug(7101)<<"Floppy::freeSpace(): create m_mtool"<<endl;
   m_mtool=new Program(args);

   if (!m_mtool->start())
   {
      delete m_mtool;
      m_mtool=0;
      errorMissingMToolsProgram("mdir");
      return -1;
   }


   clearBuffers();

   int result;
   bool loopFinished(false);
   bool errorOccured(false);
   do
   {
      bool stdoutEvent;
      bool stderrEvent;
      result=m_mtool->select(1,0,stdoutEvent, stderrEvent);
      if (stdoutEvent)
         if (readStdout()==0)
            loopFinished=true;
      if (stderrEvent)
      {
         if (readStderr()==0)
            loopFinished=true;
         else
            if (stopAfterError(url,drive))
            {
               loopFinished=true;
               errorOccured=true;
            }
      }
   } while (!loopFinished);

   //kdDebug(7101)<<"Floppy::freeSpace(): delete m_mtool"<<endl;
   delete m_mtool;
   m_mtool=0;
   //now mdir has finished
   //let's parse the output
   terminateBuffers();

   if (errorOccured)
   {
      return -1;
   }

   if (m_stdoutSize==0)
   {
      error( KIO::ERR_COULD_NOT_STAT, url.prettyURL());
      return -1;
   }

   kdDebug(7101)<<"Floppy::freeSpace(): parse stuff"<<endl;
   QString outputString(m_stdoutBuffer);
   QTextIStream output(&outputString);
   QString line;
   int lineNumber(0);
   while (!output.atEnd())
   {
      line=output.readLine();
      if (line.find("bytes free")==36)
      {
         QString tmp=line.mid(24,3);
         tmp=tmp.stripWhiteSpace();
         tmp+=line.mid(28,3);
         tmp=tmp.stripWhiteSpace();
         tmp+=line.mid(32,3);
         tmp=tmp.stripWhiteSpace();

         return tmp.toInt();
      }
      lineNumber++;
   }
   return -1;
}

void FloppyProtocol::stat( const KURL & _url)
{
   kdDebug(7101)<<"Floppy::stat() "<<_url.path()<<endl;
   KURL url(_url);
   QString path(url.path());

   if ((path.isEmpty()) || (path=="/"))
   {
      url.setPath("/a/");
      redirection(url);
      finished();
      return;
   }
   StatInfo info=this->_stat(url);
   if (info.isValid)
   {
      UDSEntry entry;
      createUDSEntry(info,entry);
      statEntry( entry );
      finished();
      //kdDebug(7101)<<"Floppy::stat(): ends"<<endl;
      return;
   }
   //otherwise the error() was already reported in _stat()
}

void FloppyProtocol::mkdir( const KURL& url, int)
{
   kdDebug(7101)<<"FloppyProtocol::mkdir()"<<endl;
   QString path(url.path());

   if ((path.isEmpty()) || (path=="/"))
   {
      KURL newUrl(url);
      newUrl.setPath("/a/");
      redirection(newUrl);
      finished();
      return;
   }
   QString drive;
   QString floppyPath;
   getDriveAndPath(path,drive,floppyPath);
   if (floppyPath.isEmpty())
   {
      finished();
      return;
   }
   if (m_mtool!=0)
      delete m_mtool;
   //kdDebug(7101)<<"Floppy::stat(): create args"<<endl;
   QStringList args;

   args<<"mmd"<<(drive+floppyPath);
   kdDebug(7101)<<"Floppy::mkdir(): executing: mmd -"<<(drive+floppyPath)<<"-"<<endl;

   m_mtool=new Program(args);
   if (!m_mtool->start())
   {
      delete m_mtool;
      m_mtool=0;
      errorMissingMToolsProgram("mmd");
      return;
   }


   clearBuffers();
   int result;
   bool loopFinished(false);
   bool errorOccured(false);
   do
   {
      bool stdoutEvent;
      bool stderrEvent;
      result=m_mtool->select(1,0,stdoutEvent, stderrEvent);
      if (stdoutEvent)
         if (readStdout()==0)
            loopFinished=true;
      if (stderrEvent)
      {
         if (readStderr()==0)
            loopFinished=true;
         else
            if (stopAfterError(url,drive))
            {
               loopFinished=true;
               errorOccured=true;
            }
      }
   } while (!loopFinished);

   delete m_mtool;
   m_mtool=0;
   terminateBuffers();
   if (errorOccured)
      return;
   finished();
}

void FloppyProtocol::del( const KURL& url, bool isfile)
{
   kdDebug(7101)<<"FloppyProtocol::del()"<<endl;
   QString path(url.path());

   if ((path.isEmpty()) || (path=="/"))
   {
      KURL newUrl(url);
      newUrl.setPath("/a/");
      redirection(newUrl);
      finished();
      return;
   }
   QString drive;
   QString floppyPath;
   getDriveAndPath(path,drive,floppyPath);
   if (floppyPath.isEmpty())
   {
      finished();
      return;
   }

   if (m_mtool!=0)
      delete m_mtool;
   //kdDebug(7101)<<"Floppy::stat(): create args"<<endl;
   QStringList args;
   
   bool usingmdel;

   if (isfile)
   {
      args<<"mdel"<<(drive+floppyPath);
      usingmdel=true;
   }
   else
   {
      args<<"mrd"<<(drive+floppyPath);
      usingmdel=false;
   }

   kdDebug(7101)<<"Floppy::del(): executing: " << (usingmdel ? QString("mdel") : QString("mrd") ) << "-"<<(drive+floppyPath)<<"-"<<endl;

   m_mtool=new Program(args);
   if (!m_mtool->start())
   {
      delete m_mtool;
      m_mtool=0;
      errorMissingMToolsProgram(usingmdel ? QString("mdel") : QString("mrd"));
      return;
   }


   clearBuffers();
   int result;
   bool loopFinished(false);
   bool errorOccured(false);
   do
   {
      bool stdoutEvent;
      bool stderrEvent;
      result=m_mtool->select(1,0,stdoutEvent, stderrEvent);
      if (stdoutEvent)
         if (readStdout()==0)
            loopFinished=true;
      if (stderrEvent)
      {
         if (readStderr()==0)
            loopFinished=true;
         else
            if (stopAfterError(url,drive))
            {
               loopFinished=true;
               errorOccured=true;
            }
      }
   } while (!loopFinished);

   delete m_mtool;
   m_mtool=0;
   terminateBuffers();
   if (errorOccured)
      return;
   finished();
}

void FloppyProtocol::rename( const KURL &src, const KURL &dest, bool _overwrite )
{
   QString srcPath(src.path());
   QString destPath(dest.path());

   kdDebug(7101)<<"Floppy::rename() -"<<srcPath<<"- to -"<<destPath<<"-"<<endl;

   if ((srcPath.isEmpty()) || (srcPath=="/"))
      srcPath="/a/";

   if ((destPath.isEmpty()) || (destPath=="/"))
      destPath="/a/";

   QString srcDrive;
   QString srcFloppyPath;
   getDriveAndPath(srcPath,srcDrive,srcFloppyPath);
   if (srcFloppyPath.isEmpty())
   {
      finished();
      return;
   }

   QString destDrive;
   QString destFloppyPath;
   getDriveAndPath(destPath,destDrive,destFloppyPath);
   if (destFloppyPath.isEmpty())
   {
      finished();
      return;
   }

   if (m_mtool!=0)
      delete m_mtool;
   //kdDebug(7101)<<"Floppy::stat(): create args"<<endl;
   QStringList args;

   if (_overwrite)
      args<<"mren"<<"-o"<<(srcDrive+srcFloppyPath)<<(destDrive+destFloppyPath);
   else
      args<<"mren"<<"-D"<<"s"<<(srcDrive+srcFloppyPath)<<(destDrive+destFloppyPath);

   kdDebug(7101)<<"Floppy::move(): executing: mren -"<<(srcDrive+srcFloppyPath)<<"  "<<(destDrive+destFloppyPath)<<endl;

   m_mtool=new Program(args);
   if (!m_mtool->start())
   {
      delete m_mtool;
      m_mtool=0;
      errorMissingMToolsProgram("mren");
      return;
   }


   clearBuffers();
   int result;
   bool loopFinished(false);
   bool errorOccured(false);
   do
   {
      bool stdoutEvent;
      bool stderrEvent;
      result=m_mtool->select(1,0,stdoutEvent, stderrEvent);
      if (stdoutEvent)
         if (readStdout()==0)
            loopFinished=true;
      if (stderrEvent)
      {
         if (readStderr()==0)
            loopFinished=true;
         else
            if (stopAfterError(src,srcDrive))
            {
               loopFinished=true;
               errorOccured=true;
            }
      }
   } while (!loopFinished);

   delete m_mtool;
   m_mtool=0;
   terminateBuffers();
   if (errorOccured)
      return;
   finished();
}

void FloppyProtocol::get( const KURL& url )
{
   QString path(url.path());
   kdDebug(7101)<<"Floppy::get() -"<<path<<"-"<<endl;

   if ((path.isEmpty()) || (path=="/"))
   {
      KURL newUrl(url);
      newUrl.setPath("/a/");
      redirection(newUrl);
      finished();
      return;
   }
   StatInfo info=this->_stat(url);
   //the error was already reported in _stat()
   if (info.isValid==false)
      return;

   totalSize( info.size);

   QString drive;
   QString floppyPath;
   getDriveAndPath(path,drive,floppyPath);
   if (floppyPath.isEmpty())
   {
      finished();
      return;
   }

   if (m_mtool!=0)
      delete m_mtool;
   //kdDebug(7101)<<"Floppy::stat(): create args"<<endl;
   QStringList args;
   args<<"mcopy"<<(drive+floppyPath)<<"-";

   kdDebug(7101)<<"Floppy::get(): executing: mcopy -"<<(drive+floppyPath)<<"-"<<endl;

   m_mtool=new Program(args);
   if (!m_mtool->start())
   {
      delete m_mtool;
      m_mtool=0;
      errorMissingMToolsProgram("mcopy");
      return;
   }

   clearBuffers();
   int result;
   int bytesRead(0);
   QByteArray array;
   bool loopFinished(false);
   bool errorOccured(false);
   do
   {
      bool stdoutEvent;
      bool stderrEvent;
      result=m_mtool->select(1,0,stdoutEvent, stderrEvent);
      if (stdoutEvent)
      {
         delete [] m_stdoutBuffer;
         m_stdoutBuffer=0;
         m_stdoutSize=0;
         if (readStdout()>0)
         {
            kdDebug(7101)<<"Floppy::get(): m_stdoutSize:"<<m_stdoutSize<<endl;
            bytesRead+=m_stdoutSize;
            array.setRawData(m_stdoutBuffer, m_stdoutSize);
            data( array );
            array.resetRawData(m_stdoutBuffer, m_stdoutSize);

         }
         else
         {
            loopFinished=true;
         }
      }
      if (stderrEvent)
      {
         if (readStderr()==0)
            loopFinished=true;
         else
            if (stopAfterError(url,drive))
            {
               errorOccured=true;
               loopFinished=true;
            }
      }
   } while (!loopFinished);

   //kdDebug(7101)<<"Floppy::get(): deleting m_mtool"<<endl;
   delete m_mtool;
   m_mtool=0;
   if (errorOccured)
      return;

   //kdDebug(7101)<<"Floppy::get(): finishing"<<endl;
   data( QByteArray() );
   finished();
}

void FloppyProtocol::put( const KURL& url, int , bool overwrite, bool )
{
   QString path(url.path());
   kdDebug(7101)<<"Floppy::put() -"<<path<<"-"<<endl;

   if ((path.isEmpty()) || (path=="/"))
   {
      KURL newUrl(url);
      newUrl.setPath("/a/");
      redirection(newUrl);
      finished();
      return;
   }
   QString drive;
   QString floppyPath;
   getDriveAndPath(path,drive,floppyPath);
   if (floppyPath.isEmpty())
   {
      finished();
      return;
   }
   int freeSpaceLeft=freeSpace(url);
   if (freeSpaceLeft==-1)
      return;

   if (m_mtool!=0)
      delete m_mtool;
   //kdDebug(7101)<<"Floppy::stat(): create args"<<endl;
   QStringList args;
   if (overwrite)
      args<<"mcopy"<<"-o"<<"-"<<(drive+floppyPath);
   else
      args<<"mcopy"<<"-s"<<"-"<<(drive+floppyPath);

   kdDebug(7101)<<"Floppy::put(): executing: mcopy -"<<(drive+floppyPath)<<"-"<<endl;

   m_mtool=new Program(args);
   if (!m_mtool->start())
   {
      delete m_mtool;
      m_mtool=0;
      errorMissingMToolsProgram("mcopy");
      return;
   }


   clearBuffers();
   int result(0);
   int bytesRead(0);
   QByteArray array;

   //from file.cc
   // Loop until we got 0 (end of data)
   do
   {
      bool stdoutEvent;
      bool stderrEvent;
      kdDebug(7101)<<"Floppy::put(): select()..."<<endl;
      m_mtool->select(0,100,stdoutEvent, stderrEvent);
      if (stdoutEvent)
      {
         if (readStdout()==0)
            result=0;
      }
      if (stderrEvent)
      {
         if (readStderr()==0)
            result=0;
         else
            if (stopAfterError(url,drive))
               result=-1;
         kdDebug(7101)<<"Floppy::put(): error: result=="<<result<<endl;
      }
      else
      {
         QByteArray buffer;
         dataReq(); // Request for data
         //kdDebug(7101)<<"Floppy::put(): after dataReq()"<<endl;
         result = readData( buffer );
         //kdDebug(7101)<<"Floppy::put(): after readData(), read "<<result<<" bytes"<<endl;
         if (result > 0)
         {
            bytesRead+=result;
            kdDebug(7101)<<"Floppy::put() bytesRead: "<<bytesRead<<" space: "<<freeSpaceLeft<<endl;
            if (bytesRead>freeSpaceLeft)
            {
               result=0;
               error( KIO::ERR_SLAVE_DEFINED, i18n("Could not write to file %1.\nThe disk in drive %2 is probably full.").arg(url.prettyURL(),drive));
            }
            else
            {
               //kdDebug(7101)<<"Floppy::put(): writing..."<<endl;
               result=::write(m_mtool->stdinFD(),buffer.data(), buffer.size());
               kdDebug(7101)<<"Floppy::put(): after write(), wrote "<<result<<" bytes"<<endl;
            }
         }
      }
   }
   while ( result > 0 );

   if (result<0)
   {
      perror("writing to stdin");
      error( KIO::ERR_CANNOT_OPEN_FOR_WRITING, url.prettyURL());
      return;
   }

   delete m_mtool;
   m_mtool=0;

   finished();
}


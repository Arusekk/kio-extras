// smb.cc adapted from file.cc !!!
// $Id$

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <sys/wait.h>

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#include <kio_rename_dlg.h>
#include <kio_skip_dlg.h>
#include <kurl.h>
#include <kprotocolmanager.h>
#include <qvaluelist.h>

#include "smb.h"
#include <sys/stat.h>

#include <iostream.h>

#include <qapplication.h>
#include <qlineedit.h>
#include <qlabel.h>
#include <qlayout.h>
#include <qdialog.h>
#include <qaccel.h>

#include <klocale.h>

#define BUF_SIZE 2048

// used to create a dialog
QApplication *QtApp;

// class adapted from passworddialog
class CallbackDialog : public QDialog
{
protected:
    QLineEdit *theLineEdit;

public:
	CallbackDialog( const char *text, bool echo=false, QWidget* parent=0, const char* name=0, bool modal=true, WFlags f=0 );
	const char *answer(); // the user answer
};

CallbackDialog::CallbackDialog( const char *text, bool echo, QWidget* parent, const char* name, bool modal, WFlags f )
   : QDialog(parent, name, modal, f)
{
	QVBoxLayout *vLay = new QVBoxLayout(this, 10 /* border */, 5);

	QLabel *l = new QLabel(text, this);
	
	l->adjustSize();
	l->setMinimumSize(l->size());
	vLay->addWidget(l);

	// The horizontal layout for label + lineedit
//	QHBoxLayout *hLay = new QHBoxLayout(5);
	
	
	theLineEdit = new QLineEdit( this );
	if (!echo) theLineEdit->setEchoMode( QLineEdit::Password );
	theLineEdit->adjustSize();
	theLineEdit->setFixedHeight(theLineEdit->height());
//	hLay->addWidget(theLineEdit,10);
	vLay->addWidget(theLineEdit,10);
//	vLay->addLayout(hLay);

	QAccel *ac = new QAccel(this);
	ac->connectItem( ac->insertItem(Key_Escape), this, SLOT(reject()) );
	connect( theLineEdit, SIGNAL(returnPressed()), SLOT(accept()) );
}

const char *CallbackDialog::answer() // the user answer
{
	if ( theLineEdit )
		return theLineEdit->text();
	else
		return 0;
}


// used by the lib to get info
// should display its argument and return an answer allocated with new.
char *getPasswordCallBack(const char * c)
{
	if (!c) return 0;
	QString s;
	bool echo=false;
	if (!strcmp(c,"User")) {
		s+=i18n("User");
		echo=true;
	}
	else if (!strcmp(c,"Password")) s+=i18n("Password");
	else if (!strncmp(c,"Password for service ",21)) {
		s+=i18n("Password for service ");
		s+=(c+21);
	}
	CallbackDialog d(s, echo);
	d.show();
	const char *rep=d.answer();
	char *ret=new char[strlen(rep)+1];
	strcpy(ret,rep);
	return ret;
}


// simple wrapper for KURL::decode
QString decode( const char *url );

int check( Connection *_con );
void sigchld_handler( int );
void sigsegv_handler( int );

int main( int argc, char **argv )
{
	signal(SIGCHLD, sigchld_handler);
	signal(SIGSEGV, sigsegv_handler);

	qDebug( "kio_smb : Starting");

	QtApp = new QApplication( argc, argv );

	Connection parent( 0, 1 );

	SmbProtocol smb( &parent );
	smb.dispatchLoop();

	qDebug( "kio_smb : Done" );
}


void sigsegv_handler( int )
{
  write(2, "kio_smb : SEGMENTATION FAULT\n", 29);
  exit(1);
}


void sigchld_handler( int )
{
  int pid, status;
    
  while( 1 ) {
    pid = waitpid( -1, &status, WNOHANG );
    if ( pid <= 0 ) {
      // Reinstall signal handler, since Linux resets to default after
      // the signal occured ( BSD handles it different, but it should do
      // no harm ).
      signal( SIGCHLD, sigchld_handler );
      return;
    }
  }
}


SmbProtocol::SmbProtocol( Connection *_conn ) : IOProtocol( _conn )
{
	smbio.setPasswordCallback(getPasswordCallBack);
}

SmbProtocol::~SmbProtocol()
{
	//qDebug( "kio_destructor : end" );
}


void SmbProtocol::slotCopy( QStringList& _source, const char *_dest )
{
	qDebug( "kio_smb : slotCopy <List> %s", _dest );
	doCopy( _source, _dest );
}


void SmbProtocol::slotCopy( const char* _source, const char *_dest )
{
	qDebug( "kio_smb : slotCopy %s %s", _source, _dest );
	QStringList lst;
	lst.append( _source );

	doCopy( lst, _dest );
}

void SmbProtocol::doCopy( QStringList& _source, const char *_dest )
{

	KURL udest( _dest );

	qDebug( "kio_smb : Making copy to %s", _dest );

	// Check wellformedness of the destination
	if ( udest.isMalformed() ) {
		error( ERR_MALFORMED_URL, _dest );
		return;
	}

	qDebug( "kio_smb : Dest ok %s", _dest );

	// Find IO server for destination
	QString exec = KProtocolManager::self().executable( udest.protocol() );
	if ( exec.isEmpty() ) {
		error( ERR_UNSUPPORTED_PROTOCOL, udest.protocol() );
		return;
	}

	// Is the left most protocol a filesystem protocol ?
	if ( KProtocolManager::self().outputType( udest.protocol() ) != KProtocolManager::T_FILESYSTEM ) {
		error( ERR_PROTOCOL_IS_NOT_A_FILESYSTEM, udest.protocol() );
		return;
	}
	qDebug( "kio_smb : IO server ok %s", _dest );

	// Check whether the URLs are wellformed
	QStringList::Iterator soit = _source.begin();
/*	for( ; soit != _source.end(); ++soit ) {
		qDebug( "kio_smb : Checking %s", soit->c_str() );
		char *workgroup=NULL, *host=NULL, *share=NULL, *file=NULL, *user=NULL;
		int result=smbio.parse(decode(soit->c_str()).ascii(), workgroup, host, share, file, user);
		if (workgroup) delete workgroup; workgroup=NULL;
		if (host) delete host; host=NULL;
		if (share) delete share; share=NULL;
		if (file) delete file; file=NULL;
		if (user) delete user; user=NULL;
		if (result==-1) {
			error( ERR_MALFORMED_URL, soit->c_str() );
			return;
		}
	}
*/
	qDebug( "kio_smb : All source URLs ok." );

	// Get a list of all source files and directories
	list<Copy> files;
	list<CopyDir> dirs;
	int size = 0;
	qDebug( "kio_smb : Iterating" );

	soit = _source.begin();
	qDebug( "kio_smb : Looping" );
	for( ; soit != _source.end(); ++soit ) {
		qDebug( "kio_smb : Looking up %s", (*soit).ascii() );
		KURL usrc( *soit );
		qDebug( "kio_smb : Parsed URL" );
		// Did an error occur ?
		int resSize;
		if ( ( resSize = listRecursive( usrc.url(), "", files, dirs) ) == -1 ) {
			// Error message is already sent
			return;
		}
		// Sum up the total amount of bytes we have to copy
		size += resSize;
	}

	qDebug( "kio_smb : Recursive check done, %d bytes", size);

	// Start a server for the destination protocol
	Slave slave( exec );
	if ( slave.pid() == -1 ) {
		error( ERR_CANNOT_LAUNCH_PROCESS, exec );
		return;
	}
  
	// Put a protocol on top of the job
	SmbIOJob job( &slave, this );

	qDebug( "kio_smb : Job started ok");

	// Tell our client what we 'r' gonna do
	totalSize( size );
	totalFiles( files.size() );
	totalDirs( dirs.size() );
  
	int processed_files = 0;
	int processed_dirs = 0;
	int processed_size = 0;
  
	// Replace the relative destinations with absolut destinations
	// by prepending the destinations path
	QString tmp1 = udest.path( 1 ); // with trailing /
	list<CopyDir>::iterator dit = dirs.begin();
	for( ; dit != dirs.end(); dit++ ) dit->relDest = tmp1 + dit->relDest;
	list<Copy>::iterator fit = files.begin();
	for( ; fit != files.end(); fit++ ) fit->relDest = tmp1 + fit->relDest;

	qDebug( "kio_smb : Destinations ok %s", _dest );

	/*****
	* Make directories
	*****/

	bool overwrite_all = false;
	bool auto_skip = false;
	static QStringList skip_list, overwrite_list;
	skip_list.clear(); overwrite_list.clear();
	// Create all directories
	dit = dirs.begin();
	for( ; dit != dirs.end(); dit++ ) {
		// Repeat until we got no error
		do {
			job.clearError();

			KURL ud( _dest );
			ud.setPath( dit->relDest );
			QString d = ud.url();

			// Is this URL on the skip list ?
			bool skip = false;
			QStringList::Iterator sit = skip_list.begin();
			for( ; sit != skip_list.end() && !skip; sit++ )
			// Is d a subdirectory of *sit ?
			if ( strncmp( *sit, d, sit->length() ) == 0 )
				skip = true;
			if ( skip ) continue;

			// Is this URL on the overwrite list ?
			bool overwrite = false;
			QStringList::Iterator oit = overwrite_list.begin();
			for( ; oit != overwrite_list.end() && !overwrite; oit++ )
			if ( strncmp( *oit, d, oit->length() ) == 0 ) overwrite = true;
			if ( overwrite ) continue;

			// Tell what we are doing
			makingDir( d );

			qDebug( "kio_smb : Making remote dir %s", d.ascii() );
			// Create the directory
			job.mkdir( d, dit->mode );
			while( !job.hasFinished() )
			job.dispatch();

			// Did we have an error ?
			if ( job.hasError() ) {
				// Can we prompt the user and ask for a solution ?
				if ( job.errorId() == ERR_DOES_ALREADY_EXIST ) {
					static QString old_path = ud.path( 1 );
					static QString old_url = ud.url( 1 );
					// Should we skip automatically ?
					if ( auto_skip ) {
						job.clearError();
						// We dont want to copy files in this directory, so we put it on the skip list.
						skip_list.append( ud.url(1) );
						continue;
					} else if ( overwrite_all ) {
						job.clearError();
						continue;
					}

					RenameDlg_Mode m = (RenameDlg_Mode)( M_MULTI | M_SKIP | M_OVERWRITE );
					QString tmp2 = ud.url();
					static QString n;
					RenameDlg_Result r = open_RenameDlg( dit->absSource, tmp2, m, n );
					if ( r == R_CANCEL ) {
						error( ERR_USER_CANCELED, "" );
						return;
					} else if ( r == R_RENAME ) {
						KURL u( n );
						// The Dialog should have checked this.
						if ( u.isMalformed() )
						assert( 0 );
						// The new path with trailing '/'
						QString tmp3 = u.path( 1 );
						renamed( tmp3 );
						///////
						// Replace old path with tmp3
						///////
						list<CopyDir>::iterator dit2 = dit;
						// Change the current one and strip the trailing '/'
						dit2->relDest = u.path( -1 );
						// Change the name of all subdirectories
						dit2++;
						for( ; dit2 != dirs.end(); dit2++ )
							if ( strncmp( dit2->relDest, old_path, old_path.length() ) == 0 )
								dit2->relDest.replace( 0, old_path.length(), tmp3 );
						// Change all filenames
						list<Copy>::iterator fit2 = files.begin();
						for( ; fit2 != files.end(); fit2++ )
							if ( strncmp( fit2->relDest, old_path, old_path.length() ) == 0 )
								fit2->relDest.replace( 0, old_path.length(), tmp3 );
						// Don't clear error => we will repeat the current command
					} else if ( r == R_SKIP ) {
						// Skip all files and directories that start with 'old_url'
						skip_list.append( old_url );
						// Clear the error => The current command is not repeated => skipped
						job.clearError();
					} else if ( r == R_AUTO_SKIP ) {
						// Skip all files and directories that start with 'old_url'
						skip_list.append( old_url );
						// Clear the error => The current command is not repeated => skipped
						job.clearError();
						auto_skip = true;
					} else if ( r == R_OVERWRITE ) {
						// Dont bother for subdirectories
						overwrite_list.append( old_url );
						// Clear the error => The current command is not repeated => we will
						// overwrite every file in this directory or any of its subdirectories
						job.clearError();
					} else if ( r == R_OVERWRITE_ALL ) {
						job.clearError();
						overwrite_all = true;
					} else
						assert( 0 );
				}
				// No need to ask the user, so raise an error
				else {
					error( job.errorId(), job.errorText() );
					return;
				}
			}
		}
    	while( job.hasError() );
      
		processedDirs( ++processed_dirs );
	}

	qDebug( "kio_smb : Created directories %s", _dest );

	/*****
	* Copy files
	*****/

	time_t t_start = time( 0L );
	time_t t_last = t_start;

	fit = files.begin();
	for( ; fit != files.end(); fit++ ) {

		bool overwrite = false;
		bool skip_copying = false;

		// Repeat until we got no error
		do {
			job.clearError();

			KURL ud( _dest );
			ud.setPath( fit->relDest );
			QString d = ud.url();

			// Is this URL on the skip list ?
			bool skip = false;
			QStringList::Iterator sit = skip_list.begin();
			for( ; sit != skip_list.end() && !skip; sit++ )
			// Is 'd' a file in directory '*sit' or one of its subdirectories ?
			if ( strncmp( *sit, d, sit->length() ) == 0 )
				skip = true;

			if ( skip ) continue;
    
			// What we are doing
			QString realpath = fit->absSource;
			copyingFile( realpath, d );
    
			qDebug( "kio_smb : Writing to %s", d.ascii() );

			// Is this URL on the overwrite list ?
			QStringList::Iterator oit = overwrite_list.begin();
			for( ; oit != overwrite_list.end() && !overwrite; oit++ )
				if ( strncmp( *oit, d, oit->length() ) == 0 )
					overwrite = true;

			job.put( d, fit->mode, overwrite_all || overwrite, false, fit->size );

			while( !job.isReady() && !job.hasFinished() )
				job.dispatch();

			// Did we have an error ?
			if ( job.hasError() ) {
				int currentError = job.errorId();

				qDebug("################# COULD NOT PUT %d", currentError);
				if ( currentError != ERR_DOES_ALREADY_EXIST &&
							currentError != ERR_DOES_ALREADY_EXIST_FULL )
				{
					// Should we skip automatically ?
					if ( auto_skip ) {
						job.clearError();
						skip_copying = true;
						continue;
					}
					QString tmp2 = ud.url();
					SkipDlg_Result r;
					r = open_SkipDlg( tmp2, ( files.size() > 1 ) );
					if ( r == S_CANCEL ) {
						error( ERR_USER_CANCELED, "" );
						return;
					} else if ( r == S_SKIP ) {
						// Clear the error => The current command is not repeated => skipped
						job.clearError();
						skip_copying = true;
						continue;
					} else if ( r == S_AUTO_SKIP ) {
						// Clear the error => The current command is not repeated => skipped
						job.clearError();
						skip_copying = true;
						continue;
					} else
						assert( 0 );
				}
				// Can we prompt the user and ask for a solution ?
				else if ( /* m_bGUI && */ currentError == ERR_DOES_ALREADY_EXIST ||
							currentError == ERR_DOES_ALREADY_EXIST_FULL )
				{
					// Should we skip automatically ?
					if ( auto_skip ) {
						job.clearError();
						continue;
					}

					RenameDlg_Mode m = (RenameDlg_Mode)( M_SINGLE | M_OVERWRITE );
					if ( files.size() > 1 )
						m = (RenameDlg_Mode)( M_MULTI | M_SKIP | M_OVERWRITE );

					QString tmp2 = ud.url().data();
					QString n;
					RenameDlg_Result r = open_RenameDlg( fit->absSource, tmp2, m, n );

					if ( r == R_CANCEL ) {
						error( ERR_USER_CANCELED, "" );
						return;
					} else if ( r == R_RENAME ) {
						KURL u( n );
						// The Dialog should have checked this.
						if ( u.isMalformed() )
							assert( 0 );
						renamed( u.path( -1 ) );
						// Change the destination name of the current file
						fit->relDest = u.path( -1 );
						// Dont clear error => we will repeat the current command
					} else if ( r == R_SKIP ) {
						// Clear the error => The current command is not repeated => skipped
						job.clearError();
					} else if ( r == R_AUTO_SKIP ) {
						// Clear the error => The current command is not repeated => skipped
						job.clearError();
						auto_skip = true;
					} else if ( r == R_OVERWRITE ) {
						overwrite = true;
						// Dont clear error => we will repeat the current command
					} else if ( r == R_OVERWRITE_ALL )  {
						overwrite_all = true;
						// Dont clear error => we will repeat the current command
					} else
						assert( 0 );
				}
				// No need to ask the user, so raise an error
				else {
					error( currentError, job.errorText() );
					return;
				}
			}
		}
		while( job.hasError() );

		if ( skip_copying ) continue;

		qDebug( "kio_smb : Opening %s", fit->absSource.ascii() );

		int fd = smbio.open( decode(fit->absSource.ascii()).ascii() );
		if ( fd == -1 ) {
			error( ERR_CANNOT_OPEN_FOR_READING, fit->absSource );
			return;
		}

		// You can use any buffer size
		char buffer[ BUF_SIZE*2 ];
		int count;
		do {
			count=smbio.read(fd, buffer, sizeof(buffer));
			if (count==-1) {
				error( ERR_COULD_NOT_READ, fit->absSource );
				return;
			}
			if (count==0) break;
			job.data( buffer, count );
			processed_size += count;

			time_t t = time( 0L );
			if ( t - t_last >= 1 ) {
				processedSize( processed_size );
				speed( processed_size / ( t - t_start ) );
				t_last = t;
			}

			// Check parent
			while ( check( connection() ) )
				dispatch();
			// Check for error messages from slave
			while ( check( &slave ) )
				job.dispatch();

			// An error ?
			if ( job.hasFinished() ) {
				smbio.close( fd );
				finished();
				return;
			}

		} while (count>0);


		job.dataEnd();
		
		smbio.close( fd );

		while( !job.hasFinished() )
			job.dispatch();

		time_t t = time( 0L );

		processedSize( processed_size );
		if ( t - t_start >= 1 ) {
			speed( processed_size / ( t - t_start ) );
			t_last = t;
		}
		processedFiles( ++processed_files );
	}

	qDebug( "kio_smb : Copied files %s", _dest );

	finished();
}

  
void SmbProtocol::slotGet( const char *_url )
{
	qDebug( "kio_smb : slotGet %s", _url );

	KURL usrc( _url );
	if ( usrc.isMalformed() ) {
		error( ERR_MALFORMED_URL, strdup(_url) );
		return;
	}
/*	char *workgroup=NULL, *host=NULL, *share=NULL, *file=NULL, *user=NULL;
	int result=smbio.parse(decode(_url).ascii(), workgroup, host, share, file, user);
	if (workgroup) delete workgroup; workgroup=NULL;
	if (host) delete host; host=NULL;
	if (share) delete share; share=NULL;
	if (file) delete file; file=NULL;
	if (user) delete user; user=NULL;
	if (result==-1) {
		error( ERR_MALFORMED_URL, url.c_str() );
		return;
	}*/

	struct stat buff;
	if ( smbio.stat( decode(strdup(_url)).ascii(), &buff ) == -1 ) {
		error( ERR_DOES_NOT_EXIST, strdup(_url) );
		return;
	}

	if ( S_ISDIR( buff.st_mode ) ) {
		error( ERR_IS_DIRECTORY, strdup(_url) );
		return;
	}
	qDebug( "kio_smb : Get, checkpoint 3" );

	int fd = smbio.open( decode(strdup(_url)).ascii() , O_RDONLY);
	if ( fd == -1 ) {
		error( ERR_CANNOT_OPEN_FOR_READING, strdup(_url) );
		return;
	}

	ready();

	gettingFile( _url );

	totalSize( buff.st_size );
	int processed_size = 0;
	time_t t_start = time( 0L );
	time_t t_last = t_start;

	// smblib accepts any buffer size, but there was a comment in
	// a kioslave saying that >2048 introduced problems for ioslaves
	// I should really investigate...
	char buffer[BUF_SIZE];
	int count;
	do {
		count=smbio.read(fd, buffer, sizeof(buffer));
		if (count==-1) {
			error( ERR_COULD_NOT_READ, strdup(_url) );
			return;
		}
		if (count==0) break;
		data( buffer, count );
		processed_size += count;

		time_t t = time( 0L );
		if ( t - t_last >= 1 ) {
			processedSize( processed_size );
			speed( processed_size / ( t - t_start ) );
			t_last = t;
		}

	} while (count>0);
	qDebug( "kio_smb : Get, checkpoint 4" );

	dataEnd();
  
	smbio.close( fd );

	processedSize( buff.st_size );
	time_t t = time( 0L );
	if ( t - t_start >= 1 )
		speed( processed_size / ( t - t_start ) );

	finished();
}


void SmbProtocol::slotGetSize( const char *_url )
{
	qDebug( "kio_smb : Getting size" );
	
	KURL usrc( _url );
	if ( usrc.isMalformed() ) {
		error( ERR_MALFORMED_URL, strdup(_url) );
		return;
	}
/*	char *workgroup=NULL, *host=NULL, *share=NULL, *file=NULL, *user=NULL;
	int result=smbio.parse(decode(_url).ascii(), workgroup, host, share, file, user);
	if (workgroup) delete workgroup; workgroup=NULL;
	if (host) delete host; host=NULL;
	if (share) delete share; share=NULL;
	if (file) delete file; file=NULL;
	if (user) delete user; user=NULL;
	if (result==-1) {
		error( ERR_MALFORMED_URL, strdup(_url) );
		return;
	}*/

	qDebug( "kio_smb : Getting size, url OK" );
	struct stat buff;
	if ( smbio.stat( decode(strdup(_url)).ascii(), &buff ) == -1 ) {
		error( ERR_DOES_NOT_EXIST, strdup(_url) );
		return;
	}

	if ( S_ISDIR( buff.st_mode ) )  { // !!! needed ?
		error( ERR_IS_DIRECTORY, strdup(_url) );
		return;
	}

	totalSize( buff.st_size );

	finished();
	qDebug( "kio_smb : Getting size, end" );
}


void SmbProtocol::slotListDir( const char *_url )
{
	qDebug( "kio_smb : listDir 1 %s", _url);
	
	KURL usrc( _url );
	if ( usrc.isMalformed() ) {
		error( ERR_MALFORMED_URL, strdup(_url) );
		return;
	}
	qDebug( "kio_smb : listDir 2 %s", _url);
/*	char *workgroup=NULL, *host=NULL, *share=NULL, *file=NULL, *user=NULL;
	int result=smbio.parse(decode(_url).ascii(), workgroup, host, share, file, user);
	if (workgroup) delete workgroup; workgroup=NULL;
	if (host) delete host; host=NULL;
	if (share) delete share; share=NULL;
	if (file) delete file; file=NULL;
	if (user) delete user; user=NULL;
	if (result==-1) {
		error( ERR_MALFORMED_URL, strdup(_url) );
		return;
	}*/
	qDebug( "kio_smb : listDir 3 %s", _url);

	struct stat buff;
	if ( smbio.stat( decode(_url).ascii(), &buff ) == -1 ) {
		error( ERR_DOES_NOT_EXIST, strdup(_url) );
		return;
	}

	if ( !S_ISDIR( buff.st_mode ) ) {
		error( ERR_IS_FILE, strdup(_url) );
		return;
	}

	struct SMBdirent *ep;
	int dp = smbio.opendir( decode(strdup(_url)).ascii() );
	if ( dp == -1 ) {
		error( ERR_CANNOT_ENTER_DIRECTORY, strdup(_url) );
		return;
	}

	while ( ( ep = smbio.readdir( dp ) ) != 0L ) {
		if ( strcmp( ep->d_name, "." ) == 0 || strcmp( ep->d_name, ".." ) == 0 )
		continue;

		qDebug( "kio_smb : Listing %s", ep->d_name );

		UDSEntry entry;
		UDSAtom atom;
		atom.m_uds = UDS_NAME;
		atom.m_str = ep->d_name;
		entry.push_back( atom );

		atom.m_uds = UDS_FILE_TYPE;
		atom.m_long = ep->st_mode;
		entry.push_back( atom );
		atom.m_uds = UDS_SIZE;
		atom.m_long = ep->st_size;
		entry.push_back( atom );
		atom.m_uds = UDS_MODIFICATION_TIME;
		atom.m_long = ep->st_mtime;
		entry.push_back( atom );
		atom.m_uds = UDS_ACCESS;
		atom.m_long = ep->st_mode;
		entry.push_back( atom );
		atom.m_uds = UDS_ACCESS_TIME;
		atom.m_long = ep->st_atime;
		entry.push_back( atom );
		atom.m_uds = UDS_CREATION_TIME;
		atom.m_long = ep->st_ctime;
		entry.push_back( atom );

		listEntry( entry );
	}

	smbio.closedir( dp );

	finished();
}


void SmbProtocol::slotTestDir( const char *_url )
{
	qDebug( "kio_smb : testing %s", _url );
	
	KURL usrc( _url );
	if ( usrc.isMalformed() ) {
		error( ERR_MALFORMED_URL, strdup(_url) );
		return;
	}
/*	qDebug( "kio_smb : testing %s, kurl OK", decode(_url).ascii() );
	char *workgroup=NULL, *host=NULL, *share=NULL, *file=NULL, *user=NULL;
	int result=smbio.parse(decode(_url).ascii(), workgroup, host, share, file, user);
	if (workgroup) delete workgroup; workgroup=NULL;
	if (host) delete host; host=NULL;
	if (share) delete share; share=NULL;
	if (file) delete file; file=NULL;
	if (user) delete user; user=NULL;
	if (result==-1) {
		error( ERR_MALFORMED_URL, url.c_str() );
		return;
	}*/
	qDebug( "kio_smb : testing %s, smburl OK", decode(_url).ascii() );

	struct stat buff;
	if ( smbio.stat( decode(strdup(_url)).ascii(), &buff ) == -1 ) {
		error( ERR_DOES_NOT_EXIST, strdup(_url) );
		return;
	}

	if ( S_ISDIR( buff.st_mode ) )
		isDirectory();
	else
		isFile();

	finished();
	qDebug( "kio_smb : testing %s, end", _url );
}


long SmbProtocol::listRecursive( const char *smbURL, const char *dest, list<Copy>& _files, list<CopyDir>& _dirs, bool dirChecked)
{
	KURL u(dest);
	if (!dirChecked) {
		struct stat statBuf;
		if (smbio.stat(decode(smbURL).ascii(),&statBuf)==-1) return -1;

		if ( !S_ISDIR(statBuf.st_mode) ) {
			Copy c;
			c.absSource = smbURL;
			c.relDest = dest + u.filename();
			qDebug( "kio_smb : dest file name : %s", c.relDest.ascii());
			if ( c.relDest.isEmpty() ) return -1;
			c.mode = statBuf.st_mode;
			c.size = statBuf.st_size;
			_files.push_back( c );
			return statBuf.st_size;
		}
	}

	int dd=smbio.opendir(decode(smbURL).ascii());
	if (dd==-1) {
		qDebug( "kio_smb : %s should have been a valid directory!", smbURL);
		return -1;
	}
	
	CopyDir c;
	c.absSource = smbURL;
	c.relDest = dest;
	c.mode = 04755; //statBuf.st_mode;
	_dirs.push_back( c );

	SMBdirent *dent;
	long totalSize=0;
	// I don't know about QStr(ing)List compatibility
	QStringList newDirs;  // this will do fine and won't bloat memory
	
	// First add all files in this dir. We'll do directories later, so
	// that the connection to the SMB server isn't broken.
	while ((dent=smbio.readdir(dd))) {
		QString newName = dent->d_name;
		if ( !S_ISDIR(dent->st_mode) ) {
			Copy c;
			c.absSource = smbURL + newName;
			c.relDest = dest + u.filename();
			qDebug( "kio_smb : dest file name : %s", c.relDest.ascii());
			if ( c.relDest.isEmpty() ) return -1;
			c.mode = dent->st_mode;
			c.size = dent->st_size;
			_files.push_back( c );
			totalSize+=dent->st_size;
		} else newDirs.append(dent->d_name);
	}
	smbio.closedir(dd);

	// Now we can go into each directory found recursively
	QStringList::Iterator ndit = newDirs.begin();
	for( ; ndit != newDirs.end(); ++ndit ) {
		QString ndName = (*ndit);
		QString newURL = smbURL + ("/" + ndName);
		QString newDest = dest + ("/" + ndName);
		int plus=listRecursive(newURL.ascii(), newDest.ascii(), _files, _dirs, true);
		if (plus == -1) {
			qDebug( "kio_smb : recursive copy error, aborting..." );
			return -1;
		}
		totalSize+=plus;
	}
	
	return totalSize;
}

void SmbProtocol::slotData( void *, int  )
{
}

void SmbProtocol::slotDataEnd()
{
}


void SmbProtocol::jobError( int _errid, const char *_txt )
{
    error( _errid, _txt );
}

/*************************************
 *
 * SmbIOJob
 *
 *************************************/

SmbIOJob::SmbIOJob( Connection *_conn, SmbProtocol *_Smb ) : IOJob( _conn )
{
  m_pSmb = _Smb;
}
  
void SmbIOJob::slotError( int _errid, const char *_txt )
{
  IOJob::slotError( _errid, _txt );
  m_pSmb->jobError( _errid, _txt );
}

// utility

int check( Connection *_con )
{
  int err;
  struct timeval tv;
  tv.tv_sec = 0;
  tv.tv_usec = 0;
  fd_set rfds;
  FD_ZERO( &rfds );
  FD_SET( _con->inFD(), &rfds );

again:
  if ( ( err = ::select( _con->inFD(), &rfds, 0L, 0L, &tv ) ) == -1 && errno == EINTR )
    goto again;

  // No error and something to read ?
  if ( err != -1 && err != 0 )
    return 1;

  return 0;
}

QString decode( const char *url )
{
	QString s=url;
	KURL::decode(s);
	return s;
}

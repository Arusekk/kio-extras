/***************************************************************************
                          klibssh.h  -  description
                             -------------------
    begin                : Tue Jul 31 2001
    copyright            : (C) 2001 by Lucas Fisher
    email                : ljfisher@iastate.edu
 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#ifndef KSSHPROCESS_H
#define KSSHPROCESS_H

#define KSSHPROC 7116

#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>

#include <qvaluelist.h>

#include <kdebug.h>

#include "process.h"

/************************
 * SSH Option
 *
 * SSH options are configured much like UDS entries.
 * Each option is assigned a constant and a string, bool,
 * or number is number is assigned based on the option.
 *
 */

class SshOpt {
public:
    Q_UINT32 opt;
    QString  str;
    Q_INT32  num;
    bool     boolean;
};

// we can do this like UDSAtomType (ORing the type with the name) because
// we have too many options for ssh
enum SshOptType {
  /* Request server to invoke subsystem. (str) */
  SSH_SUBSYSTEM,
  /* Connect to port on the server. (num) */
  SSH_PORT,
  /* Connect to host. (str) */
  SSH_HOST,
  /* connect using this username. (str) */
  SSH_USERNAME,
  /* connect using this password. (str) */
  SSH_PASSWD,
  /* connect using this version of the SSH protocol. num == 1 or 2 */
  SSH_PROTOCOL,
  /* whether to forward X11 connections. (boolean) */
  SSH_FORWARDX11,
  /* whether to do agent forwarding. (boolean) */
  SSH_FORWARDAGENT,
  /* use as escape character. 0 for none  (num) */
  SSH_ESCAPE_CHAR,
  /* command for ssh to perform once it is connected */
  SSH_COMMAND,
  /* Set ssh verbosity. This may be added multiple times. It may also cause KSSHProcess
   * to fail since we don't understand all the debug messages. */
  SSH_VERBOSE,
  /* Set a ssh option as one would find in the ssh_config file
   * The str member should be set to 'optName value' */
  SSH_OPTION,
  /* Set some other option not supported by KSSHProcess. The option should
   * be specified in the str member of SshOpt. */
  SSH_OTHER,
  SSH_OPT_MAX // always last
}; // that's all for now


typedef QValueList<SshOpt> SshOptList;
typedef QValueListIterator<SshOpt> SshOptListIterator;
typedef QValueListConstIterator<SshOpt> SshOptListConstIterator;

enum SshVersion {
    OPENSSH_2_9P1,
    OPENSSH_2_9P2,
    OPENSSH_2_9,   // if we don't find the previous 2.9 verisons use this
    OPENSSH,       // if we don't match any of the above, use the latest version
    SSH_3_0_0,
    SSH,
    SSH_VER_MAX    // always last
};

enum SshError {
    /* Cannot lauch ssh client */
    ERR_CANNOT_LAUNCH,
    /* Interaction with the ssh client failed. This happens when we can't
    find the password prompt or something similar */
    ERR_INTERACT,
    /* Arguments for both a remotely executed subsystem and command were provide.
       Only one or the other may be used */
    ERR_CMD_SUBSYS_CONFLICT,
    /* No password was supplied */
    ERR_NEED_PASSWD,
    /* No usename was supplied */
    ERR_NEED_USERNAME,
    /* Timed out waiting for a response from ssh or the server */
    ERR_TIMED_OUT,
    /* Internal error, probably from a system call */
    ERR_INTERNAL,
    /* ssh was disconnect from the host */
    ERR_DISCONNECTED,
    /* No ssh options have been set. Call setArgs() before calling connect. */
    ERR_NO_OPTIONS,
    /* A host key was received from an unknown host. 
     * Call connect() with the acceptHostKey argument to accept the key. */
    ERR_NEW_HOST_KEY,
    /* A host key different from what is stored in the user's known_hosts file
     * has be received. This is an indication of an attack*/
    ERR_DIFF_HOST_KEY,
    /* An invalid option was found in the SSH option list */
    ERR_INVALID_OPT,
    ERR_MAX
};



/********************
 * Provides easy and version independent access to ssh.
 * @author Lucas Fisher
 */

class KSSHProcess {
public: 
	KSSHProcess();
    KSSHProcess(QString pathToSsh);
	~KSSHProcess();
    QString version();
    int error(QString& msg);
    int error() { return mError; }
    void kill(int signal = SIGTERM);
    void printArgs();
    bool setArgs(const SshOptList& opts);
    bool connect(bool acceptHostKey = false);
private:
    QString mSshPath;
    int mVersion;
    QString mPassword;
    QString mUsername;
    QString mHost;
    bool mConnected;
    int mPort;
    int mError;
    QString mErrorMsg;
    MyPtyProcess ssh;
    QCStringList mArgs;
    void init();

    static const char * const versionStrs[];
    static const char * const passwdPrompt[];
    static const char * const authFailedPrompt[];
    static const char * const hostKeyMissing[];
    static const char * const hostKeyChanged[];
    static const char * const continuePrompt[];
};

#endif

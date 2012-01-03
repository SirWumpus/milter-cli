/*
 * milter-cli.c
 *
 * Copyright 2003, 2009 by Anthony Howe. All rights reserved.
 *
 * The following should be added to the sendmail.mc file:
 *
 *	INPUT_MAIL_FILTER(
 *		`milter-cgi',
 *		`S=unix:/var/lib/milter-cli/socket, T=S:10s;R:10s'
 *	)dnl
 *
 * $OpenBSD$
 */

/***********************************************************************
 *** Leave this header alone. Its generate from the configure script.
 ***********************************************************************/

#include "config.h"

/***********************************************************************
 *** You can change the stuff below if the configure script doesn't work.
 ***********************************************************************/

#ifndef RUN_AS_USER
#define RUN_AS_USER			"milter"
#endif

#ifndef RUN_AS_GROUP
#define RUN_AS_GROUP			"milter"
#endif

#ifndef MILTER_CF
#define MILTER_CF			"/etc/mail/" MILTER_NAME ".cf"
#endif

#ifndef PID_FILE
#define PID_FILE			"/var/run/milter/" MILTER_NAME ".pid"
#endif

#ifndef SOCKET_FILE
#define SOCKET_FILE			"/var/run/milter/" MILTER_NAME ".socket"
#endif

#ifndef WORK_DIR
#define WORK_DIR			"/var/tmp"
#endif

#ifndef SENDMAIL_CF
#define SENDMAIL_CF			"/etc/mail/sendmail.cf"
#endif

#ifndef SAFE_PATH
#define SAFE_PATH			"/bin:/usr/bin"
#endif

/***********************************************************************
 *** No configuration below this point.
 ***********************************************************************/

/* Re-assert this macro just in case. May cause a compiler warning. */
#define _REENTRANT	1

#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/stat.h>
#include <netdb.h>
#include <sys/wait.h>
#include <sysexits.h>

#include <com/snert/lib/version.h>

#ifdef HAVE_FCNTL_H
# include <fcntl.h>
#endif
#ifdef HAVE_SYS_RESOURCE_H
# include <sys/resource.h>
#endif
#ifdef HAVE_POLL_H
# include <poll.h>
# ifndef INFTIM
#  define INFTIM	(-1)
# endif
#endif

#include <com/snert/lib/sys/Time.h>
#include <com/snert/lib/mail/limits.h>
#include <com/snert/lib/mail/smf.h>
#include <com/snert/lib/mail/smdb.h>
#include <com/snert/lib/type/Vector.h>
#include <com/snert/lib/util/Buf.h>
#include <com/snert/lib/util/Text.h>
#include <com/snert/lib/util/getopt.h>
#include <com/snert/lib/util/Token.h>

#if LIBSNERT_MAJOR < 1 || LIBSNERT_MINOR < 75
# error "LibSnert 1.75.8 or better is required"
#endif

#ifndef HAVE_SMFI_SETMLREPLY
# error "smfi_setmlreply() is missing. Please install a newer version of libmilter from sendmail 8.13 or better."
#endif

#ifdef MILTER_BUILD_STRING
# define MILTER_STRING	MILTER_NAME "/" MILTER_VERSION "." MILTER_BUILD_STRING
#else
# define MILTER_STRING	MILTER_NAME "/" MILTER_VERSION
#endif

/***********************************************************************
 *** Constants
 ***********************************************************************/

#define MAX_REPORT		32

#define NO_CHILD		((pid_t) 0)
#define CHILD_INPUT(d)		(d)->childIn[1]
#define CHILD_OUTPUT(d)		(d)->childOut[0]

#define CHILD_ACCEPT		0
#define CHILD_TEMPFAIL		1
#define CHILD_REJECT		2
#define CHILD_DISCARD		3
#define CHILD_TAG		4
#define CHILD_BCC		5
#define CHILD_REDIRECT		6

#define	TAG_FORMAT		"%05d %s: "
#define	TAG_ARGS		data->work.cid, data->work.qid

#define X_SCANNED_BY		"X-Scanned-By"
#define X_MILTER_REPORT		"X-" MILTER_NAME "-Report"
#define X_ORIGINAL_RECIPIENT	"X-Original-Recipient"

/***********************************************************************
 *** Global Variables
 ***********************************************************************/

typedef struct {
	char *commandLine;
	char *basename;
	char **argv;
	int argc;
} command;

typedef struct {
	int status;
	Vector report;
	command *command;
} cmdResult;

typedef struct {
	smfWork work;
	int hasReport;				/* per message */
	int hasSubject;				/* per message */
	pid_t child;				/* per message */
	int childIn[2];				/* per message */
	int childOut[2];			/* per message */
	Vector rcpts;				/* per message */
	cmdResult content;			/* per message */
	cmdResult envelope;			/* per message */
	long chunksSent;			/* per message */
	char helo[SMTP_DOMAIN_LENGTH+1];	/* per connection */
	char line[SMTP_TEXT_LINE_LENGTH+1];	/* general purpose */
	char subject[SMTP_TEXT_LINE_LENGTH+1];	/* per message */
	char client_name[SMTP_DOMAIN_LENGTH+1];	/* per connection */
	char client_addr[IPV6_TAG_LENGTH+IPV6_STRING_LENGTH];	/* per connection */
} *workspace;

static char *command_env[] = { "PATH=" SAFE_PATH, NULL };
static char *x_milter_report = X_MILTER_REPORT;
static char *accessConnect = MILTER_NAME "-connect:";
static char *accessAuth = MILTER_NAME "-auth:";
static char *accessFrom = MILTER_NAME "-from:";
static char *accessTo = MILTER_NAME "-to:";

#if defined(OPEN_MAX)
static unsigned long max_open_files = OPEN_MAX;
#elif defined(_POSIX_OPEN_MAX)
static unsigned long max_open_files = _POSIX_OPEN_MAX;
#else
static unsigned long max_open_files = 16;
#endif

static command cmdContent;
static command cmdEnvelope;

static Option optIntro		= { "",	NULL, "\n# " MILTER_NAME "/" MILTER_VERSION "." MILTER_BUILD_STRING "\n#\n# " MILTER_COPYRIGHT "\n#\n" };
static Option optContentFilter	= { "content-filter",	"",	"Command to filter message content." };
static Option optContentMaxSize	= { "content-max-size",	"64",	"Max. number of kilobytes of the message to process, 0 for unlimited." };
static Option optEnvelopeFilter	= { "envelope-filter",	"",	"Command to filter envelope details." };
static Option optFilterTimeout	= { "filter-timeout",	"30",	"The filter command I/O timeout in seconds." };
static Option optMilterId	= { "milter-id",	"",	"A milter instance ID string." };

#ifdef DROPPED_ADD_HEADERS
static Option optAddHeaders	= { "add-headers",	"-",	"Add extra informational headers when message passes." };
#endif

static Option *optTable[] = {
	&optIntro,
#ifdef DROPPED_ADD_HEADERS
	&optAddHeaders,
#endif
	&optContentFilter,
	&optContentMaxSize,
	&optEnvelopeFilter,
	&optFilterTimeout,
	&optMilterId,
	NULL
};

/***********************************************************************
 *** Routines
 ***********************************************************************/

static int
reaper(pid_t child)
{
	int status;

	while (waitpid(child, &status, 0) < 0 && errno == EINTR)
		;

	return status;
}

int
setNonBlocking(int fd, int flag)
{
	long flags;

	flags = (long) fcntl(fd, F_GETFL);

	if (flag)
		flags |= O_NONBLOCK;
	else
		flags &= ~O_NONBLOCK;

	return fcntl(fd, F_SETFL, flags);
}

int
hasInput(int fd, long timeout)
{
#if defined(HAVE_POLL)
	struct pollfd fds;

	fds.fd = fd;
	fds.events = POLLIN;
	if (timeout <= 0)
		timeout = INFTIM;

	do {
		errno = 0;
		fds.revents = 0;
		if (poll(&fds, 1, timeout) == 0)
			errno = ETIMEDOUT;
		else if ((fds.revents & (POLLHUP|POLLIN)) == POLLHUP)
			errno = EPIPE;
		else if (fds.revents & POLLERR)
			errno = EIO;
		else if (fds.revents & POLLNVAL)
			errno = EBADF;
	} while (errno == EINTR);

#elif defined(HAVE_SELECT)
	fd_set rdset, rdset2;
	struct timeval tv, tv2;

	FD_ZERO(&rdset2);
	FD_SET(fd, &rdset2);
	tv2.tv_sec = timeout / 1000L;
	tv2.tv_usec = (timeout % 1000L) * 1000L;

	do {
		tv = tv2;
		errno = 0;
		rdset = rdset2;
		if (select(fd + 1, &rdset, NULL, NULL, timeout <= 0 ? NULL : &tv) == 0)
			errno = ETIMEDOUT;
	} while (errno == EINTR);
#else
	errno = 0;
#endif
	return errno == 0;
}

static void
cmdInit(Option *option, command *cmd)
{
	if (cmd->commandLine == NULL || *cmd->commandLine == '\0') {
		cmd->commandLine = NULL;
		return;
	}

	if (TokenSplit(cmd->commandLine, NULL, &cmd->argv, &cmd->argc, 0)) {
		syslog(LOG_ERR, "error parsing %s='%s': %s (%d)", option->name, option->string, strerror(errno), errno);
		exit(1);
	}

	if ((cmd->basename = strrchr(cmd->argv[0], '/')) == NULL)
		cmd->basename = cmd->argv[0];
	cmd->basename++;
}

/*
 * A milter CLI script reads mail headers and message body from
 * standard input and may write to standard ouput a report.
 *
 * The script must exit with one of the following values:
 *
 *  0	accept the message, ignore standard output
 *
 *  1	tempfail the message, only the first 32 lines from
 *	standard output will be used for SMTP response
 *
 *  2	reject the message, only the first 32 lines from
 *	standard output will be used for SMTP response
 *
 *  3	discard the message, log standard output
 *
 *  4	tag subject with first line of output, subsequent
 *	output lines are added as a X-Milter-CLI-Report
 *	header.
 *
 *  5	copy message to addresses given by standard output
 *	one address per line
 *
 *  6	redirect message to addresses given by standard output
 *	one address per line
 *
 * ??	tempfail the message, ignore standard output
 *
 */
static int
cmdStart(workspace data, command *cmd)
{
	int fd;

	/* No commands */
	if (cmd->commandLine == NULL || cmd->argc <= 0)
		return -1;

	if (pipe(data->childIn))
		goto error0;

	if (pipe(data->childOut))
		goto error1;

	if ((data->child = fork()) == -1)
		goto error2;

	if (data->child == 0) {
		/* The Child */
		closelog();

		/* Redirect standard I/O for the child. */
		if (dup2(data->childIn[0], 0) < 0)
			_exit(10);

		if (dup2(data->childOut[1], 1) < 0)
			_exit(11);

		if (dup2(data->childOut[1], 2) < 0)
			_exit(12);

		/* Close all other file descriptors now. */
		for (fd = 3; fd < max_open_files; fd++)
			(void) close(fd);

		/* Do not allow the child to use seteuid() back to root. */
		(void) setuid(geteuid());

		/* Time for a change of scenery. */
		(void) execve(cmd->argv[0], cmd->argv, command_env);

		/* Exit without running atexit() routines. */
		_exit(EX_UNAVAILABLE);
	}

	/* The Parent */

	/* Close our copies of the child's standard I/O handles. */
	close(data->childIn[0]);
	close(data->childOut[1]);

	smfLog(SMF_LOG_INFO, TAG_FORMAT "started %s[%d] %s", TAG_ARGS, cmd->basename, data->child, cmd->commandLine);

	return 0;
error2:
	(void) close(data->childOut[0]);
	(void) close(data->childOut[1]);
error1:
	(void) close(data->childIn[0]);
	(void) close(data->childIn[1]);
error0:
	syslog(LOG_ERR, TAG_FORMAT "cmdStart() failed: %s (%d)", TAG_ARGS, strerror(errno), errno);
	data->child = NO_CHILD;

	return -1;
}

static int
cmdStop(workspace data, command *cmd, cmdResult *result)
{
	char *p;
	int rc, line;

	rc = -1;

	if (data->child == NO_CHILD)
		goto error0;

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "enter cmdStop(%lx, %lx, %lx)", TAG_ARGS, (long) data, (long) cmd, (long) result);

	if (close(CHILD_INPUT(data))) {
		syslog(LOG_ERR, TAG_FORMAT "write error to child=%d: %s (%d)", TAG_ARGS, data->child, strerror(errno), errno);
		(void) kill(-data->child, SIGKILL);
		goto error1;
	}

	setNonBlocking(CHILD_OUTPUT(data), 1);

	smfLog(SMF_LOG_DEBUG, TAG_FORMAT "read from child=%d", TAG_ARGS, data->child);

	for (line = 0; line < MAX_REPORT; line++) {
		if (!hasInput(CHILD_OUTPUT(data), optFilterTimeout.value)) {
			smfLog(SMF_LOG_DEBUG, TAG_FORMAT "no input from child=%d errno=(%d)", TAG_ARGS, data->child, errno);
			break;
		}
		if (TextReadLine(CHILD_OUTPUT(data), data->line, SMTP_REPLY_LINE_LENGTH+1) < 0) {
			smfLog(SMF_LOG_DEBUG, TAG_FORMAT "child=%d EOF", TAG_ARGS, data->child);
			break;
		}
		for (p = data->line; *p != '\0'; p++)
			if (*p == '\r' || *p == '\n')
				*p = '\0';
		smfLog(SMF_LOG_DIALOG, TAG_FORMAT "< %s", TAG_ARGS, data->line);
		VectorAdd(result->report, strdup(data->line));
	}

	if (MAX_REPORT <= line) {
		smfLog(SMF_LOG_DEBUG, TAG_FORMAT "discard remaining input from child=%d to EOF", TAG_ARGS, data->child);
		while (hasInput(CHILD_OUTPUT(data), optFilterTimeout.value)) {
			if (TextReadLine(CHILD_OUTPUT(data), data->line, SMTP_REPLY_LINE_LENGTH+1) < 0)
				break;
		}
	}
error1:
	close(CHILD_OUTPUT(data));
	smfLog(SMF_LOG_DIALOG, TAG_FORMAT "waiting on child=%d", TAG_ARGS, data->child);
	result->status = reaper(data->child);

	if (WIFSIGNALED(result->status)) {
		syslog(LOG_ERR, TAG_FORMAT "%s[%d] terminated on signal=%d%s", TAG_ARGS, cmd->basename, data->child, WTERMSIG(result->status), WCOREDUMP(result->status) ? ", core dumped" : "");
		result->status = 0;
	} else if (WIFEXITED(result->status)) {
		result->status = WEXITSTATUS(result->status);
		if (VectorLength(result->report) <= 0 && 0 < result->status)
			VectorAdd(result->report, strdup("message rejected"));
		smfLog(SMF_LOG_INFO, TAG_FORMAT "%s[%d] exit status=%d", TAG_ARGS, cmd->basename, data->child, result->status);
	} else {
		result->status = 0;
	}

	rc = 0;
error0:
	smfLog(SMF_LOG_TRACE, TAG_FORMAT "exit  cmdStop(%lx, %lx, %lx) rc=%d", TAG_ARGS, (long) data, (long) cmd, (long) result, rc);
	data->child = NO_CHILD;

	return rc;
}

static long
cmdWritePipe(workspace data, const char *chunk, long size)
{
	long offset, sent;

	for (offset = 0; offset < size; offset += sent) {
		if ((sent = write(CHILD_INPUT(data), chunk+offset, size-offset)) < 0) {
			if (errno != EAGAIN) {
				if (offset == 0) {
					(void) close(CHILD_INPUT(data));
					return -1;
				}
				break;
			}
			sent = 0;
		}
	}

	return offset;
}

/***********************************************************************
 *** Handlers
 ***********************************************************************/

/*
 * Open and allocate per-connection resources.
 */
static sfsistat
filterOpen(SMFICTX *ctx, char *client_name, _SOCK_ADDR *raw_client_addr)
{
	int access;
	workspace data;

	if (raw_client_addr == NULL) {
		smfLog(SMF_LOG_TRACE, "filterOpen() got NULL socket address, accepting connection");
		goto error0;
	}

	if (raw_client_addr->sa_family != AF_INET
#ifdef HAVE_STRUCT_SOCKADDR_IN6
	&& raw_client_addr->sa_family != AF_INET6
#endif
	) {
		smfLog(SMF_LOG_TRACE, "filterOpen() unsupported socket address type, accepting connection");
		goto error0;
	}

	if ((data = calloc(1, sizeof *data)) == NULL)
		goto error0;

	data->work.ctx = ctx;
	data->work.qid = smfNoQueue;
	data->work.cid = smfOpenProlog(ctx, client_name, raw_client_addr, data->client_addr, sizeof (data->client_addr));

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterOpen(%lx, '%s', [%s])", TAG_ARGS, (long) ctx, client_name, data->client_addr);

	if ((data->rcpts = VectorCreate(10)) == NULL)
		goto error1;
	VectorSetDestroyEntry(data->rcpts, free);

	if ((data->content.report = VectorCreate(10)) == NULL)
		goto error2;
	VectorSetDestroyEntry(data->content.report, free);
	data->content.command = &cmdContent;

	if ((data->envelope.report = VectorCreate(10)) == NULL)
		goto error3;
	VectorSetDestroyEntry(data->envelope.report, free);
	data->envelope.command = &cmdEnvelope;

	if (smfi_setpriv(ctx, (void *) data) == MI_FAILURE) {
		syslog(LOG_ERR, TAG_FORMAT "failed to save workspace", TAG_ARGS);
		goto error4;
	}

	access = smfAccessHost(&data->work, MILTER_NAME "-connect:", client_name, data->client_addr, SMDB_ACCESS_OK);

	switch (access) {
#ifdef ENABLE_BLACKLIST
	case SMDB_ACCESS_REJECT:
		return smfReply(&data->work, 550, "5.7.1", "connection %s [%s] blocked", client_name, data->client_addr);
#endif
	case SMDB_ACCESS_ERROR:
		return SMFIS_REJECT;
	}

	TextCopy(data->client_name, sizeof (data->client_name), client_name);
	data->child = NO_CHILD;

	return SMFIS_CONTINUE;
error4:
	VectorDestroy(data->envelope.report);
error3:
	VectorDestroy(data->content.report);
error2:
	VectorDestroy(data->rcpts);
error1:
	free(data);
error0:
	return SMFIS_ACCEPT;
}

static sfsistat
filterHelo(SMFICTX * ctx, char *helohost)
{
	workspace data;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterHelo");

	/* Reset this again. A HELO/EHLO is treated like a RSET command,
	 * which means we arrive here after the connection but also after
	 * MAIL or RCPT, in which case $i (data->work.qid) is invalid.
	 */
	data->work.qid = smfNoQueue;

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterHelo(%lx, '%s')", TAG_ARGS, (long) ctx, helohost);

	if (helohost != NULL)
		TextCopy(data->helo, sizeof(data->helo), helohost);

	return SMFIS_CONTINUE;
}

static sfsistat
filterMail(SMFICTX *ctx, char **args)
{
	int access;
	workspace data;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterMail");

	if ((data->work.qid = smfi_getsymval(ctx, "i")) == NULL)
		data->work.qid = smfNoQueue;

	data->child = NO_CHILD;
	data->hasReport = 0;
	data->hasSubject = 0;
	data->chunksSent = 0;
	VectorRemoveAll(data->rcpts);

	data->content.status = CHILD_ACCEPT;
	VectorRemoveAll(data->content.report);

	data->envelope.status = CHILD_ACCEPT;
	VectorRemoveAll(data->envelope.report);

	data->work.skipMessage = data->work.skipConnection;

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterMail(%lx, %lx) MAIL='%s'", TAG_ARGS, (long) ctx, (long) args, args[0]);

	access = smfAccessMail(&data->work, accessFrom, args[0], SMDB_ACCESS_UNKNOWN);

	switch (access) {
	case SMDB_ACCESS_ERROR:
		return SMFIS_REJECT;
#ifdef ENABLE_BLACKLIST
	case SMDB_ACCESS_REJECT:
		return smfReply(&data->work, 550, "5.7.1", "sender blocked");
#endif
	}

	access = smfAccessAuth(&data->work, accessAuth, smfi_getsymval(ctx, smMacro_auth_authen), args[0], NULL, NULL);

	switch (access) {
	case SMDB_ACCESS_ERROR:
		return SMFIS_REJECT;
#ifdef ENABLE_BLACKLIST
	case SMDB_ACCESS_REJECT:
		return smfReply(&data->work, 550, "5.7.1", "sender blocked");
#endif
	case SMDB_ACCESS_OK:
		syslog(LOG_INFO, TAG_FORMAT "sender %s authenticated, accept", TAG_ARGS, args[0]);
		return SMFIS_ACCEPT;
	}

	return SMFIS_CONTINUE;
}

static sfsistat
filterRcpt(SMFICTX *ctx, char **args)
{
	workspace data;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterRcpt");

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterRcpt(%lx, %lx) RCPT='%s'", TAG_ARGS, (long) ctx, (long) args, args[0]);

	switch (smfAccessRcpt(&data->work, accessTo, args[0])) {
	case SMDB_ACCESS_REJECT:
		return smfReply(&data->work, 550, "5.7.1", "recipient blocked");
	case SMDB_ACCESS_ERROR:
		return SMFIS_REJECT;
	}

	/* Maintain historical behaviour for now until I can study
	 * the impact of the following change to the content filter.
	 */
	if (data->work.skipRecipient)
		data->work.skipMessage = 1;

	if (VectorAdd(data->rcpts, data->work.rcpt))
		return smfReply(&data->work, 452, "4.3.2", "out of memory, cannot add recipient to list");

	data->work.rcpt = NULL;

	return SMFIS_CONTINUE;
}

#if SMFI_VERSION > 3
static sfsistat
filterData(SMFICTX *ctx)
{
	long i;
	workspace data;
	ParsePath *rcpt;
	char *report_line;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterData");

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterData(%lx)", TAG_ARGS, (long) ctx);

	if (data->work.skipMessage)
		return SMFIS_CONTINUE;

	if (cmdStart(data, &cmdEnvelope))
		return SMFIS_CONTINUE;

	smfLog(SMF_LOG_DIALOG, TAG_FORMAT "> %s", TAG_ARGS, data->client_addr);
	(void) cmdWritePipe(data, data->client_addr, strlen(data->client_addr));
	(void) cmdWritePipe(data, "\n", 1);

	smfLog(SMF_LOG_DIALOG, TAG_FORMAT "> %s", TAG_ARGS, data->client_name);
	(void) cmdWritePipe(data, data->client_name, strlen(data->client_name));
	(void) cmdWritePipe(data, "\n", 1);

	smfLog(SMF_LOG_DIALOG, TAG_FORMAT "> %s", TAG_ARGS, data->helo);
	(void) cmdWritePipe(data, data->helo, strlen(data->helo));
	(void) cmdWritePipe(data, "\n", 1);

	smfLog(SMF_LOG_DIALOG, TAG_FORMAT "> %s", TAG_ARGS, data->work.mail->address.string);
	(void) cmdWritePipe(data, data->work.mail->address.string, data->work.mail->address.length);
	(void) cmdWritePipe(data, "\n", 1);

	smfLog(SMF_LOG_DIALOG, TAG_FORMAT "> %s", TAG_ARGS, data->work.qid);
	(void) cmdWritePipe(data, data->work.qid, strlen(data->work.qid));
	(void) cmdWritePipe(data, "\n", 1);

	for (i = 0; i < VectorLength(data->rcpts); i++) {
		if ((rcpt = VectorGet(data->rcpts, i)) == NULL)
			continue;
		smfLog(SMF_LOG_DIALOG, TAG_FORMAT "> %s", TAG_ARGS, rcpt->address.string);
		(void) cmdWritePipe(data, rcpt->address.string, rcpt->address.length);
		(void) cmdWritePipe(data, "\n", 1);
	}

	if (cmdStop(data, &cmdEnvelope, &data->envelope))
		return SMFIS_CONTINUE;

	switch (data->envelope.status) {
	case CHILD_ACCEPT:
		break;
	case CHILD_TEMPFAIL:
		return smfMultiLineReplyA(&data->work, 450, NULL, (char **) VectorBase(data->envelope.report));
	case CHILD_REJECT:
		return smfMultiLineReplyA(&data->work, 550, NULL, (char **) VectorBase(data->envelope.report));
	case CHILD_DISCARD:
		if (smfLogDetail & SMF_LOG_INFO) {
			for (i = 0; i < VectorLength(data->envelope.report); i++) {
				if ((report_line = VectorGet(data->envelope.report, i)) != NULL)
					syslog(LOG_INFO, TAG_FORMAT "%s", TAG_ARGS, report_line);
			}
		}
		return SMFIS_DISCARD;
	case CHILD_TAG:
	case CHILD_BCC:
	case CHILD_REDIRECT:
		break;
	default:
		return smfReply(&data->work, 450, "4.7.1", "message rejected");
	}

	return SMFIS_CONTINUE;
}
#endif

static sfsistat
filterHeader(SMFICTX *ctx, char *name, char *value)
{
	workspace data;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterHeader");

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterHeader(%lx, '%s', '%s')", TAG_ARGS, (long) ctx, name, value);

	if (data->work.skipMessage)
		return SMFIS_CONTINUE;

	if (TextInsensitiveCompare(name, "Subject") == 0) {
		(void) strncpy(data->subject, value, sizeof (data->subject) - 1);
		data->subject[sizeof (data->subject) - 1] = '\0';
		data->hasSubject = 1;
	} else if (TextInsensitiveCompare(name, x_milter_report) == 0) {
		data->hasReport = 1;
	}

	/* If no child command is already running and the envelope
	 * command was not run or returned with accept, then proceed
	 * with the content command.
	 */
	if (data->child == NO_CHILD && data->envelope.status == CHILD_ACCEPT && cmdStart(data, &cmdContent) == 0) {
		smfLog(SMF_LOG_DIALOG, TAG_FORMAT "> %s", TAG_ARGS, data->work.qid);
		(void) cmdWritePipe(data, data->work.qid, strlen(data->work.qid));
		(void) cmdWritePipe(data, "\n", 1);
	}

	if (data->child != NO_CHILD) {
		smfLog(SMF_LOG_DIALOG, TAG_FORMAT "> %s: %s", TAG_ARGS, name, value);
		(void) cmdWritePipe(data, name, strlen(name));
		(void) cmdWritePipe(data, ": ", 2);
		(void) cmdWritePipe(data, value, strlen(value));
		(void) cmdWritePipe(data, "\n", 1);
	}

	return SMFIS_CONTINUE;
}

static sfsistat
filterEndHeaders(SMFICTX *ctx)
{
	workspace data;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterEndHeaders");

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterEndHeaders(%lx)", TAG_ARGS, (long) ctx);

	if (data->work.skipMessage)
		return SMFIS_CONTINUE;

	/* We repeat this here in case the message had no headers. */
	if (data->child == NO_CHILD && data->envelope.status == CHILD_ACCEPT && cmdStart(data, &cmdContent) == 0){
		smfLog(SMF_LOG_DIALOG, TAG_FORMAT "> %s", TAG_ARGS, data->work.qid);
		(void) cmdWritePipe(data, data->work.qid, strlen(data->work.qid));
		(void) cmdWritePipe(data, "\n", 1);
	}

	if (data->child != NO_CHILD) {
		smfLog(SMF_LOG_DIALOG, TAG_FORMAT ">", TAG_ARGS);
		(void) cmdWritePipe(data, "\n", 1);
	}

	return SMFIS_CONTINUE;
}

static sfsistat
filterBody(SMFICTX *ctx, unsigned char *chunk, size_t size)
{
	workspace data;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterBody");

	if (0 < optContentMaxSize.value && optContentMaxSize.value <= data->chunksSent)
		return SMFIS_CONTINUE;

	if (size == 0)
		chunk = "";
	else if (size < 20)
		chunk[--size] = '\0';

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterBody(%lx, '%.20s...', %lu) maxChunks=%ld chunksSent=%lu", TAG_ARGS, (long) ctx, chunk, (unsigned long) size, optContentMaxSize.value, data->chunksSent);

	if (data->work.skipMessage)
		return SMFIS_CONTINUE;

 	/* Keep track of how much of the body we process. */
 	data->chunksSent++;

	/* We repeat this here in case the message some how managed to
	 * get this far without sending any headers or end-of-header
	 * line. I don't think can ever happen, but I prefer to be safe.
	 */
	if (data->child == NO_CHILD && data->envelope.status == CHILD_ACCEPT && cmdStart(data, &cmdContent) == 0){
		smfLog(SMF_LOG_DIALOG, TAG_FORMAT "> %s", TAG_ARGS, data->work.qid);
		(void) cmdWritePipe(data, data->work.qid, strlen(data->work.qid));
		(void) cmdWritePipe(data, "\n", 1);
	}

	smfLog(SMF_LOG_DIALOG, TAG_FORMAT "> %.20s...", TAG_ARGS, chunk);

	if (data->child != NO_CHILD)
		(void) cmdWritePipe(data, chunk, size);

	return SMFIS_CONTINUE;
}

static sfsistat
statusAction(workspace data, cmdResult *result)
{
	int i, j;
	Buf *header;
	char *report;
	ParsePath *rcpt;

	switch (result->status) {
	case CHILD_ACCEPT:
		break;
	case CHILD_TEMPFAIL:
		return smfMultiLineReplyA(&data->work, 450, NULL, (char **) VectorBase(result->report));
	case CHILD_REJECT:
		return smfMultiLineReplyA(&data->work, 550, NULL, (char **) VectorBase(result->report));
	case CHILD_TAG:
		/* Tag the subject if not already tagged. */
		report = VectorGet(result->report, 0);
		if (report != NULL && TextInsensitiveStartsWith(data->subject, report) < 0) {
			(void) snprintf(data->line, sizeof (data->line), "%s %s", report, data->subject);
			(void) smfHeaderSet(data->work.ctx, "Subject", data->line, 1, data->hasSubject);
			VectorRemove(result->report, 0);
		}
		break;
	case CHILD_REDIRECT:
		/* Remove previous list of recipients from Sendmail's list
		 * and record them in the redirected message in case it was
		 * not spam and needs to be resent later. Sometimes the To:
		 * or Cc: headers are useless ie. undisclosed recipients.
		 */
		for (i = 0; i < VectorLength(data->rcpts); i++) {
			if ((rcpt = VectorGet(data->rcpts, i)) == NULL)
				continue;

			if (smfi_addheader(data->work.ctx, X_ORIGINAL_RECIPIENT, rcpt->address.string) == MI_SUCCESS)
				(void) smfi_delrcpt(data->work.ctx, rcpt->address.string);
		}
		/*@fallthrough@*/
	case CHILD_BCC:
		/* Add to the recipient list. */
		for (i = 0; i < VectorLength(result->report); i++) {
			if ((report = VectorGet(result->report, i)) == NULL)
				continue;

			/* Allow for intermixed recipient and report lines.
			 * A report line is assumed to be a phrase or
			 * something containing at least one space.
			 */
			if (strchr(report, ' ') != NULL) {
syslog(LOG_DEBUG, TAG_FORMAT "report-line='%s'", TAG_ARGS, report);
				continue;
			}

			if (smfi_addrcpt(data->work.ctx, report) == MI_FAILURE)
				syslog(LOG_ERR, TAG_FORMAT "add recipient <%s> failed", TAG_ARGS, report);

			/* Remove the recipient, leaving only the report
			 * lines that can be added to a header.
			 */
			VectorRemove(result->report, i);
		}
		break;
	case CHILD_DISCARD:
	default:
		if (smfLogDetail & SMF_LOG_INFO) {
			for (i = 0; i < VectorLength(result->report); i++) {
				if ((report = VectorGet(result->report, i)) != NULL)
					syslog(LOG_INFO, TAG_FORMAT "%s", TAG_ARGS, report);
			}
		}

		if (result->status == CHILD_DISCARD)
			return SMFIS_DISCARD;

		return smfReply(&data->work, 450, "4.7.1", "message rejected");
	}

	if (0 < VectorLength(result->report) && (header = BufCreate(SMTP_TEXT_LINE_LENGTH)) != NULL) {
		BufAddString(header, result->command->commandLine);
		BufAddString(header, "\n  ");

		for (i = 0; i < VectorLength(result->report); i++) {
			if ((report = VectorGet(result->report, i)) == NULL)
				continue;

			/* Remove trailing white space. */
			for (j = (int) strlen(report); 0 < j-- && isspace(report[j]); )
				report[j] = '\0';

			/* Add the report line, replace empty lines by "__". */
			BufAddString(header, report[0] == '\0' ? "__" : report);
			BufAddString(header, "\n  ");
		}

		/* Remove our trailing whitespace "\n  ". */
		BufSetLength(header, BufLength(header)-3);

		/* Add or replace the report header. */
		(void) smfHeaderSet(data->work.ctx, x_milter_report, BufBytes(header), 1, data->hasReport);
		BufDestroy(header);
	}

	return SMFIS_CONTINUE;
}

static sfsistat
filterEndMessage(SMFICTX *ctx)
{
	sfsistat rc;
	workspace data;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterEndMessage");

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterEndMessage(%lx)", TAG_ARGS, (long) ctx);

	if (data->work.skipMessage)
		return SMFIS_CONTINUE;

#ifdef DROPPED_ADD_HEADERS
	/* Add trace to the message. There can be many of these, one
	 * for each filter/host that looks at the message.
	 */
	if (optAddHeaders.value) {
		long length;
		const char *if_name, *if_addr;

		if ((if_name = smfi_getsymval(ctx, smMacro_if_name)) == NULL)
			if_name = smfUndefined;
		if ((if_addr = smfi_getsymval(ctx, smMacro_if_addr)) == NULL)
			if_addr = "0.0.0.0";

		length = snprintf(data->line, sizeof (data->line), MILTER_STRING " (%s [%s]); ", if_name, if_addr);
		length += TimeStampAdd(data->line + length, sizeof (data->line) - length);
		(void) smfi_addheader(ctx, X_SCANNED_BY, data->line);
	}
#endif

	/* Collect the results of the running content command. */
	(void) cmdStop(data, &cmdContent, &data->content);

	/* Envelope tempfail and reject happens in filterData(), but
	 * here we may tag, copy, or redirect the message before
	 * checking the content command status.
	 */
	if ((rc = statusAction(data, &data->envelope)) != SMFIS_CONTINUE)
		return rc;

	/* Finally check the result of the content command, which
	 * could tempfail or reject the message. Its possible for
	 * the message to be double-tagged by both the envelope
	 * and content commands.
	 *
	 * Its also possible for the envelope command to copy or
	 * redirect and then have the content command do the inverse
	 * redirect or copy respectively. In such cases the email
	 * may be copied or redirected to two different addresses.
	 */
	return statusAction(data, &data->content);
}

/*
 * Close and release per-message resources if the message is aborted outside
 * the filter's control and the filter has not completed its message-oriented
 * processing, ie. MAIL..HELO, MAIL..RSET, MAIL..QUIT, and disconnection
 * sequences. filterEndMessage() and filterAbort() are mutually exclusive.
 */
static sfsistat
filterAbort(SMFICTX * ctx)
{
	workspace data;

	if ((data = (workspace) smfi_getpriv(ctx)) == NULL)
		return smfNullWorkspaceError("filterAbort");

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterAbort(%lx)", TAG_ARGS, (long) ctx);

	if (data->child != NO_CHILD) {
		(void) kill(data->child, SIGKILL);
		(void) reaper(data->child);
		(void) close(CHILD_INPUT(data));
		(void) close(CHILD_OUTPUT(data));
		data->child = NO_CHILD;
	}

	return SMFIS_CONTINUE;
}

/*
 * Close and release per-connection resources.
 */
static sfsistat
filterClose(SMFICTX *ctx)
{
	workspace data;
	unsigned short cid = 0;

	if ((data = (workspace) smfi_getpriv(ctx)) != NULL) {
		cid = smfCloseEpilog(&data->work);
		VectorDestroy(data->envelope.report);
		VectorDestroy(data->content.report);
		VectorDestroy(data->rcpts);
		free(data);
	}

	smfLog(SMF_LOG_TRACE, TAG_FORMAT "filterClose(%lx)", cid, smfNoQueue, (long) ctx);

	return SMFIS_CONTINUE;
}


/***********************************************************************
 ***  Milter Definition Block
 ***********************************************************************/

static smfInfo milter = {
	MILTER_MAJOR,
	MILTER_MINOR,
	MILTER_BUILD,
	MILTER_NAME,
	MILTER_AUTHOR,
	MILTER_COPYRIGHT,
	RUN_AS_USER,
	RUN_AS_GROUP,
	MILTER_CF,
	PID_FILE,
	"unix:" SOCKET_FILE,
	WORK_DIR,
	SMF_STDIO_CLOSE,

	/* struct smfiDesc */
	{
		MILTER_NAME,		/* filter name */
		SMFI_VERSION,		/* version code -- do not change */
		SMFIF_ADDHDRS|SMFIF_CHGHDRS|SMFIF_ADDRCPT|SMFIF_DELRCPT, /* flags */
		filterOpen,		/* connection info filter */
		filterHelo,		/* SMTP HELO command filter */
		filterMail,		/* envelope sender filter */
		filterRcpt,		/* envelope recipient filter */
		filterHeader,		/* header filter */
		filterEndHeaders,	/* end of header */
		filterBody,		/* body block filter */
		filterEndMessage,	/* end of message */
		filterAbort,		/* message aborted */
		filterClose		/* connection cleanup */
#if SMFI_VERSION > 2
		, NULL			/* Unknown/unimplemented commands */
#endif
#if SMFI_VERSION > 3
		, filterData		/* SMTP DATA command */
#endif
	}
};

/***********************************************************************
 *** Startup
 ***********************************************************************/

void
atExitCleanUp()
{
	smdbClose(smdbAccess);
	smfAtExitCleanUp();
}

static int
mprintf(char **out, const char *fmt, ...)
{
	int length;
	va_list args;

	va_start(args, fmt);

	if (out == NULL)
		return -1;

	/* I tried to use vsnprintf() to compute the length first before
	 * allocating the buffer, but on my only linux machine, vsnprintf()
	 * return -1 if the buffer is not large enough to hold the string.
	 */
	if ((*out = malloc(256)) == NULL)
		return -1;

	if ((length = vsnprintf(*out, 128, fmt, args)) <= 0 && 256 <= length) {
		free(*out);
		*out = NULL;
		return -1;
	}

	va_end(args);

	return length;
}

static int
initInstance(void)
{
	int rc = 0;
	char *dirname, *slash;

	/* Skip if no ID was given. */
	if (*optMilterId.string == '\0')
		return 0;

	/* No undo error code here, since we will exit in main(). */
	if (mprintf(&milter.package, MILTER_NAME "-%s", optMilterId.string) < 0)
		return -1;

	if (mprintf(&x_milter_report, "X-%s-Report", milter.package) < 0)
		return -1;

	if (mprintf(&accessConnect, "%s-connect:", milter.package) < 0)
		return -1;

	if (mprintf(&accessAuth, "%s-auth:", milter.package) < 0)
		return -1;

	if (mprintf(&accessFrom, "%s-from:", milter.package) < 0)
		return -1;

	if (mprintf(&accessTo, "%s-to:", milter.package) < 0)
		return -1;

	if ((dirname = strdup(smfOptPidFile.string)) == NULL)
		return -1;

	slash = strrchr(dirname, '/');
	*slash = '\0';

	if (smfOptPidFile.initial != smfOptPidFile.string)
		free(smfOptPidFile.string);
	if (mprintf(&smfOptPidFile.string, "%s/%s.pid", dirname, milter.package) < 0)
		rc = -1;

	free(dirname);

	if (strncmp(smfOptMilterSocket.string, "unix:", 5) == 0 || strncmp(smfOptMilterSocket.string, "local:", 6) == 0) {
		if ((dirname = strdup(smfOptMilterSocket.string)) == NULL)
			rc = -1;

		slash = strrchr(dirname, '/');
		*slash = '\0';

		if (smfOptMilterSocket.initial != smfOptMilterSocket.string)
			free(smfOptMilterSocket.string);
		if (mprintf(&smfOptMilterSocket.string, "%s/%s.socket", dirname, milter.package) < 0)
			rc = -1;

		free(dirname);
	}

	return rc;
}

int
main(int argc, char **argv)
{
	int argi;

	/* Defaults */
	smfOptFile.initial = MILTER_CF;
	smfOptPidFile.initial = PID_FILE;
	smfOptRunUser.initial = RUN_AS_USER;
	smfOptRunGroup.initial = RUN_AS_GROUP;
	smfOptWorkDir.initial = WORK_DIR;
	smfOptMilterSocket.initial = "unix:" SOCKET_FILE;

	/* Make sure script out is initially logged. */
	smfOptVerbose.initial = "info";

	/* Parse command line options looking for a file= option. */
	optionInit(optTable, smfOptTable, NULL);
	argi = optionArrayL(argc, argv, optTable, smfOptTable, NULL);

	/* Parse the option file followed by the command line options again. */
	if (smfOptFile.string != NULL && *smfOptFile.string != '\0') {
		/* Do NOT reset this option. */
		smfOptFile.initial = smfOptFile.string;
		smfOptFile.string = NULL;

		optionInit(optTable, smfOptTable, NULL);
		(void) optionFile(smfOptFile.string, optTable, smfOptTable, NULL);
		(void) optionArrayL(argc, argv, optTable, smfOptTable, NULL);
	}

	/* Show them the funny farm. */
	if (smfOptHelp.string != NULL) {
		optionUsageL(optTable, smfOptTable, NULL);
		exit(2);
	}

	/* When milter-id is given, we have to redefine several milter
	 * strings into milter-cli-ID strings in order to distinguish
	 * one instance from another.
	 */
	if (initInstance()) {
		fprintf(stderr, "initialisation error: %s (%d)\n", strerror(errno), errno);
		return 1;
	}

	if (smfOptQuit.string != NULL) {
		/* Use SIGQUIT signal in order to avoid delays
		 * caused by libmilter's handling of SIGTERM.
		 * smfi_stop() takes too long since it waits
		 * for connections to terminate, which could
		 * be a several minutes or longer.
		 */
		exit(pidKill(smfOptPidFile.string, SIGQUIT) != 0);
	}

	if (smfOptRestart.string != NULL) {
		(void) pidKill(smfOptPidFile.string, SIGQUIT);
		sleep(2);
	}

	if (smfOptDaemon.value && smfStartBackgroundProcess())
		return 1;

	openlog(milter.package, LOG_PID, LOG_MAIL);

#ifdef HAVE_GETRLIMIT
{
	struct rlimit limit;

	if (getrlimit(RLIMIT_NOFILE, &limit) == 0)
		max_open_files = (unsigned long) limit.rlim_cur;
}
#endif
	smfLog(SMF_LOG_DEBUG, "max_open_files=%lu", max_open_files);

	(void) smfi_settimeout((int) smfOptMilterTimeout.value);
	(void) smfSetLogDetail(smfOptVerbose.string);

	optFilterTimeout.value *= 1000;
	if (optFilterTimeout.value < 0)
		optFilterTimeout.value = 0;

	if (0 < optContentMaxSize.value)
		optContentMaxSize.value = 1 + optContentMaxSize.value * 1024 / MILTER_CHUNK_SIZE;

	cmdContent.commandLine = optContentFilter.string;
	cmdInit(&optContentFilter, &cmdContent);

	cmdEnvelope.commandLine = optEnvelopeFilter.string;
	cmdInit(&optEnvelopeFilter, &cmdEnvelope);

	if (atexit(atExitCleanUp)) {
		syslog(LOG_ERR, "atexit() failed\n");
		return 1;
	}

	if (*smfOptAccessDb.string != '\0') {
		if (smfLogDetail & SMF_LOG_DATABASE)
			smdbSetDebugMask(SMDB_DEBUG_ALL);

		if ((smdbAccess = smdbOpen(smfOptAccessDb.string, 1)) == NULL) {
			syslog(LOG_ERR, "failed to open \"%s\"", smfOptAccessDb.string);
			return 1;
		}
	}

	return smfMainStart(&milter);
}

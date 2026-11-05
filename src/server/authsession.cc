/**
 * Module: authsession.cc
 * Description: Authentication support
 *
 * Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2009-2013 Vyatta, Inc.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 *
 **/

#include <libaudit.h>
#include <array>
#include <cstring>
#include <ctime>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <string>
#include <errno.h>
#include <unistd.h>
#include "common.hh"
#include "authbase.hh"
#include "authsession.hh"

using namespace std;

const string AuthSession::_session_file = "/var/run/gui/session";
const unsigned long AuthSession::_session_timeout = 30 * 60; //30 minutes (in seconds)

static bool
trusted_file(int fd)
{
	struct stat st;
	return fd >= 0 && fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
	       st.st_uid == 0 && (st.st_mode & 07777) == 0600 && st.st_nlink == 1;
}

Lock::Lock(const string &file) :
	_fp(NULL),
	_fp_tmp(NULL),
	_dir_fd(-1),
	_lck_fd(-1)
{
	const size_t slash = file.rfind('/');
	if (slash == string::npos || geteuid() != 0)
		return;
	_file = file.substr(slash + 1);
	const string dir = file.substr(0, slash);
	_dir_fd = open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	struct stat st;
	if (_dir_fd < 0 || fstat(_dir_fd, &st) != 0 || st.st_uid != 0 ||
	    (st.st_mode & 07777) != 0700)
		return;

	// Keep a stable lock inode for both the reader and the Perl issuer.
	const int flags = O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC;
	const string lck_file = _file + ".lck";
	_lck_fd = openat(_dir_fd, lck_file.c_str(), O_RDONLY | O_CREAT | flags, 0600);
	if (!trusted_file(_lck_fd))
		return;
	for (int attempt = 0; flock(_lck_fd, LOCK_EX | LOCK_NB) != 0; ++attempt) {
		if (attempt == 4 || (errno != EWOULDBLOCK && errno != EINTR))
			return;
		usleep(50000);
	}

	const int fd = openat(_dir_fd, _file.c_str(), O_RDONLY | flags);
	if (trusted_file(fd))
		_fp = fdopen(fd, "r");
	if (!_fp) {
		if (fd >= 0)
			close(fd);
		return;
	}

	// The validated runtime directory is under root-owned /run.
	string tmp_file = file + ".XXXXXX";
	const int tmp_fd = mkostemp(&tmp_file[0], O_CLOEXEC);
	if (tmp_fd < 0)
		return;
	_tmp_file = tmp_file.substr(slash + 1);
	if (trusted_file(tmp_fd))
		_fp_tmp = fdopen(tmp_fd, "w");
	if (!_fp_tmp)
		close(tmp_fd);
}

Lock::~Lock()
{
	if (_fp_tmp)
		fclose(_fp_tmp);
	if (_fp)
		fclose(_fp);
	if (!_tmp_file.empty())
		unlinkat(_dir_fd, _tmp_file.c_str(), 0);
	if (_lck_fd >= 0)
		close(_lck_fd);
	if (_dir_fd >= 0)
		close(_dir_fd);
}

bool
Lock::commit()
{
	if (!status() || ferror(_fp) || ferror(_fp_tmp))
		return false;
	const int result = fclose(_fp_tmp);
	_fp_tmp = NULL;
	if (result != 0 || renameat(_dir_fd, _tmp_file.c_str(), _dir_fd, _file.c_str()) != 0)
		return false;
	_tmp_file.clear();
	return true;
}

static string
session_key(const string &value)
{
	const string scheme = Rest::AUTH_VYATTA_SESSION + " ";
	const string cookie = Rest::AUTH_VYATTA_PATH_LOC + "=";
	string key;
	if (value.compare(0, scheme.size(), scheme) == 0) {
		key = value.substr(scheme.size());
	} else {
		size_t start = 0;
		while (start < value.size()) {
			start = value.find_first_not_of(" \t", start);
			if (start == string::npos)
				break;
			const size_t end = value.find(';', start);
			if (value.compare(start, cookie.size(), cookie) == 0) {
				const size_t key_start = start + cookie.size();
				key = value.substr(key_start, end == string::npos ? end : end - key_start);
				const size_t key_end = key.find_last_not_of(" \t");
				if (key_end != string::npos)
					key.resize(key_end + 1);
				break;
			}
			if (end == string::npos)
				break;
			start = end + 1;
		}
	}
	if (key.size() != 16 || key.find_first_not_of("0123456789abcdefABCDEF") != string::npos)
		return "";
	return key;
}

bool
AuthSession::handle(const string &auth)
{
	return !session_key(auth).empty();
}

static bool
parse_session_row(const string &row, std::array<string, 5> &fields)
{
	size_t start = 0;
	for (size_t i = 0; i + 1 < fields.size(); ++i) {
		const size_t end = row.find(',', start);
		if (end == string::npos)
			return false;
		fields[i] = row.substr(start, end - start);
		start = end + 1;
	}
	fields.back() = row.substr(start, row.size() - start - 1);
	return !fields[1].empty() && !fields[2].empty() &&
	       fields[2].find_first_not_of("0123456789") == string::npos &&
	       fields.back().find(',') == string::npos;
}

bool
AuthSession::authorized(const string &val, Session &session)
{
	const string key = session_key(val);
	if (key.empty())
		return false;

	Lock lock(_session_file);
	if (!lock.status()) {
		syslog(LOG_ERR, "Failed to access vyatta session information");
		return false;
	}

	const time_t now = time(NULL);
	if (now < 0)
		return false;
	const bool refresh = session._request.get(Rest::HTTP_REQ_PRAGMA)
		.find(Rest::PRAGMA_NO_VYATTA_SESSION_UPDATE) == string::npos;
	FILE *fp = lock.get_fp();
	FILE *fp_tmp = lock.get_fp_tmp();
	char buf[1024];
	string user;
	bool service_user = false;
	while (fgets(buf, sizeof(buf), fp)) {
		const string row(buf);
		// Refuse a partial record without replacing the existing store.
		if (row.empty() || row.back() != '\n')
			return false;
		std::array<string, 5> fields;
		if (!parse_session_row(row, fields))
			continue;

		errno = 0;
		const unsigned long issued = strtoul(fields[2].c_str(), NULL, 10);
		if (errno || issued > static_cast<unsigned long>(now) ||
		    static_cast<unsigned long>(now) - issued >= _session_timeout)
			continue;

		if (fields[0] == key) {
			if (!user.empty())
				return false;
			user = fields[1];
			service_user = fields[4] == "service-user";
			if (refresh)
				fields[2] = to_string(now);
			if (fprintf(fp_tmp, "%s,%s,%s,%s,%s\n", fields[0].c_str(),
			            fields[1].c_str(), fields[2].c_str(), fields[3].c_str(),
			            fields[4].c_str()) < 0)
				return false;
		} else if (fputs(row.c_str(), fp_tmp) < 0) {
			return false;
		}
	}
	if (user.empty())
		return false;

	int ngroups = 10;
	gid_t groups[10];
	uid_t uid = 0;
	gid_t gid = 0;
	if (!service_user) {
		const struct passwd *pw = getpwnam(user.c_str());
		if (!pw)
			return false;
		uid = pw->pw_uid;
		gid = pw->pw_gid;
		if (getgrouplist(user.c_str(), gid, groups, &ngroups) == -1)
			return false;
		for (int i = 0; i < ngroups; ++i) {
			const struct group *gr = getgrgid(groups[i]);
			if (gr && strcmp(gr->gr_name, "vyattacfg") == 0)
				session._access_level = Session::k_VYATTACFG;
		}
	}

	// Publish while still privileged. Failure leaves the original store intact.
	if (!lock.commit()) {
		syslog(LOG_ERR, "Failed to update vyatta session information");
		return false;
	}

	if (!service_user) {
		if (audit_setloginuid(uid) < 0) {
			syslog(LOG_ERR, "Failed to set loginuid");
			return false;
		}
		if (setgroups(ngroups, groups) != 0 || setegid(gid) != 0 || seteuid(uid) != 0)
			return false;
	} else {
		session._access_level = Session::k_VYATTASERVICE_USER;
		session._service_user = true;
	}

	session._user = user;
	session._session_key = key;
	session._auth_type = Rest::AUTH_TYPE_VYATTA_SESSION;
	return true;
}

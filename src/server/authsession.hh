/**
 * Module: authbasic.hh
 * This code was originally developed by Vyatta, Inc.
 * Portions created by Vyatta are Copyright (C) 2009, 2010 Vyatta, Inc.
 * All Rights Reserved.
 * Authors: Michael Larson
 * Date: 2010
 * Description: authentication basic implementation
 *
 **/

#ifndef __AUTHSESSION_HH__
#define __AUTHSESSION_HH__

#include <cstdio>
#include "http.hh"
#include "authbase.hh"

class Lock
{
public:
	Lock(const std::string &file);
	~Lock();
	Lock(const Lock &) = delete;
	Lock &operator=(const Lock &) = delete;

	bool
	status() const {
		return _fp && _fp_tmp;
	}
	bool commit();

	FILE*
	get_fp() {
		return _fp;
	}

	FILE*
	get_fp_tmp() {
		return _fp_tmp;
	}

private:
	std::string _file;
	std::string _tmp_file;
	FILE* _fp;
	FILE* _fp_tmp;
	int _dir_fd;
	int _lck_fd;
};



class AuthSession : protected AuthBase
{
public:
	friend class Authenticate;

public: //methods
	AuthSession(bool debug) : AuthBase(debug) {}
	virtual ~AuthSession() {}

	bool
	handle(const std::string &auth);

	bool
	authorized(const std::string &auth, Session &session);

private: //variables
	const static std::string _session_file;
	const static unsigned long _session_timeout;
};

#endif //__AUTHSESSION_HH__

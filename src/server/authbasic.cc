/**
 * Module: authenticate.cc
 * Description: Authentication support
 *
 * Copyright (c) 2019, AT&T Intellectual Property.  All rights reserved.
 * Copyright (c) 2009-2013 Vyatta, Inc.
 * All Rights Reserved.
 *
 * SPDX-License-Identifier: GPL-2.0-only
 **/

#include <libaudit.h>
#include <iostream>
#include <openssl/evp.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <grp.h>
#include <pwd.h>
#include <string>
#include <errno.h>
#include "common.hh"
#include "authbase.hh"
#include "authbasic.hh"

#include "debug.h"

using namespace std;



/**
 *
 *
 **/
static int
conv_fun(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *data)
{
	int count;
	struct pam_response *r;

	r = (struct pam_response *)calloc(num_msg, sizeof(pam_response));
	if (!r)
		return PAM_BUF_ERR;

	for(count = 0; count < num_msg; ++count) {
		switch(msg[count]->msg_style) {
		case PAM_PROMPT_ECHO_OFF:
		case PAM_PROMPT_ECHO_ON:
			// Nothing special to do here
			break;
		case PAM_ERROR_MSG:
			syslog(LOG_ERR, "webgui: %s\n", msg[count]->msg);
			break;
		case PAM_TEXT_INFO:
			syslog(LOG_INFO, "webgui: %s\n", msg[count]->msg);
			break;
		default:
			syslog(LOG_ERR, "webgui: Erroneous Conversation (%d)\n",
			       msg[count]->msg_style);
			break;
		}

		r[count].resp_retcode = 0;
		r[count].resp = x_strdup((char *)data);
	}

	*resp = r;
	return PAM_SUCCESS;
}


/**
 *
 *
 **/
static bool
has_basic_scheme(const string &auth)
{
	const size_t size = Rest::AUTH_BASIC.size();
	return auth.size() > size && auth[size] == ' ' &&
	       auth.compare(0, size, Rest::AUTH_BASIC) == 0;
}

bool
AuthBasic::parse_credentials(const string &auth, string &username, string &password)
{
	if (!has_basic_scheme(auth))
		return false;

	const size_t max_decoded = 1024;
	const size_t max_encoded = 4 * ((max_decoded + 2) / 3);
	const size_t offset = Rest::AUTH_BASIC.size() + 1;
	const size_t size = auth.size() - offset;
	if (size == 0 || size > max_encoded || size % 4 != 0)
		return false;

	size_t padding = 0;
	if (auth.back() == '=') {
		padding = auth[auth.size() - 2] == '=' ? 2 : 1;
	}
	const char *alphabet =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	if (auth.find_first_not_of(alphabet, offset) !=
	    (padding ? auth.size() - padding : string::npos))
		return false;

	// EVP_DecodeBlock writes three bytes per quartet, including padding.
	unsigned char decoded[3 * (max_encoded / 4)];
	const int result = EVP_DecodeBlock(decoded,
		reinterpret_cast<const unsigned char *>(auth.data() + offset), static_cast<int>(size));
	if (result < 0 || static_cast<size_t>(result) < padding)
		return false;
	const size_t length = static_cast<size_t>(result) - padding;
	if (length > max_decoded)
		return false;

	const string credentials(reinterpret_cast<const char *>(decoded), length);
	const size_t separator = credentials.find(':');
	if (separator == 0 || separator == string::npos ||
	    credentials.find('\0') != string::npos)
		return false;

	username = credentials.substr(0, separator);
	password = credentials.substr(separator + 1);
	return true;
}


/**
 *
 *
 **/
bool
AuthBasic::handle(const string &auth)
{
	return has_basic_scheme(auth);
}


/**
 *
 *
 **/
bool
AuthBasic::authorized(const string &val, Session &session)
{
	string username;
	string password;
	if (!parse_credentials(val, username, password)) {
		session.vyatta_debug("AAB");
		return false;
	}

	session._user = username;

	string pam_service = "login";
	string path = session._request.get(Rest::HTTP_REQ_URI);
	
	if (path.find(Rest::SERVICE_REQ_ROOT) == 0
		|| session._request.get(Rest::HTTP_REQ_PRAGMA).find(Rest::PRAGMA_SERVICE_USER) != string::npos) {
		pam_service = "vyatta-service-users.conf";
		session._service_user = true;
		session._access_level = Session::k_VYATTASERVICE_USER;
	}

	//now have user and pw--need to  figure out what to do with this...

	struct passwd *pw = NULL;
	gid_t primary_g_gr_gid = 0;
	if (!session._service_user) {
		//for now check if this is a member of the vyattacfg group-- auth will really happen at the server level once configured...

		pw = getpwnam(username.c_str());
		if (!pw) {
			session.vyatta_debug("AAC");
			dsyslog(_debug, "%s: auth3", __func__);
			return false;
		}

		//debug
		dsyslog(_debug, "%s: auth4", __func__);

		primary_g_gr_gid = pw->pw_gid;

		/* Retrieve group list */
		int ngroups = 10;
		gid_t groups[10];
		if (getgrouplist(username.c_str(), pw->pw_gid, groups, &ngroups) == -1) {
			session.vyatta_debug("AAF0");
			return false;
		}

		for (int j = 0; j < ngroups; j++) {
			struct group *gr = getgrgid(groups[j]);
			if (gr != NULL) {
				if (strcmp(gr->gr_name,"vyattacfg") == 0) {
					session._access_level = Session::k_VYATTACFG;
					primary_g_gr_gid = gr->gr_gid;
					if (_debug) {
						session._response.append(Rest::HTTP_RESP_DEBUG,"AAF0");
					}
				}
			}
		}

		if (setgroups(ngroups,groups) != 0) {
			session.vyatta_debug("AAF5");
			return false;
		}

		dsyslog(_debug, "%s: !auth6b:%d", __func__, primary_g_gr_gid);
	}

	char *passwd = strdup(password.c_str());
	if (!passwd) {
		return false;
	}
	pam_conv conv = { conv_fun, passwd };
	dsyslog(_debug, "%s: auth8", __func__);

	pam_handle_t *pam = NULL;
	int result = pam_start(pam_service.c_str(), username.c_str(), &conv, &pam);
	if (result != PAM_SUCCESS) {
		dsyslog(_debug, "%s: pam_start failed: result=%d", __func__, result);
		session.vyatta_debug("AAG");
		free(passwd);
		return false;
	}

	dsyslog(_debug, "%s: auth9: pam=%p", __func__, pam);

	result = pam_authenticate(pam, 0);
	if (result != PAM_SUCCESS) {
		dsyslog(_debug, "%s: pam_authenticate failed: result=%d", __func__, result);
		session.vyatta_debug("AAH");
		pam_end(pam, result);
		free(passwd);
		return false;
	}

	result = pam_acct_mgmt(pam, 0);
	if (result != PAM_SUCCESS) {
		dsyslog(_debug, "%s: pam_acct_mgmt failed: result=%d", __func__, result);
		session.vyatta_debug("AAI");
		pam_end(pam, result);
		free(passwd);
		return false;
	}

	result = pam_end(pam, result);
	if (result != PAM_SUCCESS) {
		dsyslog(_debug, "%s: pam_end failed: result=%d", __func__, result);
		session.vyatta_debug("AAJ");
		free(passwd);
		return false;
	}
	free(passwd);

	dsyslog(_debug, "%s: auth10", __func__);

	if (!session._service_user) {
		uid_t pw_uid = pw->pw_uid;
		if (audit_setloginuid(pw_uid) < 0) {
			syslog(LOG_ERR, "Failed to set loginuid\n");
			return false;
		}
		if (setegid(primary_g_gr_gid) != 0) {
			dsyslog(_debug, "%s: auth11", __func__);
			session.vyatta_debug("AAK");
			return false;
		}
		dsyslog(_debug, "%s: auth6c %d ", __func__, pw_uid);
		if (seteuid(pw_uid) != 0) {
			dsyslog(_debug, "%s: auth12", __func__);
			session.vyatta_debug("AAL");
			return false;
		}
	}
	dsyslog(_debug, "%s: auth13", __func__);

	// TODO: Want to set back uid and gid on failure...

	session._auth_type = Rest::AUTH_TYPE_BASIC;

	return true;
}



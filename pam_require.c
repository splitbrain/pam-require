/*
pam_require - A simple PAM account module
Copyright (C) 2003-2004 Andreas Gohr <a.gohr@web.de>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

*/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

/* for solaris compatibility */
#define _POSIX_PTHREAD_SEMANTICS

#ifdef HAVE_SECURITY_PAM_APPL_H
#include <security/pam_appl.h>
#elif defined(HAVE_PAM_PAM_APPL_H)
#include <pam/pam_appl.h>
#endif

#ifdef HAVE_SECURITY_PAM_MISC_H
#include <security/pam_misc.h>
#elif defined(HAVE_PAM_PAM_MISC_H)
#include <pam/pam_misc.h>
#endif

#ifndef HAVE_PAM_PAM_MODULES_H
#include <security/pam_modules.h>
#else
#include <pam/pam_modules.h>
#endif

#include <syslog.h>
#include <string.h>
#include <sys/types.h>
#include <grp.h>
#include <pwd.h>
#include <unistd.h>
#include <malloc.h>
#include <stdarg.h>

/* taken from pam_ldap */
#if defined(HAVE_SECURITY_PAM_MISC_H) || defined(HAVE_PAM_PAM_MISC_H)
#define CONST_ARG const
#else
#define CONST_ARG
#endif

#ifndef PAM_EXTERN
#define PAM_EXTERN extern
#endif

static int check_groups ( const char *, const char * );
static void _pam_log ( int err, const char *format, ... );

/* --------------------------- PAM functions --------------------------------*/

/* function for account modules - The only one this module handles */
PAM_EXTERN int pam_sm_acct_mgmt ( pam_handle_t *pamh,
                                  int flags,
                                  int argc,
                                  const char *argv[] ) {
  const char *user = NULL;
  char *current = NULL;
  int rval;
  int i, j;
  int allow = 0;
  
  /* get username from PAM or fail */
  if ( ( rval = pam_get_user ( pamh,(CONST_ARG char **) &user, NULL ) ) != PAM_SUCCESS ) {
    _pam_log ( LOG_ERR, "pam_require: can't get username: %s", pam_strerror ( pamh, rval ) );
    return PAM_AUTH_ERR;
  }

  /* check all arguments */
  for ( i = 0; i < argc; i++ ) {
    /* skip standard params */
    if ( strcmp ( argv[i], "debug" ) == 0 ) { continue; }
    if ( strcmp ( argv[i], "no_warn" ) == 0 ) { continue; }
    if ( strcmp ( argv[i], "use_first_pass" ) == 0 ) { continue; }
    if ( strcmp ( argv[i], "try_first_pass" ) == 0 ) { continue; }
    if ( strcmp ( argv[i], "use_mapped_pass" ) == 0 ) { continue; }
    if ( strcmp ( argv[i], "expose_account" ) == 0 ) { continue; }

    /* Replace : with space  */
    current = strdup ( argv[i] );
    for ( j = 0; j < strlen ( current ); j++ ) {
      if ( current[j] == ':' ) current[j] = ' ';
    }
    
    if ( current[0] == '!' ) {
      if ( current[1] == '@' ) {
        /* check if user is _not_ member of required group */
        if ( check_groups ( user, current+2 ) ) {
          allow = 0;
          break;
        }
      } else {
        /* check if username does _not_ match */
        if ( strcmp ( current + 1, user ) == 0 ) {
          allow = 0;
          break;
        }
      }
    } else if ( current[0] == '@' ) {
      /* check if user is member of required group */
      if ( check_groups ( user, current+1 ) ) {
        allow = 1;
        break;
      }
    } else {
      /* check if username matches */
      if ( strcmp ( current, user ) == 0 ) {
        allow = 1;
        break;
      }
    }
    free ( current );
  }

  if(allow){
    _pam_log( LOG_INFO, "login for %s granted", user );
    return PAM_SUCCESS;
  }else{
    _pam_log ( LOG_WARNING, "login for %s denied", user ); 
    return PAM_AUTH_ERR;
  }
}

/* function for auth modules - ignore us! */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh,
                                   int flags,
                                   int argc,
                                   const char **argv){
  return PAM_IGNORE;
}

/* function for password modules - ignore us! */
PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh,
                                int flags,
                                int argc,
                                const char **argv){
  return PAM_IGNORE;
}

/* functions for session modules - ignore us */
PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh,
                                   int flags,
                                   int argc,
                                   const char **argv){
  return PAM_IGNORE;
}
PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh,
                                    int flags,
                                    int argc,
                                    const char **argv){
  return PAM_IGNORE;
}
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh,
                                 int flags,
                                 int argc,
                                 const char **argv){
  return PAM_IGNORE;
}

/* --------------------------- my own functions -----------------------------*/

/* function for correct syslog logging 
   provided by Scipio <scipio@freemail.hu> */
static void _pam_log ( int err, const char *format, ... ){
    va_list args;

    va_start ( args, format );
    openlog ( "pam_require", LOG_CONS|LOG_PID, LOG_AUTH );
    vsyslog ( err, format, args );
    va_end ( args );
    closelog ( );
}


/* check if user is in given group */
int check_groups ( const char *user, const char *groupname ) {
  int i;
  struct group *grp;
  struct passwd *pwd;

  /* find GID for required group */
  grp = getgrnam ( groupname );
  if ( grp == NULL ) {
    _pam_log ( LOG_ERR, "Group '%s' does not exist", groupname );
    return 0;
  }

  /* find UID for current user */
  pwd = getpwnam(user);
  if ( pwd == NULL ) {
    _pam_log ( LOG_ERR, "User '%s' does not exist", user );
    return 0;
  }
 
  /* check for primary group */
  if (pwd->pw_gid == grp->gr_gid) {
    return 1;
  }
  
  /* check for secondary group membership */
  i = 0;
  while (grp->gr_mem[i] != NULL) {
    if (strcmp (user, grp->gr_mem[i]) == 0){
      return 1;
    }
    i++;
  }

  return 0;
}



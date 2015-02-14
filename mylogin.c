/*
 * mylogin.c
 * Shows user info from local pwfile.
 *  
 * Usage: userinfo username
 */

#define _XOPEN_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pwdblib.h"   /* include header declarations for pwdblib.c */
// so that I can use getpass()
#include <pwd.h>
#include <unistd.h>

/* Define some constants. */
#define USERNAME_SIZE (32)
#define NOUSER (-1)
#define PASSWORD_SIZE (128) // according to passwd


int print_info(const char *username)
{
  struct pwdb_passwd *p = pwdb_getpwnam(username);
  if (p != NULL) {
    printf("Name: %s\n", p->pw_name);
    printf("Passwd: %s\n", p->pw_passwd);
    printf("Uid: %u\n", p->pw_uid);
    printf("Gid: %u\n", p->pw_gid);
    printf("Real name: %s\n", p->pw_gecos);
    printf("Home dir: %s\n",p->pw_dir);
    printf("Shell: %s\n", p->pw_shell);
	return 0;
  } else {
    return NOUSER;
  }
}

void read_username(char *username)
{
  printf("login: ");
  fgets(username, USERNAME_SIZE, stdin);

  /* remove the newline included by getline() */
  username[strlen(username) - 1] = '\0';
}



int main(int argc, char **argv)
{
  /* 
   * Write "login: " and read user input. Copies the username to the
   * username variable.
   */
  char username[USERNAME_SIZE];
  read_username(username);

  /* Write "Password: " and read user password without echoing it. */
  char password[PASSWORD_SIZE]; // char array (string) with room for the password
  char *pw[PASSWORD_SIZE]; // pointers to the chars
  pw[0] = getpass("Password: "); // read the password safely

  printf("\nThe password typed was: \"%s\"\n", *pw);

  /*
   * Check password
   */
  struct pwdb_passwd *pwentry = pwdb_getpwnam(username);

  if (pwentry != NULL)
  {
    printf("pwentry->pw_uid: %d\n", pwentry->pw_uid);
    printf("pwentry->pw_passwd: %s\n", pwentry->pw_passwd);
    // hash the password
    char hash[PASSWORD_SIZE];
    char *phash[PASSWORD_SIZE];
    phash[0] = crypt(password, "salt");

    printf("hash: %s\n", *phash);
    int result;
    //int *presult = strcmp(hash, pwentry->pw_passwd);
    //printf("result: %i\n", *presult);

  } else
  {
    printf("Unknown user or incorrect password.\n");
  }

  return 0;
}
  
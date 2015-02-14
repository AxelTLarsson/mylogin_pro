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

  /* Write "Password: " and read user password input without echoing it. */
  char *entered_pw[PASSWORD_SIZE];
  *(entered_pw) = getpass("Password: "); // read the password safely

  printf("\nThe password typed was: \"%s\"\n", *entered_pw);

  /*
   * Check username and password
   */
  struct pwdb_passwd *pwentry = pwdb_getpwnam(username);

  if (pwentry != NULL)
  {

    // Retrieve the salt (by copying so that we do not lose information)
    // Test copying strings
    char *source[128], buf[128];
    *(source) = "hejsan svejsan";
    strlcpy(buf, source[0], sizeof(buf));
    printf("source: %s\n", *source);
    printf("buf: %s\n", buf);

    source[0] = "Bajs";
    printf("source: %s\n", *source);
    printf("buf: %s\n", buf);

    char salt[3];
    strlcpy(salt, pwentry->pw_passwd, 3);
    printf("salt: %s\n", salt);


    // Hash entered password (overwrite memory where entered password resides with the hash instead)

    // Compare

    // Print some info
    printf("pwentry->pw_uid: %d\n", pwentry->pw_uid);
    printf("pwentry->pw_passwd: %s\n", pwentry->pw_passwd);


    char *stored_hash[PASSWORD_SIZE];
    *(stored_hash) = pwentry->pw_passwd;
    printf("TEST: %s\n", *stored_hash);

/*
    // Save the stored hashed password for later comparison
    char h[PASSWORD_SIZE];
    char *hashed_passwd[PASSWORD_SIZE];
    *hashed_passwd[0] = pwentry->pw_passwd;
    printf("hashed_passwd: %s\n", hashed_passwd); 
  

    
    // Get the salt
    char salt[2];
    char *psalt;
    psalt = pwentry->pw_passwd;
    psalt[2] = '\0';
    printf("salt %s\n", psalt);

    // hash the entered password
    char hash[PASSWORD_SIZE];
    char *phash[PASSWORD_SIZE];
    phash[0] = crypt(*pw, psalt);

    printf("hash: %s\n", *phash);
    
    
    printf("comparing '%s' with '%s'\n", *phash, *hashed_passwd);
    int result = strcmp(*phash, psalt);
    printf("result: %i\n", result);

    */

  } else
  {
    printf("Unknown user or incorrect password.\n");
  }

  return 0;
}
  
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
  while (1)
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

    // printf("\nThe password typed was: \"%s\"\n", *entered_pw);

    /*
     * Check username and password
     */
    struct pwdb_passwd *pwentry = pwdb_getpwnam(username);

    if (pwentry != NULL)
    {

      // Retrieve the salt (by copying so that we do not lose information)
      char salt[3];
      strncpy(salt, pwentry->pw_passwd, 3);
      // printf("salt: %s\n", salt);

      // Hash entered password
      char *entered_hash[PASSWORD_SIZE];
      *(entered_hash) = crypt(*entered_pw, salt);
      // printf("entered_hash: %s\n", *entered_hash);

      // Retrieve stored hash
      char *stored_hash[PASSWORD_SIZE];
      *(stored_hash) = pwentry->pw_passwd;
      // printf("stored_hash: %s\n", *stored_hash); 
    
      // Compare stored hash with entered password hash
      // printf("comparing '%s' with '%s'\n", *entered_hash, *stored_hash);
      if (strcmp(*entered_hash, *stored_hash) == 0)
      {
        printf("User authenticated succesfully.\n");
        return 0;
      }

    } 

    printf("Unknown user or incorrect password.\n");
    
  }
}
  
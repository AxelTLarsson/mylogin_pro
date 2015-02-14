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
#define PASSWORD_LEN (128) // maximum allowed password length according to passwd
#define PW_AGE_MAX (10) // password age defined as number of successful logins before reminding user to change password
#define MAX_PW_TRIES (5) // max number of allowed tries before account is locked


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
    printf("Unsuccessful logins: %i\n", p->pw_failed);
    printf("Successful logins: %i\n", p->pw_age);
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
    char *entered_pw[PASSWORD_LEN];
    *(entered_pw) = getpass("Password: "); // read the password safely

    // printf("\nThe password typed was: \"%s\"\n", *entered_pw);

    /*
     * Check username and password
     */
    struct pwdb_passwd *pwentry = pwdb_getpwnam(username);

    if (pwentry != NULL)
    {
      // Check that user account isn't locked
      if (pwentry->pw_failed >= MAX_PW_TRIES)
      {
        printf("User account is locked, max tries exceeded.\nAsk administrator to reset the file 'pw_failed' in pwfile.\n");
        return 1;
      }

      // Retrieve the salt (by copying so that we do not lose information)
      char salt[3];
      strlcpy(salt, pwentry->pw_passwd, 3);
      // printf("salt: %s\n", salt);

      // Hash entered password
      char *entered_hash[PASSWORD_LEN];
      *(entered_hash) = crypt(*entered_pw, salt);
      // printf("entered_hash: %s\n", *entered_hash);

      // Retrieve stored hash
      char *stored_hash[PASSWORD_LEN];
      *(stored_hash) = pwentry->pw_passwd;
      // printf("stored_hash: %s\n", *stored_hash); 
    
      // Compare stored hash with entered password hash
      // printf("comparing '%s' with '%s'\n", *entered_hash, *stored_hash);
      if (strcmp(*entered_hash, *stored_hash) == 0)
      {
        printf("User authenticated succesfully.\n");
        // Reset pw_failed counter
        pwentry->pw_failed = 0;

        // Increment pw_age
        if (++pwentry->pw_age >= PW_AGE_MAX)
        {
          printf("Please change your password, it is becoming old.\n");
        }

        pwdb_update_user(pwentry);

        return 0;
      }
      
      // Increment pw_failed counter
      pwentry->pw_failed++;
      pwdb_update_user(pwentry);

    } 

    printf("Unknown user or incorrect password.\n");
  
    
  }
}
  
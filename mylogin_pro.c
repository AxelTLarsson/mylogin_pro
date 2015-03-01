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
#include <signal.h>
#include <wait.h>  // get rid of "warning: implicit declaration of function ‘waitpid’"
#include <errno.h> // get some sweet errors
#include <grp.h>  // allows us to change supplementary groups

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

/* Signal handler */
void sig_handler(int signo)
{
  if (signo == SIGINT)
  {
    printf("CTRL+C received.\n");
  }
  if (signo == SIGQUIT)
  {
    printf("SIGQUIT received.\n");
  }
  if (signo == SIGHUP)
  {
    printf("SIGHUP received.\n");
  }
}

/* Start shell for user after successful authentication */
int open_shell(char * user, char *pref_shell, uid_t uid, gid_t gid)
{
  #define PROGRAM "/usr/bin/xterm"

  pid_t pid; 
  int status;

  pid = fork();

  if (pid==0) {
    /* Set righ real and effective user and group */  
    
    // Set GID
    setgid(gid);
    switch(errno)
    {
     case EINVAL:
      printf("EINVAL: The value of the new euid argument is invalid.\n");
      break;
    case EPERM:
      printf("EPERM: The process may not change to the specified GID.\n");
      break;
    }

    // Fix supplementary groups
    initgroups(user, gid);
    if (errno == EPERM)
    {
      printf("EPERM: The calling process is not privileged.\n");
    }
 

    // Set UID
    setuid(uid);
    // Check for errors
    switch(errno)
    {
     case EINVAL:
      printf("EINVAL: The value of the new euid argument is invalid.\n");
      break;
    case EPERM:
      printf("EPERM: The process may not change to the specified UID.\n");
      break;
    }


   


    /* This is the child process. Run an xterm window */
    execl(PROGRAM,PROGRAM,"-e",pref_shell,"-l",NULL);

    /* if child returns we must inform parent.
     * Always exit a child process with _exit() and not return() or exit().
     */
    _exit(-1);
  } else if (pid < 0) { /* Fork failed */
    printf("Fork faild\n");
    status = -1;
  } else {
    /* This is parent process. Wait for child to complete */
  if (waitpid(pid, &status, 0) != pid) {
    status = -1;
  }
  }

  return status;


}

int main(int argc, char **argv)
{

  // Tell kernel that the function sig_handler should handle signals
  signal(SIGINT, sig_handler);  // interrupt
  signal(SIGQUIT, sig_handler); // quit
  signal(SIGHUP, sig_handler);  // hang up

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
        printf("User account is locked, max tries exceeded.\nAsk administrator to reset the field 'pw_failed' in pwfile.\n");
      } 
      else
      {
        // Retrieve the salt (by copying so that we do not lose information)
        char salt[3];
        strncpy(salt, pwentry->pw_passwd, 3);
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

          open_shell(pwentry->pw_name, pwentry->pw_shell, pwentry->pw_uid, pwentry->pw_gid);
          //return 0;
        }
        else
        {
          printf("Unknown user or incorrect password.\n");  
          // Increment pw_failed counter
          pwentry->pw_failed++;
          pwdb_update_user(pwentry);  
        }
      }
    } else
    {
      printf("Unknown user or incorrect password.\n");  
    }
  }
  return 0;
}
  
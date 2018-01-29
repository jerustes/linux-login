/* $Header: https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/login_linux.c 585 2013-01-19 10:31:04Z pk@CHALMERS.SE $ */

/* gcc -Wall -g -o mylogin login.linux.c -lcrypt */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <sys/types.h>
#include <crypt.h>
#include "pwent.h"

#define TRUE 1
#define FALSE 0
#define LENGTH 16
#define HARD_L 10
#define PENALTY 10

void sighandler() {
	//Signaling handling routines here

	//signal(SIGINT, SIG_IGN);
	int i;
	for(i = 1; i <=31 ; i++)
	{
	   signal(i,SIG_IGN);
	}
	/* Sigaction is recommended instead of signal
		int sigaction(int signum, const struct sigaction *act,
              struct sigaction *oldact);
    */

}


int main(int argc, char *argv[]) {

	mypwent *passwddata;
	/* see pwent.h */

	char important[LENGTH] = "***IMPORTANT***";

	char user[LENGTH];
	char *enc_pass; 		//Encrypted password 
	char prompt[] = "password: ";
	char *user_pass;

	//Password age
	int limit_age = 10;
	//Failed attempts
	int limit_attmp = 5;
	int i_penalty = PENALTY; //penalty counter

	sighandler();

	while (TRUE) {
		/* check what important variable contains - do not remove, part of buffer overflow test */
		printf("Value of variable 'important' before input of login name: %s\n",
				important);

		printf("login: ");
		fflush(NULL); /* Flush all  output buffers */
		__fpurge(stdin); /* Purge any data in stdin buffer */

		/*
		if (gets(user) == NULL) 
			exit(0); 							
		*/

		if(fgets(user, sizeof(user), stdin) == NULL){ //user --> Name



			printf("OVERFLOW");
			exit(0);
		}else{
			/*
			char aux = '\0';
			strtok(user, '\n');
			strcat(user, aux);
			*/
//@TODO polish
			user[strlen(user)-1] = '\0';
		}


		/* check to see if important variable is intact after input of login name - do not remove */
		printf("Value of variable 'important' after input of login name: %*.*s\n",
				LENGTH - 1, LENGTH - 1, important);

		user_pass = getpass(prompt);

		if(mygetpwnam(user) == NULL){
			printf("Login Incorrect \n");
			continue;
		}
		passwddata = mygetpwnam(user); //mypwent struct
		

		if (passwddata != NULL) {
			/* You have to encrypt user_pass for this to work */
			/* Don't forget to include the salt */

			/* We will assume db data is all correct and fitting requisites:
				salt is two-digit correctly and the encryption is done with that one */

			//CRYPT
			enc_pass = crypt(user_pass, passwddata->passwd_salt);


			if (!strcmp(enc_pass, passwddata->passwd)) { //CORRECT LOGIN

				//reset password_failures and age +1
				reset_failed(user, passwddata);
				age_pass(user, passwddata);

				if(passwddata->pwage >= limit_age){ //Password too old, alert!
					printf("*WARNING* Password is too old!\n");
				}

				printf(" You're in !\n");
				break;
				/*  check UID, see setuid(2) */
				/*  start a shell, use execve(2) */

			}
		}
		//Failed attempt
		failed_attmpt(user, passwddata);
		printf("Login Incorrect \n");

		//Brute force limits
			//soft limit
		if(passwddata->pwfailed >= limit_attmp && passwddata->pwfailed < HARD_L){ //Failed too much, give penalty!
			i_penalty = PENALTY;
			printf("Too many failed attempts");

			while(i_penalty <= PENALTY && i_penalty > 0) {
				printf("%d\n", i_penalty);
					sleep(3);
					i_penalty--;
			}
		}

			//HARD limit
		if(passwddata->pwfailed >= HARD_L){
			printf("ATTACK DETECTED. Shutting down...\n");
			sleep(1);
			printf("...\n");
			sleep(1);
			printf("bye\n");
			sleep(1);
			exit(0);
			//system("shutdown -P now");
		}
		/* All this, assuming the attacker doesn´t close the program and open it again,
		   in which case, the soft limit "time penalty" would be avoided and
		   the hard limit just kicks you out, so you could go in and try again
			
			possible solutions:
		   HARD: block login even when using the correct password
		*/

	}
	return 0;
}




# Linux Login Shell

A Linux login shell written in C.

## Compile:
`gcc -o mylogin_pro mylogin_pro.c pwdblib.c -lcrypt`

## Run:
`./mylogin_pro`

It should actually be run with sudo, since it should spawn a new terminal defined for each user in `pwfile` but the path `/usr/bin/xterm` might not exist so this will not always work.

username      | password
------------- | -------------
donald        | quack01
scrooge       | quack03
minnie        | cheese02

## Exit:
Since this is a proper implementation (sort of) it cannot be killed with `Ctrl + C`, instead do:
`killall mylogin_pro` from another terminal tab/window.

## Docs
[Documentation](./docs/lab2.pdf)

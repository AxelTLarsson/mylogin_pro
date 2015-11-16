# Linux Login Shell

A Linux login shell written in C.

## Compile:
`gcc -o mylogin_pro mylogin_pro.c pwdblib.c -lcrypt`

## Run:
`./mylogin_pro`

## Exit:
Since this is a proper implementation (sort of) it cannot be killed with `Ctrl + C`, instead do:
`killall mylogin_pro` from another terminal tab/window.

## Docs
[Documentation](./docs/lab2.pdf)

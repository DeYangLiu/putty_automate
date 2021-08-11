# background
SecureCRT can execute python scripts, it can send commands based on the outputs of a serial port.

putty/plink has standard input and output, we can do something.

fork a process running the plink,
rediect its stdin and stdout,
and scripting what you ever wants!

# usage
step1:
 use putty.exe, naming a serial port as `serial`.
step2:
 run the io_redirect.exe

# scripting
edit redirect_plink_io.c
gcc redirect_plink_io.c -o io_redirect

# TODO
1. async read and write serial ports;
2. passing ctrl-c signal to plink.exe;

import termios
import socket
import select
import enum
import sys
import tty

from paramiko.py3compat import u

class Decryption(enum.Enum):
    bfinject = 0
    clutch = 1

def interactive_shell(chan, callback=None):
    oldtty = termios.tcgetattr(sys.stdin)
    try:
        tty.setraw(sys.stdin.fileno())
        tty.setcbreak(sys.stdin.fileno())
        chan.settimeout(0.0)

        while True:
            r, w, e = select.select([chan, sys.stdin], [], [])
            if chan in r:
                try:
                    x = u(chan.recv(1024))
                    if len(x) == 0:
                        sys.stdout.write("\r\n[+] Terminating SSH connection\r\n")
                        sys.stdout.flush()
                        if callback != None:
                            callback()
                        break
                    sys.stdout.write(x)
                    sys.stdout.flush()
                except socket.timeout:
                    pass
            if sys.stdin in r:
                x = sys.stdin.read(1)
                if len(x) == 0:
                    break
                chan.send(x)

    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, oldtty)

def isNumber(string):
    try: 
        int(string)
        return True
    except ValueError:
        return False

def usage():
    print "\nUsage: ios_ss.py -l <port> [-p <password>] -a <app_name> [-c|-b] [-i] [-f]"
    print "\t-l [--lport]: Local SSH port forwarding (has to be an Int)."
    print "\t-p [--password]: (optional) Device's root password (default is `alpine`)."
    print "\t-a [--app]: iOS Application name."
    print "\t-c : Use Clutch to decrypt."
    print "\t-b : Use BFInject to decrypt (default)."
    print "\t-i : Opens a SSH connection with the device and gives an interactive shell, ignoring the decryption task."
    print "\t-f [--full]: Performs the decryption, decrypted app transfer, unpacking and file organization tasks."

def parse_clutch_apps(apps):
    parsed = {}
    for app in apps:
        components = app.split(":")
        app_id = components[0].strip()
        app_name = components[1].strip()
        parsed[app_id] = app_name
    return parsed

def execute_command(ssh_client, cmd):
    stdin, stdout, stderr = ssh_client.exec_command(cmd)
    output_lines = []
    while not stdout.channel.exit_status_ready():
        try:
            output = stdout.readlines()
            if len(output) > 0:
                for line in output:
                    output_lines.append(line.rstrip())
        except:
            while True:
                output = stdout.read()
                buffer_str = ''
                # Remove none ascii characters
                for c in output:
                    if ord(c) >= 0 or ord(c) <= 255:
                        buffer_str += c
                if len(buffer_str) > 0:
                    for line in buffer_str.split('\n'):
                        output_lines.append(line.rstrip())
                if output == '':
                    break
            
    return output_lines

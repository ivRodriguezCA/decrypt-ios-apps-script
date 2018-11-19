#!/usr/bin/python

import subprocess
import paramiko
import helpers
import signal
import getopt
import sys
import os

from time import sleep

#Global variables
itnl_pid = None
root_password = 'alpine'
app_name = None
ssh_client = paramiko.SSHClient()

def start_itunnel(lport, interactive, decryption_type):
	print "[+] Starting iTunnel on local port " + lport
	args = ['itnl', '--lport', lport, '--iport', '22']
	itnl_process = subprocess.Popen(args, stdout=subprocess.PIPE, preexec_fn=os.setsid)
	global itnl_pid
	itnl_pid = itnl_process.pid
	while True:
		output = itnl_process.stdout.readline()
		if "[INFO]" in output:
			print output.replace('[INFO]','[+]').rstrip()
			if "Device connected" in output:
				break
		if "[ERROR]" in output:
			print "[-] Error starting iTunnel (maybe there's another app using the same port)"
			sys.exit()
	ssh_into_device(lport, interactive, decryption_type)

def cleanup():
	if ssh_client != None and ssh_client.get_transport() != None and ssh_client.get_transport().is_active():
		print "[+] Stopping SSH connection"
		ssh_client.close()

	global itnl_pid
	if itnl_pid != None:
		print "[+] Stopping iTunnel"
		os.killpg(os.getpgid(itnl_pid), signal.SIGTERM)
		itnl_pid = None

def interactive_shell_callback():
	cleanup()

def print_usage():
	helpers.usage()

def ssh_into_device(lport, interactive, decryption_type):
	print "[+] SSH'ing into device"
	try:
		ssh_client.load_system_host_keys()
		ssh_client.set_missing_host_key_policy(paramiko.WarningPolicy)
		ssh_client.connect('localhost', port=lport, username='root', password=root_password)
		if interactive:
			interactive_shell()
		else:
			decrypt_application(decryption_type, lport)
			
	except Exception as e:
		print "[-] SSH error: ", e
		cleanup()
		sys.exit()
	finally:
		cleanup()

def decrypt_application(decryption_type, lport):
	if decryption_type == helpers.Decryption.bfinject:
		decrypt_with_bfinject()
	elif decryption_type == helpers.Decryption.clutch:
		decrypt_with_clutch()

	print "[+] Waiting for 20s for decryption to be done"
	sleep(20)
	transfer_decrypted_app(lport)

def decrypt_with_bfinject():
	print "[+] Waiting 10s for you to launch the app on your device"
	sleep(10)
	print "[+] Time's up!"
	print "[+] Decypting application using `bfinject`"
	cmd = 'cd /jb/bfinject; bash bfinject -P ' + app_name + ' -L decrypt\n'
	print "\t# cd /jb/bfinject"
	print "\t# bash bfinject -P '" + app_name + "' -L decrypt"
	output = helpers.execute_command(ssh_client, cmd)
	for op in output:
		print "\t", op

def decrypt_with_clutch():
	print "[+] Decypting application using `clutch`"
	cmd = 'clutch -i\n'
	print "\t# ", cmd.rstrip()
	apps = helpers.execute_command(ssh_client, cmd)
	for ap in apps:
		print "\t", ap

	parsed_apps = helpers.parse_clutch_apps(apps)
	found_app_id = None
	found_app_name = None
	for a_id in parsed_apps:
		a_name = parsed_apps[a_id]
		if app_name in a_name:
			found_app_id = a_id
			found_app_name = a_name
			break

	if found_app_id == None:
		print "[-] Aborting. No app found with the name `", app_name, "`"
		cleanup()

	else:
		print "[+] Decrypting `" + found_app_name + "`"
		cmd = 'clutch -d ' + found_app_id + '\n'
		print "\t# ", cmd.rstrip()
		output = helpers.execute_command(ssh_client, cmd)
		for op in output:
			print "\t", op

def find_decrypted_path():
	sftp = ssh_client.open_sftp()
	sftp.chdir("/private/var/mobile/Containers/Data/Application/")
	apps = sftp.listdir()
	for app in apps:
		try:
			plist_file_path = '/private/var/mobile/Containers/Data/Application/' + app + '/.com.apple.mobile_container_manager.metadata.plist'
			plist_file = sftp.file(plist_file_path)
			while True:
				line = plist_file.read()
				buffer_str = ''
				# Remove none ascii characters
				for c in line:
					if ord(c) >= 0 or ord(c) <= 255:
						buffer_str += c
				if len(buffer_str) > 0 and app_name.lower() in buffer_str:
					sftp.close()
					return '/private/var/mobile/Containers/Data/Application/' + app + '/Documents/decrypted-app.ipa'
				if line == '':
					break
				
		except IOError:
			continue

	sftp.close()
	return None

def transfer_decrypted_app(lport):
	remote_path = find_decrypted_path()
	desktop_path = os.path.expanduser('~/Desktop/')
	local_path = desktop_path + 'decrypted-app.ipa'
	if remote_path != None:
		print "[+] Transfering dectypted app to ~/Desktop"
		sftp = ssh_client.open_sftp()
		sftp.get(remote_path, local_path)
		sftp.close()
	else:
		print "[-] Aborting. Could not find `decrypted-app.ipa` in any of the Applications' directories"
		cleanup()

def interactive_shell():
	print "[+] Initiating an interactive shell"
	channel = ssh_client.get_transport().open_session()
	channel.get_pty()
	channel.invoke_shell()
	helpers.interactive_shell(channel, interactive_shell_callback)

def main(argv):
	try:
		lport = None
		interactive = False
		decryption_type = helpers.Decryption(0)

		options = "hl:p:a:cbi"
		long_options = ["lport=","password=","app="]
		opts, args = getopt.getopt(argv, options, long_options)

		#Parsing command line options
		for opt, arg in opts:
			if opt == '-h':
				print_usage()
				sys.exit()
			elif opt in ("-l", "--lport"):
				lport = arg
			elif opt in ("-p", "--password"):
				global root_password
				root_password = arg
			elif opt in ("-a", "--app"):
				global app_name
				app_name = arg.strip()
			elif opt == '-c':
				decryption_type = helpers.Decryption(1)
			elif opt == '-b':
				decryption_type = helpers.Decryption(0)
			elif opt == '-i':
				interactive = True

		#Checking the reminder of the command line options
		if len(args) > 0:
			if args[-1] == '-c':
				decryption_type = helpers.Decryption(1)
			elif args[-1] == '-b':
				decryption_type = helpers.Decryption(0)
			elif args[-1] == '-i':
				interactive = True

		if lport != None and helpers.isNumber(lport) and app_name != None:
			start_itunnel(lport, interactive, decryption_type)
		else:
			print_usage()
			sys.exit()

	except getopt.GetoptError:
		print_usage()
		sys.exit()
	except SystemExit as e:
		pass
	except KeyboardInterrupt:
		cleanup()
	except Exception as e:
		print "[-] Unexpected error: ", e
		cleanup()
		print_usage()
		sys.exit()

if __name__ == '__main__':
    main(sys.argv[1:])
#!/usr/bin/python

import subprocess
import paramiko
import helpers
import zipfile
import signal
import shutil
import getopt
import sys
import os

from time import sleep

#Global variables
itnl_pid = None
root_password = 'alpine'
app_name = None
ssh_client = paramiko.SSHClient()

def start_itunnel(lport):
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

def cleanup():
	if ssh_client != None and ssh_client.get_transport() != None and ssh_client.get_transport().is_active():
		print "[+] Stopping SSH connection"
		ssh_client.close()

	global itnl_pid
	if itnl_pid != None:
		print "[+] Stopping iTunnel"
		os.killpg(os.getpgid(itnl_pid), signal.SIGTERM)
		itnl_pid = None

	sys.exit()

def interactive_shell_callback():
	cleanup()

def print_usage():
	helpers.usage()

def ssh_into_device(lport, interactive, decryption_type, full_reversing):
	print "[+] SSH'ing into device"
	try:
		ssh_client.load_system_host_keys()
		ssh_client.set_missing_host_key_policy(paramiko.WarningPolicy)
		ssh_client.connect('localhost', port=lport, username='root', password=root_password)
		if interactive:
			interactive_shell()
		else:
			decrypt_application(decryption_type, lport, full_reversing)
			
	except Exception as e:
		print "[-] SSH error: ", e
		cleanup()
		sys.exit()
	finally:
		cleanup()

def decrypt_application(decryption_type, lport, full_reversing):
	if decryption_type == helpers.Decryption.bfinject:
		decrypt_with_bfinject()
	elif decryption_type == helpers.Decryption.clutch:
		decrypt_with_clutch()

	print "[+] Waiting for 20s for decryption to be done"
	sleep(20)
	transfer_decrypted_app(lport)
	if full_reversing:
		unpack_decrypted()
		organize_files()
		convert_plists()

def decrypt_with_bfinject():
	print "[+] Waiting 10s for you to launch the app on your device"
	sleep(10)
	print "[+] Time's up!"
	print "[+] Decypting application using `bfinject`"
	cmd = 'cd /jb/bfinject; bash bfinject -P ' + app_name + ' -L decrypt\n'
	print "\t# cd /jb/bfinject"
	print "\t# bash bfinject -P '" + app_name + "' -L decrypt"
	output = helpers.execute_command(ssh_client, cmd)
	has_error = False
	for op in output:
		print "\t", op
		if "[!]" in op:
			has_error = True
	if has_error:
		print "[-] Aborting. There was an error with bfinject"
		cleanup()
		sys.exit()

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
		print "[+] Transfering decrypted app to ~/Desktop"
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

def unpack_decrypted():
	print "[+] Extracting the apps' contents"
	desktop_path = os.path.expanduser('~/Desktop/')
	local_path = desktop_path + 'decrypted-app.ipa'
	decrypted_zip_path = desktop_path + 'decrypted-app.zip'
	extract_folder = desktop_path + 'DecryptedContent/'
	payload_folder = extract_folder + 'Payload/'
	# Copy the .ipa to a .zip
	os.popen('cp ' + local_path + ' ' + decrypted_zip_path)
	# Create a new folder to extract its content
	os.mkdir(extract_folder)
	# Extract .zip contents
	zip_ref = zipfile.ZipFile(decrypted_zip_path, 'r')
	zip_ref.extractall(extract_folder)
	zip_ref.close()
	files = os.listdir(payload_folder)
	# Move all the files within the .app
	for file in files:
		if '.app' in file:
			app_payload_path = payload_folder + file
			os.popen('mv ' + app_payload_path + '/* ' + extract_folder)
			os.popen('rm -rf ' + app_payload_path)
			break
	# Remove .zip file
	os.popen('rm  ' + decrypted_zip_path)

def organize_files():
	print "[+] Starting to organize files."
	desktop_path = os.path.expanduser('~/Desktop/')
	extract_folder = desktop_path + 'DecryptedContent/'
	# Create media folder and move files
	media_path = extract_folder + 'media/'
	os.mkdir(media_path)
	os.popen('mv ' + extract_folder + '*.png ' + media_path)
	os.popen('mv ' + extract_folder + '*.jpg ' + media_path)
	os.popen('mv ' + extract_folder + '*.jpeg ' + media_path)
	os.popen('mv ' + extract_folder + '*.mov ' + media_path)
	os.popen('mv ' + extract_folder + '*.mp3 ' + media_path)
	os.popen('mv ' + extract_folder + '*.mp4 ' + media_path)
	# Create nibs folder and move files
	nibs_path = extract_folder + 'nibs/'
	os.mkdir(nibs_path)
	os.popen('mv ' + extract_folder + '*.nib ' + nibs_path)
	os.popen('mv ' + extract_folder + '*.storyboardc ' + nibs_path)
	# Create json folder and move files
	jsons_path = extract_folder + 'jsons/'
	os.mkdir(jsons_path)
	os.popen('mv ' + extract_folder + '*.json ' + jsons_path)
	# Create plist folder and move files
	plists_path = extract_folder + 'plists/'
	os.mkdir(plists_path)
	os.popen('mv ' + extract_folder + '*.plist ' + plists_path)
	# Create html folder and move files
	htmls_path = extract_folder + 'htmls/'
	os.mkdir(htmls_path)
	os.popen('mv ' + extract_folder + '*.html ' + htmls_path)
	print "[+] Done organizing files."

def convert_plists():
	desktop_path = os.path.expanduser('~/Desktop/')
	extract_folder = desktop_path + 'DecryptedContent/plists'
	files = os.listdir(extract_folder)
	if len(files) > 0:
		print "[+] converting .plist files to xml format."
	for file in files:
		os.popen('plutil -convert xml1 ' + file)

def main(argv):
	try:
		lport = None
		interactive = False
		full_reversing = False
		decryption_type = helpers.Decryption(0)

		options = "hl:p:a:cbif"
		long_options = ["lport=","password=","app=","full="]
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
			elif opt in ("-f", "--full"):
				full_reversing = True

		#Checking the reminder of the command line options
		if len(args) > 0:
			if args[-1] == '-c':
				decryption_type = helpers.Decryption(1)
			elif args[-1] == '-b':
				decryption_type = helpers.Decryption(0)
			elif args[-1] == '-i':
				interactive = True

		# desktop_path = os.path.expanduser('~/Desktop/')
		# extract_folder = desktop_path + 'DecryptedContent/'
		# media_path = extract_folder + 'media/'
		# print 'mv ' + extract_folder + '*.png ' + media_path
		# return

		if lport != None and helpers.isNumber(lport) and app_name != None:
			start_itunnel(lport)
			ssh_into_device(lport, interactive, decryption_type, full_reversing)
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
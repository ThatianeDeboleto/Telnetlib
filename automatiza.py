import getpass
import telnetlib

HOST = "localhost"
user = input("Enter your remote account: ")
password = getpass.getpass()

tn = telnetlib.Telnet(HOST)

tn.read_until(b"login: ")
tn.write(user.encode('ascii') + b"\n")
if password:
    tn.read_until(b"Password: ")
    tn.write(password.encode('ascii') + b"\n")

tn.write(b"ls\n")
tn.write(b"exit\n")

print(tn.read_all().decode('ascii'))


# Exercise 2: Python code to get the running configuration
import getpass
import telnetlib

IP = input("Enter the IP Address :")
user = input("Enter your username :")
password = getpass.getpass()
tn = telnetlib.Telnet(IP)
tn.read_until(b"Username: ")
tn.write(user.encode("ascii") + b"\n")
if password:
    tn.read_until(b"Password: ")
    tn.write(password.encode("ascii") + b"\n")
tn.write(b"enable\n")
tn.write(b"cisco\n")
tn.write(b"terminal length 0\n")
tn.write(b"show run\n")
tn.write(b"exit\n")

# Exercise 1: Python code to Change the Hostname using telnet.
import getpass
import telnetlib

# Declare a variable for storing the IP address
IP = "192.168.100.20"

# Declare a variable for storing username
user = input("Enter your username :")

# Use getpass module which we imported, to get the password from the user
password = getpass.getpass()

# Pass the IP variable value in to the telnetlib
tn = telnetlib.Telnet(IP)

# Now the code will read each output from the cisco switch 
tn.read_until(b"Username: ")
tn.write(user.encode("ascii") + b"\n")
if password:
    tn.read_until(b"Password: ")
    tn.write(password.encode("ascii") + b"\n")

''' Now specify the commands in the right sequence.enable password,
then change to configuration terminal and change the hostname, 
finally save the configuration and exit '''

tn.write(b"enable\n")
tn.write(b"cisco\n")
tn.write(b"conf t\n")
tn.write(b"hostname CoreSW\n")
tn.write(b"end\n")
tn.write(b"write memory\n")
tn.write(b"exit\n")

print(tn.read_all().decode('ascii'))

# Exercise 4: Create multiple VLANs using python for loop
import getpass
import telnetlib
IP = input("Enter IP Address: ")
user = input("Enter your username: ")
password = getpass.getpass()
tn = telnetlib.Telnet(IP)
tn.read_until(b"Username: ")
tn.write(user.encode("ascii") + b"\n")
if password:
    tn.read_until(b"Password: ")
    tn.write(password.encode("ascii") + b"\n")
tn.write(b"enable\n")
tn.write(b"cisco\n")
tn.write(b"conf t\n")

''' Create a for loop to create multiple VLANs,
also note that we are converting the value on 'n' 
to string value using str() command '''
for n in range (2, 10): # with number 2 and keep increment until 10, but 10 is not included
    tn.write(b"vlan " + str(n).encode("ascii") + b"\n")
    tn.write(b"name VLAN_" + str(n).encode("ascii") + b"\n")

tn.write(b"end\n")
tn.write(b"show vlan br\n\n")
tn.write(b"exit\n")
print(tn.read_all().decode("ascii"))

import getpass
import telnetlib

# If the credentials are different for each switches, put the code inside the for loop
user = input("Enter your username :")
password = getpass.getpass()

#  Open the file 
f = open("switches.txt")

# For loop will get the IP from the file one by one and execute the code
for IP in f:
    IP = IP.strip()
    print("Configuring Switch " + (IP))
    tn = telnetlib.Telnet(IP)
    tn.read_until(b"Username: ")
    tn.write(user.encode("ascii") + b"\n")
    if password:
        tn.read_until(b"Password: ")
        tn.write(password.encode("ascii") + b"\n")
    tn.write(b"enable\n")
    tn.write(b"cisco\n")
    tn.write(b"conf t\n")
    
    for n in range (2, 10):
        tn.write(b"vlan " + str(n).encode("ascii") + b"\n") 
        tn.write(b"name VLAN_" + str(n).encode("ascii") + b"\n") 
    tn.write(b"end\n")
    tn.write(b"show vlan br\n\n")
    tn.write(b"exit\n")
    print(tn.read_all().decode("ascii"))
    
    # Exercise 8: Backup the configuration of all switches
import getpass
import telnetlib
user = input("Enter your username :")
password = getpass.getpass()
f = open("switches.txt")
for IP in f:
    # IP.strip() is used to remove any white-spaces 
    IP = IP.strip()
    print("Taking backup of Switch " + (IP))
    tn = telnetlib.Telnet(IP)
    tn.read_until(b"Username: ")
    tn.write(user.encode("ascii") + b"\n")
    if password:
        tn.read_until(b"Password: ")
        tn.write(password.encode("ascii") + b"\n")
    tn.write(b"enable\n")
    tn.write(b"cisco\n")
    # terminal length 0 command show configuration portion in one go
    tn.write(b"terminal length 0\n")
    tn.write(b"show run\n")
    tn.write(b"exit\n")
    #read all the output of the operations to a variable named as output
    output = tn.read_all()
    #opening a file SW+IP address with write permission
    config = open("SW" + IP, "w")
    #write the configurations to the config variable, for each switch
    config.write(output.decode("ascii"))
    config.write("\n")
    #close the files opened
    config.close()
    print(tn.read_all().decode("ascii"))
    
    # Python telnetlib  
import getpass
import telnetlib

commands = ["terminal length 0",
            "sh ip int bri",
            "exit"
            ]

IP = '192.168.10.10'
user = input("Enter your username :")
password = getpass.getpass()


def send_cmd(command):
    '''send commands from list'''
    for cmd in command:
        tn.write(cmd.encode('ascii') + b"\n")
    result = tn.read_all().decode('ascii')
    return result
    
tn = telnetlib.Telnet(IP)
tn.read_until(b"Username: ")
tn.write(user.encode("ascii") + b"\n")
if password:
    tn.read_until(b"Password: ")
    tn.write(password.encode("ascii") + b"\n")

output = send_cmd(commands)
print(output)
print(tn.read_all().decode('ascii'))

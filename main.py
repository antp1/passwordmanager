import re
#from passlib.hash import sha256_crypt
import base64

class PasswordManager(object):
    '''
    The PasswordManager class should have just 2 member variable, 
    which will store the user name and the encrypted password (astring).
    '''
    def __init__(self, username, passowrd):
        self.idu = username
        self.pwd = passowrd
    
    '''
    The PasswordManager class should have the following two protected functions
    
    encrypt(string) : takes a password (string) and returns the encrypted form of the password
    '''
    
    #key = b'pRmgMa8T0INjEAfksaq2aafzoZXEuwKI7wDe4c1F8AY='
    def encrypt(self):
        encrypt_pwd = base64.b64encode(self.pwd.encode())
        return encrypt_pwd;
        
    '''
    verifyPassword(string): takes a string (a password) and returns true if, once encrypted, 
                            it matches the encrypted string stored in the the member variable. 
                            Else returns false.
    '''
    def verifyPassword(self):
        try:
            file = open("password.txt",'r')
            line = file.readline()
            while line:
                line = line.strip()
                info = line.split(',')
                info_pwd = base64.b64decode(info[1]).decode('utf-8')
                if self.idu == info[0] and self.pwd == info_pwd :
                   return True
                line = file.readline()
            file.close()
        except:
            return False
        return False;
    '''
    The PasswordManager class should have the following two public functions
    
    validatePassword(string): this takes a string (a password) and returns true if it meets the following criteria
                            - The password must not contain any whitespace
                            - The password must be at least 6 characters long.
                            - The password must contain at least one uppercase and at least one 
                            lowercase letter.
                            - The password must have at least one digit and symbol.
                            If the password doesnot meet the serequirements,the program should 
                            display a message telling the
                            user why the password is invalid,specifically. 
                            It should also continue to loop until the user 
                            enters a valid password.
    '''
    def validatePassword(self):
        password = self.pwd.strip()
        self.pwd = password
        while True:
            if  re.search('\s',self.pwd) is not None:
                print("The password must not contain any whitespace!")
                self.pwd = input("Enter the password again: ")
            elif len(self.pwd) < 6:
                print("The password must be at least 6 characters long!")
                self.pwd = input("Enter the password again: ")
            elif re.search('[0-9]',self.pwd) is None or re.search('[!@#$%^&*()?]',self.pwd) is None:
                print("The password must have at least one digit and symbol!")
                self.pwd = input("Enter the password again: ")
            elif re.search('[A-Z]',self.pwd)is None or re.search('[a-z]',self.pwd) is None: 
                print("The password must contain at least one uppercase and at least one lowercase letter!")
                self.pwd = input("Enter the password again: ")
            
            else:
                break
        return self.pwd;
    
    '''setNewPassword: takes a string (a proposed password). If it meets the criteria in 
                    validatePassword, it encrypts the password and stores it in the member variable 
                    and returns true. Otherwise returns false. Storage
    '''
    def setNewPassword(self):
        with open('password.txt', 'r+') as file:
            allfile = file.read()
            file.seek(0)
            line = allfile.split('\n')
            for i in range(len(line) - 1):
                info = line[i].split(',')
                info_pwd = base64.b64decode(info[1]).decode('utf-8')
                if self.idu == info[0] and self.pwd == info_pwd :
                    self.pwd = input('New Passowrd:')
                    self.validatePassword()
                    file.write(self.idu + ',' + self.encrypt().decode('utf-8') + '\n');
                    print("Changed")
                else:
                    file.write(line[i] + '\n')
            file.truncate();
        
        
       

def registerUser():
    username = input('Username:')
    password = input('Passowrd:')
    user = PasswordManager(username, password)
    password = user.validatePassword()
    encrypt_pwd = user.encrypt()
    try:
        file = open("password.txt",'a')
    except:
    # if file does not exist, create it
        file = open("password.txt",'w')
        
    file.write(username + ',' + encrypt_pwd.decode('utf-8') + '\n');
    file.close();

def login():
    username = input('Username:')
    password = input('Passowrd:')
    user = PasswordManager(username, password)
    if user.verifyPassword() is True:
        print ("Logged In");
    else:
        print ("The user name or password is incorrect.");

def changepassword():
    username = input('Username:')
    password = input('Passowrd:')
    user = PasswordManager(username, password)
    if user.verifyPassword() is True:
        user.setNewPassword()
    else:
        print ("The user name or password is incorrect.");
    
    
    
ans=True
while ans:
    '''The main function should create and use one instance of the PasswordManager class.
       Your program will use the following menu to prompt the user to test the implementation:
       A. New User
       B. Validate Password
       C. Login
       D. Change Password'''
    print("""
    A. New User
    B. Validate Password
    C. Login
    D. Change Password
    """)
    ans=input("What would you like to do? ")
    if ans=="A":
        registerUser()
    elif ans=="B":
        username = input('Username:')
        password = input('Passowrd:')
        user = PasswordManager(username, password)
        password = user.validatePassword()
    elif ans=="C":
        login()
    elif ans=="D":
        changepassword()
    else:
       print("\n Try again");
       

    

from cryptography.fernet import Fernet

'''
This code lets you store passwords in a .txt file called 'passwords' with a bit of encription.
This is NOT a safe way to encrypt stuff, but just fun to have a go at!
'''

# Opens the .txt file and reads/decrypts it
def view():
    with open("passwords.txt", "r") as f:
        for line in f.readlines():
            data = line.rstrip()
            user, passw, use = data.split("|")
            print("User:", user, "| Password:", fer.decrypt(passw.encode()).decode(), "| Usage:", use)

# Adds the information to the .txt file, encrypting the password
def add():
    name = input("Account name: ")
    pwd = input("Password: ")
    usage = input("Where is this password from: ")
    with open("passwords.txt", "a") as f:
        f.write(name + "|" + fer.encrypt(pwd.encode()).decode() + "|" + usage + "\n")

# Loads the information from the file and returns it
def load_key():
    file = open("key.key", "rb")
    key = file.read()
    file.close()
    return key

# Starts the script
if __name__ == "__main__":
    key = load_key()
    fer = Fernet(key)

    # Generates the loop to add, view or quit the script. A delete function with indexes could be a nice addition for
    # the future.
    while True:
        mode = input("Would you like to add a new password or view existing ones? (View/Add/Quit) ").lower()
        if mode == "quit":
            break
        if mode == "view":
            view()
        elif mode == "add":
            add()
        else:
            print("Invalid mode.")
            continue

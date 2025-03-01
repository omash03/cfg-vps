import Config as cfg
import paramiko as pmk
import os
from scp import SCPClient


SSH = pmk.SSHClient()
SCP = None
newname = input("Enter the name of the new server: ")
password = None
sudo_password = None
add_debug_user = None

SSH.set_missing_host_key_policy(pmk.AutoAddPolicy())

def get_debug_user_input():
    while True:
        user_input = input("Create a debug user on the new server? (y/n): ").strip().lower()
        if user_input in ['y', 'n']:
            add_debug_user = user_input
            return add_debug_user
        else:
            print("Invalid input. Please enter 'y' or 'n'.")

def user_exists(SSH, username):
    stdout = SSH.exec_command(f"getent passwd {username}")
    output = stdout.read().decode().strip()
    return bool(output)

# Function to create an SCP client
def create_scp_client(ssh_client):
    return SCPClient(ssh_client.get_transport())

def cmd_output(stdout, stderr):
    output = stdout.read().decode()
    error = stderr.read().decode()
    print("Output: ", output)
    print("Error: ", error)

# Probably didn't need to support multiple key types, but I was bored
def ssh_connect(SSH, hostname, username, key_path, password=None):
    print(f"Attempting to connect to {hostname} as {username}...")
    
    # Try different key types in order: ED25519 (modern) first, then RSA
    key_types = [
        {"class": pmk.Ed25519Key, "name": "ED25519"},
        {"class": pmk.RSAKey, "name": "RSA"}
    ]
    
    # First try without passphrase
    for key_type in key_types:
        try:
            print(f"Trying {key_type['name']} key without passphrase...")
            private_key = key_type["class"].from_private_key_file(key_path)
            SSH.connect(hostname=hostname, 
                       username=username, 
                       pkey=private_key)
            print(f"Connected using {key_type['name']} key without passphrase.")
            return True
        except FileNotFoundError:
            print(f"Key file not found: {key_path}")
            raise
        except (pmk.ssh_exception.PasswordRequiredException):
            print(f"{key_type['name']} key requires passphrase.")
            continue
        except pmk.ssh_exception.SSHException as e:
            print(f"Failed with {key_type['name']} key: {str(e)}")
            continue
        except Exception as e:
            print(f"Unexpected error with {key_type['name']} key: {str(e)}")
            continue
    
    # If we're here, no key worked without passphrase
    # Try again with passphrase
    passphrase = input("Enter SSH key passphrase (leave blank for password auth): ")
    if passphrase:
        for key_type in key_types:
            try:
                print(f"Trying {key_type['name']} key with passphrase...")
                private_key = key_type["class"].from_private_key_file(key_path, password=passphrase)
                SSH.connect(hostname=hostname, 
                           username=username,
                           pkey=private_key)
                print(f"Connected using {key_type['name']} key with passphrase.")
                return True
            except pmk.ssh_exception.AuthenticationException:
                print(f"Invalid passphrase for {key_type['name']} key.")
                continue
            except pmk.ssh_exception.SSHException as e:
                print(f"Failed with {key_type['name']} key: {str(e)}")
                continue
            except Exception as e:
                print(f"Unexpected error with {key_type['name']} key: {str(e)}")
                continue
    
    # If key authentication failed, try password
    try:
        password = password or input("Enter SSH password: ")
        SSH.connect(hostname=hostname, 
                  username=username, 
                  password=password)
        print("Connected using password authentication.")
        return True
    except pmk.ssh_exception.AuthenticationException:
        print("Authentication failed with all methods.")
        raise
    except Exception as e:
        print(f"Unexpected error during password auth: {str(e)}")
        raise


# Function to execute a command if sudo password required
def exec_sudo_cmd(SSH, cmd):
    print(f"Executing command: {cmd}")
    
    try:
        # Execute command without sudo password first
        command = f"sudo -n {cmd}"
        stdin, stdout, stderr = SSH.exec_command(command)
        output = stdout.read().decode()
        error = stderr.read().decode()
        
        # If successful, no password needed
        if not ('sudo: a password is required' in error):
            print(f"Command executed without sudo password")
            return stdin, stdout, stderr
        
        # If we reach here, sudo password is required
        raise Exception("Sudo password required")

    except Exception:
        print(error) # Debugging
        passwd = input("Enter the sudo password (leave blank if not needed): ")
        
        command = f"sudo -S -p '' {cmd}"
        stdin, stdout, stderr = SSH.exec_command(command, get_pty=True)

        # Only send password if one was provided
        if passwd:
            stdin.write(f'{passwd}\n')
            stdin.flush()
            
        error = stderr.read().decode()
        # Check for incorrect password or command failure
        if 'incorrect password' in error.lower() or 'sudo:' in error.lower():
            print("Error: Incorrect sudo password or command failed.")
        else:
            cmd_output(stdout, stderr)
            print(f"Finished executing command: {cmd}")  # Debugging statement
        
        sudo_password = passwd
        print(f"Executed sudo command: {command}")  # Debugging statement  
        cmd_output(stdout, stderr) # Debugging statement

        return stdin, stdout, stderr


# Function to create a debug user
def create_debug_user():

    if add_debug_user == 'y':
        if not user_exists(SSH, "debug"):
            password = input("Input a password for the debug user: ")
            stdin, stdout, stderr = SSH.exec_command("sudo adduser debug")
            cmd_output(stdout, stderr)
            stdin.write(f'{password}\n')
            cmd_output(stdout, stderr)
            stdin.write(f'{password}\n')
            cmd_output(stdout, stderr)
            stdin.write("debug\n")
            cmd_output(stdout, stderr)
            stdin.write("debug\n")
            cmd_output(stdout, stderr)
    elif add_debug_user == 'n':
        print("Skipping debug user creation.")    
    else:
        print("User 'debug' already exists.")


# Function to move the wireguard config and enable the systemd service
def mv_cfg_en_serv():

    # Move files to new server
    SCP = SCPClient(SSH.get_transport())
    SCP.put(f'tmp/{newname}.conf', f'~/{newname}.conf')
    SCP.put('wg-quick@wg0.service', '~/')
    SCP.close()

    # Remove temporary file from local machine
    if os.path.exists(f'{newname}.conf'):
        os.remove(f'{newname}.conf')
    else:
        print("Cannot remove non-existent file.")

    # TODO: Add check for existing wireguard config and ask if user wants to overwrite or create new conf name
    # Execute Commands on new server
    exec_sudo_cmd(SSH, "apt update && apt upgrade -y && apt install -y wireguard && apt install -y resolvconf")
    exec_sudo_cmd(SSH, f"mv ~/{newname}.conf /etc/wireguard/wg0.conf")
    exec_sudo_cmd(SSH, "mv ~/wg-quick@wg0.service /etc/systemd/system/wg-quick@wg0.service")
    exec_sudo_cmd(SSH, "systemctl enable wg-quick@wg0.service")
    exec_sudo_cmd(SSH, "systemctl start wg-quick@wg0.service")


def main():
    # TODO: Add sudo compatibility for all possible sudo commands on vpn server

    # SSH to VPN server
    sudo_password = None
    ssh_connect(SSH, cfg.HOST, cfg.USERNAME, cfg.KEY_PATH)
    print("Connected to VPN server.")

    # Check if the VPN configuration file already exists
    stdin, stdout, stderr = SSH.exec_command(f"test -f ~/configs/{newname}.conf && echo exists || echo not exists")
    file_status = stdout.read().decode().strip()
    print(f"File Status: {file_status}")


    if file_status == "exists":
        use_existing = input(f"The configuration file for {newname} already exists. Do you want to use the existing configuration? (y/n): ").strip().lower()
        if use_existing == 'y':
            print(f"Using existing configuration for {newname}.")

            # Store the VPN config
            SCP = SCPClient(SSH.get_transport())
            SCP.get(f'~/configs/{newname}.conf', f'tmp/{newname}.conf')
            SCP.close()
            sudo_password = None

            # Add PersistentKeepalive to newname.conf locally if not already present
            with open(f'tmp/{newname}.conf', 'r+') as file:
                lines = file.readlines()
                if not lines[-1].strip().startswith('PersistentKeepalive'):
                    file.write('PersistentKeepalive = 25\n')

            # SSH to new server
            SSH.close()
            ssh_connect(SSH, cfg.NEW_HOST, cfg.NEW_USER, cfg.NEW_USER_KEY)

            mv_cfg_en_serv()

            SSH.close()
            print("Disconnected from new server.")
        else:
            print("Exiting.")
            SSH.close()
            exit()
    else:
        # Create VPN Configuration
        stdin, stdout, stderr = SSH.exec_command("sudo pivpn -a")
        stdin.write(newname + "\n")
        stdin.flush()
        cmd_output(stdout, stderr)

        # Add PersistentKeepalive to wg0.conf above the last line
        stdin, stdout, stderr = exec_sudo_cmd(SSH, "sed -i '$i PersistentKeepalive = 25' /etc/wireguard/wg0.conf")
        cmd_output(stdout, stderr)

        # Store the VPN config
        SCP = SCPClient(SSH.get_transport())
        SCP.get(f'~/configs/{newname}.conf', f'tmp/{newname}.conf')
        SCP.close()

        # Add PersistentKeepalive to newname.conf locally
        with open(f'tmp/{newname}.conf', 'a') as file:
            file.write('PersistentKeepalive = 25\n')

        # SSH to new server
        SSH.close()
        sudo_password = None
        print("disconnected from vpn server")

        ssh_connect(SSH, cfg.NEW_HOST, cfg.NEW_USER, cfg.NEW_USER_KEY)
        print("Connected to new server.")

        create_debug_user()
        mv_cfg_en_serv()

        # Close Connection
        SSH.close()

if __name__ == "__main__":
    main()
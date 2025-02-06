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


def ssh_connect(SSH, hostname, username, key_path, password=None):
    try:
        # Try RSA key without passphrase first
        private_key = pmk.RSAKey.from_private_key_file(key_path)
        SSH.connect(hostname=hostname, 
                   username=username, 
                   pkey=private_key)
    except FileNotFoundError:
        print("File not found. Please check the path to the key file.")
        raise

    except (pmk.ssh_exception.PasswordRequiredException, pmk.ssh_exception.SSHException):
        print("No passphrase-less key found or invalid key format. Trying with passphrase.")
        try:
            # Try RSA key with passphrase
            passphrase = input("Enter the SSH key pass: (Leave blank to proceed to password auth): ")
            if passphrase:
                private_key = pmk.RSAKey.from_private_key_file(key_path, password=passphrase)
                SSH.connect(hostname=hostname, 
                           username=username,
                           pkey=private_key)
                print("Connected using RSA key with passphrase.")
            else:
                private_key = pmk.RSAKey.from_private_key_file(key_path)
                print("No passphrase provided")
                exit()

        except (pmk.ssh_exception.PasswordRequiredException, pmk.ssh_exception.SSHException):
            print("Invalid passphrase or key format. Trying password authentication.")
            password = input("Enter the SSH password: ")
            SSH.connect(hostname=hostname, 
                      username=username, 
                      password=password)
        except pmk.ssh_exception.AuthenticationException:
            print("Authentication failed.")
            raise


# Function to execute a command if sudo password required
def exec_sudo_cmd(SSH, cmd):
    print(f"Executing command: {cmd}")
    
    # Check to see if sudo is required
    SSH.exec_command(cmd)
    stdin, stdout, stderr = SSH.exec_command(cmd)
    error = stderr.read().decode()

    if 'permission denied' in error.lower() or 'sudo:' in error.lower():
        print(error) # Debugging
        passwd = input("Enter the sudo password: ")
        
        command = f"sudo -S -p '' {cmd}"
        stdin, stdout, stderr = SSH.exec_command(command, get_pty=True)

        # Send the sudo password followed by a newline
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

        return stdin, stdout, stderr, sudo_password
    else:
        print(f"No sudo needed")
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
    exec_sudo_cmd(SSH, "apt update && apt upgrade -y && apt-get install -y wireguard")
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
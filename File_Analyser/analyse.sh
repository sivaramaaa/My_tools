
cyan='\033[0;36m'
NC='\033[0m'
green='\033[1;32m'
yellow='\033[1;33m'
aslr=0


#___________________________ANIMATE MODULE ______________________________________________________________________________

 animate() {
  b=0
  echo -e "\n"

 while [ $b -lt 2 ];
 do for a in \\ \| \/ -;
 do echo -ne "\033[s[${cyan} $a ${NC}]\033[u";
 sleep 0.2 ;
 done;
 b=$(( $b+1)) ;
 done

}

#______________________________ASLR MODULE_______________________________________________________________________

aslr() {


echo -ne "${green} Enter 1-on or 0-off or c-to-check : ${NC}" ; read  pass

if test "$pass" = "c"
then
      cat /proc/sys/kernel/randomize_va_space
 fi    

if test "$pass" = "1"
then
     echo "switching on aslr"
     echo 1 |sudo tee /proc/sys/kernel/randomize_va_space
 fi

if test "$pass" = "0"
then

     echo "switching off aslr"
     echo 0 |sudo tee /proc/sys/kernel/randomize_va_space
fi
}
 
#____________BINARY MODULE _______________________________________________________________________________________________

bin()

{
   while :
do
    case "$1" in
      -f | --file)
	  file=`find /home/siva/Desktop/ -name $2 2>/dev/null`
          echo "file found : $file"   
	  shift 2
	  ;;
     
      -a | --aslr)
	  aslr=1 # You may want to check validity of $2
	  shift 
	  ;;

      -fu | --fuser)
	  file="$2"
          echo "file found : $file"   
	  shift 2
	  ;;
      
     
      -*)
	  echo "Error: Unknown option: $1" >&2
	  exit 1
	  ;;
      *)  # No more options
	  break
	  ;;
    esac
done

if [ $aslr != 1 ]
then
  
  animate

  echo -n -e  "  [${cyan}+${NC}]${yellow} ANALYSING BINARY ${NC}" 
  
  animate

  echo -ne  " [${cyan}+${NC}]${green} Granting  binary file : exeutable Permision \n ${NC}"

  echo -e "\n"

  echo -ne  " [${cyan}+${NC}]${green} DO u want binary to be SUID y or n : ${NC}"

  read  su_choice

       if [ $su_choice == 'n' ]
       then 

           chmod 777 $file

       else
           chmod u+s-w,g-w,o-rwx $file

       fi	   
 
  echo -e "\n"

  ls -al  $file

  echo -e "\n"

  animate

  echo -ne  "  [${cyan}+${NC}]${green} This the binary file Type :\n ${NC}"

  echo -e "\n"

  file $file

  animate 

 echo -ne "[${cyan}+${NC}]${green} This are the only binary file Protections :)\n ${NC}"  

 /bin/checksec -f $file



elif [ $aslr==1 ] 
then

 aslr

fi

}

#__________________________FORSTEG MODULE____________________________________________________________________________

forsteg()
{
   str1="carvedf"
   str2="carveds"
   pk=0
   while :
do
    case "$1" in
      -f | --file)
	  file=`find /home/siva/Desktop/ -name $2 2>/dev/null`
          echo "file found : $file"   
	  shift 2
	  ;;
     
      -pk | --password-crack)
	  pk=1 # You may want to check validity of $2
	  shift 
	  ;;

      -fu | --fuser)
	  file="$2"
          echo "file found : $file"   
	  shift 2
	  ;;
      -pdf | --pdf-forensic )
	  $pdf_for=1  
	  shift 2
	  ;;
     
      -*)
	  echo "Error: Unknown option: $1" >&2
	  exit 1
	  ;;
      *)  # No more options
	  break
	  ;;
    esac
done

if [ $pk == 1 ] 
then

echo -ne "${green} Enter 1-Brute-force attack or 2-Plain-text attack  : ${NC}" ; read  pass

    if [ $pass == 1 ]
    then
          fcrackzip -u -D -p "/home/siva/Desktop/tools/rockyou.txt" $file -v

          exit 1

     else

          echo -ne "${green} Enter Plain-text-name > : ${NC}" ; read  name

           plaintxt=`find /home/siva/Desktop/ -name $name 2>/dev/null` 
           strip=${plaintxt#/}
            zip archive.zip $plaintxt

         /home/siva/Desktop/tools/pkcrack-1.2.2/src/pkcrack -C $file -c $name -P archive.zip -p $strip -d decrypted.zip -a 
       
       exit 1 
    fi
  if [ $pdf_for == 1 ]
  then
     
    animate

    echo -e  "  [${cyan}+${NC}]${green} Running PDFid ... \n ${NC}"
    python  /home/siva/Desktop/tools/pdfid_v0_2_1/pdfid.py $file
    
    echo -e "\n"
    echo -ne "${green} Enter 1)Javascript-Extract 2) Pdf-parser  3)peepdf > : ${NC}" ; read opt

         if [ $opt == 1  ]
         then 

               echo -e  "  [${cyan}+${NC}]${green} Extracting Javascript ... \n ${NC}"
               pdfextrace --js $file 

            if [ $opt == 2 ]
            then 
      
                 echo -e  "  [${cyan}+${NC}]${green} Running Pdf-parser ... \n ${NC}"
                 /home/siva/Desktop/tools/pdf-parser $file 

           else 
 
                 echo -e  "  [${cyan}+${NC}]${green} Entering Peepdf interactive mode ... \n ${NC}"
                  python /home/siva/Desktop/tools/peepdf/bin/peepdf.py -i $file
           fi

         exit 1
 
   fi
else

animate

  echo -n -e  "  [${cyan}+${NC}]${yellow} ANALYSING FILE ${NC}" 

  animate

  echo -ne  "  [${cyan}+${NC}]${green} This the file Type is :\n ${NC}"

  echo -e "\n"

  file $file

  animate

  echo -ne  "  [${cyan}+${NC}]${green} Checking metadata using exiftool  :\n ${NC}"

  exiftool $file

  animate 

 echo -ne "[${cyan}+${NC}]${green} Carving file using FOREMOST \n ${NC}"  

  fname=`basename $file`
 
 foremost -c '/home/siva/Desktop/tools/foremost.conf' $file -o "$fname$str1" -v

 animate 

 echo -ne "[${cyan}+${NC}]${green} Carving file using Scalpel \n ${NC}"  
 
 scalpel -c '/home/siva/Desktop/tools/scalpel.conf' $file -o "$fname$str2"

 echo -e "\n"

  echo -ne "[${cyan}+${NC}]${green} Try using Stegstolve to carve LSB encoded images !! \n ${NC}" 

fi
 
}




#_________________________MAIN MODULE_________________________________________________________________________________________

if [ $1 == '-bin' ]
then

  shift 
  bin $*

elif [ $1 == '-for' ]
then
  shift
  forsteg $*

else
  echo "Invalid option"

fi




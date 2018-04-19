#!/bin/bash

# Checking Arguments
if [ "$#" -lt "2" ]; then
  echo "Invalid number of parameters"
  echo "Usage: $0 /path/to/analyze extension list@domain.tld[optional] -d[optional]"
  echo "e.g. $0 /path/to/analyze php my_list@domain.tld -d"
  echo "To enable debug mode: $0 /path/to/analyze extension -d"
  exit 1
elif [ "$#" -gt "4" ]; then
  echo "Excesive parameters detected..."
  echo "Usage: $0 /path/to/analyze extension list@domain.tld[optional] -d[optional]"
  echo "e.g. $0 /path/to/analyze php my_list@domain.tld -d"
  echo "To enable debug mode: $0 /path/to/analyze extension -d"
  exit 1
elif [ "$#" -eq "3" ]; then
  #for i in "$@" ; do [[ $i == "-d" ]] && DEBUG=true ; done
  if [ "$3" == "-d" ]; then
    DEBUG=true;
  elif [ "$3" != "" ]; then
    EMAIL="$3"
    if [[ $EMAIL != *"@"* ]]; then echo "Invalid e-mail address" && exit 1; fi
  fi
else
  if [ "$4" == "-d" ]; then
    DEBUG=true;
  elif [ "$4" != "" ]; then
    EMAIL="$4"
    if [[ $EMAIL != *"@"* ]]; then echo "Invalid e-mail address" && exit 1; fi
  fi
fi

if [ $DEBUG ]; then echo "Path to analyze: $1"; fi
if [ $DEBUG ]; then echo "Filetype to analyze: $2"; fi

#trap 'echo -e "$(tput bel)"' SIGINT SIGTERM

# Declaring Variables
TIMESTAMPLOG=$(date "+%Y-%m-%d_%H-%M-%S")
TEMP_FILE=templist.txt
SUSPICIOUS_LIST=suspicious.txt
VERY_SUSPICIOUS_LIST=very_suspicious.txt
ALL_SUSPICIOUS=all_suspicious.txt
SUSPECTED_FILES=$(echo "$TIMESTAMPLOG""_Suspected_Files.txt")
LOGFILE="/var/log/obfuscated_files.log"
LOGFILE_LOCAL="obfuscated_files.log"
mkdir "$TIMESTAMPLOG"
LOGPATH="$TIMESTAMPLOG"
touch "$TIMESTAMPLOG""/stats.txt"
STATSLOG="$TIMESTAMPLOG""/stats.txt"

# Testing command for full path of analysed files
BINFULLPATH=$(realpath /usr)
if [ "$BINFULLPATH" = "/usr" ] ; then FULLPATHCOMMAND="realpath"; else FULLPATHCOMMAND="readlink -f"; fi

# Creating logfile
if [ -f "$LOGFILE" ]; then touch "$LOGFILE"; fi

# Removing temp files
rm -f $SUSPICIOUS_LIST
rm -f $TEMP_FILE
rm -f $VERY_SUSPICIOUS_LIST
#rm -f $SUSPECTED_FILES

# Composing the list of files to verify obfuscation
find $1 -type f -iname "*.$2" >> $TEMP_FILE
NUM_FILES=$(wc -l $TEMP_FILE | awk '{print $1}')
echo "$NUM_FILES files to be analyzed..."
if [ $DEBUG ] ; then echo "Only showing the VERY SUSPECTED files... to see the SUSPECTED files enable DEBUG MODE or read the report generated at the end..."; fi

ITER=0
while read line; do
  #echo -n X
  TIMESTAMPFILE=$(date "+%Y-%m-%d %H:%M:%S")
  
  REAL_PATH=$($FULLPATHCOMMAND $line)
  LINES_W_SPACE_CHAR=$(fgrep -e " " $line | wc -l | awk '{print $1}')
  SPACE_CHARS=$(fgrep -o " " $line | wc -l | awk '{print $1}')
  CHARS=$(cat $line | wc -c | awk '{print $1}')
  LINES=$(cat $line | wc -l | awk '{print $1}')
  LINES_WO_BLANK=$(echo "$LINES - $LINES_W_SPACE_CHAR" | bc)
  MIMETYPE=$(file $line | awk -F ": " '{print $2}')
  ((ITER++))
  if [ $DEBUG ]; then echo "Analyzing file $ITER of $NUM_FILES : $REAL_PATH"; fi

  # Calculating the score rates to detect if file is obfuscated
  # based on quantity of blank spaces, lines and chars
  if [ "$LINES" -eq "0" ]; then SCORE=0; else SCORE=$(echo "$LINES / $LINES_W_SPACE_CHAR" | bc); fi
  if [ "$CHARS" -eq "0" ]; then SCORE2=0; else SCORE2=$(echo "$CHARS / $LINES" | bc); fi
  if [ "$CHARS" -eq "0" ]; then SCORE3=0; else SCORE3=$(echo "$CHARS / $SPACE_CHARS" | bc); fi

  # Alerting the score of suspicious files
  if ([ "$SCORE" -ge "7" ] && [ "$SCORE2" -gt "75" ] && [ "$SCORE3" -gt "100" ]); then
    echo -e "$(tput setab 0)$(tput setaf 1)$(tput bold)[VERY SUSPICIOUS]$(tput sgr0) $SCORE3 - $SCORE2 - $SCORE - $TIMESTAMPFILE - $REAL_PATH - $MIMETYPE" >> $VERY_SUSPICIOUS_LIST
    echo -e "$(tput setab 0)$(tput setaf 1)$(tput bold)VERY Suspicious File Detected:$(tput sgr0) $SCORE3 - $SCORE2 - $SCORE - $TIMESTAMPFILE - $REAL_PATH - $MIMETYPE"
    echo "$TIMESTAMPFILE - VERY Suspicious File Detected: $SCORE3 - $SCORE2 - $SCORE - $REAL_PATH" >> $LOGFILE || echo "$TIMESTAMPFILE - VERY Suspicious File Detected: $SCORE2 - $SCORE - $REAL_PATH - $MIMETYPE" >> $LOGFILE_LOCAL
    echo "$REAL_PATH" >> $ALL_SUSPICIOUS
  elif ([ "$SCORE" -ge "7" ] || [ "$SCORE2" -gt "75" ] || [ "$SCORE3" -gt "100" ]); then
    echo -e "$(tput setab 0)$(tput setaf 3)$(tput bold)[SUSPICIOUS]$(tput sgr0) $SCORE3 - $SCORE2 - $SCORE - $TIMESTAMPFILE - $REAL_PATH - $MIMETYPE" >> $SUSPICIOUS_LIST
    if [ $DEBUG ]; then echo -e "$(tput setab 0)$(tput setaf 3)$(tput bold)Suspicious File Detected:$(tput sgr0) $SCORE3 - $SCORE2 - $SCORE - $TIMESTAMPFILE - $REAL_PATH - $MIMETYPE"; fi
    echo "$TIMESTAMPFILE - Suspicious File Detected: $SCORE3 - $SCORE2 - $SCORE - $REAL_PATH" >> $LOGFILE || echo "$TIMESTAMPFILE - Suspicious File Detected: $SCORE2 - $SCORE - $REAL_PATH - $MIMETYPE" >> $LOGFILE_LOCAL
    echo "$REAL_PATH" >> $ALL_SUSPICIOUS
  fi
#done | pv -s $(wc -l "$TEMP_FILE") - < $TEMP_FILE
done < $TEMP_FILE

# Collecting Suspicious
while read line; do
  stat $line >> "$STATSLOG"
  DIRECTORY=$(dirname $line)
  mkdir -p $DIRECTORY
  cp -a $line $DIRECTORY
done < $ALL_SUSPICIOUS
cp -a $SUSPECTED_FILES $LOGPATH
$(tar -czvpf $LOGPATH.tar.gz $LOGPATH/*)

# Ordering suspected files to be treated in sequence (more suspected firstly)
if [ -e "$VERY_SUSPICIOUS_LIST" ]; then $(cat "$VERY_SUSPICIOUS_LIST" | sort -k 2 -r -n >> "$SUSPECTED_FILES"); fi
if [ -e "$SUSPICIOUS_LIST" ]; then $(cat "$SUSPICIOUS_LIST" | sort -k 2 -r -n >> "$SUSPECTED_FILES"); fi

NUM_SUSPECTED_FILES=$(wc -l $SUSPICIOUS_LIST | awk '{print $1}')
NUM_VERY_SUSPECTED_FILES=$(wc -l $VERY_SUSPICIOUS_LIST | awk '{print $1}')
NUM_TOTAL_SUSPECTED_FILES=$(wc -l $SUSPECTED_FILES | awk '{print $1}')

echo ""
echo -e "$(tput setab 0)$(tput setaf 1)$(tput bold)[VERY SUSPICIOUS]$(tput sgr0): $NUM_VERY_SUSPECTED_FILES"
echo -e "$(tput setab 0)$(tput setaf 3)$(tput bold)[SUSPICIOUS]$(tput sgr0): $NUM_SUSPECTED_FILES"
echo "[TOTAL SUSPECTED FILES]: $NUM_TOTAL_SUSPECTED_FILES"
echo ""
echo "A report was saved by priority in: " $($FULLPATHCOMMAND $SUSPECTED_FILES)
if ([ "$EMAIL" != "" ] && [ -e "$SUSPECTED_FILES" ]); then mutt -s "Obfuscated Files Finder Report" $EMAIL < $SUSPECTED_FILES && echo "Mail message sent with report to $EMAIL"; fi

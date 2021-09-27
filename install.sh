#!/usr/bin/env bash
# Install script for blackwidow & injectx fuzzer
# Crated by @xer0dayz - https://sn1persecurity.com

OKBLUE='\033[94m'
OKRED='\033[91m'
OKGREEN='\033[92m'
OKORANGE='\033[93m'
RESET='\e[0m'

echo -e "$OKRED $RESET"
echo -e "$OKRED $RESET"
echo -e "$OKRED                  _.._$RESET"
echo -e "$OKRED                .'    '.$RESET"
echo -e "$OKRED               /   __   \ $RESET"
echo -e "$OKRED            ,  |   ><   |  ,$RESET"
echo -e "$OKRED           . \  \      /  / .$RESET"
echo -e "$OKRED            \_'--\`(  )'--'_/$RESET"
echo -e "$OKRED              .--'/()\'--.$RESET"
echo -e "$OKRED  @xer0dayz  /  /\` '' \`\  \ $RESET"
echo -e "$OKRED               |        |$RESET"
echo -e "$OKRED                \      /$RESET"
echo -e "$OKRED $RESET"
echo ""
echo -e "$OKRED + -- --=[ https://sn1persecurity.com $RESET"
echo -e "$OKRED + -- --=[ blackwidow by @xer0dayz $RESET"
echo ""

echo -e "$OKBLUE[*]$RESET Installing BlackWidow... $RESET"
apt update
apt install -y python3 python3-requests python3-pip python3-lxml python3-requests openssl ca-certificates python3-dev wget git
cp -f $PWD/blackwidow /usr/bin/blackwidow
cp -f $PWD/injectx.py /usr/bin/injectx.py
cp -f $PWD/blackwidow.desktop /usr/share/applications/ 2> /dev/null
cp -f $PWD/blackwidow.desktop /usr/share/applications/blackwidow.desktop 2> /dev/null
cp -f $PWD/blackwidow.desktop /usr/share/kali-menu/applications/blackwidow.desktop2> /dev/null
echo -e "$OKBLUE[*]$RESET Done! $RESET"
echo -e "$OKRED[>]$RESET To run, type 'blackwidow'! $RESET"
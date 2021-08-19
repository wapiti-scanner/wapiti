#!/bin/sh
rm ../data/language/de/LC_MESSAGES/wapiti.mo 2> /dev/null
rm ../data/language/fr/LC_MESSAGES/wapiti.mo 2> /dev/null
rm ../data/language/en/LC_MESSAGES/wapiti.mo 2> /dev/null
rm ../data/language/es/LC_MESSAGES/wapiti.mo 2> /dev/null
rm ../data/language/ms/LC_MESSAGES/wapiti.mo 2> /dev/null
rm ../data/language/pt/LC_MESSAGES/wapiti.mo 2> /dev/null
rm ../data/language/zh/LC_MESSAGES/wapiti.mo 2> /dev/null
echo "German"
msgfmt de.po -o ../data/language/de/LC_MESSAGES/wapiti.mo
echo "English"
msgfmt en.po -o ../data/language/en/LC_MESSAGES/wapiti.mo
echo "Spanish"
msgfmt es.po -o ../data/language/es/LC_MESSAGES/wapiti.mo
echo "French"
msgfmt fr.po -o ../data/language/fr/LC_MESSAGES/wapiti.mo
echo "Malay"
msgfmt ms.po -o ../data/language/ms/LC_MESSAGES/wapiti.mo
echo "Portuguese"
msgfmt pt.po -o ../data/language/pt/LC_MESSAGES/wapiti.mo
echo "Chinese"
msgfmt zh.po -o ../data/language/zh/LC_MESSAGES/wapiti.mo

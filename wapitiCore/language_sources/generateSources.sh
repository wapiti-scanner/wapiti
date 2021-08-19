#!/bin/sh
# -f, --files-from=FICHIER    obtenir la liste des fichiers d'entrée à partir du FICHIER
# -j, --join-existing         joindre les messages au fichier existant
# --no-location               ne pas créer les commentaires de numérotation du type "#: fichier:ligne"
# --omit-header               ne pas créer d'en-têtes de la forme 'msgid ""'
# First generate the template with all current strings, it will delete the previous file (so remove old strings)
xgettext --copyright-holder="2009-2021 Nicolas SURRIBAS" --package-name="Wapiti" --package-version="GIT" --from-code=UTF-8 -L Python --no-wrap -d wapiti -o template.po -f file_list.txt  --no-location --omit-header

# Next, update the translation files by adding entry for new strings
# while keeping already translated strings if they are still used.
# Old references will be commented and put at the end of files
echo "German"
msgmerge --update --no-fuzzy-matching --backup=off de.po template.po
echo "English"
msgmerge --update --no-fuzzy-matching --backup=off en.po template.po
echo "Spanish"
msgmerge --update --no-fuzzy-matching --backup=off es.po template.po
echo "French"
msgmerge --update --no-fuzzy-matching --backup=off fr.po template.po
echo "Malay"
msgmerge --update --no-fuzzy-matching --backup=off ms.po template.po
echo "Portuguese"
msgmerge --update --no-fuzzy-matching --backup=off pt.po template.po
echo "Chinese"
msgmerge --update --no-fuzzy-matching --backup=off zh.po template.po

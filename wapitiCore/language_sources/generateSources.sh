#!/bin/sh
# -f, --files-from=FICHIER    obtenir la liste des fichiers d'entrée à partir du FICHIER
# -j, --join-existing         joindre les messages au fichier existant
# --no-location               ne pas créer les commentaires de numérotation du type «#: fichier:ligne»
# --omit-header               ne pas créer d'en-têtes de la forme « msgid "" »'
xgettext --copyright-holder="2009-2020 Nicolas SURRIBAS" --package-name="Wapiti" --package-version="GIT" --from-code=UTF-8 -L Python --no-wrap -d wapiti -o de.po -f file_list.txt -j --no-location --omit-header
xgettext --copyright-holder="2009-2020 Nicolas SURRIBAS" --package-name="Wapiti" --package-version="GIT" --from-code=UTF-8 -L Python --no-wrap -d wapiti -o en.po -f file_list.txt -j --no-location --omit-header
xgettext --copyright-holder="2009-2020 Nicolas SURRIBAS" --package-name="Wapiti" --package-version="GIT" --from-code=UTF-8 -L Python --no-wrap -d wapiti -o es.po -f file_list.txt -j --no-location --omit-header
xgettext --copyright-holder="2009-2020 Nicolas SURRIBAS" --package-name="Wapiti" --package-version="GIT" --from-code=UTF-8 -L Python --no-wrap -d wapiti -o fr.po -f file_list.txt -j --no-location --omit-header
xgettext --copyright-holder="2009-2020 Nicolas SURRIBAS" --package-name="Wapiti" --package-version="GIT" --from-code=UTF-8 -L Python --no-wrap -d wapiti -o ms.po -f file_list.txt -j --no-location --omit-header
xgettext --copyright-holder="2009-2020 Nicolas SURRIBAS" --package-name="Wapiti" --package-version="GIT" --from-code=UTF-8 -L Python --no-wrap -d wapiti -o zh.po -f file_list.txt -j --no-location --omit-header
xgettext --copyright-holder="2009-2020 Nicolas SURRIBAS" --package-name="Wapiti" --package-version="GIT" --from-code=UTF-8 -L Python --no-wrap -d wapiti -o pt.po -f file_list.txt -j --no-location --omit-header

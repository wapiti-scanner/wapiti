from wapitiCore.parsers.swf import extract_links_from_swf


def test_doabc():
    with open("tests/parsers/data/wivet_doabc.swf", "rb") as fd:
        assert ["../innerpages/19_1f52a.php", "../innerpages/19_2"] == sorted(extract_links_from_swf(fd))


def test_actiongeturl():
    with open("tests/parsers/data/actiongeturl.swf", "rb") as fd:
        assert ["subscribe.aspx"] == sorted(extract_links_from_swf(fd))


def test_actionconstantpool_doaction():
    with open("tests/parsers/data/actionconstantpool_doaction.swf", "rb") as fd:
        assert ["/big/", "/small/", "?cashKiller=", "_main.xml"] == sorted(extract_links_from_swf(fd))


def test_definebutton2_actionpush():
    with open("tests/parsers/data/definebutton2_actionpush.swf", "rb") as fd:
        assert [
                   "gal_anim_project1.html",
                   "gal_anim_project2.html",
                   "gal_anim_project3.html",
                   "gal_anim_project4.html",
                   "gal_anim_project5.html",
                   "gal_anim_project6.html",
                   "gal_anim_project7.html",
                   "gal_anim_project8.html",
                   "gal_anim_project9.html",
                   "gal_vid_project1.html",
                   "gal_vid_project2.html",
                   "gal_vid_project3.html",
                   "gal_vid_project4.html",
                   "gal_vid_project5.html",
                   "gal_vid_project6.html",
                   "http://www.apple.com/quicktime/download",
                   "http://www.apple.com/quicktime/download/"
               ] == sorted(extract_links_from_swf(fd))

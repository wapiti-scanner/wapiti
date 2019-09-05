Introduction
============

All installation methods assume you already have a Python 3.5 or more recent on your system.

Note that if you have all the requirements pre-installed on your system, it is not necessary to use the setup.py script
to use Wapiti : just extract the archive and launch the "wapiti" command line in the "bin" folder :

 `./bin/wapiti` or `python bin/wapiti`.

You may want to install Wapiti to the system just to make access easier.  
If you haven't sufficient privileges are you are afraid of breaking some dependencies in your python packages then
using a virtual environment is the way to go. Just refer to the related section.

Otherwise you will have to launch setup.py as a privileged user.

Enjoy Wapiti.


Installing Wapiti using a virtual environment
=============================================

Let's create a virtual environment called 'wapiti3'.  
In this example it will be created in the current working directory.

`python -m venv wapiti3`

Now let's activate it (make it our current working environment) :
 
`. ./wapiti3/bin/activate`

Or alternatively on Windows :

`wapiti3\Scripts\activate.bat`

Now you are in the virtual environment you can install Wapiti and its dependencies :

`python3 setup.py install`

To leave the virtual environment just call the following command :

`deactivate`

Remember that you will need to reactivate the environment each time you want to use Wapiti. 


Installing Wapiti without virtual environment
=============================================

You can install wapiti the regular way :

`python setup.py install`


Installing Wapiti using pip
===========================

There is a Pip package called wapiti3 :

`pip install wapiti3`


Installing Wapiti from the Git repository
=========================================

You can pull latest dev version from Git :

`git clone https://git.code.sf.net/p/wapiti/git wapiti-git`

Then use setup.py for installation. Remember that dev version may contain unknown bugs.


Installation tutorials
======================

I made several YouTube videos to show Wapiti installation :

* on Windows : https://www.youtube.com/watch?v=j3LCVj15VBE
* on OpenSUSE : https://www.youtube.com/watch?v=RmF2Sr2B3ZA
* on Ubuntu : https://www.youtube.com/watch?v=TD5rehelHPY

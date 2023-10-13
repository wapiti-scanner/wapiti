Introduction
============

All installation methods assume you already have a Python 3.10 or more recent on your system.

Note that if you have all the requirements pre-installed on your system, it is not necessary to use the setup.py script
to use Wapiti : just extract the archive and launch the "wapiti" command line in the "bin" folder :

 ```sh
 ./bin/wapiti
 ``` 
 
 or 
 
 ```sh
 python bin/wapiti
 ```

You may want to install Wapiti to the system just to make access easier.  
If you haven't sufficient privileges are you are afraid of breaking some dependencies in your python packages then
using a virtual environment is the way to go. Just refer to the related section.

Otherwise, you will have to launch setup.py as a privileged user.

Enjoy Wapiti.

# Installing Wapiti using a virtual environment

Let's create a virtual environment called 'wapiti3'.  
In this example it will be created in the current working directory.

```sh
python -m venv wapiti3
```

Now let's activate it (make it our current working environment) :
 
```sh
. wapiti3/bin/activate
```

Now you are in the virtual environment you can install Wapiti and its dependencies :

```sh
make install
```

or

```sh
pip install .
```

To leave the virtual environment just call the following command :

`deactivate`

Remember that you will need to reactivate the environment each time you want to use Wapiti. 

# Installing Wapiti without virtual environment

You can install wapiti the regular way :

```sh
make install
```

or

```sh
pip install .
```

# Installing Wapiti using pip

There is a Pip package called wapiti3 :

```sh
pip install wapiti3
```

# Installing Wapiti from the Git repository

You can pull latest dev version from Git :

```sh
git clone git@github.com:wapiti-scanner/wapiti.git
```

Then use [make or pip](#installing-wapiti-without-virtual-environment) for installation. Remember that dev version may contain unknown bugs.

# Installation tutorials

I made several YouTube videos to show Wapiti installation :

* on OpenSUSE : https://www.youtube.com/watch?v=RmF2Sr2B3ZA
* on Ubuntu : https://www.youtube.com/watch?v=TD5rehelHPY

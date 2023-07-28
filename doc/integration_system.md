# Integration test documentation
----
Table of content
- [Working principle](#working-principle)
- [How to use it](#how-to-use-it)
    - [Basic usage](#basic-usage) 
    - [Integration test creation guide](#integration-test-creation-guide)
    - [Creating and understanding filters](#creating-and-understanding-filters)
    - [Miscellaneous and notes](#miscellaneous-and-notes)
----

## Working principle

This integration test system relies on scenarios. A scenario is basically made up of : 
 - Wapiti attacking one or more target with some options (one or more modules, a custom endpoint etc.).
 - Wapiti generating one report per target, agnostic of any non-constant data (date, IDs, etc.) and filtered of another redundant data.
 - Reports are then compared to reference reports (also called assertions), if they look exactly the same, then the test passes, otherwise, a diff is dumped in the logs and in a text file that can be retrieved as a GitHub  CI artifact.

A target is a website Wapiti can scan or crawl with some vulnerabilities or not.
All the scenarios are executed on Docker with one or more container per target, one for Wapiti and another one for the endpoint.

During an usual test run, the system will acknowledge all the scenarios you want to test (they can be set through the ``TESTS`` environment variable), and will then try to attack targets. Scenarios and targets order are not fixed.

As some targets are mutualized for some scenario, all the containers (even those who will not be used) will be built and executed during a run. 

## How to use it 
### Basic usage
The whole system is located at tests/integration.

```Bash
Entrypoint to run integration tests
Usage: ./run.sh [options]
Options:
    --help           Display this message and exit
    --docker-clean   Kill containers, remove and prune all docker images, volumes, and system, be carefull when using this option
    --verbose-build  Print the build messages before running the tests
```

After the run, a file named .dump_diff_file.txt containing a concatenation of all the reports differences of all the targets of all the scenarios will be created at tests/integration. 

In case you want to disable a scenario, you can open the ``run.sh`` file and remove scenarios in the variable ``TESTS``. You can also export this variable in you shell but make sure to comment the one in ``run.sh`` to avoid overwriting. The formats of scenario in this variable should be single-space-separated. 

```Bash
TESTS="test_mod_wp_enum test_mod_http_headers test_mod_csp"
```

There is no checking regarding what you put in this variable, use it carefully.  

### Integration test creation guide 

To create your own scenario:

1. Start by create a directory in tests/integration. By convention, follow the other directories when it comes to naming. Name start by `test_` followed by what you test, underscore-separated. Keep in mind that this will be your scenario name.
<br/>

2. Populate your directory just like this:
    ```
    - test_dummy_name
    - assertions
        - check.sh 
    ```
    It is mandatory to have a `check.sh` inside an `assertions` directory so the system can check your assertions
    <br/>

    __check.sh__
    The system either let you the choice to set a symbolic link the default check.sh located in ``tests\integration`` to the ``assertions`` directory. 
    ```Bash
    # Admitting you are at the root of the git project : 
    ln -s ../../check.sh test/integrations/test_dummy_name/assertions/check.sh
    ```
    Or write your own if you need a specific way to check the reports. The only constraints are: be named ``check.sh`` and be a bash script
<br/>

3. Populate your directory with files required by your targets (aside the assertions directory) such as php files, Dockerfiles, executables etc.
<br/>

4. Modify the `docker-compose.setup.yml` to add your targets as containers .This file already contains severals shortcuts to help you setup a PHP server as well as some hashes of images. It is mandatory to: 
    - Use existing or setup your own healthchecks.
    - Use images by their hashes, either the one provided or by adding them to the `.env` file

    For shortcuts: 

    - `default_php_setup` setup a PHP web server and connect it to the test-network

    - `default_mysql_setup` setup a Mysql database and connect it to the test-network

    - `healthcheck_mysql` setup a healthcheck for a Mysql database 

    - `healthcheck_web` setup a healthcheck for a server hosting a website 


    Here are 2 targets examples:
    ```yml
    dummy_target:
        <<: [ *default_php_setup, *healthcheck_web ]
        depends_on:
        endpoint:
            condition: service_healthy
        volumes:
        - ./test_dummy_name/target_1/php/src/:/var/www/html/

    built_dummy_target:
        build:
        context: ./test_dummy_name/target_2/
        dockerfile: "./test_dummy_name/target_2/Dockerfile"
        args:
            PHP_HASH_TAG: ${PHP_HASH}
        volumes:
        - ./test_dummy_name/target_2/php/src/:/var/www/html/
        <<: *healthcheck_web
        networks:
        - test-network
    ```

    To make sure Wapiti waits for the containers to be ready, add dependances : 
    ```yml
    depends_on:
        dummy_target: 
            condition: service_healthy
        built_dummy_target: 
            condition: service_healthy
    ```
<br/>

5. Modify the ``tests/integration/wapiti/module.json`` to define the behavior of Wapiti toward the target(s). You can supply:
    - A filter per scenario to avoid bloating the reports and the assertions. If you don't a default one will be supplied (see [this section](#creating-and-understanding-filters) for more informations).
    - Supplementary arguments per scenario or per target (supplementary arguments will sum up unless you specify you want target supplementary argument to override scenario supplementary argument)
    - Modules 
    <br/>

    As Docker relies on hostnames, you can indicate them as their names preprended by ``http(s)://`` so Wapiti can attack them. 

    Here is an example:
    ```JSON
    "test_dummy_name": {
        "modules": "dummy",
        "supplementary_argument": "--auth-method digest",
        "report_filter_tree": {},
        "targets": [
            {
                "name": "http://dummy_target/endpoint1/index.php"
            },
            {
                "name": "http://dummy_target/endpoint2/index.php",
                "supplementary_argument": "--endpoint http://endpoint/"
            },
            {
                "name": "http://built_dummy_target",
                "supplementary_argument": "--auth-method basic",
                "erase_global_supplementary": true
            }
        ]
    },
    ```
    <br/>

    As shown, you can also define multiples targets on a single container, which allow you to host mutliple websites on a single server. Wapiti will be launched on each target and thus, will produce as many reports as there is target for a given scenario. 
    <br/>

    ``supplementary_argument`` and ``report_filter_tree`` can be omitted. All the other keys are mandatory (``modules`` should be left as an empty string when testing without any module)
    <br/>

    __supplementary_argument__
    As you can see above, the first target will inherit from the scenario supplementary argument, the second one will have both argument and the third one runs with it own supplementary argument

    Some arguments are already supplied by default and can't be changed. Wapiti will always be run with ``--detailed-report --flush-session --verbose 2 -f json``. The outpout path of the reports will also be supplied, supplying it here may break you scenario. 
    <br/>

    __report_filter_tree__
    The report filter tree value should be a json following strictly the same structure of a Wapiti report in json, you can find what it looks like in ``tests/integration/wapiti/templates_and_data.py``. The goal of applying a filter is not only to prevent having large reports made of useless data, but also remove data that may vary arbitrarily from one report to another.
<br/>

6. Generate (or regenerate your own assertions)
    Run the tests once 
    ```Bash 
    ./run.sh
    ```
    All the reports from the different targets will be generated in the ``tests/integration/.test`` directory. From here you can generate or regenerate your assertions by using the script ``regenerate_assertions.sh``, if left empty, it will erase all the assertions by the produced reports. To replace specific assertions, specify them by their names
    ```Bash
    ./regenerate_assertions.sh test_dummy_name
    ```
    (This script doesn't have any checking system, supplying unknown or mistyped arguments may lead to unexpected behavior, use it carefully)
    Or you can copy it yourself:
    ```Bash
    cp tests/integrations/.test/test_dummy_name/dummy_target_endpoint1_index.php.out tests/integrations/test_dummy_name/assertions/dummy_target_endpoint1_index.php.json
    cp tests/integrations/.test/test_dummy_name/dummy_target_endpoint2_index.php.out tests/integrations/test_dummy_name/assertions/dummy_target_endpoint2_index.php.json
    cp tests/integrations/.test/test_dummy_name/built_dummy_target.out tests/integrations/test_dummy_name/assertions/built_dummy_target.json
    ``` 
    <br/>
    You can finally, re-run the tests and observe if the assertions are respected or not.
### Creating and understanding filters

The default filter can be found in ``tests\integration\wapiti\templates_and_data.py``. It will remove every WSTG code explanations shipped by default on each report:
```JSON
{
    "vulnerabilities": {},
    "anomalies": {},
    "additionals": {},
    "infos": {}
}
```
<br/>

If you want to create your own filter, you can look at the general template in ``tests\integration\wapiti\templates_and_data.py``. Any key with a corresponding empty object in the filter will indicate to the system that everything produced in the report inside this key will be copied. Non-written keys will be ignored.
For arrays, you can indicate in the filter, a single element and the system will treat every elements of the arrays in the output report as the first occurence of the report. 
<br/>
As an example, for this dummy raw output:

```JSON 
{
    "vulnerabilities": {
        "A dummy vuln":{
            "wanted_data": 34,
            "wanted_array": [
                {
                    "wanted_array_data": "blablabla",
                    "bloat_array_data": 455
                },
                {
                    "wanted_array_data": "blebleble",
                    "bloat_array_data": 456
                },
                {
                    "wanted_array_data": "bliblibli",
                    "bloat_array_data": 457
                }
            ],
            "bloat_data": "blablabla"
        }
    },
    "info":{
        "value1": 1,
        "value2": 2,
        "value3": 3,
        "value4": 4,
        "value5": 5
    }
}
```
If we want to keep the wanted data, the infos and get rid of the bloat data, we should write the following filter:
```JSON
{
    "vulnerabilities":{
        "A dummy vuln":{
            "wanted_data": 0,
            "wanted_array":[
                {
                    "wanted_array_data": ""
                }
            ]
        }
    },
    "info":{}
}
```
The produced output will be:
 ```JSON 
{
    "vulnerabilities": {
        "A dummy vuln":{
            "wanted_data": 34,
            "wanted_array": [
                {
                    "wanted_array_data": "blablabla"
                },
                {
                    "wanted_array_data": "blebleble"
                },
                {
                    "wanted_array_data": "bliblibli"
                }
            ]
        }
    },
    "info":{
        "value1": 1,
        "value2": 2,
        "value3": 3,
        "value4": 4,
        "value5": 5
    }
}
```

### Miscellaneous and notes

- As modules are added to Wapiti, the constant ``EXISTING_MODULES`` in ``tests/integrations/wapiti/templates_and_data.py`` should be updated in consequences, not having a new module in this variable will make the system crash. This is a security to prevent you from launching tests with modules that doesn't exist or with a typo 

# Integration test documentation
----
Table of content
- [Working principle](#working-principle)
- [How to use it](#how-to-use-it)
    - [Basic usage](#basic-usage) 
    - [Integration test creation guide](#integration-test-creation-guide)
    - [Creating and understanding filters](#creating-and-understanding-filters)
    - [Miscellaneous and notes](#miscellaneous-and-notes)
- [The automated way](#the-automated-way)
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
    --debug-containers  Attach all containers to the STDOUT
```

After the run, a file named ``.dump_diff_file.txt`` containing a concatenation of all the reports differences of all the targets of all the scenarios will be created at tests/integration. 

In case you want to disable a scenario, you can open the [run.sh](../tests/integration/run.sh) file and remove scenarios in the variable ``TESTS``. You can also export this variable in you shell but make sure to comment the one in [run.sh](../tests/integration/run.sh) to avoid overwriting. The formats of scenario in this variable should be single-space-separated. 

```Bash
TESTS="test_mod_wp_enum test_mod_http_headers test_mod_csp"
```

There is no checking regarding what you put in this variable, use it carefully.  

### Integration test creation guide 

To create your own scenario:

1. Start by create a directory in [tests/integration](../tests/integration/). By convention, follow the other directories when it comes to naming. Name start by `test_` followed by what you test, underscore-separated. Keep in mind that this will be your scenario name.
<br/>

2. Populate your directory just like this:
    ```
    - test_dummy_name/
        - assertions/
            - check.sh 
    ```
    It is mandatory to have a `check.sh` inside an `assertions` directory so the system can check your assertions
    <br/>

    __check.sh__
    The system either let you the choice to set a symbolic link the [default check.sh](../tests/integration/check.sh)
    ```Bash
    # Admitting you are at the root of the git project : 
    ln -s ../../check.sh tests/integrations/test_dummy_name/assertions/check.sh
    ```
    Or write your own if you need a specific way to check the reports. The only constraints are: be named ``check.sh`` and be a bash script (which can call external scripts in other languages as you wish).
<br/>

3. Populate your directory with files required by your targets (aside the assertions directory) such as php files, Dockerfiles, executables etc.
<br/>

4. Write a `docker-compose.setup.yml` at the root of your directory to add your targets as containers. It is mandatory to: 
    - Use existing or setup your own healthchecks.
    - Use images by their hashes, either the one provided or by adding them to the `.env` file you can file in the parent directory (it will be automaticaly sourced)

    You can add some extensions among the existing ones you can find in other integration tests: 

    - `default_php_setup` setup a PHP web server and connect it to the test-network

    - `default_mysql_setup` setup a Mysql database and connect it to the test-network

    - `healthcheck_mysql` setup a healthcheck for a Mysql database 

    - `healthcheck_web` setup a healthcheck for a server hosting a website 

    And you must include a Wapiti service since it depends on your services

    Here is a typical [docker-compose.setup.yml](./docker-compose.dummy.yml), you can safely start off by copying and pasting the following yaml (and remove extensions you don't need after) : 
    ```yml
    version: '3.9'
    x-default_php_setup:
        &default_php_setup
        image: php${PHP_HASH}
        networks:
            - test-network

    x-healthcheck_web:
        &healthcheck_web
        healthcheck:
            test: ${DEFAULT_WEB_HEALTHCHECK_COMMAND}
            interval: ${DEFAULT_HEALTHCHECKS_INTERVAL}
            timeout: ${DEFAULT_HEALTHCHECKS_TIMEOUT}
            start_period: ${DEFAULT_HEALTHCHECKS_START_PERIOD}
            retries: ${DEFAULT_HEALTHCHECKS_RETRIES}

    x-default_mysql_setup:
        &default_mysql_setup
        image: mysql${MYSQL_HASH}
        networks:
            - test-network

    x-healthcheck_mysql:
        &healthcheck_mysql
        healthcheck:
            test: ${DEFAULT_MYSQL_HEALTHCHECK_COMMAND}
            start_period: ${DEFAULT_HEALTHCHECKS_START_PERIOD}
            interval: ${DEFAULT_HEALTHCHECKS_INTERVAL}
            timeout: ${DEFAULT_HEALTHCHECKS_TIMEOUT}
            retries: ${DEFAULT_HEALTHCHECKS_RETRIES}

    services:

    # Write your services here

    wapiti:
        build:
            context: "../../"
            dockerfile: "./tests/integration/wapiti/Dockerfile.integration"
            no_cache: true
        container_name: wapiti
        volumes:
            - ./.test:/home/
        networks:
            - test-network
        command: "${TESTS}"
        depends_on:
            # Make wapiti depends on your services (service_healthy)

    # Don't forget to add anything volume related if you work with it

    networks:
    test-network:
    ```
<br/>

5. Add a ``behavior.json`` file at the root of you directory to define the behavior of Wapiti toward the target(s). You can supply:
    - A filter per scenario to avoid bloating the reports and the assertions. If you don't a default one will be supplied (see [this section](#creating-and-understanding-filters) for more informations).
    - Supplementary arguments per scenario or per target (supplementary arguments will sum up unless you specify you want target supplementary argument to override scenario supplementary argument)
    - Modules 
    <br/>

    As Docker relies on hostnames, you can indicate them as their names preprended by ``http(s)://`` so Wapiti can attack them. 

    Here is an example:
    ```JSON
    {
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
        }
    }
    ```
    <br/>

    As shown, you can also define multiples targets on a single container, which allow you to host mutliple websites on a single server. Wapiti will be launched on each target and thus, will produce as many reports as there is target for a given scenario. (Changing the scope in the supplementary argument is also doable).
    <br/>

    ``supplementary_argument`` and ``report_filter_tree`` can be omitted. All the other keys are mandatory (``modules`` should be left as an empty string when testing without any module)
    <br/>

    __supplementary_argument__
    As you can see above, the first target will inherit from the scenario supplementary argument, the second one will have both argument and the third one runs with it own supplementary argument

    Some arguments are already supplied by default and can't be changed. Wapiti will always be ran with ``--detailed-report --flush-session --verbose 2 -f json``. The outpout path of the reports will also be supplied, supplying it here may break you scenario. 
    <br/>

    __report_filter_tree__
    The report filter tree value should be a json following strictly the same structure of a Wapiti report in json, you can find what it looks like in [templates_and_data.py](../tests/integration/wapiti/templates_and_data.py). The goal of applying a filter is not only to prevent having large reports made of useless data, but also remove data that may vary arbitrarily from one report to another.
<br/>

6. Generate (or regenerate your own assertions)
    Run the tests once 
    ```Bash 
    ./run.sh
    ```
    All the reports from the different targets will be generated in the [.test](tests/integration/.test) directory. From here you can generate or regenerate your assertions by using the script [regenerate_assertions.sh](../tests/integration/regenerate_assertions.sh), __if left empty, it will erase all the assertions by the produced reports__. To replace specific assertions, specify them by their names
    ```Bash
    ./regenerate_assertions.sh test_dummy_name
    ```
    (This script doesn't have any checking system, supplying unknown or mistyped arguments may lead to unexpected behavior, use it carefully)
    Or you can copy them yourself:
    ```Bash
    cp tests/integrations/.test/test_dummy_name/dummy_target_endpoint1_index.php.out tests/integrations/test_dummy_name/assertions/dummy_target_endpoint1_index.php.json
    cp tests/integrations/.test/test_dummy_name/dummy_target_endpoint2_index.php.out tests/integrations/test_dummy_name/assertions/dummy_target_endpoint2_index.php.json
    cp tests/integrations/.test/test_dummy_name/built_dummy_target.out tests/integrations/test_dummy_name/assertions/built_dummy_target.json
    ``` 
    <br/>

    __You are done__
    You can finally, re-run the tests and observe if the assertions are respected or not.
    Your integration test folder should look like something like this:
    ```txt
        - test_dummy_name/
            - docker-compose.setup.yml
            - behavior.json
            - Dockerfile.dummy (if you need one or more)
            - assertions/
                - check.sh 
                - built_dummy_target.json
                - dummy_target_endpoint1_index.php.json
                - dummy_target_endpoint2_index.php.json
            - php/src/
                - index.php 
                - (other files)
            - (other files)

    ```

### Creating and understanding filters

The default filter can be found in [templates_and_data.py](../tests/integration/wapiti/templates_and_data.py). It will remove every WSTG code explanations shipped by default on each report:
```JSON
{
    "vulnerabilities": {},
    "anomalies": {},
    "additionals": {},
    "infos": {}
}
```
<br/>

If you want to create your own filter, you can look at the general template in [templates_and_data.py](../tests/integration/wapiti/templates_and_data.py). Any key with a corresponding empty object in the filter will indicate to the system that everything produced in the report inside this key will be copied. Non-written keys will be ignored.
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

- As modules are added to Wapiti, the constant ``EXISTING_MODULES`` in [templates_and_data.py](../tests/integration/wapiti/templates_and_data.py) should be updated in consequences, not having a new module in this variable will make the system crash. This is a security to prevent you from launching tests with modules that doesn't exist or with a typo 
- If the report is altered in any way, the Python dictionary ``TREE_CHECKER`` in [templates_and_data.py](../tests/integration/wapiti/templates_and_data.py)  should be updated accordingly. 
- In the different docker-compose files, services like ``endpoint`` and ```wapiti``` are mutualized. In order for docker to merge them perfectly, it is required to not change their names (or you may experience duplicate services, bugs, and extended building and testing time)
- If you want to mutualize a service between some integration tests, make sure to create a specific folder next to the ``test_*`` ones (like ``endpoint``, ``dns-endpoint``, etc.) to store its config files and make it agnostic from any tests 
- Sometimes, when running the CI locally on limited hardware, some containers may appears as unhealthy and stop [run.sh](../tests/integration/run.sh). This is mostly due to the databases not ready for some services. Don't hesitate to increase ``DEFAULT_HEALTHCHECKS_RETRIES`` in the [.env](../tests/integration/.env) file. 
- When creating a ``docker-compose.setup.yml`` file, write paths as if you were in the parent directory since the project path is in [the integration folder](../tests/integration/)
- If for any reason you want to completely delete a test (not disabling it), you can simply remove its associated folder.  

## The automated way

To avoid repetitive task, the script [init_test.sh](../tests/integration/init_test.sh) has been created. It setups default integration tests by:

- Creating a folder with the supplied name
- Creating the assertion folder
- making a symlink to the default [check.sh](../tests/integration/check.sh)
- Creating a default ``behavior.json`` with the supplied name
- Creating a default [docker-compose.setup.yml](docker-compose.dummy.yml)

So you can focus on things that will vary among all those files. You may need to remove some generated content inside those files (even remove the symlink) to adjust the test to your needs.
This script is able to create as many integration tests as you supply them by argument:
```Bash
./init_test.sh test_dummy_1 test_dummy_2 test_dummy_3
```
It will also check if your tests start by the prefix ``test_`` and if you are using the name of a test that already exists
pamalt_canari - PaloAlto + Maltego Canari Package
=================================================================

Author: David Bressler (@bostonlink)

## 1.0 - About

Video Demo: http://www.youtube.com/watch?v=C7u0z6I_EXE

pamalt is a project that integrates the PAN web API to create Maltego transforms. This functionality gives the ability to Information Security Teams and SOCs the ability to graph and create Machines (Maltego Radium) to view the threat landscape of an organization.

* `src/pamalt_canari` directory is where all modules are stored
* `src/pamalt_canari/transforms` directory is where all nwmaltego transforms are stored
* `src/pamalt_canari/transforms/common` directory is where the nwmodule is stored and is a PAN REST API wrapper
* `src/pamalt_canari/transforms/common/entities.py` is where all nwmaltego custom entities are defined
* `maltego/` is where the Maltego entity exports are stored.
* `src/pamalt_canari/resources/maltego` directory is where the `entities.mtz` files are stored for auto
  install and uninstall.

## 2.0 - Installation

### 2.1 - Supported Platforms
pamalt_canari has currently been tested on Mac OS X and Linux.
Further testing will be done on Windows in the near future.

### 2.2 - Requirements
pamalt_canari is supported and tested on Python 2.7.3
The canari framework must be installed to use this package
See: https://github.com/allfro/canari

### 2.3 - How to install
Once you have the Canari framework installed and working, follow the directions below to install pamalt_canari

Install the package:

```bash
$ cd pamalt_canari
$ python setup.py install
```
Then install the canari package by issuing the following:

```bash
$ canari install-package pamalt_canari
```
Once installed you must edit the pamalt_canari.conf file with the PAN appliance hostname or IP address.

```bash
$ vim pamalt_canari/pamalt_canari.conf
```
Upon running the first transform the package will ask for user credentials to the PAN appliance.  It then creates a cookie for use within the package.  There is no need to store username or password credentials within the configuration file.

## Special Thanks!

Rich Popson (@Rastafari0728)<br/>
Nadeem Douba (@ndouba)<br/>
Paterva (@Paterva)<br/>
MassHackers (@MassHackers)<br/>

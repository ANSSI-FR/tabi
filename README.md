# TaBi - Track BGP Hijacks

Developed since 2011 for the needs of the [French Internet Resilience
Observatory](http://www.ssi.gouv.fr/observatoire), TaBi is a framework that
ease the detection of BGP IP prefixes conflicts, and their classification into
BGP hijacking events. The term **prefix hijacking** refers to an event when an
AS, called an *hijacking AS*, advertises illegitimately a prefix equal or more
specific to a prefix delegated to another AS, called the *hijacked AS*.

Usually, TaBi processes BGP messages that are archived in MRT files. Then, in
order to use it, you will then need to install a MRT parser.  Its favorite
companion is [MaBo](https://github.com/ANSSI-FR/mabo), but it is also
compatible with CAIDA's
[bgpreader](https://bgpstream.caida.org/docs/tools/bgpreader). Internally, TaBi
translates BGP messages into its own representation. Therefore, its is possible
to implement new inputs depending on your needs.


## Authors

  * Nicolas Vivet <nicolas.vivet@ssi.gouv.fr>
  * Guillaume Valadon <guillaume.valadon@ssi.gouv.fr>
  * Julie Rossi <julie.rossi@ssi.gouv.fr>
  * François Contat <francois.contat@ssi.gouv.fr>


## Building TaBi

TaBi depends on two external Python modules. The easiest method to install them
is to use [virtualenv](https://virtualenv.pypa.io) and
[pip](https://pip.pypa.io/).

If you use a Debian-like system you can install these dependencies using:
```shell
apt-get install python-dev python-pip python-virtualenv
```

Then install TaBi in a virtual environment:
```shell
virtualenv ve_tabi
source ve_tabi/bin/activate
pip install py-radix python-dateutil
python setup.py install
```

Removing TaBi and its dependencies is therefore as simple as removing the `ve_tabi` directory ans the cloned
repository.


## Usage

Historically TaBi was designed to process MRT dump files from the collectors
of the [RIPE RIS](https://www.ripe.net/analyse/internet-measurements/routing-information-service-ris/ris-raw-data).

### Grabbing MRT dumps

You will then need to retrieve some MRT dumps. Copying and pasting the
following commands in a terminal will grab a full BGP view and some updates.

```shell
wget -c http://data.ris.ripe.net/rrc01/2016.01/bview.20160101.0000.gz
wget -c http://data.ris.ripe.net/rrc01/2016.01/updates.20160101.0000.gz
```

### `tabi` - the command line tool

The `tabi` command is the legacy tool that uses TaBi to build technical
indicators for the [Observatory reports](http://www.ssi.gouv.fr/observatoire).
It uses [mabo](https://github.com/ANSSI-FR/mabo) to parse MRT dumps.

Given the name of the BGP collector, an output directory and MRT dumps using the
RIS naming convention, `tabi` will follow the evolution of routes seen in MRT
dumps (or provided with the `--ases` option), and detect BGP IP prefixes
conflicts.

Several options can be used to control tabi behavior:
```shell
$ tabi --help
Usage: tabi [options] collector_id output_directory filenames*

Options:
  -h, --help            show this help message and exit
  -f, --file            files content comes from mabo
  -p PIPE, --pipe=PIPE  Read the MRT filenames used as input from this pipe
  -d, --disable         disable checks of the filenames RIS format
  -j JOBS, --jobs=JOBS  Number of jobs that will process the files
  -a ASES, --ases=ASES  File containing the ASes to monitor
  -s, --stats           Enable code profiling
  -m OUTPUT_MODE, --mode=OUTPUT_MODE
                        Select the output mode: legacy, combined or live
  -v, --verbose         Turn on verbose output
  -l, --log             Messages are written to a log file.
```

Among this options, two are very interesting:
 * `-j` that forks several `tabi` processes to process the MRT dumps faster
 * `-a` that can be used to limit the output to a limited list of ASes

Note that the legacy output mode will likely consume all file descriptors as it
creates two files per processed AS (i.e. **around 100k opened files**). The
default is the combined output mode.

Here is an example call to tabi:
```shell
tabi -j 8 rrc01 results/ bview.20160101.0000.gz updates.20160101.0000.gz
```

After around 5 minutes of processing, you will find the following files in `results/2016.01/`:
- `all.defaults.json.gz` that contains all default routes seen by TaBi
- `all.routes.json.gz` that contains all routes monitored
- `all.hijacks.json.gz` that contains all BGP prefix conflicts


## Using TaBi as a Python module

TaBi could also be used as a regular Python module in order to use it in your
own tool.

The [example](examples/annotation/README.md) provided in this repository enhance
BGP prefix conflicts detection, with possible hijacks classification. To do so,
it relies on external data sources such as RPKI ROA, route objects and other IRR
objects.

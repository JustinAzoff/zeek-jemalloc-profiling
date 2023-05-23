# Installing

    zkg install zeek-jemalloc-profiling

# Verify jemalloc support:

    root@x230:~# zeekctl jeprof.check
    jemalloc profiling enabled: True

# Enabling

In your node.cfg add jeprof_enable=1 like so:

    [worker-1]
    type=worker
    host=localhost
    interface=af_packet::eth0
    lb_method=custom
    lb_procs=2
    jeprof_enable=1

# All options

Node options:

    jeprof_enable=1  # Enable jeprof
    jeprof_all_workers=true #Enable profiling on all workers instead of just the first one

Global options for broctl.cfg:

    jeprof.malloc_conf=...  # extra options to add to MALLOC_CONF
    jeprof.lg_prof_interval=30 # see http://jemalloc.net/jemalloc.3.html#opt.lg_prof_interval

# Processing profile output

    ./process.py /usr/local/zeek/spool | tee -a jeprof.log

# Graphing

The ``process.py`` script can be useful to stream the profile to an external metrics
system for long term recording.

For interactive debugging it can be more useful to use the ``jeprof`` utility
directly with the ``.heap`` files stored in a worker's spool directory.

Either by using the text interface directly, or export data to an SVG file (or the dot raw data with ``--dot``):

    $ jeprof /opt/zeek/bin/zeek --svg $(ls /opt/zeek/spool/worker-1-1/jeprof.out*heap | tail -n 1) > profile-$(date +%Y%m%d-%H%M%S).svg

Above command will produce an SVG for the most recent .heap file created.

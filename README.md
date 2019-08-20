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

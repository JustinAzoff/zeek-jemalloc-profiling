"""
# Zeek jemalloc Profiling

This plugin enables jemalloc profiling
"""

from __future__ import print_function
import ZeekControl.plugin as PluginBase
from ZeekControl import cmdresult
BINARY = "zeek"

import os
import subprocess
import sys

#little namespacing
class JE:
    @classmethod
    def get_stats(binary=BINARY):
        env = os.environ.copy()
        env["MALLOC_CONF"] = "stats_print:true"
        p = subprocess.Popen([binary, "-N"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        out, err = p.communicate()
        if b'built-in' not in out:
            raise Exception("plugin list failed")
        if b'jemalloc statistics' not in err:
            raise Exception("No jemalloc stats was found, not built against jemalloc?")
        return err.decode().split("\n")

    @classmethod
    def get_config():
        cfg = {}
        stats = JE.get_stats()
        conf_lines = [line for line in stats if 'config.' in line]
        for line in conf_lines:
            opt, arg = line.split(": ")
            opt = opt.strip()
            arg = arg.strip()
            cfg[opt] = arg
        return cfg

    @classmethod
    def is_profiling_enalbed():
        cfg = JE.get_config()
        return cfg.get('config.prof', '') == 'true'


class JEMallocProfiling(PluginBase.Plugin):
    def __init__(self):
        super(JEMallocProfiling, self).__init__(apiversion=1)

    def name(self):
        return "jemalloc-profiling"

    def pluginVersion(self):
        return 1

    def options(self):
        return [
            ("workers", "string", "first", "which workers to run on per node [first,all]"),
            ("lg_prof_interval", "int", 20, "see http://jemalloc.net/jemalloc.3.html#opt.lg_prof_interval"),
            ("malloc_conf", "string", "", "extra options to append to MALLOC_CONF"),
        ]

    def init(self):
        self.log_directory = self.getGlobalOption("logdir")
        self.binary = self.getGlobalOption(BINARY)
        profile_all_workers = self.getOption("workers") == "all"
        lg_prof_interval = self.getOption("lg_prof_interval")
        malloc_conf_extra = self.getOption("malloc_conf")

        def get_malloc_conf():
            base = "prof:true,prof_prefix:jeprof.out,lg_prof_interval:{}".format(lg_prof_interval)
            if not malloc_conf_extra:
                return base
            return base + "," + malloc_conf_extra
        full_malloc_conf = get_malloc_conf()

        seen_hosts = set()
        for nn in self.nodes():
            first_on_host = nn.host not in seen_hosts
            seen_hosts.add(nn.host)

            profile_this_worker = profile_all_workers or first_on_host
            if profile_this_worker:
                nn.env_vars.setdefault("MALLOC_CONF", full_malloc_conf)
                self.message("Enabling jemalloc profiling on {} {}".format(nn.host, nn.name))
        return True


    def commands(self):
        return [
            ("check", "", "Verify that jemalloc is in use and profiling is enabled")
            ("process", "", "Process profile output")
        ]

    def cmd_custom(self, cmd, args, cmdout):
        if cmd == 'check':
            return self.cmd_custom_check()
        if cmd == 'process':
            return self.cmd_custom_process()
        raise Exception("HUH?")

    def cmd_custom_check(self):
        enabled = JE.is_profiling_enalbed()
        self.message("jemalloc profiling enabled: {}".format(enabled))
        results = cmdresult.CmdResult()
        results.ok = enabled
        return results

    def cmd_custom_process(self):
        pass

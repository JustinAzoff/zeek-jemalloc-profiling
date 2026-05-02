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

class JEMallocProfiling(PluginBase.Plugin):
    def __init__(self):
        super(JEMallocProfiling, self).__init__(apiversion=1)
        self.binary = None

    def name(self):
        return "jeprof"

    def nodeKeys(self):
        return ["enable", "all_workers"]


    def pluginVersion(self):
        return 1

    def options(self):
        return [
            ("lg_prof_interval", "int", 28, "see http://jemalloc.net/jemalloc.3.html#opt.lg_prof_interval"),
            ("malloc_conf", "string", "", "extra options to append to MALLOC_CONF"),
            ("malloc_conf_env_var", "string", "MALLOC_CONF", "name of the environment variable to set (e.g. MALLOX_CONF for FreeBSD)"),
        ]

    def _get_malloc_stats(self):
        if not self.binary or not os.path.exists(self.binary):
            raise Exception("Zeek binary path not configured or not found: {}".format(self.binary))

        env = os.environ.copy()
        env[self.getOption("malloc_conf_env_var")] = "stats_print:true"
        p = subprocess.Popen([self.binary, "-N"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        out, err = p.communicate()

        if p.returncode != 0:
            raise Exception("Zeek binary failed to run. Stderr: {}".format(err.decode(errors='ignore')))
        if b'built-in' not in out:
            raise Exception("Plugin list failed.  Is '{}' a valid Zeek binary?".format(self.binary))
        if b'jemalloc statistics' not in err:
            raise Exception("No jemalloc stat found.  Is Zeek at '{}' built against jemalloc?.".format(self.binary))
        return err.decode().split("\n")

    def _get_malloc_conf(self):
        cfg = {}
        stats = self._get_malloc_stats()
        conf_lines = [line for line in stats if 'config.' in line]
        for line in conf_lines:
            opt, arg = line.split(": ")
            opt = opt.strip()
            arg = arg.strip()
            cfg[opt] = arg
        return cfg

    def _is_profiling_enabled(self):
        try:
            cfg = self._get_malloc_conf()
            return cfg.get('config.prof', '') == 'true'
        except Exception as e:
            self.error("jemalloc check resolved in error: {}".format(e))
            return False

    def init(self):
        self.spool_directory = self.getGlobalOption("spooldir")
        self.binary = self.getGlobalOption(BINARY)
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
            profile_this_process = False
            if nn.type != "worker":
                profile_this_process = self._to_bool(nn.jeprof_enable or 'false')
            else:
                first_on_host = nn.host not in seen_hosts
                seen_hosts.add(nn.host)
                profile_this_process = first_on_host or self._to_bool(nn.jeprof_all_workers or 'false')

            if profile_this_process:
                nn.env_vars.setdefault(self.getOption("malloc_conf_env_var"), full_malloc_conf)
                #self.message("Enabling jemalloc profiling on {} {}".format(nn.host, nn.name))
        return True


    def commands(self):
        return [
            ("check", "", "Verify that jemalloc is in use and profiling is enabled"),
            ("process", "", "Process profile output"),
        ]

    def cmd_custom(self, cmd, args, cmdout):
        if cmd == 'check':
            return self.cmd_custom_check()
        if cmd == 'process':
            return self.cmd_custom_process()
        raise Exception("HUH?")

    def cmd_custom_check(self):
        enabled = self._is_profiling_enabled()
        if enabled:
            self.message("jemalloc profiling enabled: {}".format(enabled))
        else:
            self.message("jemalloc profiling is NOT enabled")

        results = cmdresult.CmdResult()
        results.ok = enabled
        return results

    def cmd_custom_process(self):
        results = cmdresult.CmdResult()
        results.ok = True
        return results

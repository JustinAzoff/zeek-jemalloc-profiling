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
    def get_stats(binary=BINARY)
        env = os.environ.copy()
        env["MALLOC_CONF"] = "stats_print:true"
        p = subprocess.Popen([binary "-N"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
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

    def init(self):
        self.log_directory = self.getGlobalOption("logdir")
        self.binary = self.getGlobalOption(BINARY)
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
        self.message("jemalloc profiling enabled: {}".format(enabled)
        results = cmdresult.CmdResult()
        results.ok = enabled
        return results

    def cmd_custom_process(self):
        pass

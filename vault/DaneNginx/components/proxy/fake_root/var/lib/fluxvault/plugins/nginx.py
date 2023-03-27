import asyncio
from enum import Enum
from pathlib import Path

import apt
from fluxvault.extensions import FluxVaultExtensions
from fluxvault.log import log

plugin = FluxVaultExtensions(plugin_name="nginx", required_packages=[])

class NginxSignal(Enum):
    quit = "quit"
    reload = "reload"
    reopen = "reopen"
    stop = "stop"


async def nginx_process(signal: NginxSignal | None = None):
    # cmd = ["nginx"]

    # if signal:
    #     cmd.extend(["-s", signal.value])

    # cmd = "".join(cmd)

    # wrote the one liner first, thought the list thing felt better but
    # then went back to the one liner; more succinct
    cmd = f"nginx -s {signal.value}" if signal else "nginx"

    try:
        await asyncio.create_subprocess_exec(cmd)
    except Exception as e:
        #ToDo: use RPC Errors and provide meaningful feedback. The whole transport errors thing
        # needs work
        print(repr(e))


def nginx_is_running() -> bool:
    nginx_pid = Path("/run/nginx.pid")
    return True if nginx_pid.exists() else False

@plugin.create
def install():
    pkg_name = "nginx"

    cache = apt.cache.Cache()
    cache.update()
    cache.open()

    pkg = cache[pkg_name]
    if pkg.is_installed:
        log.warn(f"{pkg_name} already installed")
    else:
        pkg.mark_install()

        try:
            cache.commit()
        except Exception as exc:
            log.error(f"Package installation failed: {exc}")


async def wait_to_exit():
    await asyncio.sleep(3)
    # just trying non zero error code here for thrills
    exit(1)

@plugin.create
async def commit_seppuku():
    """We are the primary container process. This will restart the container with default settings. Will it though?"""
    # we do this so this function can return
    asyncio.create_task(wait_to_exit())

@plugin.create
async def start():
    if nginx_is_running():
        await nginx_process()
    else:
        await reload_config()

@plugin.create
async def reload_config():
    if nginx_is_running():
        await nginx_process(NginxSignal.reload)
    else:
        await nginx_process()

@plugin.create
async def reload_logfiles():
    if nginx_is_running():
        await nginx_process(NginxSignal.reopen)
    else:
        await nginx_process()

@plugin.create
async def stop():
    if nginx_is_running():
        await nginx_process(NginxSignal.stop)


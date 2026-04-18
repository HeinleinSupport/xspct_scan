# SPDX-License-Identifier: EUPL-1.2
# Copyright (C) 2026 Carsten Rosenberg <c.rosenberg@heinlein-support.de>
"""olefy_v2 entry point — invoked by ``olefy_v2`` console script or ``python -m olefy_v2``."""

import asyncio
import logging
import ssl
import sys

from aiohttp import web

from olefy_v2.daemon import config, load_config, configure_logging, make_app

try:
    import uvloop
except ImportError:
    uvloop = None  # type: ignore[assignment]


def main() -> None:
    path = sys.argv[1] if len(sys.argv) == 2 else None
    load_config(path)
    configure_logging()

    _logger = logging.getLogger('olefy')

    if uvloop is not None:
        uvloop.install()
        _logger.info('uvloop installed')

    async def _run() -> None:
        app = await make_app()
        runner = web.AppRunner(app, backlog=int(config['olefy_listen_backlog']))
        await runner.setup()

        ssl_context: 'ssl.SSLContext | None' = None
        if config['olefy_tls']['tls_enabled']:
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(
                config['olefy_tls']['tls_cert'],
                config['olefy_tls']['tls_key'],
            )
            _logger.info('TLS enabled')

        addrs = config['olefy_listen_address']
        if isinstance(addrs, str):
            addrs = [addrs]
        port = int(config['olefy_listen_port'])
        for addr in addrs:
            site = web.TCPSite(runner, addr, port, ssl_context=ssl_context)
            await site.start()
            _logger.info('Listening on %s:%d', addr, port)

        try:
            while True:
                await asyncio.sleep(3600)
        except (asyncio.CancelledError, KeyboardInterrupt):
            pass
        finally:
            await runner.cleanup()

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()

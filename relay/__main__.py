import asyncio
import aiohttp.web
import logging
import platform
import sys
import Crypto
import time

from . import app, CONFIG


def crypto_check():
    vers_split = platform.python_version().split('.')
    pip_command = 'pip3 uninstall pycrypto && pip3 install pycryptodome'

    if Crypto.__version__ != '2.6.1':
        return

    if int(vers_split[1]) > 7 and Crypto.__version__ == '2.6.1':
        logging.error('PyCrypto is broken on Python 3.8+. Please replace it with pycryptodome before running again. Exiting in 10 sec...')
        logging.error(pip_command)
        time.sleep(10)
        sys.exit()

    else:
        logging.warning('PyCrypto is old and should be replaced with pycryptodome')
        logging.warning(pip_command)


async def start_webserver():
    runner = aiohttp.web.AppRunner(app)
    await runner.setup()
    try:
        listen = CONFIG['listen']
    except:
        listen = 'localhost'
    try:
        port = CONFIG['port']
    except:
        port = 8080

    logging.info('Starting webserver at {listen}:{port}'.format(listen=listen,port=port))

    site = aiohttp.web.TCPSite(runner, listen, port)
    await site.start()

def main():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    asyncio.ensure_future(start_webserver(), loop=loop)
    loop.run_forever()


if __name__ == '__main__':
    crypto_check()
    main()

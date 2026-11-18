# Zeekr voor Homey (onofficieel)

Een onofficiële Homey-app waarmee je je Zeekr-auto via **Homey Flows** kunt bedienen en
uitlezen: voorverwarmen/koelen, laden starten/stoppen, laadlimiet, vergrendelen, en status
zoals accu %, actieradius, laadvermogen, binnen-/buitentemperatuur en deuren/ramen.

De cloud-laag is overgezet (in JavaScript) uit het reverse-engineering-werk van
**[OpenZeekr](https://github.com/borconi/openzeekr)** (MIT) van borconi. Deze app praat met
dezelfde Geely/ECARX TSP-cloud. De Bluetooth digitale sleutel van OpenZeekr zit er bewust
**niet** in — die werkt alleen vlak bij de auto en is voor Homey niet nodig.

> ⚠️ Gebruik dit alleen met je **eigen** Zeekr-account en auto. Het is een onofficiële,
> reverse-engineered koppeling: Zeekr kan de API zonder aankondiging veranderen, waarna de app
> pas weer werkt nadat iemand hem aanpast. Geen garantie, geen support. Alleen EU is end-to-end
> geverifieerd; andere regio's zijn onbeproefd.

## Belangrijk vooraf

**1. Eén login tegelijk.** De Zeekr-cloud staat per account maar één actieve sessie toe. Logt
Homey in, dan word je uitgelogd in de officiële Zeekr-app, en andersom. **Aanbevolen:** maak
een **tweede Zeekr-account** (ander e-mailadres), **deel je auto** daarmee vanuit je
hoofdaccount (in de Zeekr-app), en gebruik dat tweede account in Homey. Dan blijft de app op je
telefoon gewoon ingelogd. Raakt Homey toch uitgelogd ("op een ander apparaat ingelogd"), dan
logt een flow-actie of een tik op de tegel Homey weer in.

**2. App-sleutels.** De app heeft zes sleutels nodig die Zeekr niet publiceert (dezelfde die
OpenZeekr gebruikt). De officiële OpenZeekr-APK heeft ze ingebouwd. Haal ze uit die APK met het
meegeleverde script (zie hieronder) en plak ze één keer in de app-instellingen. De sleutels
staan alleen op je eigen Homey.

## Stap 1 — Sleutels uit je OpenZeekr-APK halen

Je hebt nodig: de **OpenZeekr release-APK** (die je op je telefoon gebruikt — download hem van
<https://github.com/borconi/openzeekr/releases>) en **Node.js 18+** op je computer.

```bash
node tools/extract-keys.js pad/naar/openzeekr.apk zeekr-keys.json
```

Het script leest de sleutels uit de APK (geen root of Frida nodig), schrijft ze naar
`zeekr-keys.json` en stuurt niets naar buiten. Het ondersteunt `arm64-v8a`- en `x86_64`-builds.
Open daarna `zeekr-keys.json`, kopieer de inhoud, en bewaar hem voor stap 3. **Verwijder het
bestand als je klaar bent** en zet het nooit online.

> Gebruik je OpenZeekr al en heb je de sleutels daar al als JSON geëxporteerd (Instellingen →
> Exporteren), dan kun je stap 1 overslaan en die JSON in stap 3 gebruiken.

## Stap 2 — De app op je Homey zetten

Homey Pro (2023) nodig. Installeer de [Homey CLI](https://apps.developer.homey.app/) en, in deze
map:

```bash
npm install -g homey
homey login
homey app install
```

De app verschijnt dan bij je Homey-apps.

## Stap 3 — Account en sleutels invullen

Homey-app → **Apps** → **Zeekr (onofficieel)** → **Configureren**:

1. Vul **e-mailadres**, **wachtwoord** en **regio** in (gebruik je tweede account — zie boven).
2. Plak bij **App-sleutels** de JSON uit stap 1.
3. **Opslaan**, dan **Test inloggen**. Je zou je auto('s) in de lijst moeten zien.

Voeg daarna het apparaat toe: **Apparaten** → **+** → **Zeekr** → kies je auto.

## Flows

**Acties:** klimaat starten (temperatuur + duur) / stoppen, ontdooien, stoelverwarming en
-ventilatie per stoel, stuurverwarming, laden starten/stoppen, laadlimiet, accu
voorconditioneren, ramen (sluiten/ventileren), achterklep, lichten/claxon, wachtmodus, en
"status nu ophalen".

**Triggers:** laden gestart/gestopt, kabel aangesloten/losgekoppeld, klimaat aan/uit,
actieradius veranderd, status bijgewerkt (met accu/actieradius/locatie), commando mislukt.

**Voorwaarden:** laadt de auto, kabel aangesloten, klimaat aan, accu boven/onder X %,
actieradius boven/onder X km.

Voorbeeld: *Elke werkdag om 07:00, als de buitentemperatuur onder 3 °C is → Zeekr klimaat
starten op 21 °C voor 15 minuten.*

De status wordt standaard elke 5 minuten opgehaald (instelbaar per apparaat).

## Ontwikkelen

```bash
npm test                 # unit-tests (ondertekening, crypto, status, login-flow)
homey app validate --level publish
homey app run            # live op je Homey, met logs
```

De ondertekening (`lib/zeekr/signing.js`) is byte-voor-byte gecontroleerd tegen de
`zeekr_ev_api`-referentiecode. De sleutel-extractie (`tools/extract-keys.js`) is getest tegen
gecompileerde fixture-libraries (arm64 en x86_64) met nep-testwaarden.

## Dankwoord

Deze app bestaat dankzij het reverse-engineering-werk van
[OpenZeekr](https://github.com/borconi/openzeekr) (borconi) en de projecten die daar genoemd
worden. Zoals daar gebruikelijk: **er worden geen Zeekr-sleutels meegeleverd** — die lever je zelf
aan vanuit je eigen app-installatie.

## Licentie

MIT.

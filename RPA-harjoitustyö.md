# IoT‑pohjainen RPA‑järjestelmä Node‑REDillä ja MCP‑ohjauksella

---

## 1. Johdanto

Robotic Process Automation (RPA) on perinteisesti yhdistetty toimistoympäristöihin, joissa ohjelmistorobotit suorittavat toistuvia ja sääntöpohjaisia tehtäviä ihmisen puolesta. Tyypillisiä esimerkkejä ovat ohjelmistojen testaukset, hyväksyntä- ja tarkastusporsessit (esim. matkalaskut), tiedostojen käsittely, lomakkeiden täyttö ja tietojen siirtäminen järjestelmästä toiseen. Viime vuosina automaation kenttä on kuitenkin laajentunut merkittävästi: RPA ei ole enää vain “hiiren klikkailua”, vaan yhä useammin fyysisen ja digitaalisen maailman yhdistämistä.

Tämä kehitys on seurausta kahdesta suuresta muutoksesta. Ensimmäinen on IoT‑laitteiden ja edullisten sulautettujen alustojen, kuten Raspberry Pi:n, yleistyminen. Ne mahdollistavat fyysisen ympäristön tilan mittaamisen, ohjaamisen ja valvonnan tavalla, joka aiemmin vaati raskaita teollisuusjärjestelmiä. Toinen muutos on suurten kielimallien (LLM) ja Model Context Protocol (MCP) ‑rajapinnan kehittyminen. MCP tarjoaa tavan, jolla LLM voi ymmärtää käyttäjän luonnollisella kielellä antamia komentoja ja muuntaa ne rakenteisiksi, täsmällisiksi ohjeiksi automaatiojärjestelmille.

Tämän harjoitustyön tavoitteena on kuvata ja mallintaa kokonaisuutta, joka yhdistää nämä kaksi maailmaa: IoT‑pohjaisen automaation ja luonnollisen kielen ohjauksen. Järjestelmä toteutetaan Raspberry Pi ‑alustalla, jossa Node‑RED toimii automaation ja orkestroinnin keskuksena. Node‑RED vastaanottaa sensoridataa, suorittaa RPA‑tyyppisiä päätöksiä ja ohjaa laitteita. MCP‑palvelut puolestaan mahdollistavat sen, että käyttäjä voi antaa komentoja suomen kielellä, ja LLM tulkitsee ne automaatiolle sopivaan muotoon.

Kokonaisuus muodostaa modernin, modulaarisen ja laajennettavan automaatiojärjestelmän, jossa fyysiset tapahtumat, ohjelmallinen logiikka ja luonnollisen kielen ohjaus toimivat saumattomasti yhdessä. Harjoitustyön tarkoituksena on osoittaa, miten RPA‑ajattelu voidaan tuoda osaksi IoT‑ympäristöä ja miten LLM‑pohjainen komentotulkinta voi toimia uudenlaisena käyttöliittymänä automaatiolle. Tämä avaa mahdollisuuksia tulevaisuuden järjestelmille, joissa käyttäjä voi ohjata sekä fyysisiä että digitaalisia prosesseja yhtä luontevasti kuin keskustelisi toisen ihmisen kanssa.

### 1.1 RPA:n merkitys SSOT-automaatiossa

SSOT-automaation käytön merkittävin este on pelko käytön monimutkaisuudesta ja käyttöönoton vaatimasta lisätyöstä. Käytännössä pelätään kongnitiivista kuormaa, jonka SSOT-automaation käyttö vaatii. Kongnitiivinen kuorma on MS-Copilotin sanoin: 

> ***aivojen työmuistiin kohdistuvaa henkistä rasitusta ja tiedonkäsittelyn määrää, kun ihminen suorittaa tehtäviä, jotka vaativat tarkkaavaisuutta, muistia, oppimista ja ongelmanratkaisua***. 

RPA (Robotic Process Automation) mahdollistaa SSOT-automaation prosessien automatisoinnin MCP-palvelujen avulla. Käytännössä tavoitteena on ohjata SSOT-automaatiota keskustelemalla automaatiojärjestelmän kanssa yhä luontevasti kuin ystävällisen ja avuliaan työntekijän kanssa.

---
---

## 2. Arkkitehtuurin yleiskuva

Tässä luvussa kuvataan järjestelmän kokonaisarkkitehtuuri ja sen keskeiset komponentit. Tavoitteena on muodostaa selkeä käsitys siitä, miten fyysiset IoT‑laitteet, Node‑RED‑automaatio, MCP‑rajapinta ja LLM‑ohjaus muodostavat yhtenäisen, modernin RPA‑järjestelmän. Arkkitehtuuri on suunniteltu modulaariseksi, laajennettavaksi ja helposti testattavaksi, jotta se tukee sekä harjoitustyön tavoitteita että tulevia jatkokehityksiä.

---

### 2.1 Järjestelmän kokonaisrakenne  

Järjestelmä koostuu neljästä pääkerroksesta:

1. Fyysinen kerros (IoT‑laitteet ja sensorit)  
Raspberry Pico toimii alustana, johon liitetään fyysisiä sensoreita ja toimilaitteita. Sensorit tuottavat reaaliaikaista dataa, kuten pohjaveden pinnankorkeutta, kosteutta, laitteiden tilaa ja toimintaa. Raspberry Pi Zero 2 W on SSOT-EDGE laitteen alustana ja kytkee RTIC-MESH yhteyden välitysellä fyysisen kerroksen laitteet SSOT-automaation Node-RED automaatiokerrokseen

2. Automaatiokerros (Node‑RED)  
Node‑RED toimii järjestelmän “aivoina”. Se vastaanottaa sensoridataa, suorittaa RPA‑logiikkaa, ohjaa laitteita ja tarjoaa rajapinnat ulkoisille palveluille. Node‑RED myös tallentaa tapahtumia tietokantaan ja tuottaa reaaliaikaisen dashboardin testaukseen.

3. Ohjauskerros (MCP‑palvelut)  
Model Context Protocol toimii rajapintana, jonka kautta LLM voi lähettää rakenteisia komentoja Node‑REDille. MCP määrittelee komentojen muodot, parametrit ja sallitut toiminnot.

4. Luonnollisen kielen kerros (LLM‑ohjaus)  
Käyttäjä antaa komennot suomenkielellä. LLM tulkitsee ne, muuntaa MCP‑komennoksi ja välittää Node‑REDille. LLM myös muotoilee vastaukset käyttäjälle.

Näiden kerrosten välinen vuorovaikutus muodostaa kokonaisuuden, jossa fyysiset tapahtumat ja luonnollisen kielen ohjaus toimivat saumattomasti yhdessä. LLM-ohjausta käytetään käyttöliittymänä, joka ei tarkoita tekoälyn (LLM) tekemiä ohjauspäätöksiä. Kaikki komennot ja komentoihin liittyvät vahvistukset esim. kysymykseen "Oletko varma?" ovat aina käyttäjän vastuulla.

---

### 2.2 Fyysisen ja digitaalisen automaation yhdistäminen  

Perinteinen RPA keskittyy ohjelmistojen sisäisiin prosesseihin. Tässä järjestelmässä RPA‑ajattelu laajennetaan fyysiseen maailmaan:

* Sensorit tuottavat dataa, joka toimii automaation syötteenä
* Node‑RED tekee päätöksiä sääntöjen ja logiikan perusteella
* Toimilaitteet reagoivat automaation tuloksiin
* LLM:n avulla voidaan hallita prosesseja luonnollisella kielellä

Tämä yhdistelmä mahdollistaa uudenlaisen automaation, jossa fyysiset tapahtumat ja digitaalinen logiikka muodostavat yhtenäisen prosessin.

---

### 2.3 Node‑RED automaatiokerroksena (SSOT-EDGE ja SSOT-SCADA)

Node‑RED toimii järjestelmän keskeisenä orkestrointialustana. Sen rooli sisältää:
* Sparkplug- ja MQTT‑viestien vastaanoton ja lähetyksen
* sensoridatan käsittelyn ja normalisoinnin
* RPA‑logiikan toteutuksen (switch‑ehdot, funktiot, tilakoneet)
* aikasarjatietokantakirjaukset
* MCP‑komentojen vastaanoton ja suorituksen
* dashboardin reaaliaikaiseen seurantaan

Node‑RED sopii automaatiokerrokseksi sen visuaalisen käyttöliittymän, laajennettavuuden ja IoT‑yhteensopivuuden vuoksi. Se soveltuu erinomaisesti tavoitteisiin, joissa yhdistyvät sensoridata, automaatio ja ulkoiset rajapinnat.

---

### 2.4 MCP rajapintana luonnollisen kielen ohjaukselle  
Model Context Protocol toimii sillanrakentajana LLM:n ja Node‑REDin välillä. MCP:n avulla:
* LLM ymmärtää käyttäjän suomenkieliset komennot
* komennot muunnetaan rakenteisiksi JSON‑muotoisiksi ohjeiksi
* Node‑RED suorittaa komennot täsmällisesti ja turvallisesti
* järjestelmä palauttaa tulokset LLM:lle
* LLM tuottaa käyttäjälle suomenkielisen vastauksen

MCP:n etuna on sen selkeä ja laajennettava rakenne: uusia komentoja voidaan lisätä ilman, että toimintaa tarvitsee muuttaa. Tämä tekee järjestelmästä joustavan ja helposti ylläpidettävän.

---

### 2.5 Tietovirrat ja komponenttien roolit  
Järjestelmän tietovirrat voidaan jakaa kolmeen päätyyppiin:

1. Sensoridata → Node‑RED
* Sensorit lähettävät dataa MQTT:n kautta 
* SSOT-EDGE Node‑RED vastaanottaa, tulkitsee datan
* SSOT-EDGE Node-RED lähettää normalisoidun datan Sparkpluginin kautta 
* SSOT-SCADA Node‑RED vastaanottaa, tulkitsee ja tallentaa datan
* RPA‑logiikka reagoi poikkeamiin tai tapahtumiin

2. MCP‑komennot → Node‑RED
* Käyttäjä antaa komennon suomeksi
* LLM tulkitsee sen ja tuottaa MCP‑komennon
* Node‑RED suorittaa komennon ja palauttaa tuloksen

3. Node‑RED → käyttäjä / LLM
* Hälytykset
* raportit
* sensoridatan tilannekuva
* vahvistukset suoritetuista komennoista

Näiden tietovirtojen avulla järjestelmä toimii automaattisesti käyttäjän ohjaamana. Automaattinen toiminta tarkoittaa käyttäjän antamien ehtojen ja rajaarvojen mukaista toimintaa.

---
---

## 3. Raspberry Pi alustana

Raspberry Pi toimii tämän harjoitustyön fyysisenä perustana ja IoT‑automaation keskuslaitteena. Sen rooli on vastaanottaa sensoridataa, suorittaa paikallista logiikkaa, ajaa Node‑RED‑palvelua ja tarjota rajapinnat sekä fyysisille laitteille että ulkoisille palveluille. Raspberry Pi valittiin alustaksi sen edullisuuden, laajan yhteisötuen, helpon laajennettavuuden ja Linux‑pohjaisen ympäristön vuoksi, joka soveltuu erinomaisesti automaatioprojekteihin.

* ***Raspberry Pi tarjoaa harjoitustyölle vakaan ja joustavan alustan, jossa yhdistyvät fyysiset sensorit, automaatio, tietoliikenne ja ulkoiset rajapinnat. Node‑RED toimii automaation keskuksena, MQTT välittää sensoridatan ja MCP mahdollistaa luonnollisen kielen ohjauksen. Tämä kokonaisuus muodostaa modernin IoT‑pohjaisen RPA‑järjestelmän perustan.***

---

### 3.1 Laitteisto ja käyttöjärjestelmä  
SSOT-EDGE laitteen alustana on Raspberry Pi Zero 2 W ‑malli, joka sisältää:
* ARM‑pohjaisen prosessorin
* ajaa tehokkaasti natiivipalveluita (myös docker-kontit mahdollisia)
    * virtuaaliympäristö haastava GPIO‑liittimien ohjauksessa
* GPIO‑liittimet fyysisten sensorien ja toimilaitteiden ohjaamiseen
* Sarjaporttiliikenneen antureille SSOT-RTIC-MESH-GW ohjelman välityksellä
* RMQTT brokerin Node-RED ja SSOT-RTIC-MESH-GW yhteyden MQTT-viesteille
* Wi‑Fi‑yhteyden

SSOT-SCADA laitteen alustana on Raspberry Pi 5 ‑malli, joka sisältää:
* Tehokkaan ARM‑pohjaisen prosessorin
* Mahdollisuuden ajaa Docker‑kontteja tehokkaasti
* Ethernet- ja/tai Wi‑Fi‑yhteyden
* SSOT-SCADA voidaan toteuttaa myös virtuaalipalvelmella

Käyttöjärjestelmänä toimii Raspberry Pi OS, joka tarjoaa vakaan Debian‑pohjaisen ympäristön Node‑REDin ja MQTT‑brokerin ajamiseen.

Asennusvaiheet sisältävät:
1. Raspberry Pi OS ‑kuvan kirjoittamisen SD‑kortille
2. Ensimmäisen käynnistyksen ja verkkoasetusten määrittämisen
3. SSH‑yhteyden käyttöönoton
4. Järjestelmän päivityksen (apt update && apt upgrade)

Näiden jälkeen laite on valmis Node‑RED‑ympäristön käyttöönottoon.

---

### 3.2 Node‑RED asennus ja konfigurointi
Node‑RED toimii automaatiokerroksen ytimenä. Se voidaan asentaa kahdella tavalla:

1. Natiiviasennus Raspberry Pi Zero 2 W OS:ään
Node‑RED tarjoaa valmiin asennusskriptin, joka:
* asentaa Node.js:n
* asentaa Node‑REDin
* konfiguroi palvelun systemd‑palveluksi

Tämä on suositeltu tapa, jos halutaan kevyt ja suorituskykyinen ympäristö pienillä resursseilla

2. Docker‑konttina Raspberry Pi 5 OS:ään Docker‑asennus tarjoaa lisäksi:
* eristetyn ympäristön
* helpon päivitettävyyden

Mutta vaatii ememmän muistia ja tehoa mitä Raspberry Pi 5:lla on riittävästi

Node‑RED käynnistyy oletuksena portissa 1880 ja tarjoaa selainpohjaisen editorin, jossa automaatiovirrat rakennetaan visuaalisesti.  

---

### 3.3 Sensorien ja laitteiden liittäminen (GPIO, I2C, SPI)  
Raspberry Pi:n GPIO‑liittimet mahdollistavat fyysisten laitteiden liittämisen suoraan automaatiojärjestelmään. SSOT-automaatiossa anturit asetetaan pääsääntöisesti Raspberry Pico kontrollerin välityksellä, josta data siirretään Raspberry Zerolle sarjaportin välityksellä.
Raspberry Pico on kytkettynä relekorttiin, joka mahdollistaa karamottoreiden ja ilmanpaine kompressorien ohjauksen. Releiden lisäksi Picoon voidaan liittää:
* paine‑ ja kosteusantureita
* painikkeita ja kytkimiä
* Karamoottori asentoanturi (A/D-muunnin)
* LED‑indikaattoreita
* I2C‑ ja SPI‑pohjaisia laajennusmoduuleja

Fyysiset sensorit tuottavat harjoitustyössä reaaliaikaista dataa, jota käytetään RPA‑logiikan syötteenä ja MCP‑komentojen suorituksessa.

---

### 3.4 MQTT‑brokerin käyttöönotto (RMQTT ja Mosquitto)  
MQTT on kevyt viestinvälitysprotokolla, joka soveltuu erinomaisesti IoT‑ympäristöihin. SSOT-automaatiossa RMQTT‑broker toimii:
* sensoridatan välittäjänä
* MCP‑komentojen suorituksessa

SSOT-automaatiossa Mosquitto‑broker toimii:
* Node‑REDin sisääntulokanavana nettiin
* MCP‑komentojen siirtotienä 
* tilapäivitysten ja hälytysten jakelijana

MQTT:n etuja ovat:
* pieni viestikoko
* publish/subscribe‑malli
* hyvä suorituskyky Raspberry Pi:llä
* helppo integrointi Node‑REDiin

Broker voidaan ajaa joko natiivisti tai Docker‑kontissa.

---

### 3.5 Turvallisuus ja verkkoasetukset  
Koska Raspberry Pi toimii automaation keskuslaitteena, sen turvallisuus on keskeinen osa arkkitehtuuria. SSOT-automaatiossa huomioidaan seuraavat periaatteet:
* oletussalasanojen vaihtaminen
* Node‑RED‑editorin suojaaminen salasanalla
* MQTT‑brokerin sertifikaatit
* MQTT-välityspalvelimen ACL (Access Control Lists)

---
---

## 4. IoT‑sensorien ja laitteiden simulointi

IoT‑sensorit muodostavat järjestelmän “aistit”, joiden tuottama data toimii automaation ja RPA‑logiikan syötteenä. SSOT-automaatiossa voidaan käyttää sekä fyysisiä sensoreita että virtuaalisia simulaattoreita. Tämä mahdollistaa järjestelmän testaamisen ja kehittämisen myös tilanteissa, joissa kaikkia fyysisiä komponentteja ei ole saatavilla. Node‑RED tarjoaa erinomaiset työkalut sensoridatan vastaanottamiseen, muokkaamiseen ja simuloimiseen, mikä tekee siitä joustavan alustan IoT‑pohjaisen RPA‑järjestelmän rakentamiseen.

* ***Tässä luvussa esitetään, miten IoT‑sensorit ja toimilaitteet liitetään Raspberry Pi:hin ja miten niiden dataa voidaan simuloida Node‑REDissä. Fyysiset sensorit tuovat järjestelmään konkreettisen ulottuvuuden, kun taas virtuaalisensorit mahdollistavat nopean kehityksen ja testauksen. Standardoitu sensoridata ja selkeät testausmenetelmät muodostavat perustan luotettavalle IoT‑pohjaiselle RPA‑järjestelmälle, jota voidaan ohjata MCP‑palveluiden kautta luonnollisella kielellä.***

---

### 4.1 Fyysiset sensorit (ilmanpaine, kosteus, painike, LED)  
Fyysiset sensorit liitetään Raspberry Picon GPIO‑liittimiin tai I2C/SPI‑väyliin. Harjoitustyössä voidaan käyttää esimerkiksi seuraavia komponentteja:

**Ilmanpaine- ja kosteusanturit**
* Moisture Sensor v2.0: yksinkertainen kosteusanturi 
* BME280: tarkka I2C‑pohjainen anturi, joka mittaa ilmanpainetta

Nämä anturit soveltuvat hyvin RPA‑logiikan syötteiksi, kuten:

* hälytykset liian korkeasta pohjavedestä
* automaattiset raportit ympäristöolosuhteista
* MCP‑komennot esim. “Anna säätökaivon A1 vedenkorkeuden raportti viimeisen viikon ajalta”

**Painikkeet ja kytkimet**

Painikkeet mahdollistavat fyysisen vuorovaikutuksen automaation kanssa. Niitä voidaan käyttää esimerkiksi:
* manuaaliseen käynnistykseen
* hätätilanteiden simulointiin
* testaukseen

**LED‑indikaattorit ja releet**

LED‑valot ja relemoduulit toimivat toimilaitteina, joita Node‑RED voi ohjata:
* LED voi ilmaista järjestelmän tilan
* rele voi ohjata esimerkiksi karamoottoria, kompressoria, pumppua tai muuta laitetta

Fyysiset komponentit tuovat harjoitustyöhön konkreettisen ulottuvuuden ja havainnollistavat, miten RPA voi vaikuttaa fyysiseen maailmaan.

---

### 4.2 Virtuaalisensorit Node‑REDissä  

Kaikkia fyysisiä sensoreita ei tarvitse asentaa heti. Node‑RED mahdollistaa sensoridatan simuloimisen esimerkiksi seuraavilla tavoilla:

**Inject‑solmu**
* tuottaa arvoja manuaalisesti tai ajastetusti
* sopii yksinkertaiseen testaukseen

**Function‑solmu**
* voi generoida satunnaista tai mallinnettua dataa
* mahdollistaa realistisen sensorikäyttäytymisen simulaation

**Dashboard‑sliderit ja syöttökentät**
* käyttäjä voi itse muuttaa sensorin arvoa
* sopii MCP‑komentojen testaukseen

Virtuaalisensorit ovat erityisen hyödyllisiä kehitysvaiheessa, jolloin RPA‑logiikka ja MCP‑rajapinta voidaan rakentaa valmiiksi ennen fyysisten laitteiden liittämistä.

---

### 4.3 Sensoridatan formaatti ja standardointi  
Jotta Node‑RED voi käsitellä sensoridataa luotettavasti, data kannattaa standardoida yhtenäiseen JSON‑muotoon. Tämä helpottaa:
* RPA‑logiikan rakentamista
* MCP‑komentojen tulkintaa
* tietokantakirjauksia
* dashboardin visualisointia

*Esimerkki standardoidusta viestistä:*

```json
{ 
    "deviceId": "A1", 
    "type": "patoKorkeus", 
    "value": 60, 
    "unit": "cm", 
    "timestamp": "2026-01-03T14:32:10Z" 
}
```
Standardointi mahdollistaa myös sen, että fyysiset ja virtuaaliset sensorit voidaan käsitellä samalla logiikalla.

---

### 4.4 Testaus- ja validointimenetelmät  

Sensoridatan testaus on keskeinen osa harjoitustyötä. Testausmenetelmät voidaan jakaa kolmeen tasoon:

**1. Yksikkötestaus Node‑REDissä**
* yksittäisten solmujen toiminnan tarkistus
* debug‑solmun käyttö
* simuloidut syötteet

**2. Integraatiotestaus**
* sensorit → MQTT → Node‑RED
* Node‑RED → aikasarjatietokanta → dashboard
* MCP‑komennot → Node‑RED → toimilaitteet

**3. Skenaariotestaus**

Esimerkiksi:
* “Kuivavara laskee alle 20 cm → Node‑RED lähettää hälytyksen”
* “Painiketta painetaan → Node‑RED suorittaa MCP‑komennon”
* “LLM antaa komennon ‘Käynnistä laite uudelleen’ → Node‑RED ohjaa relettä”

Testaus varmistaa, että järjestelmä toimii luotettavasti sekä fyysisillä että virtuaalisilla sensoreilla.

---
---

## 5. Node‑RED automaatiokerros

Node‑RED toimii koko harjoitustyön automaation ytimenä. Se vastaanottaa sensoridataa, suorittaa RPA‑logiikkaa, ohjaa fyysisiä laitteita ja tarjoaa rajapinnat ulkoisille palveluille, kuten MCP‑ohjaukselle. Node‑RED:n visuaalinen flow‑malli tekee siitä erinomaisen työkalun sekä nopeaan prototypointiin että tuotantotasoiseen automaatioon. Tässä luvussa kuvataan Node‑REDin keskeiset roolit, rakenteet ja käytännön toteutukset harjoitustyössä.

* ***Node‑RED toimii harjoitustyön automaatiokerroksena, joka yhdistää sensoridatan, RPA‑logiikan, tietokantakerroksen ja MCP‑ohjauksen. Sen visuaalinen flow‑malli tekee automaatiosta läpinäkyvää ja helposti laajennettavaa. Node‑REDin avulla fyysiset tapahtumat, digitaalinen logiikka ja luonnollisen kielen ohjaus muodostavat yhtenäisen ja modernin RPA‑järjestelmän.***

---

### 5.1 Flow‑suunnittelu  

Node‑REDin automaatio rakentuu “flow”-kaavioista, jotka koostuvat solmuista (nodes) ja niiden välisistä yhteyksistä. Flow‑suunnittelussa noudatetaan seuraavia periaatteita:

* **Modulaarisuus:** jokainen flow hoitaa yhden selkeän tehtävän (esim. sensoridatan käsittely, MCP‑komentojen vastaanotto, hälytykset).

* **Läpinäkyvyys:** debug‑solmut ja kommentit tekevät logiikasta helposti ymmärrettävää.

* **Laajennettavuus:** uusia sensoreita, komentoja ja toimilaitteita voidaan lisätä ilman, että koko järjestelmää tarvitsee muuttaa.

* **Erottelu:** fyysiset tapahtumat, RPA‑logiikka ja MCP‑rajapinta pidetään omissa flow‑kokonaisuuksissaan.

Flow‑suunnittelu on keskeinen osa SSOT-automaatiota, sillä se määrittää automaation rakenteen ja luotettavuuden.

---

### 5.2 Tapahtumapohjainen automaatio  

Node‑RED toimii tapahtumapohjaisesti: jokainen viesti, sensorimuutos tai MCP‑komento käynnistää automaation. Tyypillisiä tapahtumalähteitä ovat:

**MQTT‑viestit**
Sensorit lähettävät dataa MQTT‑brokerille, josta Node‑RED vastaanottaa sen ```mqtt in``` ‑solmulla.

**Ajastetut tapahtumat**

```inject```‑solmu voi toimia cron‑ajastimena esimerkiksi:
* tunnin välein tehtäville raporteille
* päivittäisille tarkistuksille (aamuraportti)
* automaattisille huoltotoimille

Esimerkiksi päivittäinen aamuraportti SSOT-automaation tilasta ja asioista, joista olisi hyvä olla tietoinen. Esimerkiksi kaivojen vesipintojen tai pohjaveden muutokset, joissa on tapahtunut merkittäviä muutoksia tai saattavat vaativat toimenpiteitä. Myös raportti "Kaikki näyttää olevan kunnossa." on erittäin hyödyllinen.

**HTTP‑pyynnöt**

MCP‑komennot voivat saapua Node‑REDiin HTTP‑endpointin kautta (vain testauksessa).

**GPIO‑muutokset**

Fyysiset painikkeet tai kytkimet voivat käynnistää automaation.

Tapahtumapohjaisuus tekee Node‑REDistä erittäin joustavan RPA‑moottorin, joka reagoi sekä fyysisiin että digitaalisiin signaaleihin.

---

### 5.3 RPA‑logiikka (switch, function, state machine)  

Node‑REDin RPA‑logiikka rakentuu kolmesta keskeisestä elementistä:

**1. Switch‑solmut**

Switch‑solmuilla voidaan tehdä ehtopohjaisia päätöksiä, kuten:

* “Jos kuivavara < 20 cm → lähetä hälytys”

* “Jos MCP‑komento on ‘restartDevice’ → suorita uudelleenkäynnistys”

**2. Function‑solmut**

Function‑solmut mahdollistavat JavaScript‑pohjaisen logiikan, kuten:

* datan normalisointi

* laskennat

* tilamuutokset

* MCP‑parametrien tulkinta

**3. Tilakoneet (state machine)**

Monimutkaisempi automaatio voidaan toteuttaa tilakoneena, esimerkiksi:
* “idle → running → warning → shutdown”
* “ready → processing → completed → error”

Tilakoneet tekevät automaatiosta ennustettavaa ja helposti testattavaa.

---

### 5.4 Aikasarjatietokantaintegraatio (InfluxDB)  

Node‑RED voi tallentaa sensoridataa, hälytyksiä ja MCP‑komentojen lokitietoja tietokantaan. 

Tietokantaan tallennetaan esimerkiksi:
* sensoridata
* automaation tilamuutokset

Tietokantakerros mahdollistaa raportoinnin, analytiikan ja jäljitettävyyden.

---

### 5.5 Hälytykset ja ilmoitukset (email, telnet) 
Node‑RED voi lähettää ilmoituksia useilla eri tavoilla:
* SMTP‑solmu sähköpostihälytyksiin
* Telnet‑solmu Telnet‑viesteihin

Esimerkkejä hälytyksistä:

* “Kuivavara alle 20 cm”
* “MCP‑komento epäonnistui”
* “Laite käynnistettiin uudelleen”

Hälytykset ovat keskeinen osa RPA‑järjestelmän luotettavuutta.

---

### 5.6 Dashboard reaaliaikaiseen seurantaan  

Node‑RED Dashboard tarjoaa käyttöliittymän, jossa voidaan visualisoida:
* sensoridataa
* laitteiden tilaa
* hälytyksiä
* MCP‑komentojen tuloksia
* automaation tilakoneen tilaa

Dashboard‑komponentteja ovat:

* mittarit (gauges)
* kaaviot (charts)
* taulukot
* painikkeet
* tekstikentät

Dashboard toimii sekä kehitystyökaluna että käyttöliittymänä valmiille järjestelmälle.

---
---

## 6. MCP‑palveluiden integrointi

Model Context Protocol (MCP) toimii järjestelmän älykkäänä rajapintana, jonka kautta suurten kielimallien (LLM) on mahdollista ohjata Node‑RED‑automaatioita luonnollisella kielellä. MCP määrittelee tavan, jolla LLM voi tuottaa rakenteisia komentoja, jotka Node‑RED voi suorittaa täsmällisesti, turvallisesti ja ennustettavasti. Tässä luvussa kuvataan MCP:n rooli, komentojen rakenne, integraatiot Node‑REDiin sekä luonnollisen kielen ohjauksen periaatteet.

* ***MCP‑integraatio mahdollistaa sen, että Node‑RED‑pohjaista IoT‑automaatiota voidaan ohjata luonnollisella kielellä. MCP toimii rakenteisena rajapintana LLM:n ja automaation välillä, varmistaen komentojen täsmällisyyden, turvallisuuden ja ennustettavuuden. Node‑RED vastaanottaa MCP‑komennot, suorittaa automaation ja palauttaa tulokset LLM:lle, joka muotoilee ne käyttäjälle ymmärrettävään muotoon. Tämä yhdistelmä tekee järjestelmästä modernin, joustavan ja helposti laajennettavan.***

---

### 6.1 MCP:n periaatteet ja rooli järjestelmässä  

MCP toimii välittäjänä käyttäjän ja automaatiojärjestelmän välillä. Sen keskeiset tehtävät ovat:

* **Luonnollisen kielen tulkinta:** LLM ymmärtää käyttäjän suomenkielisen komennon.
* **Rakenteinen muoto:** MCP muuntaa komennon JSON‑muotoiseksi, jossa on selkeät parametrit.
* **Validointi:** MCP varmistaa, että komento on sallittu ja parametrit ovat oikeassa muodossa.
* **Toimitus Node‑REDille:** Komento lähetetään Node‑REDin endpointiin.
* **Palautteen välitys:** Node‑REDin vastaus palautetaan LLM:lle ja muotoillaan käyttäjälle ymmärrettäväksi.

MCP:n ansiosta käyttäjä voi ohjata automaatiota ilman teknistä osaamista — pelkällä luonnollisella kielellä.

---

### 6.2 MCP‑komentojen JSON‑schema

Jokainen MCP‑komento määritellään JSON‑schemana, joka kuvaa:
* komennon nimen
* parametrit
* parametriarvojen tyypit
* sallitut arvot
* mahdolliset virhekoodit

Esimerkki MCP‑komennosta, joka säätää kaivon A1 patokorkeutta:

```json
{
  "command": "asetaPatokorkeus",
  "parameters": {
    "deviceId": "A1",
    "value": 60
  }
}
```

Esimerkki komennosta, joka hakee sensoridataa:

```json
{
  "command": "haeKuivavara",
  "parameters": {
    "deviceId": "pohjavesiputki1"
  }
}
```

JSON‑schema varmistaa, että Node‑RED saa aina täsmällisen ja yksiselitteisen komennon.

---

### 6.3 Node‑REDin MCP‑endpointit (HTTP / WebSocket / MQTT)  

Node‑RED voi vastaanottaa MCP‑komentoja useilla eri tavoilla. Harjoitustyössä käytetään tyypillisesti yhtä seuraavista:

### HTTP‑endpoint
* helppo toteuttaa
* sopii yksittäisiin komentoihin
* toimii hyvin LLM‑integraation kanssa

Node‑REDissä voidaan luoda endpoint esimerkiksi ```http in``` ‑solmulla:

```
POST /mcp/command
```

### WebSocket
* sopii reaaliaikaiseen ohjaukseen
* mahdollistaa kaksisuuntaisen viestinnän

### MQTT
* sopii IoT‑ympäristöihin
* mahdollistaa komentojen ja tilapäivitysten yhdistämisen samaan protokollaan

Esimerkiksi:

```
topic: /mcp/command
```

Node‑REDin tehtävänä on:

1. vastaanottaa MCP‑komento
2. validoida parametrit
3. suorittaa automaatio
4. palauttaa tulos MCP:lle

---

### 6.4 LLM:n ohjaus suomenkielisillä komennoilla  

LLM toimii järjestelmän “kielimoottorina”. Käyttäjä voi antaa komentoja esimerkiksi näin:
* “Nosta koneen 1 nopeutta 10 prosenttia.”
* “Näytä viimeisen tunnin lämpötilahälytykset.”
* “Pysäytä prosessi, jos lämpötila ylittää 80 astetta.”
* “Käynnistä laite uudelleen.”

LLM tulkitsee komennon ja tuottaa MCP‑komennon, joka sisältää:
* toiminnon
* parametrit
* mahdolliset lisäehdot

Esimerkiksi:

“Nosta kaivon A1 patokorkeutta 10 cm.”

→ MCP‑komento:

```json
{
  "command": "nostaPatokorkeus",
  "parameters": {
    "deviceId": "A1",
    "value": 10
  }
}
```

Node‑RED suorittaa komennon ja palauttaa tuloksen:

```json
{
  "status": "ok",
  "value": 60
}
```

LLM muotoilee vastauksen käyttäjälle:

> “Kaivon A1 patokorkeutta nostettiin 10 cm. Uusi patokorkeus on 60 cm.”

---

### 6.5 Komentojen validointi ja virheenkäsittely  

Validointi on keskeinen osa MCP‑integraatiota. Node‑RED tarkistaa:
* onko komento sallittu
* ovatko parametrit annettu ja oikeassa muodossa
* onko deviceId olemassa
* onko komento turvallinen suorittaa

Vaikka deviceId on olemassa, tulisi järjestelmän varmistaa kuvalla tai kaivon kuvaustiedoilla, että komento kohdituu oikeaan kohteeseen (mikäli kyseessä on kriittinen komento)

Esimerkiksi:
* jos käyttäjä pyytää nostamaan patokorkeutta 200 cm, Node‑RED voi hylätä komennon
* jos deviceId ei ole olemassa, Node‑RED palauttaa virheen
* jos komennon deviceId on olemassa, komennolla "avaa patoluukku"
  * lähetetään esim. kaivon kuvautiedot ja pyydetään varmistamaan komento
  * lähetetään ilmakuva, josta näkyy kaivon sijainti, ja varmistuspyyntö

Virhevastaukset palautetaan MCP‑muodossa:

```json
{
  "status": "virhe",
  "message": "Virheellinen parametsi: deviceId ei löydy"
}
```

LLM muotoilee tämän käyttäjälle:

> “Laitetta ‘Kaivo A1’ ei löytynyt. Tarkista laitteen nimi.”

---

### 6.6 Palautteiden ja tulosten muotoilu LLM:lle  

Node‑RED palauttaa MCP‑muotoisen vastauksen, joka sisältää:
* onnistumisen tai virheen
* tulokset
* mahdolliset lisätiedot

LLM muotoilee vastauksen käyttäjälle luonnollisella kielellä.

Esimerkki:

Node‑RED → MCP:

```json
{
  "status": "ok",
  "deviceId": "A1"
  "value": 60
}
```

LLM → käyttäjä:
> “Raportoitu kaivon A1 patokorkeus on 60 cm.”

Tämä kerros tekee järjestelmästä käyttäjäystävällisen ja intuitiivisen.

---
---

## 7. Luonnollisen kielen ohjaus

Luonnollisen kielen ohjaus on tämän harjoitustyön näkyvin ja käyttäjälle intuitiivisin osa. Sen avulla käyttäjä voi ohjata IoT‑pohjaista RPA‑järjestelmää suomenkielisillä komennoilla ilman teknistä osaamista tai erillisiä käyttöliittymiä. Suuret kielimallit (LLM) tulkitsevat käyttäjän antamat lauseet, muuntavat ne MCP‑komentojen kautta rakenteiseksi automaatioksi ja palauttavat tulokset takaisin käyttäjälle ymmärrettävässä muodossa. Tämä luku kuvaa luonnollisen kielen ohjauksen periaatteet, toimintamallin ja käytännön esimerkit.

* ***Luonnollisen kielen ohjaus tekee automaatiosta intuitiivista ja käyttäjäystävällistä. LLM tulkitsee suomenkieliset komennot, MCP muuntaa ne rakenteiseksi automaatioksi ja Node‑RED suorittaa ne fyysisessä tai digitaalisessa ympäristössä. Tämä kerros yhdistää IoT‑sensorit, RPA‑logiikan ja käyttäjän välisen vuorovaikutuksen tavalla, joka tekee järjestelmästä modernin, joustavan ja helposti laajennettavan.***

---

### 7.1 Suomenkielisten komentojen tulkinta  

Suomen kieli on rakenteeltaan rikas ja taivutusmuodoiltaan monimutkainen, mikä tekee siitä hyvän testialustan luonnollisen kielen ohjaukselle. LLM:n tehtävänä on:
* tunnistaa käyttäjän tarkoitus (intent)
* poimia tarvittavat parametrit (esim. laite, arvo, toiminto)
* tulkita epäsuorat tai puhekieliset ilmaukset
* huomioida konteksti ja aiemmat komennot

Esimerkkejä erilaisista suomenkielisistä komennoista:
* “Nosta patokorkeutta hieman.”
* “Paljonko patokorkeus on nyt?”
* “Jos kuivavara laskee alle 20 cm, avaa patokuukku.”
* “Käynnistä laite uudelleen.”

LLM pystyy tulkitsemaan sekä eksplisiittiset että implisiittiset pyynnöt ja muuntamaan ne MCP‑komennoksi.

---

### 7.2 MCP:n tuottamat rakenteiset komennot  

Kun LLM on tulkinnut käyttäjän pyynnön, se tuottaa MCP‑komennon, joka sisältää:
* komennon nimen
* parametrit
* mahdolliset lisäehdot
* turvallisuusrajoitukset

Esimerkki:

> Käyttäjä: “Nosta kaivon A1 patokorkeutta 10 senttiä.”

LLM → MCP:

```json
{
  "command": "nostaPatokorkeutta",
  "parameters": {
    "deviceId": "A1",
    "value": 10
  }
}
```

Toinen esimerkki:

> Käyttäjä: “Mikä on pohjavesiputken A3 kuivavara?”

LLM → MCP:

```json
{
  "command": "haeKuivavara",
  "parameters": {
    "deviceId": "A3"
  }
}
```

Tämä rakenne varmistaa, että Node‑RED saa aina täsmällisen ja yksiselitteisen komennon.

---

### 7.3 Esimerkkikomennot ja niiden muuntuminen automaatioksi  

Alla on esimerkkejä siitä, miten suomenkieliset komennot muuttuvat MCP‑muotoon ja miten Node‑RED suorittaa ne.

### Esimerkki 1: Laitteen ohjaus
Käyttäjä:

> “Avaa kaivon A2 patoluukku.”

LLM → MCP:


```json
{
  "command": "avaaPatoluukku",
  "parameters": {
    "deviceId": "A2"
  }
}
```

Node‑RED suorittaa toimilaitteen pysäytyksen ja palauttaa tuloksen.

---

Esimerkki 2: Sensoridatan kysely
Käyttäjä:

“Näytä viimeisen tunnin hälytykset.”

LLM → MCP:

```json
{
  "command": "haeHalytykset",
  "parameters": {
    "timeRange": "1h"
  }
}
```

Node‑RED hakee tiedot tietokannasta ja palauttaa ne LLM:lle.

---

Esimerkki 3: Ehtopohjainen automaatio
Käyttäjä:

“Jos kaivon 2 kuivavara laskee alle 20 cm, lähetä hälytys.”

LLM → MCP:

```json
{
  "command": "asetaHalytysRaja",
  "parameters": {
    "deviceId": "A2",
    "threshold": 20,
    "action": "lahetaHalytys"
  }
}
```

Node‑RED lisää uuden automaatioregelin flow’hun.

---

### 7.4 LLM:n rooli päätöksenteossa  

LLM ei suorita automaatiota itse — sen tehtävä on:
* tulkita käyttäjän tarkoitus
* muotoilla komento MCP‑standardin mukaisesti
* varmistaa, että komento on looginen ja ymmärrettävä
* muotoilla Node‑REDin palauttama tulos käyttäjälle

LLM toimii siis “kielitulkina” käyttäjän ja automaation välillä.

LLM ei tee päätöksiä käyttäjän puolesta, vaan Node‑RED vastaa:
* turvallisuudesta
* rajoituksista
* laitteiden ohjauksesta
* virheenkäsittelystä

Tämä erottelu tekee järjestelmästä luotettavan ja ennustettavan.

---

### 7.5 Turvallisuus ja rajaukset  

Luonnollisen kielen ohjaus tuo mukanaan uusia turvallisuusvaatimuksia. Järjestelmässä huomioidaan:

#### 1. Komentojen validointi
Node‑RED tarkistaa:
* onko komento sallittu
* ovatko parametrit järkeviä
* onko toiminto turvallinen suorittaa

#### 2. Rajoitukset
Esimerkiksi:
* patokorkeuden nostoa voi olla rajattu ±50 %
* laitetta ei voi käynnistää, jos se on virhetilassa
* kriittisiä toimintoja voidaan vaatia vahvistettavaksi

#### 3. LLM:n tulkinnan varmistaminen
Jos komento on epäselvä, järjestelmä voi pyytää tarkennusta.

#### 4. Lokitus
Kaikki MCP‑komennot ja niiden tulokset kirjataan tietokantaan.

Turvallisuus on keskeinen osa luonnollisen kielen ohjausta, koska käyttäjä voi antaa komentoja hyvin vapaamuotoisesti.

---
---

## 8. Kokonaisautomaatio: esimerkkiskenaariot

Tässä luvussa esitellään kokonaisia automaatioskenaarioita, jotka demonstroivat järjestelmän toimintaa käytännössä. Jokainen skenaario kuvaa, miten fyysiset sensorit, Node‑REDin automaatiokerros, MCP‑komennot ja luonnollisen kielen ohjaus muodostavat yhtenäisen RPA‑prosessin. Skenaariot on suunniteltu siten, että ne ovat sekä teknisesti uskottavia että helposti laajennettavissa todellisiin käyttötapauksiin.

* ***Tässä luvussa esitettävät skenaariot havainnollistavat, miten IoT‑sensorit, Node‑REDin automaatio, MCP‑komennot ja luonnollisen kielen ohjaus muodostavat yhtenäisen RPA‑järjestelmän. Käyttäjä voi antaa komentoja suomen kielellä, LLM tulkitsee ne, MCP muuntaa ne rakenteiseksi automaatioksi ja Node‑RED suorittaa ne fyysisessä tai digitaalisessa ympäristössä. Skenaariot osoittavat järjestelmän joustavuuden, laajennettavuuden ja käytännön sovellettavuuden.***

---

### 8.1 “Nosta patokorkeutta nopeutta 20 cm”  

### Käyttäjän komento
> “Nosta Kaivon A1 patokorkeutta 20 cm.”

### LLM:n tulkinta
LLM tunnistaa käyttäjän tarkoituksen: kaivon patokorkeuden säätäminen.

### MCP‑komento

```json
{
  "command": "nostaPatokorkeutta",
  "parameters": {
    "deviceId": "A1",
    "value": 20
  }
}
```

### Node‑REDin toiminta
1. Vastaanottaa MCP‑komennon MQTT‑endpointista.
2. Tarkistaa, että kaivo A1 on olemassa ja toiminnassa.
3. Laskee uuden patokorkeuden.
4. Ohjaa toimilaitetta (esim. releellä).
5. Kirjaa tapahtuman tietokantaan.
6. Palauttaa tuloksen MCP:lle.

### LLM:n vastaus käyttäjälle
> “Kaivon A1 patokorkeutta nostettiin 20 cm. Uusi patokorkeus on 60 cm.”

---

### 8.2 “Näytä viimeisen tunnin hälytykset”  

### Käyttäjän komento
> “Näytä viimeisen tunnin hälytykset.”

### LLM:n tulkinta
Käyttäjä haluaa raportin hälytyksistä.

### MCP‑komento

```json
{
  "command": "haeHälytykset",
  "parameters": {
    "timeRange": "1h"
  }
}
```

### Node‑REDin toiminta
1. Hakee tietokannasta kaikki hälytykset viimeisen tunnin ajalta.
2. Muodostaa JSON‑raportin.
3. Palauttaa tuloksen MCP:lle.

### LLM:n vastaus käyttäjälle
> “Viimeisen tunnin aikana havaittiin 2 hälytystä: kuivavaran lasku ja laitteen virhetilanne.”

---

### 8.3 “Avaa luukku, jos kuivavara alittaa 20 cm”  

### Käyttäjän komento
> “Avaa kaivon A1 patoluukku, jos kuivavara alittaa 20 cm.”

### LLM:n tulkinta
Kyseessä on ehtopohjainen automaatio.

### MCP‑komento

```json
{
  "command": "asetaHalytysRaja",
  "parameters": {
    "deviceId": "A1",
    "threshold": 20,
    "action": "avaaPatoluukku"
  }
}
```

### Node‑REDin toiminta
1. Lisää uuden automaatioregelin flow’hun.
2. Tarkkailee sensoridataa MQTT:n kautta.
3. Jos lämpötila > 80°C:
    * pysäyttää prosessin
    * lähettää hälytyksen
    * kirjaa tapahtuman

### LLM:n vastaus käyttäjälle
> “Asetin raja-arvon 20 cm. Patoluukku avataan, jos kuivavara alittuu.”

---

### 8.4 “Tee raportti päivän sensoridatasta”  

### Käyttäjän komento
> “Tee raportti tämän päivän sensoridatasta.”

### LLM:n tulkinta
Käyttäjä haluaa yhteenvedon koko päivän datasta.

### MCP‑komento

```json
{
  "command": "generoiPaivaRaportti",
  "parameters": {
    "date": "tänään"
  }
}
```

### Node‑REDin toiminta
1. Hakee tietokannasta kaikki päivän sensorimittaukset.
2. Laskee keskiarvot, minimi- ja maksimiarvot.
3. Muodostaa raportin JSON‑muodossa.
4. Palauttaa raportin MCP:lle.

### LLM:n vastaus käyttäjälle
> “Tässä on yhteenveto tämän päivän sensoridatasta: Kuivavara 50 cm, maksimi 60 cm, minimi 50 cm.Kaivon A1 patokorkeys 60 cm ”

---

### 8.5 “Käynnistä laite uudelleen”  

### Käyttäjän komento
> “Käynnistä kaivo A1 uudelleen.”

### LLM:n tulkinta
LLM tunnistaa toiminnon, mutta tarvitsee laitteen tunnisteen.
Jos käyttäjä ei anna sitä, LLM voi kysyä tarkennuksen.

### MCP‑komento

```json
{
  "command": "kaynnistaUudelleen",
  "parameters": {
    "deviceId": "A1"
  }
}
```

### Node‑REDin toiminta
1. Suorittaa laitteen pysäytyksen.
2. Odottaa määritellyn viiveen.
3. Käynnistää laitteen uudelleen.
4. Kirjaa tapahtuman.
5. Palauttaa tuloksen MCP:lle.

### LLM:n vastaus käyttäjälle
“Laite ‘kaivo A1’ käynnistettiin uudelleen onnistuneesti.”

---
---

## 9. Testaus ja validointi

Testaus ja validointi ovat keskeisiä vaiheita IoT‑pohjaisen RPA‑järjestelmän rakentamisessa. Koska järjestelmä yhdistää fyysiset sensorit, ohjelmallisen automaation, MCP‑komennot ja luonnollisen kielen ohjauksen, sen toimivuus riippuu useiden eri komponenttien saumattomasta yhteistyöstä. Tässä luvussa kuvataan testausmenetelmät, työkalut ja skenaariot, joilla varmistetaan järjestelmän luotettavuus, suorituskyky ja turvallisuus.

* ***Tässä luvussa esiteltiin testaus- ja validointimenetelmät, joilla varmistetaan IoT‑pohjaisen RPA‑järjestelmän luotettavuus. Testaus kattaa yksittäiset solmut, integraatiot, kokonaiset skenaariot ja MCP‑komentojen toiminnan. Sensoridatan simulointi, virheenkäsittely ja suorituskykytestit muodostavat kokonaisuuden, joka tekee järjestelmästä vakaan, turvallisen ja käytännössä toimivan.***

---

### 9.1 Testausmenetelmät  

Järjestelmän testaus voidaan jakaa kolmeen tasoon:

#### 1. Yksikkötestaus
Kohdistuu yksittäisiin solmuihin ja pieniin kokonaisuuksiin Node‑REDissä.
* Function‑solmujen logiikan testaus
* Switch‑ehtojen toiminnan varmistaminen
* Sensoridatan muunnosten tarkistus
* MCP‑komentojen JSON‑rakenteen validointi

Yksikkötestaus tehdään pääasiassa Node‑REDin debug‑solmujen ja simuloitujen syötteiden avulla.

#### 2. Integraatiotestaus
Testaa eri komponenttien välistä yhteistoimintaa.
* MQTT → Node‑RED → tietokanta
* MCP → Node‑RED → toimilaite
* Sensorit → Node‑RED → dashboard

Integraatiotestaus varmistaa, että tietovirrat toimivat oikein ja että järjestelmä reagoi odotetusti.

#### 3. Skenaariotestaus
Kokonaisvaltainen testaus todellisilla käyttötilanteilla.
* “Kuivavara laskee alle 20 cm → hälytys”
* “Käyttäjä antaa MCP‑komennon → laite reagoi”
* “Sensoridatan puuttuminen → virheilmoitus”

Skenaariotestaus simuloi todellisia tilanteita ja varmistaa järjestelmän käytännön toimivuuden.

---

### 9.2 Sensoridatan simulointi  

Sensoridatan simulointi on tärkeää erityisesti kehitysvaiheessa ja silloin, kun fyysisiä sensoreita ei ole saatavilla. Node‑RED tarjoaa useita tapoja simuloida dataa:

#### Inject‑solmut
* manuaaliset tai ajastetut arvot
* sopii yksinkertaiseen testaukseen

#### Function‑solmut
* satunnaisen tai mallinnetun datan generointi
* mahdollistaa realistisen käyttäytymisen simulaation

Esimerkki simuloidusta lämpötilasta:

```javascript
msg.payload = {
    temperature: 20 + Math.random() * 10,
    humidity: 40 + Math.random() * 20
};
return msg;
```

#### Dashboard‑komponentit
* sliderit ja syöttökentät
* käyttäjä voi itse muuttaa sensorin arvoa

Simulointi mahdollistaa RPA‑logiikan ja MCP‑komentojen testauksen ilman fyysisiä laitteita.

---

### 9.3 MCP‑komentojen testaus  

MCP‑komentojen testaus varmistaa, että luonnollisen kielen ohjaus toimii luotettavasti ja että Node‑RED tulkitsee komennot oikein.

#### Testattavia osa‑alueita:
* JSON‑rakenteen oikeellisuus
* pakollisten parametrien olemassaolo
* parametrien tyyppien validointi
* virheellisten komentojen käsittely
* Node‑REDin palautteiden oikeellisuus

### Esimerkki testistä:
Komento:

```json
{
  "command": "nostaParokorkeutta",
  "parameters": {
    "deviceId": "A1",
    "value": 100
  }
}
```

#### Odotettu tulos:
* Node‑RED hylkää komennon
* palauttaa virheilmoituksen
* LLM muotoilee käyttäjälle selkeän vastauksen

MCP‑testaus varmistaa, että järjestelmä ei tee vaarallisia tai epäloogisia toimintoja.

---

### 9.4 Virhetilanteiden käsittely  

Virhetilanteet ovat väistämättömiä IoT‑järjestelmissä. Järjestelmän on kyettävä käsittelemään ne turvallisesti ja ennustettavasti.

### Tyypillisiä virhetilanteita:
* sensoridatan puuttuminen
* MQTT‑yhteyden katkeaminen
* MCP‑komennon virheellinen rakenne
* toimilaitteen virhetila
* tietokantayhteyden häiriöt

### Node‑REDin virheenkäsittelyratkaisut:
* Catch‑solmut virheiden sieppaamiseen
* Status‑solmut laitteiden tilan seurantaan
* Retry‑logiikka (uudelleenyritykset)
* Hälytykset kriittisistä virheistä
* Lokitus tietokantaan

Virheenkäsittely on keskeinen osa järjestelmän luotettavuutta.

---

### 9.5 Suorituskyky ja luotettavuus  

Järjestelmän suorituskyky arvioidaan seuraavilla mittareilla:

### 1. Viive
* sensoridatan saapuminen → Node‑REDin reagointi
* MCP‑komento → toimilaitteen ohjaus

### 2. Kuormitus
* useiden sensorien yhtäaikainen data
* useiden MCP‑komentojen käsittely

### 3. Jatkuva toiminta
* Node‑REDin vakaus
* MQTT‑brokerin luotettavuus
* Raspberry Pi:n lämpötila ja resurssit

4. Palautuminen
* järjestelmän kyky palautua virhetilanteista
* automaattinen uudelleenkäynnistys

Suorituskykytestit varmistavat, että järjestelmä toimii luotettavasti myös pidemmän ajan ja kuormituksen alla.

---
---

## 10. Johtopäätökset ja jatkokehitys

Tämä harjoitustyö osoittaa, että IoT‑pohjainen automaatio, RPA‑logiikka ja luonnollisen kielen ohjaus voidaan yhdistää saumattomaksi kokonaisuudeksi, joka toimii sekä fyysisessä että digitaalisessa ympäristössä. Raspberry Pi, Node‑RED ja MCP muodostavat yhdessä modernin automaatioarkkitehtuurin, jossa käyttäjä voi ohjata järjestelmää yhtä luontevasti kuin keskustelisi toisen ihmisen kanssa. Tämä lähestymistapa edustaa uudenlaista RPA‑ajattelua: automaatio ei ole enää pelkkää hiiren klikkailua, vaan fyysisen ja digitaalisen maailman yhdistämistä.

---

### 10.1 Projektin onnistumiset  

Harjoitustyö saavutti useita keskeisiä tavoitteita:

### 1. Toimiva IoT‑pohjainen automaatioalusta
Raspberry Pi ja Node‑RED muodostivat vakaan ja laajennettavan ympäristön, jossa sensoridata, toimilaitteet ja automaatio toimivat luotettavasti.

### 2. RPA‑logiikan integrointi fyysiseen maailmaan
Perinteinen RPA laajennettiin koskemaan fyysisiä tapahtumia, kuten kuivavran muutoksia, painikkeiden painalluksia ja laitteiden ohjausta.

### 3. MCP‑pohjainen luonnollisen kielen ohjaus
Käyttäjä pystyi antamaan komentoja suomen kielellä, ja LLM tulkitsi ne MCP‑komentojen kautta täsmälliseksi automaatioksi.

### 4. Modulaarinen ja laajennettava arkkitehtuuri
Järjestelmä voidaan rakentaa siten, että uusia sensoreita, komentoja ja automaatiosääntöjä voidaan lisätä ilman suuria muutoksia kokonaisuuteen.

### 5. Reaaliaikainen seuranta ja raportointi
Node‑RED Dashboard ja tietokantakerros mahdollistivat järjestelmän tilan, hälytysten ja historian seuraamisen.

---

### 10.2 Rajoitteet 

Projektin aikana nousi esiin myös havaintoja ja kehityskohteita:

### 1. LLM‑tulkinnan epävarmuus
Luonnollisen kielen tulkinta ei ole aina yksiselitteistä. 

### 2. Raspberry Pi:n resurssirajoitukset
Vaikka Raspberry Pi soveltuu hyvin IoT‑automaatiolle, raskaammat analytiikkatehtävät tai suuret tietomäärät voivat vaatia tehokkaampaa laitteistoa.

### 3. Turvallisuus
Luonnollisen kielen ohjaus vaatii tarkkaa validointia, jotta vaarallisia tai epäloogisia komentoja ei suoriteta vahingossa.

### 4. Järjestelmän monikerroksisuus
Useiden teknologioiden yhdistäminen (Sparkplug, MQTT, Node‑RED, MCP, LLM) lisää kokonaisuuden monimutkaisuutta ja vaatii huolellista dokumentointia.

---

### 10.3 Opit

Automaatiojärjestelmän käyttäminen keskustelemalla on mahdollista, mutta väärien komentojen suorittamisen estäminen saattaa olla haastavaa.

  * testaus ei LLM palveluja käytettäessä ole koskaan aukoton
  * komennot on annettava yksiselitteisesti, mm. deviceId
  * komennon varmentaminen "RTIC MESH" komentona on suositeltavaa
    * kun toistetaan komento käyttäjälle "RTIC MESH" komentona, voidaan havaita virheet tekoälyn tulkinnassa jos käyttäjällä on riittävät tiedot RTIC-komentojen tulkintaan

---

### 10.4 RPA:n tulevaisuus IoT‑ympäristöissä  

Tämä harjoitustyö osoittaa, että RPA:n tulevaisuus ei rajoitu ohjelmistojen automatisointiin. IoT‑laitteiden, LLM‑pohjaisen komentotulkinnan ja MCP‑rajapinnan yhdistelmä avaa mahdollisuuden täysin uudenlaisille automaatiojärjestelmille, joissa:

* fyysiset tapahtumat
* ohjelmallinen logiikka
* luonnollinen kieli

toimivat saumattomasti yhdessä.

Tulevaisuuden automaatiojärjestelmät voivat olla:
* itseoppivia
* kontekstuaalisia
* käyttäjäystävällisiä
* fyysisen ja digitaalisen maailman yhdistäviä

Tämä harjoitustyö toimii konkreettisena esimerkkinä siitä, miten tällainen järjestelmä voidaan rakentaa avoimen lähdekoodin työkaluilla ja modulaarisella arkkitehtuurilla.


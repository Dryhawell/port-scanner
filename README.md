# Port Scanner

Yetkili sistemlerde TCP connect yontemiyle port gorunurlugunu analiz etmek
icin egitim amacli bir Python araci.

> Bu depo su anda **proje iskeletidir**. Tarama motoru henuz yazilmadi.

## Overview

Kullanicinin belirledigi IP veya hostname uzerinde, verilen port araligini
TCP connect ile tarayan bir guvenlik araci hedefleniyor. CLI ve GUI ayni
tarama motorunu paylasacak.

## Authorized Use

Bu arac yalnizca su hedeflerde kullanilmak uzere tasarlanmistir:

- localhost
- kullanicinin kendi cihazlari
- kullanicinin yetkili oldugu test ortamları

Izinsiz tarama yapma. Stealth scanning, IDS/IPS bypass, firewall evasion
veya saldiri otomasyonu bu projenin kapsami disindadir.

## Architecture

```
cli/ ve gui/   -> kullanici arayuzu
scanner/       -> tarama motoru
utils/         -> log ve rapor
tests/         -> birim testleri
reports/       -> JSON/CSV ciktilari
logs/          -> uygulama kayitlari
```

Asil README, CLI ve tarayici oturduktan sonra (PHASE 14) genisletilecek.

## License

MIT

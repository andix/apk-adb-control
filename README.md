# IP Scanner + ADB Control

Aplikasi Android (Kotlin, Jetpack Compose, Material 3) untuk:

- Scan range IP — default otomatis ke segmen jaringan Wi-Fi/Ethernet yang sedang tersambung.
- Connect ke ADB perangkat lain lewat jaringan (menunggu persetujuan "Allow USB debugging?" di target).
- Kartu fitur ADB: info perangkat, daftar aplikasi, install APK, uninstall, screenshot, remote tombol, ketik teks / buka URL, terminal shell, reboot.

## Download

APK debug: [`apk/ip-scanner-adb-debug.apk`](apk/ip-scanner-adb-debug.apk)

## Catatan

- Target harus mengaktifkan ADB over TCP (`adb tcpip 5555`). Wireless debugging dengan pairing code (Android 11+) belum didukung.
- Memakai [dadb](https://github.com/mobile-dev-inc/dadb) sebagai klien ADB.
- minSdk 26.

## Build

```
./gradlew assembleDebug
```

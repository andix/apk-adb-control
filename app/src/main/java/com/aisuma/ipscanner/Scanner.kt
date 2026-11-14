package com.aisuma.ipscanner

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import java.net.*
import java.util.concurrent.Executors

data class Host(
    val ip: String,
    val hostname: String?,
    val openPorts: List<Int>,
    val pingMs: Long?,
    val mac: String? = null,
    val info: String? = null,
) {
    val adb get() = 5555 in openPorts

    /** Tebakan jenis perangkat dari port/info yang terdeteksi. */
    val guess: String?
        get() = when {
            5555 in openPorts -> "Android (ADB aktif)"
            8008 in openPorts || 8009 in openPorts -> "Android TV / Chromecast"
            62078 in openPorts -> "iPhone / iPad"
            7000 in openPorts -> "Apple / AirPlay"
            445 in openPorts || 3389 in openPorts -> "PC / Laptop Windows"
            9100 in openPorts -> "Printer"
            info?.contains("samsung", true) == true -> "Samsung"
            info?.contains("tv", true) == true -> "Smart TV"
            22 in openPorts -> "Linux / server SSH"
            else -> null
        }
}

data class LocalNet(val ip: String, val prefix: Int, val start: String, val end: String)

val SCAN_PORTS = listOf(5555, 80, 443, 8008, 8009, 7000, 8080, 22, 445, 62078, 9100, 3389)

fun ipToLong(ip: String): Long? {
    val p = ip.trim().split(".")
    if (p.size != 4) return null
    var r = 0L
    for (s in p) {
        val n = s.toIntOrNull() ?: return null
        if (n !in 0..255) return null
        r = (r shl 8) or n.toLong()
    }
    return r
}

fun longToIp(v: Long) = "${(v shr 24) and 255}.${(v shr 16) and 255}.${(v shr 8) and 255}.${v and 255}"

/** Range default = segmen jaringan (Wi-Fi/Ethernet) yang sedang tersambung. */
fun detectLocalNet(ctx: Context): LocalNet? {
    val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    val candidates = buildList {
        cm.activeNetwork?.let { add(it) }
        addAll(cm.allNetworks)
    }
    for (n in candidates) {
        val caps = cm.getNetworkCapabilities(n) ?: continue
        if (!caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) &&
            !caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)
        ) continue
        val la = cm.getLinkProperties(n)?.linkAddresses
            ?.firstOrNull { it.address is Inet4Address } ?: continue
        val ip = la.address.hostAddress ?: continue
        val prefix = la.prefixLength
        val me = ipToLong(ip) ?: continue
        // batasi maksimal /22 (1022 host) supaya cepat; kalau lebih besar, pakai /24 sekitar IP hp
        val eff = if (prefix < 22) 24 else prefix
        val mask = (0xFFFFFFFFL shl (32 - eff)) and 0xFFFFFFFFL
        val net = me and mask
        val bc = net or (mask.inv() and 0xFFFFFFFFL)
        val s = if (eff >= 31) net else net + 1
        val e = if (eff >= 31) bc else bc - 1
        return LocalNet(ip, prefix, longToIp(s), longToIp(e))
    }
    return null
}


private val netDisp = Executors.newCachedThreadPool().asCoroutineDispatcher()
private val bgScope = CoroutineScope(SupervisorJob() + netDisp)

/** 1 = port terbuka, 0 = ditolak (host hidup), -1 = tidak ada respons */
private fun tcpProbe(ip: String, port: Int, timeoutMs: Int): Int = try {
    Socket().use { it.connect(InetSocketAddress(ip, port), timeoutMs) }
    1
} catch (e: ConnectException) {
    if (e.message?.contains("refused", true) == true) 0 else -1
} catch (_: Exception) {
    -1
}

private class UdpResult(val alive: Boolean, val name: String?, val info: String?)

private val NETBIOS_Q = byteArrayOf(0x12, 0x34, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x20) +
    "CK".toByteArray() + ByteArray(30) { 'A'.code.toByte() } + byteArrayOf(0, 0, 0x21, 0, 1)
private val SSDP_Q = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n" +
    "MX: 1\r\nST: ssdp:all\r\n\r\n").toByteArray()
private val MDNS_Q = byteArrayOf(0x12, 0x34, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0) +
    byteArrayOf(9) + "_services".toByteArray() + byteArrayOf(7) + "_dns-sd".toByteArray() +
    byteArrayOf(4) + "_udp".toByteArray() + byteArrayOf(5) + "local".toByteArray() +
    byteArrayOf(0, 0, 12, 0, 1)

/**
 * Kirim beberapa probe UDP sekaligus (NetBIOS, SSDP, mDNS, port tertutup).
 * Balasan data ATAU ICMP "port unreachable" = host hidup (meski semua port TCP tertutup/di-firewall).
 */
private fun udpProbe(ip: String, timeoutMs: Int): UdpResult {
    val addr = InetAddress.getByName(ip)
    val probes = listOf(137 to NETBIOS_Q, 1900 to SSDP_Q, 5353 to MDNS_Q, 33434 to byteArrayOf(0))
    val socks = mutableListOf<Pair<Int, DatagramSocket>>()
    var alive = false
    var name: String? = null
    var info: String? = null
    try {
        for ((port, data) in probes) {
            try {
                val s = DatagramSocket()
                s.connect(addr, port)
                s.send(DatagramPacket(data, data.size))
                socks += port to s
            } catch (_: Exception) {
            }
        }
        val buf = ByteArray(2048)
        val done = mutableSetOf<Int>()
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline && done.size < socks.size) {
            for ((port, s) in socks) {
                if (port in done) continue
                s.soTimeout = 30
                try {
                    val p = DatagramPacket(buf, buf.size)
                    s.receive(p)
                    alive = true
                    done += port
                    when (port) {
                        137 -> if (p.length > 72) name = String(buf, 57, 15, Charsets.ISO_8859_1).trim().ifEmpty { null }
                        1900 -> {
                            val txt = String(buf, 0, p.length, Charsets.ISO_8859_1)
                            info = txt.lines().firstOrNull { it.startsWith("SERVER:", true) }
                                ?.substringAfter(":")?.trim()
                        }
                    }
                } catch (_: PortUnreachableException) {
                    alive = true
                    done += port
                } catch (_: SocketTimeoutException) {
                } catch (_: Exception) {
                    done += port
                }
            }
            if (alive && System.currentTimeMillis() > deadline - timeoutMs / 2) break
        }
    } finally {
        socks.forEach { runCatching { it.second.close() } }
    }
    return UdpResult(alive, name, info)
}

private suspend fun probeHost(ip: String, timeoutMs: Int): Host? = coroutineScope {
    val t0 = System.currentTimeMillis()
    val udp = async(netDisp) { runCatching { udpProbe(ip, timeoutMs) }.getOrNull() }
    val tcp = SCAN_PORTS.map { p -> p to async(netDisp) { tcpProbe(ip, p, timeoutMs) } }
    val u = udp.await()
    val open = mutableListOf<Int>()
    var alive = u?.alive == true
    for ((p, d) in tcp) {
        val r = d.await()
        if (r == 1) open += p
        if (r >= 0) alive = true
    }
    if (!alive) null
    else Host(ip, u?.name, open.sorted(), System.currentTimeMillis() - t0, null, u?.info)
}

/** Tabel ARP (hanya terbaca di sebagian versi Android) → ip to mac. */
private fun readArp(): Map<String, String> = try {
    java.io.File("/proc/net/arp").readLines().drop(1).mapNotNull {
        val c = it.trim().split(Regex("\\s+"))
        if (c.size >= 4 && c[3] != "00:00:00:00:00:00" && c[2] != "0x0") c[0] to c[3] else null
    }.toMap()
} catch (_: Exception) {
    emptyMap()
}

/**
 * Pindai start..end dua putaran (putaran kedua mengulang IP yang belum terdeteksi, karena
 * perangkat yang tidur sering baru membalas setelah ARP pertama). onHost bisa dipanggil lagi
 * untuk IP yang sama (update nama/MAC). Fungsi return setelah scan SELESAI.
 */
suspend fun scanRange(
    start: Long,
    end: Long,
    timeoutMs: Int,
    onProgress: (Int, Int) -> Unit,
    onHost: (Host) -> Unit,
) = coroutineScope {
    val n = (end - start + 1).toInt()
    val found = java.util.concurrent.ConcurrentHashMap<String, Host>()
    val lock = Any()

    suspend fun pass(ips: List<Long>, base: Int, total: Int) {
        val sem = Semaphore(24)
        var done = 0
        ips.map { v ->
            launch {
                sem.withPermit {
                    val ip = longToIp(v)
                    val h = probeHost(ip, timeoutMs)
                    if (h != null) {
                        found[ip] = h
                        onHost(h)
                        // nama via reverse DNS: terpisah, tidak menahan scan
                        bgScope.launch {
                            val nm = withTimeoutOrNull(2500) {
                                runInterruptible { InetAddress.getByName(ip).canonicalHostName.takeIf { it != ip } }
                            }
                            val cur = found[ip]
                            if (nm != null && cur != null && cur.hostname == null) {
                                val upd = cur.copy(hostname = nm)
                                found[ip] = upd
                                onHost(upd)
                            }
                        }
                    }
                }
                synchronized(lock) { done++; onProgress(base + done, total) }
            }
        }.joinAll()
    }

    val all = (start..end).toList()
    pass(all, 0, n * 2)
    val missing = all.filter { !found.containsKey(longToIp(it)) }
    onProgress(n, n + missing.size)
    pass(missing, n, n + missing.size)

    // lengkapi dengan tabel ARP (jika bisa dibaca)
    val arp = readArp()
    for ((ip, mac) in arp) {
        val v = ipToLong(ip) ?: continue
        if (v !in start..end) continue
        val cur = found[ip]
        val upd = (cur ?: Host(ip, null, emptyList(), null)).copy(mac = mac)
        found[ip] = upd
        onHost(upd)
    }
    onProgress(1, 1)
}

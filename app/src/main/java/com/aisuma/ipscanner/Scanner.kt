package com.aisuma.ipscanner

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import kotlinx.coroutines.*
import java.io.IOException
import java.net.*
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.SocketChannel
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

data class Host(
    val ip: String,
    val hostname: String? = null,
    val openPorts: List<Int> = emptyList(),
    val pingMs: Long? = null,
    val mac: String? = null,
    val info: String? = null,
    val via: Set<String> = emptySet(),
    val services: List<String> = emptyList(),
    val model: String? = null,
    val self: Boolean = false,
) {
    val adb get() = 5555 in openPorts

    /** Tebakan jenis perangkat dari port / layanan / info yang terdeteksi. */
    val guess: String?
        get() {
            val s = services.joinToString(" ").lowercase()
            val i = listOfNotNull(info, model, hostname).joinToString(" ").lowercase()
            return when {
                self -> "HP ini"
                5555 in openPorts -> "Android (ADB aktif)"
                "_adb-tls" in s -> "Android (Wireless debugging aktif)"
                "samsung" in i && ("tv" in i || 8001 in openPorts || 8002 in openPorts) -> "Samsung Smart TV"
                8001 in openPorts || 8002 in openPorts || 9197 in openPorts || 7676 in openPorts -> "Samsung Smart TV"
                "androidtvremote" in s || 6466 in openPorts || 6467 in openPorts -> "Android TV"
                "googlecast" in s || 8008 in openPorts || 8009 in openPorts -> "Android TV / Chromecast"
                8060 in openPorts || "roku" in i -> "Roku"
                "samsung" in i -> "Samsung"
                "lg" in i.split(' ', '/', '-') || "webos" in i -> "LG TV"
                62078 in openPorts || "_companion-link" in s -> "iPhone / iPad"
                "_airplay" in s || "_raop" in s || 7000 in openPorts -> "Apple / AirPlay"
                "_ipp" in s || "_printer" in s || 9100 in openPorts || 631 in openPorts || 515 in openPorts -> "Printer"
                "windows" in i || 445 in openPorts || 3389 in openPorts || 135 in openPorts || 5357 in openPorts -> "PC / Laptop Windows"
                "_smb" in s || "_workstation" in s -> "PC / Laptop"
                "android" in i -> "Android"
                53 in openPorts && 80 in openPorts -> "Router / Gateway"
                22 in openPorts -> "Linux / server SSH"
                via == setOf("ARP") -> "Perangkat ber-firewall (terdeteksi via ARP)"
                else -> null
            }
        }
}

data class LocalNet(
    val ip: String, val prefix: Int, val start: String, val end: String,
    val network: Network?, val ifName: String?, val broadcast: String?,
)

val TCP_PORTS = listOf(
    5555, 80, 443, 22, 21, 23, 53, 81, 135, 139, 445, 515, 554, 631, 1883, 2869, 3389, 5000, 5001,
    5357, 5900, 6466, 6467, 7000, 7100, 7676, 8001, 8002, 8008, 8009, 8060, 8080, 8443, 8888, 9000,
    9080, 9100, 9197, 32400, 49152, 62078,
)

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
        @Suppress("DEPRECATION") addAll(cm.allNetworks)
    }
    for (n in candidates) {
        val caps = cm.getNetworkCapabilities(n) ?: continue
        if (!caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) &&
            !caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)
        ) continue
        val lp = cm.getLinkProperties(n) ?: continue
        val la = lp.linkAddresses.firstOrNull { it.address is Inet4Address } ?: continue
        val ip = la.address.hostAddress ?: continue
        val prefix = la.prefixLength
        val me = ipToLong(ip) ?: continue
        fun mask(p: Int) = (0xFFFFFFFFL shl (32 - p)) and 0xFFFFFFFFL
        val realBc = (me and mask(prefix)) or (mask(prefix).inv() and 0xFFFFFFFFL)
        // batasi maksimal /22 (1022 host) supaya cepat; kalau lebih besar, pakai /24 sekitar IP hp
        val eff = if (prefix < 22) 24 else prefix
        val net = me and mask(eff)
        val bc = net or (mask(eff).inv() and 0xFFFFFFFFL)
        val s = if (eff >= 31) net else net + 1
        val e = if (eff >= 31) bc else bc - 1
        return LocalNet(
            ip, prefix, longToIp(s), longToIp(e), n, lp.interfaceName,
            if (prefix < 31) longToIp(realBc) else null,
        )
    }
    return null
}

// ---------------------------------------------------------------- paket probe

private val NETBIOS_Q = byteArrayOf(0x12, 0x34, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0x20) +
    "CK".toByteArray() + ByteArray(30) { 'A'.code.toByte() } + byteArrayOf(0, 0, 0x21, 0, 1)

private fun ssdp(st: String) = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n" +
    "MAN: \"ssdp:discover\"\r\nMX: 2\r\nST: $st\r\n\r\n").toByteArray()

private val SSDP_QS = listOf(
    ssdp("ssdp:all"), ssdp("upnp:rootdevice"), ssdp("urn:dial-multiscreen-org:service:dial:1"),
    ssdp("urn:samsung.com:device:RemoteControlReceiver:1"),
)

private val MDNS_SERVICES = listOf(
    "_services._dns-sd._udp", "_googlecast._tcp", "_androidtvremote2._tcp", "_androidtvremote._tcp",
    "_adb-tls-connect._tcp", "_adb-tls-pairing._tcp", "_adb._tcp", "_airplay._tcp", "_raop._tcp",
    "_companion-link._tcp", "_device-info._tcp", "_smb._tcp", "_workstation._tcp", "_http._tcp",
    "_ipp._tcp", "_printer._tcp", "_spotify-connect._tcp", "_hap._tcp", "_googlezone._tcp",
    "_samsungmsf._tcp", "_amzn-wplay._tcp", "_viziocast._tcp", "_rdlink._tcp", "_sftp-ssh._tcp", "_ssh._tcp",
)

private fun mdnsQuery(unicastResponse: Boolean): ByteArray {
    val out = java.io.ByteArrayOutputStream()
    out.write(byteArrayOf(0, 0, 0, 0, 0, MDNS_SERVICES.size.toByte(), 0, 0, 0, 0, 0, 0))
    for (svc in MDNS_SERVICES) {
        for (label in "$svc.local".split(".")) {
            out.write(label.length); out.write(label.toByteArray())
        }
        out.write(0)
        out.write(byteArrayOf(0, 12, if (unicastResponse) 0x80.toByte() else 0, 1)) // PTR, IN (+QU)
    }
    return out.toByteArray()
}

private val MDNS_UNICAST = mdnsQuery(false)
private val MDNS_MCAST = mdnsQuery(true)

private val WSD_PROBE = ("""<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"><soap:Header><wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action><wsa:MessageID>urn:uuid:""" +
    java.util.UUID.randomUUID() + """</wsa:MessageID></soap:Header><soap:Body><wsd:Probe/></soap:Body></soap:Envelope>""").toByteArray()

private fun u16(b: ByteArray, i: Int) = ((b[i].toInt() and 0xff) shl 8) or (b[i + 1].toInt() and 0xff)

private fun readName(b: ByteArray, len: Int, start: Int): Pair<String, Int> {
    val labels = mutableListOf<String>()
    var i = start
    var next = -1
    var guard = 0
    while (i in 0 until len && guard++ < 64) {
        val l = b[i].toInt() and 0xff
        if (l == 0) { i++; break }
        if (l and 0xC0 == 0xC0) {
            if (i + 1 >= len) break
            if (next < 0) next = i + 2
            i = ((l and 0x3f) shl 8) or (b[i + 1].toInt() and 0xff)
            continue
        }
        labels += String(b, i + 1, minOf(l, len - i - 1), Charsets.UTF_8)
        i += l + 1
    }
    return labels.joinToString(".") to (if (next >= 0) next else i)
}

private class MdnsInfo(val hostname: String?, val instance: String?, val services: List<String>)

/** Ambil nama host (.local), nama instance, dan tipe layanan dari respons mDNS. */
private fun parseMdns(b: ByteArray, len: Int): MdnsInfo {
    val svcs = mutableSetOf<String>()
    var host: String? = null
    var inst: String? = null
    try {
        if (len < 12) return MdnsInfo(null, null, emptyList())
        val qd = u16(b, 4)
        val rr = u16(b, 6) + u16(b, 8) + u16(b, 10)
        var off = 12
        repeat(qd) { off = readName(b, len, off).second + 4 }
        repeat(rr) {
            if (off + 10 > len) return@repeat
            val (name, o) = readName(b, len, off)
            val type = u16(b, o)
            val rdlen = u16(b, o + 8)
            val rd = o + 10
            fun svcOf(n: String) = Regex("(_[A-Za-z0-9-]+)\\._(tcp|udp)").find(n)?.groupValues?.get(1)
            when (type) {
                12 -> {
                    val target = readName(b, len, rd).first
                    svcOf(target)?.let { svcs += it } ?: svcOf(name)?.let { svcs += it }
                    if (inst == null && !target.startsWith("_")) inst = target.substringBefore("._")
                }
                33 -> {
                    svcOf(name)?.let { svcs += it }
                    if (inst == null) inst = name.substringBefore("._").takeIf { !it.startsWith("_") }
                    if (host == null && rd + 6 < len) host = readName(b, len, rd + 6).first.removeSuffix(".local")
                }
                1 -> if (host == null && name.endsWith(".local")) host = name.removeSuffix(".local")
                16 -> svcOf(name)?.let { svcs += it }
            }
            off = rd + rdlen
        }
    } catch (_: Exception) {
    }
    svcs.remove("_services")
    return MdnsInfo(host?.ifBlank { null }, inst?.ifBlank { null }, svcs.toList())
}

private fun parseNetbios(b: ByteArray, len: Int): String? =
    if (len > 72) String(b, 57, 15, Charsets.ISO_8859_1).trim().ifEmpty { null } else null

private fun header(txt: String, key: String) =
    txt.lines().firstOrNull { it.startsWith("$key:", true) }?.substringAfter(":")?.trim()?.ifEmpty { null }

/** 1 = port terbuka, 0 = ditolak (host hidup), -1 = timeout, -2 = tidak ada host (ARP gagal), -3 = error lain */
private fun classify(e: Throwable): Int {
    val m = (e.message ?: "") + " " + (e.cause?.message ?: "")
    return when {
        m.contains("refused", true) -> 0
        m.contains("unreachable", true) || m.contains("no route", true) -> -2
        else -> -3
    }
}

// ---------------------------------------------------------------- scanner

/**
 * Scanner multi-metode:
 *  1. Socket diikat ke jaringan Wi-Fi (penting kalau Wi-Fi tanpa internet / ada data seluler / VPN).
 *  2. Discovery multicast: mDNS, SSDP (UPnP/DIAL), WS-Discovery, NetBIOS broadcast.
 *  3. Per IP: ICMP ping, probe UDP unicast (NetBIOS, SSDP, mDNS, port tertutup → ICMP unreachable).
 *  4. Inferensi ARP: connect TCP ke tiap IP; "No route to host" = tidak ada perangkat, timeout = ada
 *     perangkat tapi ber-firewall (laptop Windows, HP yang menolak semua koneksi).
 *  5. Sweep port TCP (41 port) ke semua host hidup memakai NIO non-blocking.
 *  6. Tabel ARP / ip neigh (jika diizinkan versi Android) untuk MAC.
 */
class NetScanner(
    private val ctx: Context,
    private val start: Long,
    private val end: Long,
    private val timeoutMs: Int,
    private val onProgress: (phase: String, done: Int, total: Int) -> Unit,
    private val onHost: (Host) -> Unit,
    private val onNote: (String) -> Unit = {},
) {
    private val found = HashMap<String, Host>()
    private val ssdpLocations = ConcurrentHashMap<String, String>()

    private fun merge(ip: String, f: (Host) -> Host) {
        val h = synchronized(found) { f(found[ip] ?: Host(ip)).also { found[ip] = it } }
        onHost(h)
    }

    private fun isFound(ip: String) = synchronized(found) { ip in found }
    private fun inRange(ip: String) = ipToLong(ip)?.let { it in start..end } == true

    @OptIn(ExperimentalCoroutinesApi::class)
    private val io = Dispatchers.IO.limitedParallelism(64)

    suspend fun run() = coroutineScope {
        val net = detectLocalNet(ctx)
        val cm = ctx.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        net?.network?.let { runCatching { cm.bindProcessToNetwork(it) } }
        val wm = ctx.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        val lock = runCatching {
            wm.createMulticastLock("ipscan").apply { setReferenceCounted(false); acquire() }
        }.getOrNull()
        try {
            val ips = (start..end).map(::longToIp)
            net?.ip?.takeIf { inRange(it) }?.let { me -> merge(me) { it.copy(self = true, via = it.via + "HP ini") } }

            // --- tahap 1: discovery multicast + ICMP + UDP sekaligus
            val disc = launch(Dispatchers.IO) { discovery(net) }
            val c = AtomicInteger()
            val tick = { onProgress("Tahap 1/3 · ICMP + UDP + mDNS/SSDP/NetBIOS", c.incrementAndGet(), ips.size * 2) }
            ips.flatMap { ip ->
                listOf(
                    launch(io) {
                        val t0 = System.currentTimeMillis()
                        val ok = runCatching { InetAddress.getByName(ip).isReachable(timeoutMs) }.getOrDefault(false)
                        if (ok) merge(ip) { it.copy(pingMs = System.currentTimeMillis() - t0, via = it.via + "ICMP") }
                        tick()
                    },
                    launch(io) {
                        udpProbe(ip)
                        tick()
                    },
                )
            }.joinAll()

            // --- tahap 2: inferensi ARP untuk IP yang belum terdeteksi (batch kecil supaya tabel ARP
            //     kernel tidak kewalahan), lalu konfirmasi ulang kandidat; IP mati dicoba lagi via ICMP/UDP
            val arpTimeout = maxOf(5000, timeoutMs)
            val rest = ips.filter { !isFound(it) }
            val dead = Collections.synchronizedSet(HashSet<String>())
            val stealth1 = Collections.synchronizedSet(HashSet<String>())
            val c2 = AtomicInteger()
            withContext(Dispatchers.IO) {
                arpProbe(rest, arpTimeout, 48, dead, stealth1) {
                    onProgress("Tahap 2/3 · inferensi ARP ${rest.size} IP", c2.incrementAndGet(), rest.size)
                }
            }
            val cand = stealth1.filter { !isFound(it) }
            val stealth = Collections.synchronizedSet(HashSet<String>())
            val retry = dead.filter { !isFound(it) }
            if (cand.isNotEmpty() || retry.isNotEmpty()) {
                val c3 = AtomicInteger()
                val tot = cand.size + retry.size
                val tk = { onProgress("Tahap 2/3 · konfirmasi ${cand.size} + ulang ${retry.size} IP", c3.incrementAndGet(), tot) }
                coroutineScope {
                    launch(Dispatchers.IO) { arpProbe(cand, arpTimeout + 1000, 24, HashSet(), stealth) { tk() } }
                    retry.forEach { ip ->
                        launch(io) {
                            val ok = runCatching { InetAddress.getByName(ip).isReachable(timeoutMs * 2) }.getOrDefault(false)
                            if (ok) merge(ip) { it.copy(via = it.via + "ICMP") }
                            else udpProbe(ip, timeoutMs * 2)
                            tk()
                        }
                    }
                }
            }

            // --- validasi inferensi ARP: kalau hampir semua IP "ada", berarti router proxy-ARP → abaikan
            val stealthOnly = stealth.filter { !isFound(it) }
            val candidates = ips.count { !isFound(it) }
            val arpReliable = !(ips.size >= 16 && stealthOnly.size > candidates * 0.8)
            if (arpReliable) {
                stealthOnly.forEach { ip -> merge(ip) { it.copy(via = it.via + "ARP") } }
            } else {
                onNote("Inferensi ARP diabaikan (router menjawab untuk semua IP). Memakai sweep port penuh.")
            }

            // --- tahap 3: sweep port TCP (host hidup saja; atau semua IP kalau ARP tidak reliabel)
            val alive = if (arpReliable) synchronized(found) { found.keys.toList() } else ips
            val targets = TCP_PORTS.flatMap { p -> alive.map { it to p } } // port-major: sebar paket per host
            val c3 = AtomicInteger()
            withContext(Dispatchers.IO) {
                nioConnect(targets, maxOf(timeoutMs, 600), 384, { isActive }) { ip, port, r ->
                    when (r) {
                        1 -> merge(ip) { it.copy(openPorts = (it.openPorts + port).distinct().sorted(), via = it.via + "TCP") }
                        0 -> merge(ip) { it.copy(via = it.via + "TCP") }
                    }
                    onProgress("Tahap 3/3 · port TCP (${alive.size} host × ${TCP_PORTS.size} port)", c3.incrementAndGet(), targets.size)
                }
            }

            disc.join()
            // deskripsi UPnP (nama TV, merk, model)
            ssdpLocations.map { (ip, loc) -> launch(Dispatchers.IO) { fetchUpnp(ip, loc) } }.joinAll()
            readArpTables()

            // reverse DNS di latar belakang, tidak menahan selesai
            synchronized(found) { found.values.filter { it.hostname == null }.map { it.ip } }.forEach { ip ->
                bgScope.launch {
                    val nm = withTimeoutOrNull(3000) {
                        runInterruptible { InetAddress.getByName(ip).canonicalHostName.takeIf { it != ip } }
                    }
                    if (nm != null) merge(ip) { if (it.hostname == null) it.copy(hostname = nm) else it }
                }
            }
            onProgress("Selesai", 1, 1)
        } finally {
            runCatching { lock?.release() }
        }
    }

    // ---- inferensi ARP lewat NIO connect ke port 9 (discard; biasanya tertutup/di-filter)
    private fun arpProbe(ips: List<String>, timeout: Int, inFlight: Int, dead: MutableSet<String>, stealth: MutableSet<String>, tick: () -> Unit) {
        nioConnect(ips.map { it to 9 }, timeout, inFlight, { true }) { ip, _, r ->
            when (r) {
                1, 0 -> merge(ip) { it.copy(via = it.via + "TCP") }
                -1 -> stealth += ip
                -2 -> dead += ip
            }
            tick()
        }
    }

    // ---- probe UDP unicast
    private fun udpProbe(ip: String, timeout: Int = timeoutMs) {
        val addr = runCatching { InetAddress.getByName(ip) }.getOrNull() ?: return
        val probes = listOf(137 to NETBIOS_Q, 1900 to SSDP_QS[0], 5353 to MDNS_UNICAST, 33434 to byteArrayOf(0))
        val socks = mutableListOf<Pair<Int, DatagramSocket>>()
        var alive = false
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
            val buf = ByteArray(4096)
            val done = mutableSetOf<Int>()
            val deadline = System.currentTimeMillis() + timeout
            while (System.currentTimeMillis() < deadline && done.size < socks.size) {
                for ((port, s) in socks) {
                    if (port in done) continue
                    s.soTimeout = 25
                    try {
                        val p = DatagramPacket(buf, buf.size)
                        s.receive(p)
                        alive = true
                        done += port
                        handlePacket(port, ip, buf, p.length, "UDP")
                    } catch (_: PortUnreachableException) {
                        alive = true
                        done += port
                    } catch (_: SocketTimeoutException) {
                    } catch (_: Exception) {
                        done += port
                    }
                }
            }
        } finally {
            socks.forEach { runCatching { it.second.close() } }
        }
        if (alive) merge(ip) { it.copy(via = it.via + "UDP") }
    }

    private fun handlePacket(port: Int, ip: String, buf: ByteArray, len: Int, tag: String) {
        if (!inRange(ip)) return
        when (port) {
            137 -> {
                val nm = parseNetbios(buf, len)
                merge(ip) { it.copy(hostname = it.hostname ?: nm, via = it.via + "NetBIOS",
                    info = it.info ?: if (nm != null) "Windows/SMB: $nm" else null) }
            }
            1900 -> {
                val txt = String(buf, 0, len, Charsets.ISO_8859_1)
                header(txt, "LOCATION")?.let { ssdpLocations.putIfAbsent(ip, it) }
                val server = header(txt, "SERVER")
                merge(ip) { it.copy(info = it.info ?: server, via = it.via + "SSDP") }
            }
            5353 -> {
                val m = parseMdns(buf, len)
                merge(ip) {
                    it.copy(
                        hostname = it.hostname ?: m.instance ?: m.hostname,
                        services = (it.services + m.services).distinct(),
                        via = it.via + "mDNS",
                    )
                }
            }
            3702 -> {
                val txt = String(buf, 0, len, Charsets.UTF_8)
                val kind = when {
                    txt.contains("Computer", true) -> "Windows PC (WS-Discovery)"
                    txt.contains("Print", true) -> "Printer (WS-Discovery)"
                    else -> "WS-Discovery"
                }
                merge(ip) { it.copy(info = it.info ?: kind, via = it.via + "WSD") }
            }
            else -> merge(ip) { it.copy(via = it.via + tag) }
        }
    }

    // ---- discovery multicast / broadcast (balasan datang unicast ke port sumber kita)
    private suspend fun discovery(net: LocalNet?) = coroutineScope {
        val iface = net?.ifName?.let { runCatching { NetworkInterface.getByName(it) }.getOrNull() }
        val jobs = listOf(
            Triple("224.0.0.251", 5353, listOf(MDNS_MCAST)),
            Triple("239.255.255.250", 1900, SSDP_QS),
            Triple("239.255.255.250", 3702, listOf(WSD_PROBE)),
        ).map { (g, p, q) -> launch(Dispatchers.IO) { listen(g, p, q, iface, false) } }
        val bc = net?.broadcast?.let { b -> launch(Dispatchers.IO) { listen(b, 137, listOf(NETBIOS_Q), iface, true) } }
        jobs.joinAll(); bc?.join()
    }

    private suspend fun listen(group: String, port: Int, payloads: List<ByteArray>, iface: NetworkInterface?, broadcast: Boolean) {
        val job = currentCoroutineContext().job
        try {
            MulticastSocket().use { s ->
                runCatching { if (iface != null) s.networkInterface = iface }
                runCatching { s.timeToLive = 4 }
                if (broadcast) s.broadcast = true
                val addr = InetAddress.getByName(group)
                fun sendAll() = payloads.forEach { runCatching { s.send(DatagramPacket(it, it.size, addr, port)) } }
                sendAll()
                val buf = ByteArray(9000)
                val t0 = System.currentTimeMillis()
                var resent = 0
                while (job.isActive && System.currentTimeMillis() - t0 < 7000) {
                    val el = System.currentTimeMillis() - t0
                    if ((resent == 0 && el > 1500) || (resent == 1 && el > 4000)) { sendAll(); resent++ }
                    s.soTimeout = 250
                    try {
                        val p = DatagramPacket(buf, buf.size)
                        s.receive(p)
                        val ip = p.address?.hostAddress ?: continue
                        handlePacket(port, ip, buf, p.length, "Multicast")
                    } catch (_: SocketTimeoutException) {
                    }
                }
            }
        } catch (_: Exception) {
        }
    }

    private fun fetchUpnp(ip: String, loc: String) {
        try {
            val c = URL(loc).openConnection() as HttpURLConnection
            c.connectTimeout = 1500; c.readTimeout = 1500
            val xml = c.inputStream.use { it.readBytes() }.toString(Charsets.UTF_8)
            fun tag(t: String) = Regex("<$t>([^<]*)</$t>").find(xml)?.groupValues?.get(1)?.trim()?.ifEmpty { null }
            val friendly = tag("friendlyName")
            val model = listOfNotNull(tag("manufacturer"), tag("modelName")).joinToString(" ").ifBlank { null }
            merge(ip) { it.copy(hostname = it.hostname ?: friendly, model = it.model ?: model) }
        } catch (_: Exception) {
        }
    }

    private fun readArpTables() {
        val entries = mutableMapOf<String, String>()
        runCatching {
            java.io.File("/proc/net/arp").readLines().drop(1).forEach {
                val c = it.trim().split(Regex("\\s+"))
                if (c.size >= 4 && c[2] != "0x0" && c[3] != "00:00:00:00:00:00") entries[c[0]] = c[3]
            }
        }
        runCatching {
            val p = ProcessBuilder("ip", "neigh", "show").redirectErrorStream(true).start()
            val out = p.inputStream.bufferedReader().readText()
            p.waitFor()
            out.lines().forEach { l ->
                val m = Regex("^(\\d+\\.\\d+\\.\\d+\\.\\d+) .*lladdr ([0-9a-fA-F:]{17}) (\\w+)").find(l.trim()) ?: return@forEach
                if (m.groupValues[3] != "FAILED" && m.groupValues[3] != "INCOMPLETE") entries[m.groupValues[1]] = m.groupValues[2]
            }
        }
        for ((ip, mac) in entries) if (inRange(ip)) merge(ip) { it.copy(mac = mac, via = it.via + "ARP") }
    }

    companion object {
        private val bgScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    }
}

/**
 * Connect TCP non-blocking massal (satu thread, Selector). Hasil per target lewat onDone:
 * 1 terbuka, 0 ditolak, -1 timeout, -2 host tidak ada (ARP gagal), -3 error.
 */
private fun nioConnect(
    targets: List<Pair<String, Int>>,
    timeoutMs: Int,
    maxInFlight: Int,
    active: () -> Boolean,
    onDone: (String, Int, Int) -> Unit,
) {
    val sel = Selector.open()
    val deadlines = HashMap<SelectionKey, Long>()
    var idx = 0
    try {
        while ((idx < targets.size || deadlines.isNotEmpty()) && active()) {
            while (deadlines.size < maxInFlight && idx < targets.size) {
                val (ip, port) = targets[idx++]
                var ch: SocketChannel? = null
                try {
                    ch = SocketChannel.open()
                    ch.configureBlocking(false)
                    if (ch.connect(InetSocketAddress(InetAddress.getByName(ip), port))) {
                        ch.close(); onDone(ip, port, 1)
                    } else {
                        val k = ch.register(sel, SelectionKey.OP_CONNECT, ip to port)
                        deadlines[k] = System.currentTimeMillis() + timeoutMs
                    }
                } catch (e: IOException) {
                    runCatching { ch?.close() }
                    onDone(ip, port, classify(e))
                }
            }
            sel.select(40)
            val it = sel.selectedKeys().iterator()
            while (it.hasNext()) {
                val k = it.next(); it.remove()
                val (ip, port) = k.attachment() as Pair<*, *>; ip as String; port as Int
                val ch = k.channel() as SocketChannel
                val r = try {
                    if (ch.finishConnect()) 1 else continue
                } catch (e: IOException) {
                    classify(e)
                }
                deadlines.remove(k); k.cancel(); runCatching { ch.close() }
                onDone(ip, port, r)
            }
            val now = System.currentTimeMillis()
            val exp = deadlines.filterValues { it < now }.keys
            for (k in exp) {
                deadlines.remove(k); k.cancel(); runCatching { k.channel().close() }
                val (ip, port) = k.attachment() as Pair<*, *>; ip as String; port as Int
                onDone(ip, port, -1)
            }
        }
    } finally {
        deadlines.keys.forEach { runCatching { it.channel().close() } }
        runCatching { sel.close() }
    }
}

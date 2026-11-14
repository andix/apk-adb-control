package com.aisuma.ipscanner

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import java.net.*

data class Host(
    val ip: String,
    val hostname: String?,
    val openPorts: List<Int>,
    val pingMs: Long?,
) {
    val adb get() = 5555 in openPorts
}

data class LocalNet(val ip: String, val prefix: Int, val start: String, val end: String)

val SCAN_PORTS = listOf(5555, 80, 443, 22, 53, 445, 8080, 8008, 7000, 62078, 554, 8000)

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

private fun probe(ip: String, timeoutMs: Int): Pair<Boolean, List<Int>> {
    val open = mutableListOf<Int>()
    var alive = false
    for (port in SCAN_PORTS) {
        try {
            Socket().use { s ->
                s.connect(InetSocketAddress(ip, port), timeoutMs)
                open += port
                alive = true
            }
        } catch (e: ConnectException) {
            // ditolak (RST) = host hidup, port tertutup
            if (e.message?.contains("refused", true) == true) alive = true
        } catch (_: Exception) {
        }
    }
    return alive to open
}

/** Pindai start..end; panggil onHost tiap host hidup, onProgress(selesai, total). */
suspend fun scanRange(
    start: Long,
    end: Long,
    timeoutMs: Int,
    onProgress: (Int, Int) -> Unit,
    onHost: (Host) -> Unit,
) = coroutineScope {
    val total = (end - start + 1).toInt()
    val sem = Semaphore(48)
    var done = 0
    val jobs = (start..end).map { v ->
        launch(Dispatchers.IO) {
            sem.withPermit {
                val ip = longToIp(v)
                val t0 = System.currentTimeMillis()
                val reachable = try {
                    InetAddress.getByName(ip).isReachable(timeoutMs)
                } catch (_: Exception) {
                    false
                }
                val ping = if (reachable) System.currentTimeMillis() - t0 else null
                val (alive, open) = probe(ip, minOf(timeoutMs, 400))
                if (reachable || alive) {
                    val name = withTimeoutOrNull(1500) {
                        runInterruptible {
                            val h = InetAddress.getByName(ip).canonicalHostName
                            if (h == ip) null else h
                        }
                    }
                    onHost(Host(ip, name, open, ping))
                }
            }
            synchronized(jobs0) { done++; onProgress(done, total) }
        }
    }
    jobs.joinAll()
}

private val jobs0 = Any()

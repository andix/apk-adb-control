package com.aisuma.ipscanner

import android.content.Context
import dadb.AdbKeyPair
import dadb.Dadb
import kotlinx.coroutines.*
import okio.buffer
import okio.source
import java.io.File

class AdbSession(val dadb: Dadb, val host: String, val port: Int) {
    /** Jalankan perintah shell di perangkat target, kembalikan stdout+stderr. */
    suspend fun sh(cmd: String): String = withContext(Dispatchers.IO) {
        val r = dadb.shell(cmd)
        (r.output + r.errorOutput).trim()
    }

    suspend fun screenshot(): ByteArray = withContext(Dispatchers.IO) {
        dadb.open("exec:screencap -p").use { it.source.readByteArray() }
    }

    suspend fun install(file: File, vararg opts: String) = withContext(Dispatchers.IO) {
        dadb.install(file, *opts)
    }

    fun close() = runCatching { dadb.close() }
}

private fun loadKeyPair(ctx: Context): AdbKeyPair {
    val priv = File(ctx.filesDir, "adbkey")
    val pub = File(ctx.filesDir, "adbkey.pub")
    if (!priv.exists() || !pub.exists()) AdbKeyPair.generate(priv, pub)
    return AdbKeyPair.read(priv, pub)
}

/**
 * Konek ke adbd di host:port. Fungsi ini menunggu sampai pengguna menekan "Izinkan"
 * pada dialog "Allow USB debugging?" di perangkat target (maks 2 menit).
 */
suspend fun connectAdb(ctx: Context, host: String, port: Int): AdbSession {
    val kp = withContext(Dispatchers.IO) { loadKeyPair(ctx) }
    val d = Dadb.create(host, port, kp, 5000, 0)
    val job = CoroutineScope(Dispatchers.IO).async { d.shell("echo ok") }
    try {
        withTimeout(120_000) { job.await() }
    } catch (t: Throwable) {
        runCatching { d.close() }
        throw if (t is TimeoutCancellationException) Exception("Tidak disetujui dalam 2 menit") else t
    }
    return AdbSession(d, host, port)
}

data class AppInfo(val pkg: String, val system: Boolean)

suspend fun AdbSession.listApps(): List<AppInfo> {
    val third = sh("pm list packages -3").lines().mapNotNull { it.removePrefix("package:").trim().takeIf { s -> s.isNotEmpty() && it.startsWith("package:") } }.toSet()
    return sh("pm list packages").lines()
        .filter { it.startsWith("package:") }
        .map { it.removePrefix("package:").trim() }
        .map { AppInfo(it, it !in third) }
        .sortedWith(compareBy({ it.system }, { it.pkg }))
}

suspend fun AdbSession.deviceInfo(): List<Pair<String, String>> {
    fun p(k: String) = "getprop $k"
    val out = sh(
        listOf(
            p("ro.product.manufacturer"), p("ro.product.model"), p("ro.build.version.release"),
            p("ro.build.version.sdk"), p("ro.product.cpu.abi"), p("ro.build.display.id"),
            "wm size", "wm density", "dumpsys battery | grep -E 'level|status|temperature'",
            "df -h /data | tail -1", "cat /proc/meminfo | head -1", "settings get secure android_id",
        ).joinToString(" ; echo '|||' ; ")
    ).split("|||").map { it.trim() }
    fun g(i: Int) = out.getOrNull(i)?.takeIf { it.isNotBlank() } ?: "-"
    val df = g(9).split(Regex("\\s+"))
    val bat = g(8).lines().joinToString(", ") { it.trim() }
    return listOf(
        "Produsen" to g(0), "Model" to g(1), "Android" to "${g(2)} (API ${g(3)})",
        "CPU ABI" to g(4), "Build" to g(5), "Layar" to g(6).replace("Physical size: ", ""),
        "Density" to g(7).replace("Physical density: ", ""),
        "Baterai" to bat,
        "Storage /data" to if (df.size >= 5) "${df[2]} terpakai dari ${df[1]} (${df[4]})" else g(9),
        "RAM" to g(10).replace("MemTotal:", "").trim(),
        "Android ID" to g(11),
    )
}

fun shQuote(s: String) = "'" + s.replace("'", "'\\''") + "'"

fun Context.copyUriToCache(uri: android.net.Uri, name: String): File {
    val f = File(cacheDir, "install_" + name.replace(Regex("[^A-Za-z0-9._-]"), "_"))
    contentResolver.openInputStream(uri)!!.use { i -> f.outputStream().use { o -> i.copyTo(o) } }
    return f
}

fun Context.displayName(uri: android.net.Uri): String =
    contentResolver.query(uri, arrayOf(android.provider.OpenableColumns.DISPLAY_NAME), null, null, null)?.use {
        if (it.moveToFirst()) it.getString(0) else null
    } ?: uri.lastPathSegment ?: "app.apk"

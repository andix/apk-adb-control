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

/**
 * Kunci RSA 2048 untuk autentikasi ADB. Dibuat & disimpan sendiri (AdbKeyPair.generate dari dadb
 * menghasilkan file kosong di Android). Private key: PKCS#8 DER (base64). Public key: format adb
 * ("<base64 struct RSA android> nama"), dikirim ke perangkat saat dialog "Allow USB debugging?".
 */
private fun loadKeyPair(ctx: Context): AdbKeyPair {
    val privF = File(ctx.filesDir, "adb_rsa.key")
    val pubF = File(ctx.filesDir, "adb_rsa.pub")
    val kf = java.security.KeyFactory.getInstance("RSA")
    runCatching {
        val der = android.util.Base64.decode(privF.readText(), android.util.Base64.DEFAULT)
        val pub = pubF.readBytes()
        if (der.isNotEmpty() && pub.size > 100) {
            return AdbKeyPair(kf.generatePrivate(java.security.spec.PKCS8EncodedKeySpec(der)), pub + 0)
        }
    }
    val gen = java.security.KeyPairGenerator.getInstance("RSA")
    gen.initialize(2048)
    val kp = gen.genKeyPair()
    val pubLine = (android.util.Base64.encodeToString(adbPublicKey(kp.public as java.security.interfaces.RSAPublicKey),
        android.util.Base64.NO_WRAP) + " ipscanner@" + android.os.Build.MODEL.replace(" ", "_")).toByteArray()
    privF.writeText(android.util.Base64.encodeToString(kp.private.encoded, android.util.Base64.NO_WRAP))
    pubF.writeBytes(pubLine)
    return AdbKeyPair(kp.private, pubLine + 0)
}

/** Struktur RSAPublicKey milik adb/mincrypt: len, n0inv, n[], rr[], e (semua little-endian). */
private fun adbPublicKey(pub: java.security.interfaces.RSAPublicKey): ByteArray {
    val words = 64
    val r32 = java.math.BigInteger.ONE.shiftLeft(32)
    val n = pub.modulus
    val n0inv = r32.subtract(n.mod(r32).modInverse(r32)).mod(r32)
    val rr = java.math.BigInteger.ONE.shiftLeft(words * 32 * 2).mod(n)
    val bb = java.nio.ByteBuffer.allocate(4 + 4 + words * 4 * 2 + 4).order(java.nio.ByteOrder.LITTLE_ENDIAN)
    bb.putInt(words)
    bb.putInt(n0inv.toLong().toInt())
    fun putBig(x: java.math.BigInteger) {
        var v = x
        repeat(words) { bb.putInt(v.mod(r32).toLong().toInt()); v = v.shiftRight(32) }
    }
    putBig(n)
    putBig(rr)
    bb.putInt(pub.publicExponent.toInt())
    return bb.array()
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

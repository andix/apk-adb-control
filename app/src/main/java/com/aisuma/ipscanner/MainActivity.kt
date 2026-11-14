package com.aisuma.ipscanner

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent { AppTheme { Root() } }
    }
}

@Composable
fun AppTheme(content: @Composable () -> Unit) {
    val ctx = LocalContext.current
    val dark = androidx.compose.foundation.isSystemInDarkTheme()
    val scheme = when {
        Build.VERSION.SDK_INT >= 31 -> if (dark) dynamicDarkColorScheme(ctx) else dynamicLightColorScheme(ctx)
        dark -> darkColorScheme()
        else -> lightColorScheme()
    }
    MaterialTheme(colorScheme = scheme) { Surface(Modifier.fillMaxSize(), content = content) }
}

/** State scan di-hoist supaya hasil tidak hilang saat pindah ke layar perangkat. */
class ScanState(ctx: Context) {
    val net = detectLocalNet(ctx)
    var start by mutableStateOf(net?.start ?: "192.168.1.1")
    var end by mutableStateOf(net?.end ?: "192.168.1.254")
    var timeout by mutableStateOf("1000")
    val hosts = mutableStateListOf<Host>()
    var progress by mutableStateOf(0f)
    var phase by mutableStateOf("")
    var note by mutableStateOf<String?>(null)
    var started by mutableStateOf(false)
    var job: Job? = null
    var scanning by mutableStateOf(false)
    var error by mutableStateOf<String?>(null)
}

@Composable
fun Root() {
    val ctx = LocalContext.current
    val scan = remember { ScanState(ctx) }
    var session by remember { mutableStateOf<AdbSession?>(null) }
    val s = session
    if (s == null) {
        ScanScreen(scan, onConnected = { session = it })
    } else {
        BackHandler { s.close(); session = null }
        DeviceScreen(s, onDisconnect = { s.close(); session = null })
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ScanScreen(st: ScanState, onConnected: (AdbSession) -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val scanning = st.scanning
    var selected by remember { mutableStateOf<Host?>(null) }

    fun resetDefault() {
        val n = detectLocalNet(ctx)
        if (n != null) { st.start = n.start; st.end = n.end; st.error = null }
        else st.error = "Tidak tersambung ke Wi-Fi/Ethernet"
    }

    fun startScan() {
        val s = ipToLong(st.start)
        val e = ipToLong(st.end)
        if (s == null || e == null || e < s) { st.error = "Range IP tidak valid"; return }
        if (e - s + 1 > 4096) { st.error = "Maksimal 4096 IP per scan"; return }
        st.error = null
        st.hosts.clear()
        st.progress = 0f
        st.phase = "Memulai…"
        st.note = null
        st.started = true
        st.scanning = true
        st.job = scope.launch {
            try {
                NetScanner(
                    ctx, s, e, st.timeout.toIntOrNull()?.coerceIn(200, 5000) ?: 1000,
                    onProgress = { ph, d, t ->
                        scope.launch { st.phase = ph; st.progress = if (t > 0) d / t.toFloat() else 0f }
                    },
                    onHost = { h ->
                        scope.launch {
                            val i = st.hosts.indexOfFirst { it.ip == h.ip }
                            if (i >= 0) st.hosts[i] = h else {
                                st.hosts.add(h)
                                st.hosts.sortBy { ipToLong(it.ip) }
                            }
                        }
                    },
                    onNote = { n -> scope.launch { st.note = n } },
                ).run()
            } finally {
                st.scanning = false
            }
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(title = {
                Column {
                    Text("IP Scanner", fontWeight = FontWeight.Bold)
                    Text(
                        st.net?.let { "HP: ${it.ip}/${it.prefix}" } ?: "Tidak tersambung ke jaringan lokal",
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            })
        }
    ) { pad ->
        Column(
            Modifier.padding(pad).fillMaxSize().padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(st.start, { st.start = it }, Modifier.weight(1f), label = { Text("Dari IP") },
                    singleLine = true, enabled = !scanning,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal))
                OutlinedTextField(st.end, { st.end = it }, Modifier.weight(1f), label = { Text("Sampai IP") },
                    singleLine = true, enabled = !scanning,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal))
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(st.timeout, { st.timeout = it.filter(Char::isDigit) }, Modifier.width(120.dp),
                    label = { Text("Timeout ms") }, singleLine = true, enabled = !scanning,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number))
                OutlinedButton(onClick = { resetDefault() }, enabled = !scanning) { Text("Segmen HP") }
                Button(onClick = { if (scanning) st.job?.cancel() else startScan() }, Modifier.weight(1f)) {
                    Text(if (scanning) "Stop" else "Scan")
                }
            }
            st.error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            if (st.started) {
                LinearProgressIndicator(progress = { st.progress }, modifier = Modifier.fillMaxWidth())
                Text(
                    if (scanning) "${st.phase} · ${(st.progress * 100).toInt()}% · ${st.hosts.size} host"
                    else "Selesai · ${st.hosts.size} host aktif",
                    style = MaterialTheme.typography.bodySmall
                )
                st.note?.let { Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.tertiary) }
            }
            LazyColumn(
                verticalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.weight(1f),
                contentPadding = PaddingValues(bottom = 16.dp)
            ) {
                items(st.hosts, key = { it.ip }) { h ->
                    ElevatedCard(onClick = { selected = h }, modifier = Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(12.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Text(h.ip, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold,
                                    modifier = Modifier.weight(1f))
                                if (h.adb) AssistChip(onClick = {}, label = { Text("ADB 5555") })
                                h.pingMs?.let { Text("  $it ms", style = MaterialTheme.typography.bodySmall) }
                            }
                            h.guess?.let { Text(it, style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary) }
                            h.hostname?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
                            h.model?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
                            h.info?.let { Text(it, style = MaterialTheme.typography.bodySmall, maxLines = 2) }
                            if (h.services.isNotEmpty())
                                Text("Layanan: " + h.services.joinToString(", ") { it.removePrefix("_") },
                                    style = MaterialTheme.typography.bodySmall)
                            if (h.via.isNotEmpty())
                                Text("Terdeteksi via " + h.via.joinToString(" · "),
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                            h.mac?.let { Text("MAC $it", style = MaterialTheme.typography.bodySmall) }
                            if (h.openPorts.isNotEmpty())
                                Text("Port: " + h.openPorts.joinToString(", "), style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }
        }
    }

    selected?.let { host -> HostSheet(host, onDismiss = { selected = null }, onConnected = { selected = null; onConnected(it) }) }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HostSheet(host: Host, onDismiss: () -> Unit, onConnected: (AdbSession) -> Unit) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var port by remember { mutableStateOf("5555") }
    var connecting by remember { mutableStateOf<Job?>(null) }
    var error by remember { mutableStateOf<String?>(null) }

    ModalBottomSheet(onDismissRequest = { if (connecting == null) onDismiss() }) {
        Column(Modifier.padding(horizontal = 20.dp).padding(bottom = 28.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text(host.ip, style = MaterialTheme.typography.headlineSmall, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold)
            host.hostname?.let { Text(it, style = MaterialTheme.typography.bodyMedium) }
            if (!host.adb) Text(
                "Port 5555 tidak terdeteksi terbuka. Aktifkan dulu di target (adb tcpip 5555), atau isi port lain.",
                style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error
            )
            OutlinedTextField(port, { port = it.filter(Char::isDigit) }, label = { Text("Port ADB") }, singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number), modifier = Modifier.fillMaxWidth())
            error?.let { Text(it, color = MaterialTheme.colorScheme.error) }
            Button(
                modifier = Modifier.fillMaxWidth(),
                onClick = {
                    error = null
                    connecting = scope.launch {
                        try {
                            onConnected(connectAdb(ctx, host.ip, port.toIntOrNull() ?: 5555))
                        } catch (e: CancellationException) {
                            throw e
                        } catch (e: Throwable) {
                            error = "Gagal konek: ${e.message ?: e.javaClass.simpleName}"
                            connecting = null
                        }
                    }
                }
            ) { Text("Connect to ADB") }
            OutlinedButton(modifier = Modifier.fillMaxWidth(), onClick = {
                val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                cm.setPrimaryClip(ClipData.newPlainText("ip", host.ip))
                Toast.makeText(ctx, "Disalin", Toast.LENGTH_SHORT).show()
            }) { Text("Salin IP") }
        }
    }

    if (connecting != null) {
        AlertDialog(
            onDismissRequest = {},
            title = { Text("Menunggu persetujuan") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
                    LinearProgressIndicator(Modifier.fillMaxWidth())
                    Text("Buka layar perangkat ${host.ip} lalu ketuk “Izinkan” pada dialog “Allow USB debugging?”. Centang “Selalu izinkan” agar tidak ditanya lagi.")
                }
            },
            confirmButton = {
                TextButton(onClick = { connecting?.cancel(); connecting = null }) { Text("Batal") }
            }
        )
    }
}

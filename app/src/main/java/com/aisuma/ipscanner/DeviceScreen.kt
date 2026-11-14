package com.aisuma.ipscanner

import android.content.ContentValues
import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.os.Build
import android.provider.MediaStore
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.List
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch

enum class Panel(val title: String, val desc: String, val icon: ImageVector) {
    Info("Info perangkat", "Model, Android, baterai, storage, RAM", Icons.Default.Info),
    Apps("Daftar aplikasi", "Semua paket, buka / stop / hapus data", Icons.AutoMirrored.Filled.List),
    Install("Install APK", "Pasang file APK dari HP ini", Icons.Default.Add),
    Uninstall("Uninstall aplikasi", "Hapus aplikasi pihak ketiga", Icons.Default.Delete),
    Screenshot("Screenshot", "Ambil tangkapan layar target", Icons.Default.AccountBox),
    Keys("Remote tombol", "Home, Back, Recent, volume, power", Icons.Default.Home),
    Input("Ketik & buka URL", "Kirim teks atau buka link di target", Icons.Default.Edit),
    Shell("Terminal shell", "Jalankan perintah adb shell", Icons.AutoMirrored.Filled.Send),
    Power("Power & reboot", "Reboot, recovery, bootloader, matikan", Icons.Default.Refresh),
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DeviceScreen(s: AdbSession, onDisconnect: () -> Unit) {
    var panel by remember { mutableStateOf<Panel?>(null) }
    val snack = remember { SnackbarHostState() }
    var model by remember { mutableStateOf("") }
    LaunchedEffect(s) { model = runCatching { s.sh("getprop ro.product.model") }.getOrDefault("") }
    BackHandler(panel != null) { panel = null }

    Scaffold(
        snackbarHost = { SnackbarHost(snack) },
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(panel?.title ?: model.ifBlank { "Perangkat" }, fontWeight = FontWeight.Bold)
                        Text("${s.host}:${s.port} · terhubung", style = MaterialTheme.typography.bodySmall)
                    }
                },
                navigationIcon = {
                    IconButton(onClick = { if (panel != null) panel = null else onDisconnect() }) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, "Kembali")
                    }
                },
                actions = { if (panel == null) TextButton(onClick = onDisconnect) { Text("Putuskan") } }
            )
        }
    ) { pad ->
        Box(Modifier.padding(pad).fillMaxSize()) {
            when (val p = panel) {
                null -> LazyVerticalGrid(
                    GridCells.Fixed(2),
                    contentPadding = PaddingValues(16.dp),
                    horizontalArrangement = Arrangement.spacedBy(12.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    items(Panel.entries) { f ->
                        ElevatedCard(onClick = { panel = f }, Modifier.fillMaxWidth().heightIn(min = 150.dp)) {
                            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                Surface(shape = CircleShape, color = MaterialTheme.colorScheme.primaryContainer) {
                                    Icon(f.icon, null, Modifier.padding(10.dp).size(24.dp),
                                        tint = MaterialTheme.colorScheme.onPrimaryContainer)
                                }
                                Text(f.title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                                Text(f.desc, style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                        }
                    }
                }
                Panel.Info -> InfoPanel(s)
                Panel.Apps -> AppsPanel(s, snack, uninstallMode = false)
                Panel.Uninstall -> AppsPanel(s, snack, uninstallMode = true)
                Panel.Install -> InstallPanel(s)
                Panel.Screenshot -> ScreenshotPanel(s, snack)
                Panel.Keys -> KeysPanel(s, snack)
                Panel.Input -> InputPanel(s, snack)
                Panel.Shell -> ShellPanel(s)
                Panel.Power -> PowerPanel(s, snack)
            }
        }
    }
}

@Composable
fun Loading() = Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { CircularProgressIndicator() }

@Composable
fun InfoPanel(s: AdbSession) {
    var rows by remember { mutableStateOf<List<Pair<String, String>>?>(null) }
    var err by remember { mutableStateOf<String?>(null) }
    LaunchedEffect(Unit) { runCatching { s.deviceInfo() }.onSuccess { rows = it }.onFailure { err = it.message } }
    err?.let { Text(it, Modifier.padding(16.dp), color = MaterialTheme.colorScheme.error) }
    val r = rows ?: return if (err == null) Loading() else Unit
    LazyColumn(contentPadding = PaddingValues(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        items(r) { (k, v) ->
            Card(Modifier.fillMaxWidth()) {
                Column(Modifier.padding(12.dp)) {
                    Text(k, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
                    Text(v, style = MaterialTheme.typography.bodyLarge)
                }
            }
        }
    }
}

@Composable
fun AppsPanel(s: AdbSession, snack: SnackbarHostState, uninstallMode: Boolean) {
    val scope = rememberCoroutineScope()
    var apps by remember { mutableStateOf<List<AppInfo>?>(null) }
    var query by remember { mutableStateOf("") }
    var showSystem by remember { mutableStateOf(!uninstallMode) }
    var target by remember { mutableStateOf<AppInfo?>(null) }
    var confirmUninstall by remember { mutableStateOf<AppInfo?>(null) }
    var busy by remember { mutableStateOf(false) }

    fun reload() = scope.launch {
        apps = null
        apps = runCatching { s.listApps() }.getOrElse { snack.showSnackbar(it.message ?: "Gagal"); emptyList() }
    }
    LaunchedEffect(Unit) { reload() }

    fun act(label: String, cmd: String) = scope.launch {
        busy = true
        val out = runCatching { s.sh(cmd) }.getOrElse { it.message ?: "Gagal" }
        busy = false
        snack.showSnackbar("$label: ${out.ifBlank { "selesai" }.take(120)}")
    }

    Column(Modifier.fillMaxSize()) {
        Row(Modifier.padding(horizontal = 16.dp, vertical = 8.dp), verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(query, { query = it }, Modifier.weight(1f), singleLine = true,
                label = { Text("Cari paket") }, leadingIcon = { Icon(Icons.Default.Search, null) })
            IconButton(onClick = { reload() }) { Icon(Icons.Default.Refresh, "Muat ulang") }
        }
        Row(Modifier.padding(horizontal = 16.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(!showSystem, { showSystem = false }, label = { Text("Pihak ketiga") })
            FilterChip(showSystem, { showSystem = true }, label = { Text("Semua") })
        }
        val list = apps
        if (list == null) Loading() else {
            val shown = list.filter { (showSystem || !it.system) && it.pkg.contains(query, true) }
            Text("${shown.size} aplikasi", Modifier.padding(horizontal = 16.dp, vertical = 6.dp), style = MaterialTheme.typography.labelMedium)
            LazyColumn(contentPadding = PaddingValues(horizontal = 16.dp, vertical = 4.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                items(shown, key = { it.pkg }) { a ->
                    ElevatedCard(onClick = { if (uninstallMode && !a.system) confirmUninstall = a else target = a }, Modifier.fillMaxWidth()) {
                        Row(Modifier.padding(12.dp), verticalAlignment = Alignment.CenterVertically) {
                            Text(a.pkg, Modifier.weight(1f), fontFamily = FontFamily.Monospace, fontSize = 13.sp)
                            if (a.system) AssistChip(onClick = {}, label = { Text("sistem") })
                        }
                    }
                }
            }
        }
    }
    if (busy) Loading()

    target?.let { a ->
        AlertDialog(
            onDismissRequest = { target = null },
            title = { Text(a.pkg, fontSize = 15.sp, fontFamily = FontFamily.Monospace) },
            text = {
                Column {
                    TextButton(onClick = { target = null; act("Buka", "monkey -p ${a.pkg} -c android.intent.category.LAUNCHER 1") }) { Text("Buka aplikasi") }
                    TextButton(onClick = { target = null; act("Force stop", "am force-stop ${a.pkg}") }) { Text("Force stop") }
                    TextButton(onClick = { target = null; act("Hapus data", "pm clear ${a.pkg}") }) { Text("Hapus data / cache") }
                    TextButton(onClick = { target = null; confirmUninstall = a }) {
                        Text("Uninstall", color = MaterialTheme.colorScheme.error)
                    }
                }
            },
            confirmButton = { TextButton(onClick = { target = null }) { Text("Tutup") } }
        )
    }
    confirmUninstall?.let { a ->
        AlertDialog(
            onDismissRequest = { confirmUninstall = null },
            title = { Text("Uninstall aplikasi?") },
            text = { Text(a.pkg) },
            confirmButton = {
                TextButton(onClick = {
                    confirmUninstall = null
                    scope.launch {
                        busy = true
                        val out = runCatching { s.sh("pm uninstall ${a.pkg}") }.getOrElse { it.message ?: "Gagal" }
                        busy = false
                        snack.showSnackbar("Uninstall ${a.pkg}: $out")
                        if (out.contains("Success")) apps = apps?.filter { it.pkg != a.pkg }
                    }
                }) { Text("Uninstall", color = MaterialTheme.colorScheme.error) }
            },
            dismissButton = { TextButton(onClick = { confirmUninstall = null }) { Text("Batal") } }
        )
    }
}

@Composable
fun InstallPanel(s: AdbSession) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var replace by remember { mutableStateOf(true) }
    var downgrade by remember { mutableStateOf(false) }
    var grant by remember { mutableStateOf(true) }
    var busy by remember { mutableStateOf(false) }
    val log = remember { mutableStateListOf<String>() }

    val pick = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        if (uris.isEmpty()) return@rememberLauncherForActivityResult
        scope.launch {
            busy = true
            val opts = buildList { if (replace) add("-r"); if (downgrade) add("-d"); if (grant) add("-g") }.toTypedArray()
            for (u in uris) {
                val name = ctx.displayName(u)
                log.add("⏳ $name …")
                val res = runCatching {
                    val f = kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) { ctx.copyUriToCache(u, name) }
                    try { s.install(f, *opts) } finally { f.delete() }
                }
                log[log.lastIndex] = if (res.isSuccess) "✅ $name terpasang" else "❌ $name: ${res.exceptionOrNull()?.message?.take(200)}"
            }
            busy = false
        }
    }

    Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text("Pilih satu atau beberapa file APK dari penyimpanan HP ini untuk dipasang ke perangkat target.")
        OptionRow("Timpa jika sudah ada (-r)", replace) { replace = it }
        OptionRow("Izinkan downgrade (-d)", downgrade) { downgrade = it }
        OptionRow("Beri semua izin otomatis (-g)", grant) { grant = it }
        Button(onClick = { pick.launch(arrayOf("*/*")) }, enabled = !busy, modifier = Modifier.fillMaxWidth()) {
            Text(if (busy) "Memasang…" else "Pilih APK & install")
        }
        if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
        log.forEach { Text(it, style = MaterialTheme.typography.bodyMedium) }
    }
}

@Composable
fun OptionRow(label: String, value: Boolean, onChange: (Boolean) -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Text(label, Modifier.weight(1f))
        Switch(value, onChange)
    }
}

@Composable
fun ScreenshotPanel(s: AdbSession, snack: SnackbarHostState) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    var bmp by remember { mutableStateOf<Bitmap?>(null) }
    var png by remember { mutableStateOf<ByteArray?>(null) }
    var busy by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(enabled = !busy, onClick = {
                scope.launch {
                    busy = true
                    runCatching { s.screenshot() }
                        .onSuccess { png = it; bmp = BitmapFactory.decodeByteArray(it, 0, it.size) }
                        .onFailure { snack.showSnackbar(it.message ?: "Gagal") }
                    busy = false
                }
            }) { Text("Ambil screenshot") }
            OutlinedButton(enabled = png != null, onClick = {
                snack.let { scope.launch { it.showSnackbar(savePng(ctx, png!!)) } }
            }) { Text("Simpan") }
        }
        if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
        bmp?.let { Image(it.asImageBitmap(), null, Modifier.weight(1f).fillMaxWidth()) }
    }
}

private fun savePng(ctx: Context, data: ByteArray): String {
    if (Build.VERSION.SDK_INT < 29) return "Simpan butuh Android 10+"
    val cv = ContentValues().apply {
        put(MediaStore.Images.Media.DISPLAY_NAME, "adb_${System.currentTimeMillis()}.png")
        put(MediaStore.Images.Media.MIME_TYPE, "image/png")
        put(MediaStore.Images.Media.RELATIVE_PATH, "Pictures/IpScanner")
    }
    val uri = ctx.contentResolver.insert(MediaStore.Images.Media.EXTERNAL_CONTENT_URI, cv) ?: return "Gagal menyimpan"
    ctx.contentResolver.openOutputStream(uri)?.use { it.write(data) }
    return "Tersimpan di Pictures/IpScanner"
}

@Composable
fun KeysPanel(s: AdbSession, snack: SnackbarHostState) {
    val scope = rememberCoroutineScope()
    val keys = listOf(
        "Home" to 3, "Back" to 4, "Recent" to 187, "Menu" to 82, "Power" to 26, "Vol +" to 24, "Vol −" to 25,
        "Mute" to 164, "Play/Pause" to 85, "Next" to 87, "Prev" to 88, "Atas" to 19, "Bawah" to 20, "Kiri" to 21,
        "Kanan" to 22, "OK" to 23, "Notifikasi" to -1, "Kunci layar" to 223,
    )
    LazyVerticalGrid(GridCells.Fixed(3), contentPadding = PaddingValues(16.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        items(keys) { (label, code) ->
            FilledTonalButton(onClick = {
                scope.launch {
                    val cmd = if (code == -1) "cmd statusbar expand-notifications" else "input keyevent $code"
                    runCatching { s.sh(cmd) }.onFailure { snack.showSnackbar(it.message ?: "Gagal") }
                }
            }, modifier = Modifier.fillMaxWidth().height(56.dp)) { Text(label, maxLines = 1, fontSize = 13.sp) }
        }
    }
}

@Composable
fun InputPanel(s: AdbSession, snack: SnackbarHostState) {
    val scope = rememberCoroutineScope()
    var text by remember { mutableStateOf("") }
    var url by remember { mutableStateOf("https://") }
    fun run(cmd: String, ok: String) = scope.launch {
        val out = runCatching { s.sh(cmd) }.getOrElse { it.message ?: "Gagal" }
        snack.showSnackbar(if (out.isBlank() || out.startsWith("Starting")) ok else out.take(150))
    }
    Column(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        OutlinedTextField(text, { text = it }, Modifier.fillMaxWidth(), label = { Text("Teks (ASCII) ke kolom aktif") })
        Button(onClick = { run("input text ${shQuote(text.replace(" ", "%s"))}", "Teks terkirim") }, Modifier.fillMaxWidth()) { Text("Kirim teks") }
        HorizontalDivider()
        OutlinedTextField(url, { url = it }, Modifier.fillMaxWidth(), label = { Text("URL") }, singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri))
        Button(onClick = { run("am start -a android.intent.action.VIEW -d ${shQuote(url)}", "URL dibuka") }, Modifier.fillMaxWidth()) { Text("Buka URL di target") }
    }
}

@Composable
fun ShellPanel(s: AdbSession) {
    val scope = rememberCoroutineScope()
    var cmd by remember { mutableStateOf("") }
    var busy by remember { mutableStateOf(false) }
    val out = remember { mutableStateListOf<String>() }
    fun run() {
        val c = cmd.trim().ifEmpty { return }
        cmd = ""
        out.add("$ $c")
        scope.launch {
            busy = true
            out.add(runCatching { s.sh(c) }.getOrElse { "error: ${it.message}" }.ifBlank { "(tanpa output)" })
            busy = false
        }
    }
    Column(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(cmd, { cmd = it }, Modifier.weight(1f), singleLine = true, label = { Text("Perintah, mis. ls /sdcard") })
            Button(onClick = { run() }, enabled = !busy) { Text("Run") }
        }
        if (busy) LinearProgressIndicator(Modifier.fillMaxWidth())
        Card(Modifier.weight(1f).fillMaxWidth()) {
            LazyColumn(Modifier.padding(12.dp), reverseLayout = true) {
                items(out.asReversed()) { Text(it, fontFamily = FontFamily.Monospace, fontSize = 12.sp) }
            }
        }
    }
}

@Composable
fun PowerPanel(s: AdbSession, snack: SnackbarHostState) {
    val scope = rememberCoroutineScope()
    var confirm by remember { mutableStateOf<Pair<String, String>?>(null) }
    val actions = listOf(
        "Reboot" to "reboot", "Reboot ke recovery" to "reboot recovery",
        "Reboot ke bootloader" to "reboot bootloader", "Matikan perangkat" to "reboot -p",
    )
    Column(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        actions.forEach { (l, c) -> FilledTonalButton(onClick = { confirm = l to c }, Modifier.fillMaxWidth()) { Text(l) } }
    }
    confirm?.let { (l, c) ->
        AlertDialog(
            onDismissRequest = { confirm = null },
            title = { Text("$l?") },
            text = { Text("Koneksi ADB akan terputus.") },
            confirmButton = {
                TextButton(onClick = {
                    confirm = null
                    scope.launch { runCatching { s.sh(c) }; snack.showSnackbar("Perintah terkirim") }
                }) { Text("Ya") }
            },
            dismissButton = { TextButton(onClick = { confirm = null }) { Text("Batal") } }
        )
    }
}

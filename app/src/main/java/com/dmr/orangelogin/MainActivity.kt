package com.dmr.orangelogin

import android.app.Activity
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Bundle
import android.util.Base64
import android.view.Gravity
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStream
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.ServerSocket
import java.net.URL
import java.net.URLDecoder
import java.net.URLEncoder
import java.security.MessageDigest
import java.security.SecureRandom

class MainActivity : Activity() {

    private val baseUrl = "https://nextendo.network"
    private val scope = "identity profil friends presence history game.matchmaking"
    private val port = 47823
    private val createFile = 1001
    private val clientId = "nxc_z_fetCuVO1qx"

    private val cBg = Color.parseColor("#0F1412")
    private val cGreen = Color.parseColor("#2ECC71")
    private val cText = Color.parseColor("#E8F0EC")
    private val cMuted = Color.parseColor("#9BB0A5")

    private lateinit var status: TextView
    private var pendingContent: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val d = resources.displayMetrics.density
        fun dp(v: Int) = (v * d).toInt()

        val root = LinearLayout(this)
        root.orientation = LinearLayout.VERTICAL
        root.setBackgroundColor(cBg)
        root.gravity = Gravity.CENTER_HORIZONTAL
        root.setPadding(dp(24), dp(40), dp(24), dp(24))

        val title = TextView(this)
        title.text = "Orange"
        title.setTextColor(cGreen)
        title.textSize = 34f
        title.setTypeface(Typeface.DEFAULT_BOLD)
        title.gravity = Gravity.CENTER
        root.addView(title)

        val subtitle = TextView(this)
        subtitle.text = "Generateur de connexion Nextendo"
        subtitle.setTextColor(cMuted)
        subtitle.textSize = 14f
        subtitle.gravity = Gravity.CENTER
        subtitle.setPadding(0, dp(6), 0, dp(32))
        root.addView(subtitle)

        val button = Button(this)
        button.text = "Se connecter a Nextendo"
        button.setTextColor(cBg)
        button.setTypeface(Typeface.DEFAULT_BOLD)
        button.isAllCaps = false
        val btnBg = GradientDrawable()
        btnBg.cornerRadius = dp(12).toFloat()
        btnBg.setColor(cGreen)
        button.background = btnBg
        val btnLp = LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, dp(52)
        )
        root.addView(button, btnLp)

        status = TextView(this)
        status.setTextColor(cMuted)
        status.textSize = 13f
        status.setPadding(0, dp(24), 0, 0)
        val scroll = ScrollView(this)
        val scLp = LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f
        )
        scroll.addView(status)
        root.addView(scroll, scLp)

        setContentView(root)

        button.setOnClickListener {
            button.isEnabled = false
            status.text = ""
            Thread {
                runLogin()
                runOnUiThread { button.isEnabled = true }
            }.start()
        }
    }

    private fun setStatus(msg: String) {
        runOnUiThread { status.append(msg + "\n") }
    }

    private fun enc(s: String): String = URLEncoder.encode(s, "UTF-8")

    private fun b64url(data: ByteArray): String =
        Base64.encodeToString(data, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

    private fun runLogin() {
        try {
            val random = SecureRandom()
            val vbytes = ByteArray(32); random.nextBytes(vbytes)
            val verifier = b64url(vbytes)
            val challenge = b64url(
                MessageDigest.getInstance("SHA-256")
                    .digest(verifier.toByteArray(Charsets.US_ASCII))
            )
            val sbytes = ByteArray(24); random.nextBytes(sbytes)
            val state = b64url(sbytes)

            val redirect = "http://127.0.0.1:$port/callback"
            val authUrl = baseUrl + "/api/oauth/authorize?response_type=code" +
                "&client_id=" + enc(clientId) +
                "&redirect_uri=" + enc(redirect) +
                "&scope=" + enc(scope) +
                "&state=" + enc(state) +
                "&code_challenge=" + enc(challenge) +
                "&code_challenge_method=S256"

            val server = ServerSocket(port, 1, InetAddress.getByName("127.0.0.1"))
            server.soTimeout = 300000
            setStatus("Ouverture du navigateur...")
            runOnUiThread {
                try {
                    startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(authUrl)))
                } catch (e: Exception) {
                    setStatus("Impossible d'ouvrir le navigateur: " + e.message)
                }
            }

            var params: Map<String, String> = emptyMap()
            while (true) {
                val socket = server.accept()
                val reader = BufferedReader(InputStreamReader(socket.getInputStream()))
                val line = reader.readLine() ?: ""
                val path = line.split(" ").getOrElse(1) { "" }
                if (!path.startsWith("/callback")) {
                    val out: OutputStream = socket.getOutputStream()
                    out.write("HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n".toByteArray())
                    out.flush(); socket.close(); continue
                }
                val query = if (path.contains("?")) path.substringAfter("?") else ""
                params = parseQuery(query)
                val ok = params["error"] == null && !params["code"].isNullOrEmpty()
                val msg = if (ok) "Connexion reussie. Reviens dans l'application."
                          else "Echec de connexion. Reviens dans l'application."
                val html = "<html><meta charset='utf-8'><body style='font-family:sans-serif'><h2>" +
                    msg + "</h2></body></html>"
                val body = html.toByteArray(Charsets.UTF_8)
                val out: OutputStream = socket.getOutputStream()
                out.write(("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n" +
                    "Connection: close\r\nContent-Length: " + body.size + "\r\n\r\n").toByteArray())
                out.write(body); out.flush(); socket.close()
                break
            }
            server.close()

            if (params["error"] != null) { setStatus("Connexion refusee: " + params["error"]); return }
            if (params["state"] != state) { setStatus("Controle de securite echoue (state)."); return }
            val code = params["code"]
            if (code.isNullOrEmpty()) { setStatus("Aucun code recu."); return }

            setStatus("Echange du code...")
            val form = "grant_type=authorization_code&code=" + enc(code) +
                "&client_id=" + enc(clientId) + "&redirect_uri=" + enc(redirect) +
                "&code_verifier=" + enc(verifier)
            val tokenResp = httpPost(baseUrl + "/api/oauth/token", form)
            if (tokenResp == null) { setStatus("Pas de reponse du serveur de token."); return }

            val tokenJson = JSONObject(tokenResp)
            val token = firstString(tokenJson, "access_token", "nex_token", "token")
            var tokenType = tokenJson.optString("token_type", "Bearer")
            if (tokenType.isEmpty()) tokenType = "Bearer"
            else tokenType = tokenType.substring(0, 1).uppercase() + tokenType.substring(1)
            if (token.isNullOrEmpty()) { setStatus("Token introuvable dans la reponse."); return }

            setStatus("Recuperation du profil...")
            var username = ""
            var friendCode = ""
            var pid: String? = null

            val prof = httpGet(baseUrl + "/api/profile", token, tokenType)
            if (prof != null) {
                val pj = JSONObject(prof)
                username = pj.optString("username", "")
                if (username.isEmpty()) {
                    username = pj.optJSONObject("profile")?.optString("name", "") ?: ""
                }
            }

            val endpoints = listOf(
                "/api/identity", "/api/me", "/api/account",
                "/api/whoami", "/api/self", "/api/user"
            )
            for (ep in endpoints) {
                val r = httpGet(baseUrl + ep, token, tokenType) ?: continue
                val j = JSONObject(r)
                val found = numericId(j)
                if (found != null) {
                    pid = found
                    if (friendCode.isEmpty()) friendCode = firstString(j, "friend_code") ?: ""
                    if (username.isEmpty()) username = firstString(j, "username", "name") ?: ""
                    break
                }
            }

            if (pid == null) { setStatus("pid introuvable sur les endpoints testes."); return }

            pendingContent = "pid=" + pid + "\nusername=" + username +
                "\nfriend_code=" + friendCode + "\ntoken=" + token + "\n"
            setStatus("Connecte: " + username + " (pid " + pid + ").")
            setStatus("Choisis ou enregistrer nextendo_account.txt...")
            runOnUiThread {
                val intent = Intent(Intent.ACTION_CREATE_DOCUMENT)
                intent.addCategory(Intent.CATEGORY_OPENABLE)
                intent.type = "text/plain"
                intent.putExtra(Intent.EXTRA_TITLE, "nextendo_account.txt")
                startActivityForResult(intent, createFile)
            }
        } catch (e: Exception) {
            setStatus("Erreur: " + (e.message ?: e.toString()))
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == createFile && resultCode == Activity.RESULT_OK) {
            val uri = data?.data ?: return
            val c = pendingContent ?: return
            try {
                contentResolver.openOutputStream(uri)?.use { it.write(c.toByteArray(Charsets.UTF_8)) }
                setStatus("Fichier enregistre. Copie-le dans le dossier config de ton emulateur.")
            } catch (e: Exception) {
                setStatus("Echec ecriture: " + e.message)
            }
        }
    }

    private fun parseQuery(q: String): Map<String, String> {
        val m = HashMap<String, String>()
        if (q.isEmpty()) return m
        for (part in q.split("&")) {
            val i = part.indexOf("=")
            if (i > 0) m[part.substring(0, i)] = URLDecoder.decode(part.substring(i + 1), "UTF-8")
        }
        return m
    }

    private fun firstString(o: JSONObject, vararg keys: String): String? {
        for (k in keys) {
            val v = o.optString(k, "")
            if (v.isNotEmpty()) return v
        }
        return null
    }

    private fun numericId(o: JSONObject): String? {
        for (k in listOf("pid", "sub", "id", "user_id", "uid", "account_id")) {
            if (o.has(k)) {
                val v = o.opt(k)
                if (v != null && v.toString().isNotEmpty() && v.toString() != "null") return v.toString()
            }
        }
        for (k in listOf("account", "user", "me", "self")) {
            val sub = o.optJSONObject(k)
            if (sub != null) {
                val r = numericId(sub)
                if (r != null) return r
            }
        }
        return null
    }

    private fun httpPost(urlStr: String, body: String): String? {
        val conn = URL(urlStr).openConnection() as HttpURLConnection
        return try {
            conn.requestMethod = "POST"
            conn.doOutput = true
            conn.connectTimeout = 30000
            conn.readTimeout = 30000
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded")
            conn.setRequestProperty("User-Agent", "orange-login")
            conn.setRequestProperty("X-Nextendo-Client-Id", clientId)
            conn.outputStream.use { it.write(body.toByteArray()) }
            readBody(conn)
        } catch (e: Exception) {
            setStatus("POST erreur: " + e.message)
            null
        } finally {
            conn.disconnect()
        }
    }

    private fun httpGet(urlStr: String, token: String, tokenType: String): String? {
        val conn = URL(urlStr).openConnection() as HttpURLConnection
        return try {
            conn.requestMethod = "GET"
            conn.connectTimeout = 20000
            conn.readTimeout = 20000
            conn.setRequestProperty("Authorization", tokenType + " " + token)
            conn.setRequestProperty("User-Agent", "orange-login")
            conn.setRequestProperty("X-Nextendo-Client-Id", clientId)
            if (conn.responseCode in 200..299) readBody(conn) else null
        } catch (e: Exception) {
            null
        } finally {
            conn.disconnect()
        }
    }

    private fun readBody(conn: HttpURLConnection): String {
        val stream = if (conn.responseCode in 200..299) conn.inputStream else conn.errorStream
        return stream?.bufferedReader()?.use { it.readText() } ?: ""
    }
}

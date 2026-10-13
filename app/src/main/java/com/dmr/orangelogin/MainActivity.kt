package com.dmr.orangelogin

import android.app.Activity
import android.content.Intent
import java.net.InetAddress
import android.net.Uri
import android.os.Bundle
import android.util.Base64
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStream
import java.net.HttpURLConnection
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

    private lateinit var clientIdField: EditText
    private lateinit var status: TextView
    private var pendingContent: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val root = LinearLayout(this)
        root.orientation = LinearLayout.VERTICAL
        val pad = (16 * resources.displayMetrics.density).toInt()
        root.setPadding(pad, pad, pad, pad)

        clientIdField = EditText(this)
        clientIdField.hint = "client_id (nxc_...)"
        clientIdField.setText("nxc_z_fetCuVO1qx")
        root.addView(clientIdField)

        val button = Button(this)
        button.text = "Se connecter a Nextendo"
        root.addView(button)

        status = TextView(this)
        status.setPadding(0, pad, 0, 0)
        val scroll = ScrollView(this)
        scroll.addView(status)
        root.addView(scroll)

        setContentView(root)

        button.setOnClickListener {
            val cid = clientIdField.text.toString().trim()
            if (cid.isEmpty()) {
                setStatus("Entre ton client_id.")
            } else {
                button.isEnabled = false
                Thread {
                    runLogin(cid)
                    runOnUiThread { button.isEnabled = true }
                }.start()
            }
        }
    }

    private fun setStatus(msg: String) {
        runOnUiThread { status.append(msg + "\n") }
    }

    private fun enc(s: String): String = URLEncoder.encode(s, "UTF-8")

    private fun b64url(data: ByteArray): String =
        Base64.encodeToString(data, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

    private fun runLogin(clientId: String) {
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
            val tokenResp = httpPost(baseUrl + "/api/oauth/token", form, clientId)
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

            val prof = httpGet(baseUrl + "/api/profile", token, tokenType, clientId)
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
                val r = httpGet(baseUrl + ep, token, tokenType, clientId) ?: continue
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

    private fun httpPost(urlStr: String, body: String, clientId: String): String? {
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

    private fun httpGet(urlStr: String, token: String, tokenType: String, clientId: String): String? {
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

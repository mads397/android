package com.bitwarden.network.service

import com.bitwarden.network.model.DigitalAssetLinkCheckResponseJson
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import timber.log.Timber
import java.net.URL
import javax.net.ssl.HttpsURLConnection

/**
 * [DigitalAssetLinkService] implementation that fetches and validates
 * `/.well-known/assetlinks.json` directly from the relying party's domain
 * instead of delegating to Google's Digital Asset Links API.
 *
 * This enables passkey operations for apps using private/self-hosted domains
 * that are not reachable from Google's servers.
 */
internal class DirectDigitalAssetLinkServiceImpl : DigitalAssetLinkService {

    private val json = Json { ignoreUnknownKeys = true }

    override suspend fun checkDigitalAssetLinksRelations(
        sourceWebSite: String,
        targetPackageName: String,
        targetCertificateFingerprint: String,
        relations: List<String>,
    ): Result<DigitalAssetLinkCheckResponseJson> = withContext(Dispatchers.IO) {
        try {
            Result.success(
                fetchAndValidate(
                    sourceWebSite,
                    targetPackageName,
                    targetCertificateFingerprint,
                    relations,
                ),
            )
        } catch (e: Exception) {
            Timber.e(e, "DirectDAL: fetch failed: %s", e.message)
            Result.failure(e)
        }
    }

    private fun fetchAndValidate(
        sourceWebSite: String,
        targetPackageName: String,
        targetCertificateFingerprint: String,
        relations: List<String>,
    ): DigitalAssetLinkCheckResponseJson {
        val site = sourceWebSite.trimEnd('/')
        val url = URL("$site/.well-known/assetlinks.json")

        Timber.d(
            "DirectDAL: fetching %s for package=%s fingerprint=%s",
            url,
            targetPackageName,
            targetCertificateFingerprint,
        )

        val connection = url.openConnection() as HttpsURLConnection
        connection.connectTimeout = CONNECT_TIMEOUT_MS
        connection.readTimeout = READ_TIMEOUT_MS
        connection.requestMethod = "GET"

        try {
            val responseCode = connection.responseCode
            Timber.d("DirectDAL: HTTP %d from %s", responseCode, url)

            if (responseCode != HttpsURLConnection.HTTP_OK) {
                return DigitalAssetLinkCheckResponseJson(
                    linked = false,
                    maxAge = null,
                    debugString = "HTTP $responseCode from $url",
                )
            }

            val body = connection.inputStream.bufferedReader().use { it.readText() }
            Timber.d("DirectDAL: response body length=%d", body.length)

            val statements = json.decodeFromString<List<AssetLinkStatement>>(body)
            Timber.d("DirectDAL: parsed %d statements", statements.size)

            for (statement in statements) {
                Timber.d(
                    "DirectDAL: statement namespace=%s pkg=%s fingerprints=%s relations=%s",
                    statement.target.namespace,
                    statement.target.packageName,
                    statement.target.sha256CertFingerprints,
                    statement.relation,
                )
            }

            val linked = statements.any { statement ->
                statement.target.namespace == "android_app" &&
                    statement.target.packageName == targetPackageName &&
                    statement.relation.any { it in relations } &&
                    statement.target.sha256CertFingerprints.any { fingerprint ->
                        fingerprint.equals(
                            targetCertificateFingerprint,
                            ignoreCase = true,
                        )
                    }
            }

            Timber.d("DirectDAL: linked=%b", linked)

            return DigitalAssetLinkCheckResponseJson(
                linked = linked,
                maxAge = null,
                debugString = if (linked) {
                    "Direct validation: matched"
                } else {
                    "Direct validation: no matching statement found for " +
                        "$targetPackageName in ${statements.size} statements"
                },
            )
        } finally {
            connection.disconnect()
        }
    }

    companion object {
        private const val CONNECT_TIMEOUT_MS = 10_000
        private const val READ_TIMEOUT_MS = 10_000
    }
}

@Serializable
private data class AssetLinkStatement(
    @SerialName("relation")
    val relation: List<String>,
    @SerialName("target")
    val target: AssetLinkTarget,
)

@Serializable
private data class AssetLinkTarget(
    @SerialName("namespace")
    val namespace: String,
    @SerialName("package_name")
    val packageName: String? = null,
    @SerialName("sha256_cert_fingerprints")
    val sha256CertFingerprints: List<String> = emptyList(),
)

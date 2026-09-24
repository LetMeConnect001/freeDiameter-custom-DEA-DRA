/*
 * app_dea : Phase 2.5 -- deterministic, reversible pseudonymization of subscriber identifiers
 * (IMSI via Subscription-Id, or User-Name) for use in THIS extension's own log output only.
 *
 * Scope, confirmed with the operator before implementation: the real identifier is NEVER
 * touched on the wire -- the external roaming partner legitimately needs it (to authenticate
 * the subscriber, fetch subscription data, ...), unlike Origin-Host/Route-Record/Session-Id
 * which are either infrastructure metadata the partner does not need, or opaque to them. This
 * is purely about what THIS extension itself writes to logs: compliance (no raw PII in log
 * files) without sacrificing debuggability (same real value -> same token, every time, so an
 * operator can correlate multiple log lines about the same subscriber without ever seeing the
 * real value; an operator holding imsi_pseudonym_key can still recover it offline for a genuine
 * incident investigation, using a separate tool kept outside the running daemon, see
 * extensions/app_dea/tools/dea_imsi_reveal.c).
 *
 * Algorithm: AES-256-SIV (RFC 5297), via GnuTLS's AEAD interface (GNUTLS_CIPHER_AES_256_SIV).
 * SIV was chosen specifically for its determinism: gnutls_aead_cipher_encrypt() with the same
 * key + a fixed nonce + the same plaintext always produces the same ciphertext (verified
 * empirically against GnuTLS 3.8.9 before writing this file). This is what makes the output
 * correlatable across log lines, at the accepted cost of revealing "these two log entries are
 * about the same subscriber" to anyone reading the logs -- a deliberate tradeoff for
 * debuggability, not a mistake. It is authenticated (tampering with a token is detected on
 * decrypt) unlike a bare block cipher; and unlike GCM/CBC it is specifically designed to
 * tolerate a fixed/reused nonce safely (RFC 5297 SS1, "nonce-misuse resistant") -- reusing a
 * nonce with GCM would be a real vulnerability, SIV is the correct primitive for this use case.
 */

#include "app_dea.h"
#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>

/* SIV's determinism only requires the nonce to be constant across calls, not secret or random
 * (see file header comment) -- any fixed value works, this one has no special meaning. */
static const unsigned char dea_siv_nonce[1] = { 0x00 };

static const char dea_hex_digits[] = "0123456789abcdef";

static char * bin_to_hex(const unsigned char * bin, size_t binlen)
{
	char * out;
	size_t i;

	CHECK_MALLOC_DO( out = malloc(binlen * 2 + 1), return NULL );
	for (i = 0; i < binlen; i++) {
		out[i*2]   = dea_hex_digits[(bin[i] >> 4) & 0xf];
		out[i*2+1] = dea_hex_digits[bin[i] & 0xf];
	}
	out[binlen*2] = '\0';
	return out;
}

/* Encrypt in/inlen with AES-256-SIV under dea_conf->imsi_pseudonym_key, hex-encode the result.
 * Never fatal to the caller: on any failure, *out_hex stays NULL and the caller just skips
 * pseudonymized logging for this message. */
static int siv_encrypt_hex(const uint8_t * in, size_t inlen, char ** out_hex)
{
	gnutls_aead_cipher_hd_t h;
	gnutls_datum_t key;
	unsigned tag_size;
	unsigned char ct[512];
	size_t ctlen = sizeof(ct);
	int ret;

	*out_hex = NULL;

	if (inlen + 64 > sizeof(ct)) {
		TRACE_DEBUG(INFO, "app_dea: subscriber identifier too long to pseudonymize (%zu bytes)", inlen);
		return 0;
	}

	key.data = (unsigned char *) dea_conf->imsi_pseudonym_key;
	key.size = sizeof(dea_conf->imsi_pseudonym_key);

	ret = gnutls_aead_cipher_init(&h, GNUTLS_CIPHER_AES_256_SIV, &key);
	if (ret != GNUTLS_E_SUCCESS) {
		TRACE_DEBUG(INFO, "app_dea: gnutls_aead_cipher_init failed: %s", gnutls_strerror(ret));
		return 0;
	}

	tag_size = gnutls_cipher_get_tag_size(GNUTLS_CIPHER_AES_256_SIV);

	ret = gnutls_aead_cipher_encrypt(h, dea_siv_nonce, sizeof(dea_siv_nonce), NULL, 0,
		tag_size, in, inlen, ct, &ctlen);
	gnutls_aead_cipher_deinit(h);

	if (ret != GNUTLS_E_SUCCESS) {
		TRACE_DEBUG(INFO, "app_dea: gnutls_aead_cipher_encrypt failed: %s", gnutls_strerror(ret));
		return 0;
	}

	*out_hex = bin_to_hex(ct, ctlen);
	return 0;
}

/* Search the (possibly repeated) Subscription-Id grouped AVP for one whose
 * Subscription-Id-Type == END_USER_IMSI (1, RFC 4006). Returns 0 with *out and *outlen set if
 * found; 0 with *out == NULL if not found or the dict_dcca AVPs are not resolvable (neither is
 * an error -- the AVP may legitimately be absent from this message or application). */
static int find_imsi_subscription_id(struct msg * msg, uint8_t ** out, size_t * outlen)
{
	struct avp * sub_id;

	*out = NULL;
	*outlen = 0;

	if (!dea_avp_subscription_id || !dea_avp_subscription_id_type || !dea_avp_subscription_id_data)
		return 0; /* dict_dcca not loaded: this AVP cannot be resolved */

	CHECK_FCT( fd_msg_search_avp(msg, dea_avp_subscription_id, &sub_id) );
	while (sub_id) {
		struct avp * type_avp = NULL, * data_avp = NULL, * next_sub_id;
		struct avp_hdr * type_hdr, * data_hdr;

		CHECK_FCT( fd_msg_search_avp(sub_id, dea_avp_subscription_id_type, &type_avp) );
		CHECK_FCT( fd_msg_search_avp(sub_id, dea_avp_subscription_id_data, &data_avp) );

		if (type_avp && data_avp) {
			CHECK_FCT( fd_msg_avp_hdr(type_avp, &type_hdr) );
			CHECK_FCT( fd_msg_avp_hdr(data_avp, &data_hdr) );
			if (type_hdr->avp_value && data_hdr->avp_value
				&& (type_hdr->avp_value->i32 == 1) /* END_USER_IMSI, RFC 4006 */) {
				*out = data_hdr->avp_value->os.data;
				*outlen = data_hdr->avp_value->os.len;
				return 0;
			}
		}

		CHECK_FCT( fd_msg_browse(sub_id, MSG_BRW_NEXT, &next_sub_id, NULL) );
		sub_id = next_sub_id;
	}

	return 0;
}

int dea_pseudonymize_subscriber_id(struct msg * msg, char ** out_hex)
{
	uint8_t * id = NULL;
	size_t idlen = 0;
	int ret;

	*out_hex = NULL;

	if (!dea_conf->pseudonymize_subscriber_id || !dea_conf->imsi_pseudonym_key_set)
		return 0;

	CHECK_FCT( find_imsi_subscription_id(msg, &id, &idlen) );

	if (!id && dea_avp_user_name) {
		struct avp * avp;
		struct avp_hdr * ahdr;

		CHECK_FCT( fd_msg_search_avp(msg, dea_avp_user_name, &avp) );
		if (avp) {
			CHECK_FCT( fd_msg_avp_hdr(avp, &ahdr) );
			if (ahdr->avp_value) {
				id = ahdr->avp_value->os.data;
				idlen = ahdr->avp_value->os.len;
			}
		}
	}

	if (!id || !idlen)
		return 0; /* nothing to pseudonymize in this message */

	ret = siv_encrypt_hex(id, idlen, out_hex);
	if ((ret == 0) && *out_hex)
		dea_stats_inc(DEA_STAT_SUBSCRIBER_PSEUDONYMIZED);
	return ret;
}

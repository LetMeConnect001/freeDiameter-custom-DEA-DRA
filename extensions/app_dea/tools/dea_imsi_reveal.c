/*
 * dea_imsi_reveal : offline companion tool for app_dea's Phase 2.5 subscriber-identifier
 * pseudonymization (see ../dea_pseudonym.c and ../README).
 *
 * app_dea logs a deterministic AES-256-SIV token instead of the real IMSI/User-Name when
 * `pseudonymize_subscriber_id` is enabled. The running daemon never reverses it -- this
 * standalone tool is the ONLY way to recover the real value, and it requires the same secret
 * key the daemon was configured with (`imsi_pseudonym_key` in app_dea.conf). Keep this tool,
 * and the key, restricted to whoever is authorized to handle subscriber PII during an
 * investigation -- do not deploy it alongside the daemon or give it to anyone who only has log
 * access.
 *
 * Build (not part of the CMake extension build on purpose -- this is an offline admin tool):
 *   gcc dea_imsi_reveal.c -o dea_imsi_reveal $(pkg-config --cflags --libs gnutls)
 *
 * Usage:
 *   dea_imsi_reveal <128-hex-char-key> <hex-token-from-the-log>
 */

#include <gnutls/gnutls.h>
#include <gnutls/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hex_decode(const char * hex, unsigned char * out, size_t outcap, size_t * outlen)
{
	size_t hexlen = strlen(hex);
	size_t i;

	if ((hexlen % 2) != 0 || (hexlen / 2) > outcap)
		return -1;

	for (i = 0; i < hexlen / 2; i++) {
		unsigned int byte;
		if (sscanf(hex + i*2, "%2x", &byte) != 1)
			return -1;
		out[i] = (unsigned char) byte;
	}
	*outlen = hexlen / 2;
	return 0;
}

int main(int argc, char ** argv)
{
	unsigned char key_bin[64];
	unsigned char token_bin[512];
	unsigned char plain[512];
	size_t key_len, token_len;
	size_t plain_len = sizeof(plain);
	gnutls_aead_cipher_hd_t h;
	gnutls_datum_t key;
	unsigned char nonce[1] = { 0x00 }; /* must match dea_siv_nonce in dea_pseudonym.c */
	unsigned tag_size;
	int ret;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s <128-hex-char-imsi_pseudonym_key> <hex-token>\n", argv[0]);
		return 1;
	}

	if (strlen(argv[1]) != 128) {
		fprintf(stderr, "Error: key must be exactly 128 hex characters (64 bytes).\n");
		return 1;
	}
	if (hex_decode(argv[1], key_bin, sizeof(key_bin), &key_len) != 0 || key_len != 64) {
		fprintf(stderr, "Error: key is not valid hexadecimal.\n");
		return 1;
	}
	if (hex_decode(argv[2], token_bin, sizeof(token_bin), &token_len) != 0) {
		fprintf(stderr, "Error: token is not valid hexadecimal, or too long.\n");
		return 1;
	}

	gnutls_global_init();

	key.data = key_bin;
	key.size = (unsigned int) key_len;

	ret = gnutls_aead_cipher_init(&h, GNUTLS_CIPHER_AES_256_SIV, &key);
	if (ret != GNUTLS_E_SUCCESS) {
		fprintf(stderr, "Error: gnutls_aead_cipher_init failed: %s\n", gnutls_strerror(ret));
		return 1;
	}

	tag_size = gnutls_cipher_get_tag_size(GNUTLS_CIPHER_AES_256_SIV);

	ret = gnutls_aead_cipher_decrypt(h, nonce, sizeof(nonce), NULL, 0,
		tag_size, token_bin, token_len, plain, &plain_len);
	gnutls_aead_cipher_deinit(h);

	if (ret != GNUTLS_E_SUCCESS) {
		fprintf(stderr, "Error: decryption/authentication failed (wrong key, or corrupted/truncated "
			"token): %s\n", gnutls_strerror(ret));
		return 1;
	}

	fwrite(plain, 1, plain_len, stdout);
	fputc('\n', stdout);

	return 0;
}

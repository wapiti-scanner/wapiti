<?php

namespace WPForms\Helpers;

/**
 * Class for encryption functionality.
 *
 * @since 1.6.1.2
 *
 * @link https://www.php.net/manual/en/intro.sodium.php
 */
class Crypto {

	/**
	 * Get a secret key for encrypt/decrypt.
	 *
	 * @since 1.6.1.2
	 *
	 * @return string
	 */
	public static function get_secret_key() {

		$secret_key = get_option( 'wpforms_crypto_secret_key' );

		// If we already have the secret, send it back.
		if ( false !== $secret_key ) {
			return base64_decode( $secret_key ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
		}

		// We don't have a secret, so let's generate one.
		$secret_key = sodium_crypto_secretbox_keygen();
		add_option( 'wpforms_crypto_secret_key', base64_encode( $secret_key ) ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode

		return $secret_key;
	}

	/**
	 * Encrypt a message.
	 *
	 * @since 1.6.1.2
	 *
	 * @param string $message Message to encrypt.
	 * @param string $key     Encryption key.
	 *
	 * @return string
	 */
	public static function encrypt( $message, $key = '' ) {

		// Create a nonce for this operation. It will be stored and recovered in the message itself.
		$nonce = random_bytes(
			SODIUM_CRYPTO_SECRETBOX_NONCEBYTES
		);

		if ( empty( $key ) ) {
			$key = self::get_secret_key();
		}

		// Encrypt message and combine with nonce.
		$cipher = base64_encode( // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
			$nonce .
			sodium_crypto_secretbox(
				$message,
				$nonce,
				$key
			)
		);

		try {
			sodium_memzero( $message );
			sodium_memzero( $key );
		} catch ( \Exception $e ) {
			return $cipher;
		}

		return $cipher;
	}

	/**
	 * Decrypt a message.
	 *
	 * @since 1.6.1.2
	 *
	 * @param string $encrypted Encrypted message.
	 * @param string $key       Encryption key.
	 *
	 * @return string
	 */
	public static function decrypt( $encrypted, $key = '' ) {

		// Unpack base64 message.
		$decoded = base64_decode( $encrypted ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode

		if ( false === $decoded ) {
			return false;
		}

		if ( mb_strlen( $decoded, '8bit' ) < ( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES + SODIUM_CRYPTO_SECRETBOX_MACBYTES ) ) {
			return false;
		}

		// Pull nonce and ciphertext out of unpacked message.
		$nonce      = mb_substr( $decoded, 0, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES, '8bit' );
		$ciphertext = mb_substr( $decoded, SODIUM_CRYPTO_SECRETBOX_NONCEBYTES, null, '8bit' );

		if ( empty( $key ) ) {
			$key = self::get_secret_key();
		}

		// Decrypt it.
		$message = sodium_crypto_secretbox_open(
			$ciphertext,
			$nonce,
			$key
		);

		// Check for decrpytion failures.
		if ( false === $message ) {
			return false;
		}

		try {
			sodium_memzero( $ciphertext );
			sodium_memzero( $key );
		} catch ( \Exception $e ) {
			return $message;
		}

		return $message;
	}
}

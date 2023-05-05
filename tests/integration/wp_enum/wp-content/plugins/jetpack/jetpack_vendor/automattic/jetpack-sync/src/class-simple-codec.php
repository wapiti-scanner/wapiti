<?php
/**
 * Simple codec for encoding and decoding sync objects.
 *
 * @package automattic/jetpack-sync
 */

namespace Automattic\Jetpack\Sync;

/**
 * An implementation of Automattic\Jetpack\Sync\Codec_Interface that uses base64
 * algorithm to compress objects serialized using json_encode.
 */
class Simple_Codec extends JSON_Deflate_Array_Codec {
	/**
	 * Name of the codec.
	 *
	 * @access public
	 *
	 * @var string
	 */
	const CODEC_NAME = 'simple';

	/**
	 * Retrieve the name of the codec.
	 *
	 * @access public
	 *
	 * @return string Name of the codec.
	 */
	public function name() {
		return self::CODEC_NAME;
	}

	/**
	 * Encode a sync object.
	 *
	 * @access public
	 *
	 * @param mixed $object Sync object to encode.
	 * @return string Encoded sync object.
	 */
	public function encode( $object ) {
		// This is intentionally using base64_encode().
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
		return base64_encode( $this->json_serialize( $object ) );
	}

	/**
	 * Encode a sync object.
	 *
	 * @access public
	 *
	 * @param string $input Encoded sync object to decode.
	 * @return mixed Decoded sync object.
	 */
	public function decode( $input ) {
		// This is intentionally using base64_decode().
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
		return $this->json_unserialize( base64_decode( $input ) );
	}

}

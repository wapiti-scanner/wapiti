<?php
/**
 * Interface for encoding and decoding sync objects.
 *
 * @package automattic/jetpack-sync
 */

namespace Automattic\Jetpack\Sync;

/**
 * Very simple interface for encoding and decoding input.
 * This is used to provide compression and serialization to messages.
 **/
interface Codec_Interface {
	/**
	 * Retrieve the name of the codec.
	 * We send this with the payload so we can select the appropriate decoder at the other end.
	 *
	 * @access public
	 *
	 * @return string Name of the codec.
	 */
	public function name();

	/**
	 * Encode a sync object.
	 *
	 * @access public
	 *
	 * @param mixed $object Sync object to encode.
	 * @return string Encoded sync object.
	 */
	public function encode( $object );

	/**
	 * Encode a sync object.
	 *
	 * @access public
	 *
	 * @param string $input Encoded sync object to decode.
	 * @return mixed Decoded sync object.
	 */
	public function decode( $input );
}

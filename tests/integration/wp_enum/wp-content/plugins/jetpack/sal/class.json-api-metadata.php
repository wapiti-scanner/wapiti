<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * WPCOM_JSON_API_Metadata class - Utility classes that don't necessarily have a home yet.
 *
 * @package automattic/jetpack
 */
/**
 * Base class for WPCOM_JSON_API_Metadata
 */
class WPCOM_JSON_API_Metadata {
	/**
	 * Checks to see if a meta key is in the array of allowed public (and whitelisted) meta data.
	 *
	 * Additionally, if the key begins with 'geo_' or '_wpas_', true will also be returned.
	 *
	 * @param string $key A post metadata key value to check.
	 * @return bool True or false depending on whether the key meets the defined criteria.
	 **/
	public static function is_public( $key ) {
		if ( empty( $key ) ) {
			return false;
		}

		// Default whitelisted meta keys.
		$whitelisted_meta = array( '_thumbnail_id' );

		// whitelist of metadata that can be accessed.
		/** This filter is documented in json-endpoints/class.wpcom-json-api-post-endpoint.php */
		if ( in_array( $key, apply_filters( 'rest_api_allowed_public_metadata', $whitelisted_meta ), true ) ) {
			return true;
		}

		if ( 0 === strpos( $key, 'geo_' ) ) {
			return true;
		}

		if ( 0 === strpos( $key, '_wpas_' ) ) {
			return true;
		}

		return false;
	}

	/**
	 * Checks to see if a meta key should be used internally only.
	 *
	 * @param string $key A post metadata key value to check.
	 * @return bool True or false depending on whether the key meets the defined criteria.
	 **/
	public static function is_internal_only( $key ) {
		// We want to always return the `_jetpack_blogging_prompt_key` key in post responses if it is available.
		if ( $key === '_jetpack_blogging_prompt_key' ) {
			return false;
		}

		if ( 0 === strpos( $key, '_jetpack_' ) ) {
			return true;
		}

		if ( 0 === strpos( $key, '_elasticsearch_' ) ) {
			return true;
		}

		return false;
	}
}

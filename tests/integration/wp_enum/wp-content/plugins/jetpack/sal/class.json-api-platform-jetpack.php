<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * WPORG_Platform class that extends SAL_Platform, returning a Jetpack_Site with a $blog_id and $token
 *
 * @package automattic/jetpack
 */

require_once __DIR__ . '/class.json-api-platform.php';

/**
 * Base class for WPORG_Platform, which extends SAL_Platform
 */
class WPORG_Platform extends SAL_Platform {

	/**
	 * Given a Jetpack blog ID, this function returns a Jetpack_Site instance
	 *
	 * @param int $blog_id A Jetpack blog ID.
	 * @return Jetpack_Site A Jetpack_Site instance including all relevant details needed to define a Jetpack site.
	 **/
	public function get_site( $blog_id ) {
		require_once __DIR__ . '/class.json-api-site-jetpack.php';
		return new Jetpack_Site( $blog_id, $this );
	}
}

// phpcs:disable Universal.Files.SeparateFunctionsFromOO.Mixed -- TODO: Move these functions to some other file.

/**
 * Given a token instance (with blog and user id related information), this function returns a new WPORG_Platform instance
 *
 * @param SAL_Token $token A token instance.
 * @see class.json-api-token.php
 * @return WPORG_Platform A WPORG_Platform instance including all relevant details needed to define a Jetpack site, as well as a token instance.
 **/
function wpcom_get_sal_platform( $token ) {
	return new WPORG_Platform( $token );
}

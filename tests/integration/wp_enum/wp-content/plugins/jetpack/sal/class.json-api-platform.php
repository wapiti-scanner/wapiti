<?php  // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * SAL_Platform class which defines a token to later be associated with a Jetpack site
 *
 * @package automattic/jetpack
 */

require_once __DIR__ . '/class.json-api-token.php';

/**
 * Base class for SAL_Platform
 */
abstract class SAL_Platform {
	/**
	 * A token that will represent a SAL_Token instance, default is empty.
	 *
	 * @var SAL_Token
	 */
	public $token;

	/**
	 * Contructs the SAL_Platform instance
	 *
	 * @param SAL_Token $token The variable which will store the SAL_Token instance.
	 */
	public function __construct( $token ) {
		if ( is_array( $token ) ) {
			$token = SAL_Token::from_rest_token( $token );
		} else {
			$token = SAL_Token::for_anonymous_user();
		}

		$this->token = $token;
	}

	/**
	 * This is the get_site function declaration, initially not implemented.
	 *
	 * @param int $blog_id The sites Jetpack blog ID.
	 * @see class.json-api-platform-jetpack.php for the implementation of this function.
	 */
	abstract public function get_site( $blog_id );
}

if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
	require_once dirname( WP_CONTENT_DIR ) . '/public.api/rest/sal/class.json-api-platform-wpcom.php';
} else {
	require_once __DIR__ . '/class.json-api-platform-jetpack.php';
}

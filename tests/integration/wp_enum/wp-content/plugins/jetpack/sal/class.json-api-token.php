<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * SAL_Token class
 *
 * @package automattic/jetpack
 */

/**
 * Base class for Jetpack_Site, so that we have a real class instead of just passing around an array.
 */
class SAL_Token {

	/**
	 * The Jetpack blog ID for the site.
	 *
	 * @var int
	 */
	public $blog_id;

	/**
	 * The Jetpack user's user ID.
	 *
	 * @var int
	 */
	public $user_id;

	/**
	 * The scope for the token, for example global or auth.
	 *
	 * @var string
	 */
	public $scope;

	/**
	 * The Client ID (or WordPress.com Blog ID of this site.
	 *
	 * @var int
	 */
	public $client_id;

	/**
	 * The user ID on the local site.
	 *
	 * @var int
	 */
	public $external_user_id;

	/**
	 * Used for tokens created by Oauth clients.
	 *
	 * @var string
	 */
	public $external_user_code;

	/**
	 * The type of authorization based on where the Jetpack connection is made - eg 'calypso', 'jetpack', 'client'.
	 *
	 * @var string
	 */
	public $auth_type;

	/**
	 * Contructs the SAL_Token instance.
	 *
	 * @param int    $blog_id The Jetpack blog ID for the site.
	 * @param int    $user_id The Jetpack user's user ID.
	 * @param string $scope The scope for the token, for example global or auth.
	 * @param int    $client_id The Client ID (or WordPress.com Blog ID of this site.
	 * @param int    $external_user_id The user ID on the local site.
	 * @param string $external_user_code Used for tokens created by Oauth clients.
	 * @param string $auth_type The type of authorization based on where the Jetpack connection is made (eg. calypso).
	 */
	public function __construct( $blog_id, $user_id, $scope, $client_id, $external_user_id, $external_user_code, $auth_type ) {
		$this->blog_id            = $blog_id; // if blog_id is set and scope is not global, limit to that blog.
		$this->user_id            = $user_id;
		$this->client_id          = $client_id;
		$this->scope              = $scope;
		$this->external_user_id   = $external_user_id;
		$this->external_user_code = $external_user_code;
		$this->auth_type          = $auth_type;
	}

	/**
	 * Set's the scope variable to 'global'.
	 *
	 * @return string
	 */
	public function is_global() {
		return $scope === 'global'; // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UndefinedVariable
	}

	/**
	 * This function is used to create a SAL_Token instance with only a user id, if a token doesn't already exist.
	 *
	 * @return SAL_Token
	 */
	public static function for_anonymous_user() {
		return new SAL_Token(
			null,
			get_current_user_id(),
			null, // there's only ever one scope in our current API implementation, auth or global.
			null,
			null,
			null,
			null
		);
	}

	/**
	 * If a user token exists, the information is used to construct a SAL_Token with the correct parameters.
	 *
	 * @param array $token An array of details relevant to the connected user (may be empty).
	 *
	 * @return SAL_Token
	 */
	public static function from_rest_token( $token ) {
		$user_id            = isset( $token['user_id'] ) ? $token['user_id'] : get_current_user_id();
		$scope              = isset( $token['scope'] ) ? $token['scope'][0] : null;
		$client_id          = isset( $token['client_id'] ) ? $token['client_id'] : null;
		$external_user_id   = isset( $token['external_user_id'] ) ? $token['external_user_id'] : null;
		$external_user_code = isset( $token['external_user_code'] ) ? $token['external_user_code'] : null;
		$auth               = isset( $token['auth'] ) ? $token['auth'] : null;

		return new SAL_Token(
			$token['blog_id'],
			$user_id,
			$scope, // there's only ever one scope in our current API implementation, auth or global.
			$client_id,
			$external_user_id,
			$external_user_code,
			$auth
		);
	}
}

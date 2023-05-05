<?php
/**
 * The Jetpack Connection Tokens class file.
 *
 * @package automattic/jetpack-connection
 */

namespace Automattic\Jetpack\Connection;

use Automattic\Jetpack\Constants;
use Automattic\Jetpack\Roles;
use DateInterval;
use DateTime;
use Exception;
use Jetpack_Options;
use WP_Error;

/**
 * The Jetpack Connection Tokens class that manages tokens.
 */
class Tokens {

	const MAGIC_NORMAL_TOKEN_KEY = ';normal;';

	/**
	 * Datetime format.
	 */
	const DATE_FORMAT_ATOM = 'Y-m-d\TH:i:sP';

	/**
	 * Deletes all connection tokens and transients from the local Jetpack site.
	 */
	public function delete_all() {
		Jetpack_Options::delete_option(
			array(
				'blog_token',
				'user_token',
				'user_tokens',
			)
		);

		$this->remove_lock();
	}

	/**
	 * Perform the API request to validate the blog and user tokens.
	 *
	 * @param int|null $user_id ID of the user we need to validate token for. Current user's ID by default.
	 *
	 * @return array|false|WP_Error The API response: `array( 'blog_token_is_healthy' => true|false, 'user_token_is_healthy' => true|false )`.
	 */
	public function validate( $user_id = null ) {
		$blog_id = Jetpack_Options::get_option( 'id' );
		if ( ! $blog_id ) {
			return new WP_Error( 'site_not_registered', 'Site not registered.' );
		}
		$url = sprintf(
			'%s/%s/v%s/%s',
			Constants::get_constant( 'JETPACK__WPCOM_JSON_API_BASE' ),
			'wpcom',
			'2',
			'sites/' . $blog_id . '/jetpack-token-health'
		);

		$user_token = $this->get_access_token( $user_id ? $user_id : get_current_user_id() );
		$blog_token = $this->get_access_token();

		// Cannot validate non-existent tokens.
		if ( false === $user_token || false === $blog_token ) {
			return false;
		}

		$method   = 'POST';
		$body     = array(
			'user_token' => $this->get_signed_token( $user_token ),
			'blog_token' => $this->get_signed_token( $blog_token ),
		);
		$response = Client::_wp_remote_request( $url, compact( 'body', 'method' ) );

		if ( is_wp_error( $response ) || ! wp_remote_retrieve_body( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return false;
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		return $body ? $body : false;
	}

	/**
	 * Perform the API request to validate only the blog.
	 *
	 * @return bool|WP_Error Boolean with the test result. WP_Error if test cannot be performed.
	 */
	public function validate_blog_token() {
		$blog_id = Jetpack_Options::get_option( 'id' );
		if ( ! $blog_id ) {
			return new WP_Error( 'site_not_registered', 'Site not registered.' );
		}
		$url = sprintf(
			'%s/%s/v%s/%s',
			Constants::get_constant( 'JETPACK__WPCOM_JSON_API_BASE' ),
			'wpcom',
			'2',
			'sites/' . $blog_id . '/jetpack-token-health/blog'
		);

		$method   = 'GET';
		$response = Client::remote_request( compact( 'url', 'method' ) );

		if ( is_wp_error( $response ) || ! wp_remote_retrieve_body( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return false;
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );

		return is_array( $body ) && isset( $body['is_healthy'] ) && true === $body['is_healthy'];
	}

	/**
	 * Obtains the auth token.
	 *
	 * @param array  $data The request data.
	 * @param string $token_api_url The URL of the Jetpack "token" API.
	 * @return object|WP_Error Returns the auth token on success.
	 *                          Returns a WP_Error on failure.
	 */
	public function get( $data, $token_api_url ) {
		$roles = new Roles();
		$role  = $roles->translate_current_user_to_role();

		if ( ! $role ) {
			return new WP_Error( 'role', __( 'An administrator for this blog must set up the Jetpack connection.', 'jetpack-connection' ) );
		}

		$client_secret = $this->get_access_token();
		if ( ! $client_secret ) {
			return new WP_Error( 'client_secret', __( 'You need to register your Jetpack before connecting it.', 'jetpack-connection' ) );
		}

		/**
		 * Filter the URL of the first time the user gets redirected back to your site for connection
		 * data processing.
		 *
		 * @since 1.7.0
		 * @since-jetpack 8.0.0
		 *
		 * @param string $redirect_url Defaults to the site admin URL.
		 */
		$processing_url = apply_filters( 'jetpack_token_processing_url', admin_url( 'admin.php' ) );

		$redirect = isset( $data['redirect'] ) ? esc_url_raw( (string) $data['redirect'] ) : '';

		/**
		* Filter the URL to redirect the user back to when the authentication process
		* is complete.
		*
		* @since 1.7.0
		* @since-jetpack 8.0.0
		*
		* @param string $redirect_url Defaults to the site URL.
		*/
		$redirect = apply_filters( 'jetpack_token_redirect_url', $redirect );

		$redirect_uri = ( 'calypso' === $data['auth_type'] )
			? $data['redirect_uri']
			: add_query_arg(
				array(
					'handler'  => 'jetpack-connection-webhooks',
					'action'   => 'authorize',
					'_wpnonce' => wp_create_nonce( "jetpack-authorize_{$role}_{$redirect}" ),
					'redirect' => $redirect ? rawurlencode( $redirect ) : false,
				),
				esc_url( $processing_url )
			);

		/**
		 * Filters the token request data.
		 *
		 * @since 1.7.0
		 * @since-jetpack 8.0.0
		 *
		 * @param array $request_data request data.
		 */
		$body = apply_filters(
			'jetpack_token_request_body',
			array(
				'client_id'     => Jetpack_Options::get_option( 'id' ),
				'client_secret' => $client_secret->secret,
				'grant_type'    => 'authorization_code',
				'code'          => $data['code'],
				'redirect_uri'  => $redirect_uri,
			)
		);

		$args = array(
			'method'  => 'POST',
			'body'    => $body,
			'headers' => array(
				'Accept' => 'application/json',
			),
		);
		add_filter( 'http_request_timeout', array( $this, 'return_30' ), PHP_INT_MAX - 1 );
		$response = Client::_wp_remote_request( $token_api_url, $args );
		remove_filter( 'http_request_timeout', array( $this, 'return_30' ), PHP_INT_MAX - 1 );

		if ( is_wp_error( $response ) ) {
			return new WP_Error( 'token_http_request_failed', $response->get_error_message() );
		}

		$code   = wp_remote_retrieve_response_code( $response );
		$entity = wp_remote_retrieve_body( $response );

		if ( $entity ) {
			$json = json_decode( $entity );
		} else {
			$json = false;
		}

		if ( 200 !== $code || ! empty( $json->error ) ) {
			if ( empty( $json->error ) ) {
				return new WP_Error( 'unknown', '', $code );
			}

			/* translators: Error description string. */
			$error_description = isset( $json->error_description ) ? sprintf( __( 'Error Details: %s', 'jetpack-connection' ), (string) $json->error_description ) : '';

			return new WP_Error( (string) $json->error, $error_description, $code );
		}

		if ( empty( $json->access_token ) || ! is_scalar( $json->access_token ) ) {
			return new WP_Error( 'access_token', '', $code );
		}

		if ( empty( $json->token_type ) || 'X_JETPACK' !== strtoupper( $json->token_type ) ) {
			return new WP_Error( 'token_type', '', $code );
		}

		if ( empty( $json->scope ) ) {
			return new WP_Error( 'scope', 'No Scope', $code );
		}

		// TODO: get rid of the error silencer.
		// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
		@list( $role, $hmac ) = explode( ':', $json->scope );
		if ( empty( $role ) || empty( $hmac ) ) {
			return new WP_Error( 'scope', 'Malformed Scope', $code );
		}

		if ( $this->sign_role( $role ) !== $json->scope ) {
			return new WP_Error( 'scope', 'Invalid Scope', $code );
		}

		$cap = $roles->translate_role_to_cap( $role );
		if ( ! $cap ) {
			return new WP_Error( 'scope', 'No Cap', $code );
		}

		if ( ! current_user_can( $cap ) ) {
			return new WP_Error( 'scope', 'current_user_cannot', $code );
		}

		return (string) $json->access_token;
	}

	/**
	 * Enters a user token into the user_tokens option
	 *
	 * @param int    $user_id The user id.
	 * @param string $token The user token.
	 * @param bool   $is_master_user Whether the user is the master user.
	 * @return bool
	 */
	public function update_user_token( $user_id, $token, $is_master_user ) {
		// Not designed for concurrent updates.
		$user_tokens = $this->get_user_tokens();
		if ( ! is_array( $user_tokens ) ) {
			$user_tokens = array();
		}
		$user_tokens[ $user_id ] = $token;
		if ( $is_master_user ) {
			$master_user = $user_id;
			$options     = compact( 'user_tokens', 'master_user' );
		} else {
			$options = compact( 'user_tokens' );
		}
		return Jetpack_Options::update_options( $options );
	}

	/**
	 * Sign a user role with the master access token.
	 * If not specified, will default to the current user.
	 *
	 * @access public
	 *
	 * @param string $role    User role.
	 * @param int    $user_id ID of the user.
	 * @return string Signed user role.
	 */
	public function sign_role( $role, $user_id = null ) {
		if ( empty( $user_id ) ) {
			$user_id = (int) get_current_user_id();
		}

		if ( ! $user_id ) {
			return false;
		}

		$token = $this->get_access_token();
		if ( ! $token || is_wp_error( $token ) ) {
			return false;
		}

		return $role . ':' . hash_hmac( 'md5', "{$role}|{$user_id}", $token->secret );
	}

	/**
	 * Increases the request timeout value to 30 seconds.
	 *
	 * @return int Returns 30.
	 */
	public function return_30() {
		return 30;
	}

	/**
	 * Gets the requested token.
	 *
	 * Tokens are one of two types:
	 * 1. Blog Tokens: These are the "main" tokens. Each site typically has one Blog Token,
	 *    though some sites can have multiple "Special" Blog Tokens (see below). These tokens
	 *    are not associated with a user account. They represent the site's connection with
	 *    the Jetpack servers.
	 * 2. User Tokens: These are "sub-"tokens. Each connected user account has one User Token.
	 *
	 * All tokens look like "{$token_key}.{$private}". $token_key is a public ID for the
	 * token, and $private is a secret that should never be displayed anywhere or sent
	 * over the network; it's used only for signing things.
	 *
	 * Blog Tokens can be "Normal" or "Special".
	 * * Normal: The result of a normal connection flow. They look like
	 *   "{$random_string_1}.{$random_string_2}"
	 *   That is, $token_key and $private are both random strings.
	 *   Sites only have one Normal Blog Token. Normal Tokens are found in either
	 *   Jetpack_Options::get_option( 'blog_token' ) (usual) or the JETPACK_BLOG_TOKEN
	 *   constant (rare).
	 * * Special: A connection token for sites that have gone through an alternative
	 *   connection flow. They look like:
	 *   ";{$special_id}{$special_version};{$wpcom_blog_id};.{$random_string}"
	 *   That is, $private is a random string and $token_key has a special structure with
	 *   lots of semicolons.
	 *   Most sites have zero Special Blog Tokens. Special tokens are only found in the
	 *   JETPACK_BLOG_TOKEN constant.
	 *
	 * In particular, note that Normal Blog Tokens never start with ";" and that
	 * Special Blog Tokens always do.
	 *
	 * When searching for a matching Blog Tokens, Blog Tokens are examined in the following
	 * order:
	 * 1. Defined Special Blog Tokens (via the JETPACK_BLOG_TOKEN constant)
	 * 2. Stored Normal Tokens (via Jetpack_Options::get_option( 'blog_token' ))
	 * 3. Defined Normal Tokens (via the JETPACK_BLOG_TOKEN constant)
	 *
	 * @param int|false    $user_id   false: Return the Blog Token. int: Return that user's User Token.
	 * @param string|false $token_key If provided, check that the token matches the provided input.
	 * @param bool|true    $suppress_errors If true, return a falsy value when the token isn't found; When false, return a descriptive WP_Error when the token isn't found.
	 *
	 * @return object|false|WP_Error
	 */
	public function get_access_token( $user_id = false, $token_key = false, $suppress_errors = true ) {
		if ( $this->is_locked() ) {
			$this->delete_all();
			return false;
		}

		$possible_special_tokens = array();
		$possible_normal_tokens  = array();
		$user_tokens             = $this->get_user_tokens();

		if ( $user_id ) {
			if ( ! $user_tokens ) {
				return $suppress_errors ? false : new WP_Error( 'no_user_tokens', __( 'No user tokens found', 'jetpack-connection' ) );
			}
			if ( true === $user_id ) { // connection owner.
				$user_id = Jetpack_Options::get_option( 'master_user' );
				if ( ! $user_id ) {
					return $suppress_errors ? false : new WP_Error( 'empty_master_user_option', __( 'No primary user defined', 'jetpack-connection' ) );
				}
			}
			if ( ! isset( $user_tokens[ $user_id ] ) || ! $user_tokens[ $user_id ] ) {
				// translators: %s is the user ID.
				return $suppress_errors ? false : new WP_Error( 'no_token_for_user', sprintf( __( 'No token for user %d', 'jetpack-connection' ), $user_id ) );
			}
			$user_token_chunks = explode( '.', $user_tokens[ $user_id ] );
			if ( empty( $user_token_chunks[1] ) || empty( $user_token_chunks[2] ) ) {
				// translators: %s is the user ID.
				return $suppress_errors ? false : new WP_Error( 'token_malformed', sprintf( __( 'Token for user %d is malformed', 'jetpack-connection' ), $user_id ) );
			}
			if ( $user_token_chunks[2] !== (string) $user_id ) {
				// translators: %1$d is the ID of the requested user. %2$d is the user ID found in the token.
				return $suppress_errors ? false : new WP_Error( 'user_id_mismatch', sprintf( __( 'Requesting user_id %1$d does not match token user_id %2$d', 'jetpack-connection' ), $user_id, $user_token_chunks[2] ) );
			}
			$possible_normal_tokens[] = "{$user_token_chunks[0]}.{$user_token_chunks[1]}";
		} else {
			$stored_blog_token = Jetpack_Options::get_option( 'blog_token' );
			if ( $stored_blog_token ) {
				$possible_normal_tokens[] = $stored_blog_token;
			}

			$defined_tokens_string = Constants::get_constant( 'JETPACK_BLOG_TOKEN' );

			if ( $defined_tokens_string ) {
				$defined_tokens = explode( ',', $defined_tokens_string );
				foreach ( $defined_tokens as $defined_token ) {
					if ( ';' === $defined_token[0] ) {
						$possible_special_tokens[] = $defined_token;
					} else {
						$possible_normal_tokens[] = $defined_token;
					}
				}
			}
		}

		if ( self::MAGIC_NORMAL_TOKEN_KEY === $token_key ) {
			$possible_tokens = $possible_normal_tokens;
		} else {
			$possible_tokens = array_merge( $possible_special_tokens, $possible_normal_tokens );
		}

		if ( ! $possible_tokens ) {
			// If no user tokens were found, it would have failed earlier, so this is about blog token.
			return $suppress_errors ? false : new WP_Error( 'no_possible_tokens', __( 'No blog token found', 'jetpack-connection' ) );
		}

		$valid_token = false;

		if ( false === $token_key ) {
			// Use first token.
			$valid_token = $possible_tokens[0];
		} elseif ( self::MAGIC_NORMAL_TOKEN_KEY === $token_key ) {
			// Use first normal token.
			$valid_token = $possible_tokens[0]; // $possible_tokens only contains normal tokens because of earlier check.
		} else {
			// Use the token matching $token_key or false if none.
			// Ensure we check the full key.
			$token_check = rtrim( $token_key, '.' ) . '.';

			foreach ( $possible_tokens as $possible_token ) {
				if ( hash_equals( substr( $possible_token, 0, strlen( $token_check ) ), $token_check ) ) {
					$valid_token = $possible_token;
					break;
				}
			}
		}

		if ( ! $valid_token ) {
			if ( $user_id ) {
				// translators: %d is the user ID.
				return $suppress_errors ? false : new WP_Error( 'no_valid_user_token', sprintf( __( 'Invalid token for user %d', 'jetpack-connection' ), $user_id ) );
			} else {
				return $suppress_errors ? false : new WP_Error( 'no_valid_blog_token', __( 'Invalid blog token', 'jetpack-connection' ) );
			}
		}

		return (object) array(
			'secret'           => $valid_token,
			'external_user_id' => (int) $user_id,
		);
	}

	/**
	 * Updates the blog token to a new value.
	 *
	 * @access public
	 *
	 * @param string $token the new blog token value.
	 * @return Boolean Whether updating the blog token was successful.
	 */
	public function update_blog_token( $token ) {
		return Jetpack_Options::update_option( 'blog_token', $token );
	}

	/**
	 * Unlinks the current user from the linked WordPress.com user.
	 *
	 * @access public
	 * @static
	 *
	 * @todo Refactor to properly load the XMLRPC client independently.
	 *
	 * @param int $user_id The user identifier.
	 *
	 * @return bool Whether the disconnection of the user was successful.
	 */
	public function disconnect_user( $user_id ) {
		$tokens = $this->get_user_tokens();
		if ( ! $tokens ) {
			return false;
		}

		if ( ! isset( $tokens[ $user_id ] ) ) {
			return false;
		}

		unset( $tokens[ $user_id ] );

		$this->update_user_tokens( $tokens );

		return true;
	}

	/**
	 * Returns an array of user_id's that have user tokens for communicating with wpcom.
	 * Able to select by specific capability.
	 *
	 * @deprecated 1.30.0
	 * @see Manager::get_connected_users
	 *
	 * @param string   $capability The capability of the user.
	 * @param int|null $limit How many connected users to get before returning.
	 * @return array Array of WP_User objects if found.
	 */
	public function get_connected_users( $capability = 'any', $limit = null ) {
		_deprecated_function( __METHOD__, '1.30.0' );
		return ( new Manager( 'jetpack' ) )->get_connected_users( $capability, $limit );
	}

	/**
	 * Fetches a signed token.
	 *
	 * @param object $token the token.
	 * @return WP_Error|string a signed token
	 */
	public function get_signed_token( $token ) {
		if ( ! isset( $token->secret ) || empty( $token->secret ) ) {
			return new WP_Error( 'invalid_token' );
		}

		list( $token_key, $token_secret ) = explode( '.', $token->secret );

		$token_key = sprintf(
			'%s:%d:%d',
			$token_key,
			Constants::get_constant( 'JETPACK__API_VERSION' ),
			$token->external_user_id
		);

		$timestamp = time();

		if ( function_exists( 'wp_generate_password' ) ) {
			$nonce = wp_generate_password( 10, false );
		} else {
			$nonce = substr( sha1( wp_rand( 0, 1000000 ) ), 0, 10 );
		}

		$normalized_request_string = join(
			"\n",
			array(
				$token_key,
				$timestamp,
				$nonce,
			)
		) . "\n";

		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
		$signature = base64_encode( hash_hmac( 'sha1', $normalized_request_string, $token_secret, true ) );

		$auth = array(
			'token'     => $token_key,
			'timestamp' => $timestamp,
			'nonce'     => $nonce,
			'signature' => $signature,
		);

		$header_pieces = array();
		foreach ( $auth as $key => $value ) {
			$header_pieces[] = sprintf( '%s="%s"', $key, $value );
		}

		return join( ' ', $header_pieces );
	}

	/**
	 * Gets the list of user tokens
	 *
	 * @since 1.30.0
	 *
	 * @return bool|array An array of user tokens where keys are user IDs and values are the tokens. False if no user token is found.
	 */
	public function get_user_tokens() {
		return Jetpack_Options::get_option( 'user_tokens' );
	}

	/**
	 * Updates the option that stores the user tokens
	 *
	 * @since 1.30.0
	 *
	 * @param array $tokens An array of user tokens where keys are user IDs and values are the tokens.
	 * @return bool Was the option successfully updated?
	 *
	 * @todo add validate the input.
	 */
	public function update_user_tokens( $tokens ) {
		return Jetpack_Options::update_option( 'user_tokens', $tokens );
	}

	/**
	 * Lock the tokens to the current site URL.
	 *
	 * @param int $timespan How long the tokens should be locked, in seconds.
	 *
	 * @return bool
	 */
	public function set_lock( $timespan = HOUR_IN_SECONDS ) {
		try {
			$expires = ( new DateTime() )->add( DateInterval::createFromDateString( (int) $timespan . ' seconds' ) );
		} catch ( Exception $e ) {
			return false;
		}

		if ( false === $expires ) {
			return false;
		}

		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
		return Jetpack_Options::update_option( 'token_lock', $expires->format( static::DATE_FORMAT_ATOM ) . '|||' . base64_encode( Urls::site_url() ) );
	}

	/**
	 * Remove the site lock from tokens.
	 *
	 * @return bool
	 */
	public function remove_lock() {
		Jetpack_Options::delete_option( 'token_lock' );

		return true;
	}

	/**
	 * Check if the domain is locked, remove the lock if needed.
	 * Possible scenarios:
	 * - lock expired, site URL matches the lock URL: remove the lock, return false.
	 * - lock not expired, site URL matches the lock URL: return false.
	 * - site URL does not match the lock URL (expiration date is ignored): return true, do not remove the lock.
	 *
	 * @return bool
	 */
	public function is_locked() {
		$the_lock = Jetpack_Options::get_option( 'token_lock' );
		if ( ! $the_lock ) {
			// Not locked.
			return false;
		}

		$the_lock = explode( '|||', $the_lock, 2 );
		if ( count( $the_lock ) !== 2 ) {
			// Something's wrong with the lock.
			$this->remove_lock();
			return false;
		}

		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode
		$locked_site_url = base64_decode( $the_lock[1] );
		$expires         = $the_lock[0];

		$expiration_date = DateTime::createFromFormat( static::DATE_FORMAT_ATOM, $expires );
		if ( false === $expiration_date || ! $locked_site_url ) {
			// Something's wrong with the lock.
			$this->remove_lock();
			return false;
		}

		if ( Urls::site_url() === $locked_site_url ) {
			if ( new DateTime() > $expiration_date ) {
				// Site lock expired.
				// Site URL matches, removing the lock.
				$this->remove_lock();
			}

			return false;
		}

		// Site URL doesn't match.
		return true;
	}
}

<?php //phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * Jetpack comments base file - where the code shared between WP.com Highlander and Jetpack Highlander is defined
 *
 * @package automattic/jetpack
 */
/**
 * All the code shared between WP.com Highlander and Jetpack Highlander
 */
class Highlander_Comments_Base {

	/**
	 * Constructor
	 */
	public function __construct() {
		$this->setup_globals();
		$this->setup_actions();
		$this->setup_filters();
	}

	/**
	 * Set any global variables or class variables
	 *
	 * @since JetpackComments (1.4)
	 */
	protected function setup_globals() {}

	/**
	 * Setup actions for methods in this class
	 *
	 * @since JetpackComments (1.4)
	 */
	protected function setup_actions() {
		// Before a comment is posted.
		add_action( 'pre_comment_on_post', array( $this, 'allow_logged_out_user_to_comment_as_external' ) );

		// After a comment is posted.
		add_action( 'comment_post', array( $this, 'set_comment_cookies' ) );
	}

	/**
	 * Setup filters for methods in this class
	 *
	 * @since JetpackComments (1.4)
	 */
	protected function setup_filters() {
		add_filter( 'comments_array', array( $this, 'comments_array' ) );
		add_filter( 'preprocess_comment', array( $this, 'allow_logged_in_user_to_comment_as_guest' ), 0 );
	}

	/**
	 * Is this a Highlander POST request?
	 * Optionally restrict to one or more credentials slug (facebook, twitter, ...)
	 *
	 * @param mixed ...$args Comments credentials slugs.
	 * @return false|string false if it's not a Highlander POST request.  The matching credentials slug if it is.
	 */
	public function is_highlander_comment_post( ...$args ) {

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Nonce verification should happen in Jetpack_Comments::pre_comment_on_post(). Internal ref for details: p1645643468937519/1645189749.180299-slack-C02HQGKMFJ8
		if ( empty( $_POST['hc_post_as'] ) ) {
			return false;
		}
		$hc_post_as = wp_unslash( $_POST['hc_post_as'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Sanitized here by comparing against known values.
		// phpcs:enable WordPress.Security.NonceVerification.Missing

		if ( $args ) {
			foreach ( $args as $id_source ) {
				if ( $id_source === $hc_post_as ) {
					return $id_source;
				}
			}
			return false;
		}
		return is_string( $hc_post_as ) && in_array( $hc_post_as, $this->id_sources, true ) ? $hc_post_as : false;
	}

	/**
	 * Signs an array of scalars with the self-hosted blog's Jetpack Token
	 *
	 * If parameter values are not scalars a WP_Error is  returned, otherwise a keyed hash value is returned using the HMAC method.
	 *
	 * @param array  $parameters Comment parameters.
	 * @param string $key Key used for generating the HMAC variant of the message digest.
	 * @return string HMAC
	 */
	public static function sign_remote_comment_parameters( $parameters, $key ) {
		unset(
			$parameters['sig'],       // Don't sign the signature.
			$parameters['replytocom'] // This parameter is unsigned - it changes dynamically as the comment form moves from parent comment to parent comment.
		);

		ksort( $parameters );

		$signing = array();
		foreach ( $parameters as $k => $v ) {
			if ( ! is_scalar( $v ) ) {
				return new WP_Error( 'invalid_input', __( 'Invalid request', 'jetpack' ), array( 'status' => 400 ) );
			}

			$signing[] = "{$k}={$v}";
		}

		return hash_hmac( 'sha1', implode( ':', $signing ), $key );
	}

	/**
	 * Adds comment author email and whether the comment is approved to the comments array
	 *
	 * After commenting as a guest while logged in, the user needs to see both:
	 * ( user_id = blah AND comment_approved = 0 )
	 * and ( comment_author_email = blah AND comment_approved = 0 )
	 * Core only does the first since the user is logged in, so this adds the second to the comments array.
	 *
	 * @param array $comments All comment data.
	 * @return array A modified array of comment data.
	 */
	public function comments_array( $comments ) {
		global $wpdb, $post;

		$commenter = $this->get_current_commenter();

		if ( ! $commenter['user_id'] ) {
			return $comments;
		}

		if ( ! $commenter['comment_author'] ) {
			return $comments;
		}

		$in_moderation_comments = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM `$wpdb->comments` WHERE `comment_post_ID` = %d AND `user_id` = 0 AND `comment_author` = %s AND `comment_author_email` = %s AND `comment_approved` = '0' ORDER BY `comment_date_gmt` /* Highlander_Comments_Base::comments_array() */",
				$post->ID,
				wp_specialchars_decode( $commenter['comment_author'], ENT_QUOTES ),
				$commenter['comment_author_email']
			)
		);

		if ( ! $in_moderation_comments ) {
			return $comments;
		}

		// @todo ZOMG this is a bad idea
		$comments = array_merge( $comments, $in_moderation_comments );
		usort( $comments, array( $this, 'sort_comments_by_comment_date_gmt' ) );

		return $comments;
	}

	/**
	 * Comment sort comparator: comment_date_gmt
	 *
	 * @since JetpackComments (1.4)
	 * @param object $a The first comment to compare dates with.
	 * @param object $b The second comment to compare dates with.
	 * @return int
	 */
	public function sort_comments_by_comment_date_gmt( $a, $b ) {
		if ( $a->comment_date_gmt === $b->comment_date_gmt ) {
			return 0;
		}

		return $a->comment_date_gmt < $b->comment_date_gmt ? -1 : 1;
	}

	/**
	 * Get the current commenter's information from their cookie
	 *
	 * @since JetpackComments (1.4)
	 * @return array Commenters information from cookie
	 */
	protected function get_current_commenter() {
		// Defaults.
		$user_id              = 0;
		$comment_author       = '';
		$comment_author_email = '';
		$comment_author_url   = '';

		if ( isset( $_COOKIE[ 'comment_author_' . COOKIEHASH ] ) ) {
			$comment_author = sanitize_text_field( wp_unslash( $_COOKIE[ 'comment_author_' . COOKIEHASH ] ) );
		}

		if ( isset( $_COOKIE[ 'comment_author_email_' . COOKIEHASH ] ) ) {
			$comment_author_email = sanitize_email( wp_unslash( $_COOKIE[ 'comment_author_email_' . COOKIEHASH ] ) );
		}

		if ( isset( $_COOKIE[ 'comment_author_url_' . COOKIEHASH ] ) ) {
			$comment_author_url = esc_url_raw( wp_unslash( $_COOKIE[ 'comment_author_url_' . COOKIEHASH ] ) );
		}

		if ( is_user_logged_in() ) {
			$user    = wp_get_current_user();
			$user_id = $user->ID;
		}

		return compact( 'comment_author', 'comment_author_email', 'comment_author_url', 'user_id' );
	}

	/**
	 * Allows a logged out user to leave a comment as a facebook or twitter credentialed user.
	 * Overrides WordPress' core comment_registration option to treat these commenters as "registered" (verified) users.
	 *
	 * @since JetpackComments (1.4)
	 */
	public function allow_logged_out_user_to_comment_as_external() {
		if ( ! $this->is_highlander_comment_post( 'facebook', 'twitter' ) ) {
			return;
		}

		add_filter( 'pre_option_comment_registration', '__return_zero' );
		add_filter( 'pre_option_require_name_email', '__return_zero' );
	}

	/**
	 * Allow a logged in user to post as a guest, FB, or twitter credentialed request.
	 * Bypasses WordPress' core overrides that force a logged in user to comment as that user.
	 * Respects comment_registration option.
	 *
	 * @since JetpackComments (1.4)
	 * @param array $comment_data All data for a specific comment.
	 * @return array Modified comment data, or an error if the required fields or a valid email address are not entered.
	 */
	public function allow_logged_in_user_to_comment_as_guest( $comment_data ) {
		// Bail if user registration is allowed.
		if ( get_option( 'comment_registration' ) ) {
			return $comment_data;
		}

		// Bail if user is not logged in or not a post request.
		if ( ! isset( $_SERVER['REQUEST_METHOD'] ) || 'POST' !== strtoupper( $_SERVER['REQUEST_METHOD'] ) || ! is_user_logged_in() ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- simple comparison
			return $comment_data;
		}

		// Bail if this is not a guest or external service credentialed request.
		if ( ! $this->is_highlander_comment_post( 'guest', 'facebook', 'twitter' ) ) {
			return $comment_data;
		}

		$user = wp_get_current_user();

		foreach ( array(
			'comment_author'       => 'display_name',
			'comment_author_email' => 'user_email',
			'comment_author_url'   => 'user_url',
		) as $comment_field => $user_field ) {
			if ( addslashes( $user->$user_field ) !== $comment_data[ $comment_field ] ) {
				return $comment_data; // some other plugin already did something funky.
			}
		}

		// phpcs:disable WordPress.Security.NonceVerification.Missing -- Nonce verification should happen in Jetpack_Comments::pre_comment_on_post()
		// phpcs:disable WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Sanitization too
		if ( get_option( 'require_name_email' ) ) {
			if ( isset( $_POST['email'] ) && 6 > strlen( wp_unslash( $_POST['email'] ) ) || empty( $_POST['author'] ) ) {
				wp_die( esc_html__( 'Error: please fill the required fields (name, email).', 'jetpack' ), 400 );
			} elseif ( ! isset( $_POST['email'] ) || ! is_email( wp_unslash( $_POST['email'] ) ) ) {
				wp_die( esc_html__( 'Error: please enter a valid email address.', 'jetpack' ), 400 );
			}
		}

		$author_change = false;
		foreach ( array(
			'comment_author'       => 'author',
			'comment_author_email' => 'email',
			'comment_author_url'   => 'url',
		) as $comment_field => $post_field ) {
			if ( ( ! isset( $_POST[ $post_field ] ) || $comment_data[ $comment_field ] !== $_POST[ $post_field ] ) && 'url' !== $post_field ) {
				$author_change = true;
			}
			$comment_data[ $comment_field ] = isset( $_POST[ $post_field ] ) ? wp_unslash( $_POST[ $post_field ] ) : null;
		}
		// phpcs:enable WordPress.Security.NonceVerification.Missing, WordPress.Security.ValidatedSanitizedInput.InputNotSanitized

		// Mark as guest comment if name or email were changed.
		if ( $author_change ) {
			$comment_data['user_ID'] = 0;
			$comment_data['user_id'] = $comment_data['user_ID'];
		}

		return $comment_data;
	}

	/**
	 * Set the comment cookies or bail if comment is invalid
	 *
	 * @since JetpackComments (1.4)
	 * @param int $comment_id The comment ID.
	 */
	public function set_comment_cookies( $comment_id ) {
		// Get comment and bail if it's invalid somehow.
		$comment = get_comment( $comment_id );
		if ( empty( $comment ) || is_wp_error( $comment ) ) {
			return;
		}

		$id_source = $this->is_highlander_comment_post();
		if ( empty( $id_source ) ) {
			return;
		}

		// Set comment author cookies.
		// phpcs:ignore WordPress.WP.CapitalPDangit
		if ( ( 'wordpress' !== $id_source ) && is_user_logged_in() ) {
			/** This filter is already documented in core/wp-includes/comment-functions.php */
			$comment_cookie_lifetime = apply_filters( 'comment_cookie_lifetime', 30000000 );
			setcookie( 'comment_author_' . COOKIEHASH, $comment->comment_author, time() + $comment_cookie_lifetime, COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true );
			setcookie( 'comment_author_email_' . COOKIEHASH, $comment->comment_author_email, time() + $comment_cookie_lifetime, COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true );
			setcookie( 'comment_author_url_' . COOKIEHASH, esc_url( $comment->comment_author_url ), time() + $comment_cookie_lifetime, COOKIEPATH, COOKIE_DOMAIN, is_ssl(), true );
		}
	}

	/**
	 * Get an avatar from Photon
	 *
	 * @since JetpackComments (1.4)
	 * @param string $url The avatar URL.
	 * @param int    $size The avatar size.
	 * @return string
	 */
	protected function photon_avatar( $url, $size ) {
		$size = (int) $size;

		return jetpack_photon_url( $url, array( 'resize' => "$size,$size" ) );
	}
}

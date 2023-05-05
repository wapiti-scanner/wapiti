<?php
/**
 * Class Jetpack_Post_By_Email
 *
 * @package automattic/jetpack
 */

use Automattic\Jetpack\Connection\Tokens;
use Automattic\Jetpack\Redirect;

/**
 * Class Jetpack_Post_By_Email
 */
class Jetpack_Post_By_Email {
	/**
	 * Initialize PBE.
	 *
	 * @return Jetpack_Post_By_Email
	 */
	public static function init() {
		static $instance = null;

		if ( ! $instance ) {
			$instance = new Jetpack_Post_By_Email();
		}

		return $instance;
	}

	/**
	 * Singleton
	 */
	private function __construct() {
		add_action( 'init', array( $this, 'action_init' ) );
	}

	/**
	 * Adds hooks for PBE.
	 */
	public function action_init() {
		if ( ! current_user_can( 'edit_posts' ) ) {
			return;
		}

		add_action( 'profile_personal_options', array( $this, 'user_profile' ) );
		add_action( 'admin_print_scripts-profile.php', array( $this, 'profile_scripts' ) );

		add_action( 'wp_ajax_jetpack_post_by_email_enable', array( $this, 'create_post_by_email_address' ) );
		add_action( 'wp_ajax_jetpack_post_by_email_regenerate', array( $this, 'regenerate_post_by_email_address' ) );
		add_action( 'wp_ajax_jetpack_post_by_email_disable', array( $this, 'delete_post_by_email_address' ) );
	}

	/**
	 * Enqueues scripts for user profile page.
	 */
	public function profile_scripts() {
		wp_enqueue_script( 'post-by-email', plugins_url( 'post-by-email.js', __FILE__ ), array( 'jquery' ), JETPACK__VERSION, true );
		wp_localize_script(
			'post-by-email',
			'pbeVars',
			array(
				'rest_nonce' => wp_create_nonce( 'wp_rest' ),
			)
		);
		wp_enqueue_style( 'post-by-email', plugins_url( 'post-by-email.css', __FILE__ ), array(), JETPACK__VERSION );
		// Inline styles. @see wp_maybe_inline_styles()
		if ( is_rtl() ) {
			wp_style_add_data( 'post-by-email', 'path', plugin_dir_path( __FILE__ ) . 'post-by-email-rtl.min.css' );
		} else {
			wp_style_add_data( 'post-by-email', 'path', plugin_dir_path( __FILE__ ) . 'post-by-email.min.css' );
		}
	}

	/**
	 * Check if the user is connected.
	 *
	 * @return bool True if connected. False if not.
	 */
	public function check_user_connection() {
		$user_token = ( new Tokens() )->get_access_token( get_current_user_id() );

		$is_user_connected = $user_token && ! is_wp_error( $user_token );

		// If the user is already connected via Jetpack, then we're good.
		if ( $is_user_connected ) {
			return true;
		}

		return false;
	}

	/**
	 * Adds field to user profile page.
	 */
	public function user_profile() {
		$blog_name = get_bloginfo( 'blogname' );
		if ( empty( $blog_name ) ) {
			$blog_name = home_url( '/' );
		}

		?>
		<div id="post-by-email" class="jetpack-targetable">
			<h3><?php esc_html_e( 'Post by Email', 'jetpack' ); ?></h3>
			<table class="form-table">
				<tr>
					<th scope="row"><?php esc_html_e( 'Email Address', 'jetpack' ); ?><span id="jp-pbe-spinner" class="spinner"></span></th>
					<td>
						<div id="jp-pbe-error" class="jetpack-inline-error"></div>
						<?php

						if ( $this->check_user_connection() ) {
							$email = $this->get_post_by_email_address();

							$enable_button_style = empty( $email ) ? '' : 'display: none;';
							$info_style          = empty( $email ) ? 'display: none;' : '';
							?>

							<input type="button" name="jp-pbe-enable" id="jp-pbe-enable" class="button" value="<?php esc_attr_e( 'Enable Post By Email', 'jetpack' ); ?>" style="<?php echo esc_attr( $enable_button_style ); ?>" />
							<div id="jp-pbe-info" style="<?php echo esc_attr( $info_style ); ?>">
								<p id="jp-pbe-email-wrapper">
									<input type="text" id="jp-pbe-email" value="<?php echo esc_attr( $email ); ?>" readonly="readonly" class="regular-text" />
									<span class="description"><a target="_blank" rel="noopener noreferrer" href="<?php echo esc_url( Redirect::get_url( 'jetpack-support-post-by-email' ) ); ?>"><?php esc_html_e( 'More information', 'jetpack' ); ?></a></span>
								</p>
								<p>
									<input type="button" name="jp-pbe-regenerate" id="jp-pbe-regenerate" class="button" value="<?php esc_attr_e( 'Regenerate Address', 'jetpack' ); ?> " />
									<input type="button" name="jp-pbe-disable" id="jp-pbe-disable" class="button" value="<?php esc_attr_e( 'Disable Post By Email', 'jetpack' ); ?> " />
								</p>
							</div>
							<?php
						} else {
							$jetpack = Jetpack::init();
							?>

							<p class="jetpack-inline-message">
								<?php
								printf(
									/* translators: Placeholder is the site's name from WordPress settings. */
									esc_html( wptexturize( __( 'To use Post By Email, you need to link your %s account to your WordPress.com account.', 'jetpack' ) ) ),
									'<strong>' . esc_html( $blog_name ) . '</strong>'
								);
								?>
								<br />
								<?php echo esc_html( wptexturize( __( "If you don't have a WordPress.com account yet, you can sign up for free in just a few seconds.", 'jetpack' ) ) ); ?>
							</p>
							<p>
								<a href="<?php echo esc_url( $jetpack->build_connect_url( false, get_edit_profile_url( get_current_user_id() ) . '#post-by-email', 'unlinked-user-pbe' ) ); ?>" class="button button-connector" id="wpcom-connect"><?php esc_html_e( 'Link account with WordPress.com', 'jetpack' ); ?></a>
							</p>
							<?php
						}
						?>
					</td>
				</tr>
			</table>
		</div>
		<?php
	}

	/**
	 * XMLRPC Query to WP.com for PBE e-mail address for user.
	 *
	 * @return string|null PBE E-mail Address or null on error.
	 */
	public function get_post_by_email_address() {
		$xml = $this->init_rest_connection();

		$xml->query( 'jetpack.getPostByEmailAddress' );

		if ( $xml->isError() ) {
			return null;
		}

		$response = $xml->getResponse();
		if ( empty( $response ) ) {
			return null;
		}

		return $response;
	}

	/**
	 * Process the REST API request to modify the "Post by Email" settings.
	 *
	 * @param string $action Allowed values: 'create', 'regenerate', 'delete'.
	 *
	 * @return array|false
	 */
	public function process_api_request( $action ) {
		$endpoint      = null;
		$error_message = esc_html__( 'Please try again later.', 'jetpack' );
		$result        = false;

		switch ( $action ) {
			case 'create':
				$endpoint      = 'jetpack.createPostByEmailAddress';
				$error_message = esc_html__( 'Unable to create the Post by Email address. Please try again later.', 'jetpack' );
				break;
			case 'regenerate':
				$endpoint      = 'jetpack.regeneratePostByEmailAddress';
				$error_message = esc_html__( 'Unable to regenerate the Post by Email address. Please try again later.', 'jetpack' );
				break;
			case 'delete':
				$endpoint      = 'jetpack.deletePostByEmailAddress';
				$error_message = esc_html__( 'Unable to delete the Post by Email address. Please try again later.', 'jetpack' );
				break;
		}

		if ( $endpoint ) {
			$result = $this->process_rest_proxy_request( $endpoint, $error_message );
		}

		return $result;
	}

	/**
	 * Calls WPCOM through authenticated request to create, regenerate or delete the Post by Email address.
	 *
	 * @since 4.3.0
	 *
	 * @param string $endpoint Process to call on WPCOM to create, regenerate or delete the Post by Email address.
	 * @param string $error    Error message to return.
	 *
	 * @return array
	 */
	private function process_rest_proxy_request( $endpoint, $error ) {
		if ( ! current_user_can( 'edit_posts' ) ) {
			return array( 'message' => $error );
		}

		$xml = $this->init_rest_connection();

		$xml->query( $endpoint );

		if ( $xml->isError() ) {
			return array( 'message' => $error );
		}

		$response = $xml->getResponse();
		if ( empty( $response ) ) {
			return array( 'message' => $error );
		}

		// Used only in Jetpack_Core_Json_Api_Endpoints::get_remote_value.
		update_option( 'post_by_email_address' . get_current_user_id(), $response );

		return $response;
	}

	/**
	 * Initialize the IXR client
	 *
	 * @return Jetpack_IXR_Client
	 */
	private function init_rest_connection() {
		return new Jetpack_IXR_Client( array( 'user_id' => get_current_user_id() ) );
	}
}

<?php
/**
 * Admin connection notices.
 *
 * @package automattic/jetpack-admin-ui
 */

namespace Automattic\Jetpack\Connection;

use Automattic\Jetpack\Redirect;
use Automattic\Jetpack\Tracking;

/**
 * Admin connection notices.
 */
class Connection_Notice {

	/**
	 * Whether the class has been initialized.
	 *
	 * @var bool
	 */
	private static $is_initialized = false;

	/**
	 * The constructor.
	 */
	public function __construct() {
		if ( ! static::$is_initialized ) {
			add_action( 'current_screen', array( $this, 'initialize_notices' ) );
			static::$is_initialized = true;
		}
	}

	/**
	 * Initialize the notices if needed.
	 *
	 * @param \WP_Screen $screen WP Core's screen object.
	 *
	 * @return void
	 */
	public function initialize_notices( $screen ) {
		if ( ! in_array(
			$screen->id,
			array(
				'jetpack_page_akismet-key-config',
				'admin_page_jetpack_modules',
			),
			true
		) ) {
			add_action( 'admin_notices', array( $this, 'delete_user_update_connection_owner_notice' ) );
		}
	}

	/**
	 * This is an entire admin notice dedicated to messaging and handling of the case where a user is trying to delete
	 * the connection owner.
	 */
	public function delete_user_update_connection_owner_notice() {
		global $current_screen;

		/*
		 * phpcs:disable WordPress.Security.NonceVerification.Recommended
		 *
		 * This function is firing within wp-admin and checks (below) if it is in the midst of a deletion on the users
		 * page. Nonce will be already checked by WordPress, so we do not need to check ourselves.
		 */

		if ( ! isset( $current_screen->base ) || 'users' !== $current_screen->base ) {
			return;
		}

		if ( ! isset( $_REQUEST['action'] ) || 'delete' !== $_REQUEST['action'] ) {
			return;
		}

		// Get connection owner or bail.
		$connection_manager  = new Manager();
		$connection_owner_id = $connection_manager->get_connection_owner_id();
		if ( ! $connection_owner_id ) {
			return;
		}
		$connection_owner_userdata = get_userdata( $connection_owner_id );

		// Bail if we're not trying to delete connection owner.
		$user_ids_to_delete = array();
		if ( isset( $_REQUEST['users'] ) ) {
			$user_ids_to_delete = array_map( 'sanitize_text_field', wp_unslash( $_REQUEST['users'] ) );
		} elseif ( isset( $_REQUEST['user'] ) ) {
			$user_ids_to_delete[] = sanitize_text_field( wp_unslash( $_REQUEST['user'] ) );
		}

		// phpcs:enable
		$user_ids_to_delete        = array_map( 'absint', $user_ids_to_delete );
		$deleting_connection_owner = in_array( $connection_owner_id, (array) $user_ids_to_delete, true );
		if ( ! $deleting_connection_owner ) {
			return;
		}

		// Bail if they're trying to delete themselves to avoid confusion.
		if ( get_current_user_id() === $connection_owner_id ) {
			return;
		}

		$tracking = new Tracking();

		// Track it!
		if ( method_exists( $tracking, 'record_user_event' ) ) {
			$tracking->record_user_event( 'delete_connection_owner_notice_view' );
		}

		$connected_admins = $connection_manager->get_connected_users( 'jetpack_disconnect' );
		$user             = is_a( $connection_owner_userdata, 'WP_User' ) ? esc_html( $connection_owner_userdata->data->user_login ) : '';

		echo "<div class='notice notice-warning' id='jetpack-notice-switch-connection-owner'>";
		echo '<h2>' . esc_html__( 'Important notice about your Jetpack connection:', 'jetpack-connection' ) . '</h2>';
		echo '<p>' . sprintf(
			/* translators: WordPress User, if available. */
			esc_html__( 'Warning! You are about to delete the Jetpack connection owner (%s) for this site, which may cause some of your Jetpack features to stop working.', 'jetpack-connection' ),
			esc_html( $user )
		) . '</p>';

		if ( ! empty( $connected_admins ) && count( $connected_admins ) > 1 ) {
			echo '<form id="jp-switch-connection-owner" action="" method="post">';
			echo "<label for='owner'>" . esc_html__( 'You can choose to transfer connection ownership to one of these already-connected admins:', 'jetpack-connection' ) . ' </label>';

			$connected_admin_ids = array_map(
				function ( $connected_admin ) {
					return $connected_admin->ID;
				},
				$connected_admins
			);

			wp_dropdown_users(
				array(
					'name'    => 'owner',
					'include' => array_diff( $connected_admin_ids, array( $connection_owner_id ) ),
					'show'    => 'display_name_with_login',
				)
			);

			echo '<p>';
			submit_button( esc_html__( 'Set new connection owner', 'jetpack-connection' ), 'primary', 'jp-switch-connection-owner-submit', false );
			echo '</p>';

			echo "<div id='jp-switch-user-results'></div>";
			echo '</form>';
			?>
			<script type="text/javascript">
				( function() {
					const switchOwnerButton = document.getElementById('jp-switch-connection-owner');
					if ( ! switchOwnerButton ) {
						return;
					}

					switchOwnerButton.addEventListener( 'submit', function ( e ) {
						e.preventDefault();

						const submitBtn = document.getElementById('jp-switch-connection-owner-submit');
						submitBtn.disabled = true;

						const results = document.getElementById('jp-switch-user-results');
						results.innerHTML = '';
						results.classList.remove( 'error-message' );

						const handleAPIError = ( message ) => {
							submitBtn.disabled = false;

							results.classList.add( 'error-message' );
							results.innerHTML = message || "<?php esc_html_e( 'Something went wrong. Please try again.', 'jetpack-connection' ); ?>";
						}

						fetch(
							<?php echo wp_json_encode( esc_url_raw( get_rest_url() . 'jetpack/v4/connection/owner' ), JSON_HEX_TAG | JSON_HEX_AMP ); ?>,
							{
								method: 'POST',
								headers: {
									'X-WP-Nonce': <?php echo wp_json_encode( wp_create_nonce( 'wp_rest' ), JSON_HEX_TAG | JSON_HEX_AMP ); ?>,
								},
								body: new URLSearchParams( new FormData( this ) ),
							}
						)
							.then( response => response.json() )
							.then( data => {
								if ( data.hasOwnProperty( 'code' ) && data.code === 'success' ) {
									// Owner successfully changed.
									results.innerHTML = <?php echo wp_json_encode( esc_html__( 'Success!', 'jetpack-connection' ), JSON_HEX_TAG | JSON_HEX_AMP ); ?>;
									setTimeout(function () {
										document.getElementById( 'jetpack-notice-switch-connection-owner' ).style.display = 'none';
									}, 1000);

									return;
								}

								handleAPIError( data?.message );
							} )
							.catch( () => handleAPIError() );
					});
				} )();
			</script>
			<?php
		} else {
			echo '<p>' . esc_html__( 'Every Jetpack site needs at least one connected admin for the features to work properly. Please connect to your WordPress.com account via the button below. Once you connect, you may refresh this page to see an option to change the connection owner.', 'jetpack-connection' ) . '</p>';
			$connect_url = $connection_manager->get_authorization_url();
			$connect_url = add_query_arg( 'from', 'delete_connection_owner_notice', $connect_url );
			echo "<a href='" . esc_url( $connect_url ) . "' target='_blank' rel='noopener noreferrer' class='button-primary'>" . esc_html__( 'Connect to WordPress.com', 'jetpack-connection' ) . '</a>';
		}

		echo '<p>';
		printf(
			wp_kses(
			/* translators: URL to Jetpack support doc regarding the primary user. */
				__( "<a href='%s' target='_blank' rel='noopener noreferrer'>Learn more</a> about the connection owner and what will break if you do not have one.", 'jetpack-connection' ),
				array(
					'a' => array(
						'href'   => true,
						'target' => true,
						'rel'    => true,
					),
				)
			),
			esc_url( Redirect::get_url( 'jetpack-support-primary-user' ) )
		);
		echo '</p>';
		echo '<p>';
		printf(
			wp_kses(
			/* translators: URL to contact Jetpack support. */
				__( 'As always, feel free to <a href="%s" target="_blank" rel="noopener noreferrer">contact our support team</a> if you have any questions.', 'jetpack-connection' ),
				array(
					'a' => array(
						'href'   => true,
						'target' => true,
						'rel'    => true,
					),
				)
			),
			esc_url( Redirect::get_url( 'jetpack-contact-support' ) )
		);
		echo '</p>';
		echo '</div>';
	}

}

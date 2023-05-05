<?php
/**
 * WordAds Admin.
 *
 * @package automattic/jetpack
 */

/**
 * The standard set of admin pages for the user if Jetpack is installed
 */
class WordAds_Admin {

	/**
	 * WordAds_Admin Constructor.
	 *
	 * @since 4.5.0
	 */
	public function __construct() {
		if ( current_user_can( 'manage_options' ) && isset( $_GET['ads_debug'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			WordAds_API::update_wordads_status_from_api();
			add_action( 'admin_notices', array( $this, 'debug_output' ) );
		}
	}

	/**
	 * Output the API connection debug
	 *
	 * @since 4.5.0
	 */
	public function debug_output() {
		global $wordads, $wordads_status_response;
		$response = $wordads_status_response;
		if ( empty( $response ) ) {
			$response = 'No response from API :(';
		} else {
			$response = print_r( $response, 1 ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_print_r
		}

		$status = $wordads->option( 'wordads_approved' ) ?
			array(
				'color'    => 'green',
				'approved' => 'Yes',
			) :
			array(
				'color'    => 'red',
				'approved' => 'No',
			);

		$type = $wordads->option( 'wordads_approved' ) ? 'updated' : 'error';
		?>
		<div class="notice <?php echo esc_attr( $type ); ?> is-dismissible">
			<p>Status: <span style="color:<?php echo esc_attr( $status['color'] ); ?>;"><?php echo esc_html( $status ); ?></p>
			<pre><?php echo esc_html( $response ); ?></pre>
		</div>
		<?php
	}
}

global $wordads_admin;
$wordads_admin = new WordAds_Admin();

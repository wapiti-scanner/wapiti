<?php

namespace WPForms\Integrations\LiteConnect;

use WPForms\Admin\Notice;
use WPForms\Helpers\Transient;
use WPForms\Tasks\Tasks;

/**
 * Class Integration.
 *
 * Base integration between Lite Connect API and WPForms.
 *
 * @since 1.7.4
 */
class Integration extends API {

	/**
	 * Authentication data.
	 *
	 * @since 1.7.4
	 *
	 * @var array
	 */
	protected $auth = [];

	/**
	 * Option name to store the total count of Lite Connect entries.
	 *
	 * @since 1.7.4
	 *
	 * @var string
	 */
	const LITE_CONNECT_ENTRIES_COUNT_OPTION = 'wpforms_lite_connect_entries_count';

	/**
	 * Post meta name to store the total count of Lite Connect form entries.
	 *
	 * @since 1.7.9
	 *
	 * @var string
	 */
	const LITE_CONNECT_FORM_ENTRIES_COUNT_META = 'wpforms_lite_connect_form_entries_count';

	/**
	 * Integration constructor.
	 *
	 * @since 1.7.4
	 */
	public function __construct() {

		static $updated;

		parent::__construct();

		$this->hooks();

		// Update the site key and access token.
		if (
			! $updated &&
			( is_admin() && ! wp_doing_ajax() ) &&
			( ( wpforms()->is_pro() && self::get_enabled_since() ) || LiteConnect::is_enabled() )
		) {
			$this->maybe_update_access_token();
			$this->update_keys();
			$updated = true;
		}
	}

	/**
	 * Hooks.
	 *
	 * @since 1.7.5
	 */
	private function hooks() {

		add_action( 'admin_init', [ $this, 'max_attempts_notice' ], 10 );
	}

	/**
	 * Update the site key and access token if they do not exist.
	 *
	 * @since 1.7.4
	 */
	public function update_keys() {

		if ( isset( $this->auth['site_key'], $this->auth['access_token'] ) ) {
			return;
		}

		$site_key = $this->get_site_key();

		$this->auth = [
			'site_key'     => $site_key,
			'access_token' => $this->get_access_token( $site_key ),
		];
	}

	/**
	 * Get the site key.
	 *
	 * @since 1.7.4
	 *
	 * @return string|false|array The site key, or false on error.
	 */
	protected function get_site_key() {

		// At first, try to get the site key from the wp-config.php file.
		$debug_site_key = $this->get_debug_setting( 'key' );

		if ( $debug_site_key !== false ) {
			return $debug_site_key;
		}

		// If site key already exists, then we won't need to regenerate it.
		$curr_key = wpforms_setting( 'site', false, self::get_option_name() );

		if ( ! empty( $curr_key['key'] ) ) {
			return $curr_key['key'];
		}

		// Generate the site key.
		return $this->generate_site_key();
	}

	/**
	 * Get the access token.
	 *
	 * @since 1.7.4
	 *
	 * @param string|array $site_key The site key.
	 * @param bool         $force    True to force generate a new access token.
	 *
	 * @return string|false|void The access token, or false on error.
	 */
	protected function get_access_token( $site_key, $force = false ) {

		if ( ! $site_key ) {
			return false;
		}

		$curr_token = wpforms_setting( 'access_token', false, self::get_option_name() );

		// It won't regenerate the access token if $force is false, and the current token is not expired.
		if ( $force === false && isset( $curr_token['expires_at'] ) && (int) $curr_token['expires_at'] - time() > 0 ) {
			return $curr_token['access_token'];
		}

		// Generate the access token.
		$response = $this->generate_access_token( $site_key );

		if ( $response ) {
			$response = json_decode( $response, true );

			if ( isset( $response['access_token'] ) ) {
				$settings                 = get_option( self::get_option_name(), [] );
				$settings['access_token'] = $response;

				update_option( self::get_option_name(), $settings );

				// Create task to refresh access token in 6 days.
				$this->refresh_access_token_task();

				return $response['access_token'];
			}

			wpforms_log(
				'Lite Connect: unable to generate access token',
				[
					'response' => $response,
					'request'  => [
						'domain'     => $this->domain,
						'site_id'    => $this->site_id,
						'wp_version' => get_bloginfo( 'version' ),
					],
				],
				[ 'type' => [ 'error' ] ]
			);
		}

		return false;
	}

	/**
	 * Create a task to refresh the access token.
	 *
	 * @since 1.7.4
	 */
	private function refresh_access_token_task() {

		$tasks = wpforms()->get( 'tasks' );

		if ( $tasks instanceof Tasks && ! $tasks->is_scheduled( RefreshAccessTokenTask::LITE_CONNECT_TASK ) ) {
			( new RefreshAccessTokenTask() )->create();
		}
	}

	/**
	 * Get the name for the Lite Connect's option.
	 *
	 * @since 1.7.4
	 *
	 * @return string
	 */
	public static function get_option_name() {

		if ( defined( 'WPFORMS_LITE_CONNECT_STAGING' ) && WPFORMS_LITE_CONNECT_STAGING ) {
			return API::STAGING_LITE_CONNECT_OPTION;
		}

		return API::LITE_CONNECT_OPTION;
	}

	/**
	 * Get the Lite Connect entries count.
	 *
	 * @since 1.7.4
	 *
	 * @return int The entries count.
	 */
	public static function get_entries_count() {

		return (int) get_option( self::LITE_CONNECT_ENTRIES_COUNT_OPTION, 0 );
	}

	/**
	 * Get the Lite Connect form entries count.
	 *
	 * @since 1.7.9
	 *
	 * @param int $form_id The form ID.
	 *
	 * @return int The form entries count.
	 */
	public static function get_form_entries_count( $form_id ) {

		return (int) get_post_meta( $form_id, self::LITE_CONNECT_FORM_ENTRIES_COUNT_META, true );
	}

	/**
	 * Get the Lite Connect new entries count (since previous import).
	 *
	 * @since 1.7.4
	 *
	 * @return int The new entries count.
	 */
	public static function get_new_entries_count() {

		// Get current total entries count.
		$count = self::get_entries_count();

		// Reduces the entries that were already imported previously from the count.
		$import     = wpforms_setting( 'import', false, self::get_option_name() );
		$prev_count = 0;

		if ( isset( $import['previous_import_count'] ) ) {
			$prev_count = (int) $import['previous_import_count'];
		}

		if ( isset( $import['previous_failed_count'] ) ) {
			$prev_count += (int) $import['previous_failed_count'];
		}

		return $count < $prev_count ? 0 : $count - $prev_count;
	}

	/**
	 * Maybe restart the import flag (for when the user re-upgrades to pro).
	 *
	 * @since 1.7.4
	 */
	public static function maybe_restart_import_flag() {

		$settings = get_option( self::get_option_name(), [] );

		if ( empty( $settings ) ) {
			return;
		}

		$status = isset( $settings['import']['status'] ) ? $settings['import']['status'] : false;

		if ( $status === 'done' ) {
			$previous_imported_entries                   = Transient::get( 'lite_connect_imported_entries' );
			$settings['import']['previous_import_count'] = is_array( $previous_imported_entries ) ? count( $previous_imported_entries ) : 0;

			$previous_failed_entries                     = Transient::get( 'lite_connect_failed_entries' );
			$settings['import']['previous_failed_count'] = is_array( $previous_failed_entries ) ? count( $previous_failed_entries ) : 0;
		}

		self::maybe_set_entries_count();

		// Reset import status to be able to restart import process.
		unset(
			$settings['import']['status'],
			$settings['import']['user_notified']
		);

		update_option( self::get_option_name(), $settings );

		if ( Transient::get( 'lite_connect_error' ) !== false ) {
			Transient::delete( 'lite_connect_error' );
		}
	}

	/**
	 * Get the Lite Connect enabled since timestamp.
	 *
	 * @since 1.7.4
	 *
	 * @return bool|int
	 */
	public static function get_enabled_since() {

		return wpforms_setting( LiteConnect::SETTINGS_SLUG . '-since' );
	}

	/**
	 * Get the Email of the user who enabled Lite Connect.
	 *
	 * @since 1.7.4
	 *
	 * @return bool|string
	 */
	public static function get_enabled_email() {

		return wpforms_setting( LiteConnect::SETTINGS_SLUG . '-email' );
	}

	/**
	 * Normalize Lite Connect entries counter when their value is wrong.
	 *
	 * @since 1.7.4
	 */
	public static function maybe_set_entries_count() {

		$settings = get_option( self::get_option_name(), [] );

		if ( empty( $settings ) ) {
			return;
		}

		$previous_import_count  = isset( $settings['import']['previous_import_count'] ) ? (int) $settings['import']['previous_import_count'] : 0;
		$previous_failed_count  = isset( $settings['import']['previous_failed_count'] ) ? (int) $settings['import']['previous_failed_count'] : 0;
		$previous_import_count += $previous_failed_count;

		// When the entries counter was manually deleted from options OR it was modified by another process,
		// we are setting the counter to the value of the previous imported entries.
		// In this way, the next form submission will increase counter properly, and user will see value of the backed up entries.
		// Obviously, this solution is not perfect, but we don't have another source of the total entries count.
		if ( $previous_import_count > self::get_entries_count() ) {
			update_option( self::LITE_CONNECT_ENTRIES_COUNT_OPTION, $previous_import_count );
		}
	}

	/**
	 * Show the Lite Connect notice about the max attempts to generate the API key.
	 *
	 * @since 1.7.5
	 */
	public function max_attempts_notice() {

		$attempts_count = get_option( self::GENERATE_KEY_ATTEMPT_COUNTER_OPTION, 0 );

		$notice_text = sprintf(
			wp_kses( /* translators: %s - WPForms documentation link. */
				__( 'Your form entries can’t be backed up because WPForms can’t connect to the backup server. If you’d like to back up your entries, find out how to <a href="%s" target="_blank" rel="noopener noreferrer">fix entry backup issues</a>.', 'wpforms-lite' ),
				[
					'a' => [
						'href'   => [],
						'target' => [],
						'rel'    => [],
					],
				]
			),
			wpforms_utm_link( 'https://wpforms.com/docs/how-to-use-lite-connect-for-wpforms/#backup-issues', 'Admin Notice' )
		);

		if ( $attempts_count >= self::MAX_GENERATE_KEY_ATTEMPTS ) {
			Notice::warning(
				$notice_text,
				[
					'dismiss' => Notice::DISMISS_GLOBAL,
					'slug'    => 'max_attempts',
				]
			);
		}
	}

	/**
	 * Maybe update access token.
	 *
	 * @since 1.7.6
	 */
	public function maybe_update_access_token() {

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$action = isset( $_GET['wpforms_lite_connect_action'] ) ? sanitize_key( $_GET['wpforms_lite_connect_action'] ) : '';

		if ( $action !== 'update-access-token' || ! current_user_can( 'manage_options' ) ) {
			return;
		}

		$this->get_access_token( $this->get_site_key(), true );
	}
}

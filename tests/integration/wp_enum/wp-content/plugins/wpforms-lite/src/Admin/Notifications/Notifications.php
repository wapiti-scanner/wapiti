<?php

namespace WPForms\Admin\Notifications;

/**
 * Notifications.
 *
 * @since 1.7.5
 */
class Notifications {

	/**
	 * Source of notifications content.
	 *
	 * @since 1.7.5
	 *
	 * @var string
	 */
	const SOURCE_URL = 'https://plugin.wpforms.com/wp-content/notifications.json';

	/**
	 * Array of license types, that are considered being Elite level.
	 *
	 * @since 1.7.5
	 *
	 * @var array
	 */
	const LICENSES_ELITE = [ 'agency', 'ultimate', 'elite' ];

	/**
	 * Option value.
	 *
	 * @since 1.7.5
	 *
	 * @var bool|array
	 */
	public $option = false;

	/**
	 * Current license type.
	 *
	 * @since 1.7.5
	 *
	 * @var string
	 */
	private $license_type;

	/**
	 * Initialize class.
	 *
	 * @since 1.7.5
	 */
	public function init() {

		$this->hooks();
	}

	/**
	 * Register hooks.
	 *
	 * @since 1.7.5
	 */
	public function hooks() {

		add_action( 'wpforms_overview_enqueue', [ $this, 'enqueues' ] );

		add_action( 'wpforms_admin_overview_before_table', [ $this, 'output' ] );

		add_action( 'wpforms_admin_notifications_update', [ $this, 'update' ] );

		add_action( 'deactivate_plugin', [ $this, 'delete' ], 10, 2 );

		add_action( 'wp_ajax_wpforms_notification_dismiss', [ $this, 'dismiss' ] );
	}

	/**
	 * Check if user has access and is enabled.
	 *
	 * @since 1.7.5
	 *
	 * @return bool
	 */
	public function has_access() {

		$access = wpforms_current_user_can( 'view_forms' ) && ! wpforms_setting( 'hide-announcements' );

		/**
		 * Allow modifying state if a user has access.
		 *
		 * @since 1.6.0
		 *
		 * @param bool $access True if user has access.
		 */
		return (bool) apply_filters( 'wpforms_admin_notifications_has_access', $access );
	}

	/**
	 * Get option value.
	 *
	 * @since 1.7.5
	 *
	 * @param bool $cache Reference property cache if available.
	 *
	 * @return array
	 */
	public function get_option( $cache = true ) {

		if ( $this->option && $cache ) {
			return $this->option;
		}

		$option = (array) get_option( 'wpforms_notifications', [] );

		$this->option = [
			'update'    => ! empty( $option['update'] ) ? (int) $option['update'] : 0,
			'feed'      => ! empty( $option['feed'] ) ? (array) $option['feed'] : [],
			'events'    => ! empty( $option['events'] ) ? (array) $option['events'] : [],
			'dismissed' => ! empty( $option['dismissed'] ) ? (array) $option['dismissed'] : [],
		];

		return $this->option;
	}

	/**
	 * Fetch notifications from feed.
	 *
	 * @since 1.7.5
	 *
	 * @return array
	 */
	public function fetch_feed() {

		$response = wp_remote_get(
			self::SOURCE_URL,
			[
				'timeout'    => 10,
				'user-agent' => wpforms_get_default_user_agent(),
			]
		);

		if ( is_wp_error( $response ) ) {
			return [];
		}

		$body = wp_remote_retrieve_body( $response );

		if ( empty( $body ) ) {
			return [];
		}

		return $this->verify( json_decode( $body, true ) );
	}

	/**
	 * Verify notification data before it is saved.
	 *
	 * @since 1.7.5
	 *
	 * @param array $notifications Array of notifications items to verify.
	 *
	 * @return array
	 */
	public function verify( $notifications ) {

		$data = [];

		if ( ! is_array( $notifications ) || empty( $notifications ) ) {
			return $data;
		}

		foreach ( $notifications as $notification ) {

			// Ignore if one of the conditional checks is true:
			//
			// 1. notification message is empty.
			// 2. license type does not match.
			// 3. notification is expired.
			// 4. notification has already been dismissed.
			// 5. notification existed before installing WPForms.
			// (Prevents bombarding the user with notifications after activation).
			if (
				empty( $notification['content'] ) ||
				! $this->is_license_type_match( $notification ) ||
				$this->is_expired( $notification ) ||
				$this->is_dismissed( $notification ) ||
				$this->is_existed( $notification )
			) {
				continue;
			}

			$data[] = $notification;
		}

		return $data;
	}

	/**
	 * Verify saved notification data for active notifications.
	 *
	 * @since 1.7.5
	 *
	 * @param array $notifications Array of notifications items to verify.
	 *
	 * @return array
	 */
	public function verify_active( $notifications ) {

		if ( ! is_array( $notifications ) || empty( $notifications ) ) {
			return [];
		}

		$current_timestamp = time();

		// Remove notifications that are not active.
		foreach ( $notifications as $key => $notification ) {
			if (
				( ! empty( $notification['start'] ) && $current_timestamp < strtotime( $notification['start'] ) ) ||
				( ! empty( $notification['end'] ) && $current_timestamp > strtotime( $notification['end'] ) )
			) {
				unset( $notifications[ $key ] );
			}
		}

		return $notifications;
	}

	/**
	 * Get notification data.
	 *
	 * @since 1.7.5
	 *
	 * @return array
	 */
	public function get() {

		if ( ! $this->has_access() ) {
			return [];
		}

		$option = $this->get_option();

		// Update notifications using async task.
		if ( empty( $option['update'] ) || time() > $option['update'] + DAY_IN_SECONDS ) {

			$tasks = wpforms()->get( 'tasks' );

			if ( ! $tasks->is_scheduled( 'wpforms_admin_notifications_update' ) !== false ) {
				$tasks
					->create( 'wpforms_admin_notifications_update' )
					->async()
					->params()
					->register();
			}
		}

		$feed   = ! empty( $option['feed'] ) ? $this->verify_active( $option['feed'] ) : [];
		$events = ! empty( $option['events'] ) ? $this->verify_active( $option['events'] ) : [];

		return array_merge( $feed, $events );
	}

	/**
	 * Get notification count.
	 *
	 * @since 1.7.5
	 *
	 * @return int
	 */
	public function get_count() {

		return count( $this->get() );
	}

	/**
	 * Add a new Event Driven notification.
	 *
	 * @since 1.7.5
	 *
	 * @param array $notification Notification data.
	 */
	public function add( $notification ) {

		if ( ! $this->is_valid( $notification ) ) {
			return;
		}

		$option = $this->get_option();

		// Notification ID already exists.
		if ( ! empty( $option['events'][ $notification['id'] ] ) ) {
			return;
		}

		update_option(
			'wpforms_notifications',
			[
				'update'    => $option['update'],
				'feed'      => $option['feed'],
				'events'    => array_merge( $notification, $option['events'] ),
				'dismissed' => $option['dismissed'],
			]
		);
	}

	/**
	 * Determine if notification data is valid.
	 *
	 * @since 1.7.5
	 *
	 * @param array $notification Notification data.
	 *
	 * @return bool
	 */
	public function is_valid( $notification ) {

		if ( empty( $notification['id'] ) ) {
			return false;
		}

		return ! empty( $this->verify( [ $notification ] ) );
	}

	/**
	 * Determine if notification has already been dismissed.
	 *
	 * @since 1.7.5
	 *
	 * @param array $notification Notification data.
	 *
	 * @return bool
	 */
	private function is_dismissed( $notification ) {

		$option = $this->get_option();

		// phpcs:ignore WordPress.PHP.StrictInArray.MissingTrueStrict
		return ! empty( $option['dismissed'] ) && in_array( $notification['id'], $option['dismissed'] );
	}

	/**
	 * Determine if license type is match.
	 *
	 * @since 1.7.5
	 *
	 * @param array $notification Notification data.
	 *
	 * @return bool
	 */
	private function is_license_type_match( $notification ) {

		// A specific license type is not required.
		if ( empty( $notification['type'] ) ) {
			return true;
		}

		return in_array( $this->get_license_type(), (array) $notification['type'], true );
	}

	/**
	 * Determine if notification is expired.
	 *
	 * @since 1.7.5
	 *
	 * @param array $notification Notification data.
	 *
	 * @return bool
	 */
	private function is_expired( $notification ) {

		return ! empty( $notification['end'] ) && time() > strtotime( $notification['end'] );
	}

	/**
	 * Determine if notification existed before installing WPForms.
	 *
	 * @since 1.7.5
	 *
	 * @param array $notification Notification data.
	 *
	 * @return bool
	 */
	private function is_existed( $notification ) {

		$activated = wpforms_get_activated_timestamp();

		return ! empty( $activated ) &&
			! empty( $notification['start'] ) &&
			$activated > strtotime( $notification['start'] );
	}

	/**
	 * Update notification data from feed.
	 *
	 * @since 1.7.5
	 * @since 1.7.8 Added `wp_cache_flush()` call when the option has been updated.
	 */
	public function update() {

		$option = $this->get_option();
		$data   = [
			'update'    => time(),
			'feed'      => $this->fetch_feed(),
			'events'    => $option['events'],
			'dismissed' => $option['dismissed'],
		];

		// phpcs:disable WPForms.PHP.ValidateHooks.InvalidHookName
		/**
		 * Allow changing notification data before it will be updated in database.
		 *
		 * @since 1.7.5
		 *
		 * @param array $data New notification data.
		 */
		$data = (array) apply_filters( 'wpforms_admin_notifications_update_data', $data );
		// phpcs:enable WPForms.PHP.ValidateHooks.InvalidHookName

		// Flush the cache after the option has been updated
		// for the case when it earlier returns an old value without the new data from DB.
		if ( update_option( 'wpforms_notifications', $data ) ) {
			wp_cache_flush();
		}
	}

	/**
	 * Remove notification data from database before a plugin is deactivated.
	 *
	 * @since 1.7.5
	 *
	 * @param string $plugin               Path to the plugin file relative to the plugins directory.
	 * @param bool   $network_deactivating Whether the plugin is deactivated for all sites in the network
	 *                                     or just the current site. Multisite only. Default false.
	 */
	public function delete( $plugin, $network_deactivating ) {

		$wpforms_plugins = [
			'wpforms-lite/wpforms.php',
			'wpforms/wpforms.php',
		];

		if ( ! in_array( $plugin, $wpforms_plugins, true ) ) {
			return;
		}

		delete_option( 'wpforms_notifications' );
	}

	/**
	 * Enqueue assets on Form Overview admin page.
	 *
	 * @since 1.7.5
	 */
	public function enqueues() {

		if ( ! $this->get_count() ) {
			return;
		}

		$min = wpforms_get_min_suffix();

		wp_enqueue_style(
			'wpforms-admin-notifications',
			WPFORMS_PLUGIN_URL . "assets/css/admin-notifications{$min}.css",
			[ 'wpforms-lity' ],
			WPFORMS_VERSION
		);

		wp_enqueue_script(
			'wpforms-admin-notifications',
			WPFORMS_PLUGIN_URL . "assets/js/admin-notifications{$min}.js",
			[ 'jquery', 'wpforms-lity' ],
			WPFORMS_VERSION,
			true
		);

		// Lity.
		wp_enqueue_style(
			'wpforms-lity',
			WPFORMS_PLUGIN_URL . 'assets/lib/lity/lity.min.css',
			[],
			WPFORMS_VERSION
		);

		wp_enqueue_script(
			'wpforms-lity',
			WPFORMS_PLUGIN_URL . 'assets/lib/lity/lity.min.js',
			[ 'jquery' ],
			WPFORMS_VERSION,
			true
		);
	}

	/**
	 * Output notifications on Form Overview admin area.
	 *
	 * @since 1.7.5
	 */
	public function output() {

		$notifications = $this->get();

		if ( empty( $notifications ) ) {
			return;
		}

		$notifications_html   = '';
		$current_class        = ' current';
		$content_allowed_tags = [
			'br'     => [],
			'em'     => [],
			'strong' => [],
			'span'   => [
				'style' => [],
			],
			'p'      => [
				'id'    => [],
				'class' => [],
			],
			'a'      => [
				'href'   => [],
				'target' => [],
				'rel'    => [],
			],
		];

		foreach ( $notifications as $notification ) {

			// Prepare required arguments.
			$notification = wp_parse_args(
				$notification,
				[
					'id'      => 0,
					'title'   => '',
					'content' => '',
					'video'   => '',
				]
			);

			$title   = $this->get_component_data( $notification['title'] );
			$content = $this->get_component_data( $notification['content'] );

			if ( ! $title && ! $content ) {
				continue;
			}

			// Notification HTML.
			$notifications_html .= sprintf(
				'<div class="wpforms-notifications-message%5$s" data-message-id="%4$s">
					<h3 class="wpforms-notifications-title">%1$s%6$s</h3>
					<div class="wpforms-notifications-content">%2$s</div>
					%3$s
				</div>',
				esc_html( $title ),
				wp_kses( wpautop( $content ), $content_allowed_tags ),
				$this->get_notification_buttons_html( $notification ),
				esc_attr( $notification['id'] ),
				esc_attr( $current_class ),
				$this->get_video_badge_html( $this->get_component_data( $notification['video'] ) )
			);

			// Only first notification is current.
			$current_class = '';
		}

		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo wpforms_render(
			'admin/notifications',
			[
				'notifications' => [
					'count' => count( $notifications ),
					'html'  => $notifications_html,
				],
			],
			true
		);
	}

	/**
	 * Retrieve notification's buttons HTML.
	 *
	 * @since 1.7.5
	 *
	 * @param array $notification Notification data.
	 *
	 * @return string
	 */
	private function get_notification_buttons_html( $notification ) {

		$html = '';

		if ( empty( $notification['btns'] ) || ! is_array( $notification['btns'] ) ) {
			return $html;
		}

		foreach ( $notification['btns'] as $btn_type => $btn ) {

			$btn = $this->get_component_data( $btn );

			if ( ! $btn ) {
				continue;
			}

			$url    = $this->prepare_btn_url( $btn );
			$target = ! empty( $btn['target'] ) ? $btn['target'] : '_blank';
			$target = ! empty( $url ) && strpos( $url, home_url() ) === 0 ? '_self' : $target;

			$html .= sprintf(
				'<a href="%1$s" class="button button-%2$s"%3$s>%4$s</a>',
				esc_url( $url ),
				$btn_type === 'main' ? 'primary' : 'secondary',
				$target === '_blank' ? ' target="_blank" rel="noopener noreferrer"' : '',
				! empty( $btn['text'] ) ? esc_html( $btn['text'] ) : ''
			);
		}

		return ! empty( $html ) ? sprintf( '<div class="wpforms-notifications-buttons">%s</div>', $html ) : '';
	}

	/**
	 * Retrieve notification's component data by a license type.
	 *
	 * @since 1.7.5
	 *
	 * @param mixed $data Component data.
	 *
	 * @return false|mixed
	 */
	private function get_component_data( $data ) {

		if ( empty( $data['license'] ) ) {
			return $data;
		}

		$license_type = $this->get_license_type();

		if ( in_array( $license_type, self::LICENSES_ELITE, true ) ) {
			$license_type = 'elite';
		}

		return ! empty( $data['license'][ $license_type ] ) ? $data['license'][ $license_type ] : false;
	}

	/**
	 * Retrieve the current installation license type (always lowercase).
	 *
	 * @since 1.7.5
	 *
	 * @return string
	 */
	private function get_license_type() {

		if ( $this->license_type ) {
			return $this->license_type;
		}

		$this->license_type = wpforms_get_license_type();

		if ( ! $this->license_type ) {
			$this->license_type = 'lite';
		}

		return $this->license_type;
	}

	/**
	 * Dismiss notification via AJAX.
	 *
	 * @since 1.7.5
	 */
	public function dismiss() {

		// Check for required param, security and access.
		if (
			empty( $_POST['id'] ) ||
			! check_ajax_referer( 'wpforms-admin', 'nonce', false ) ||
			! $this->has_access()
		) {
			wp_send_json_error();
		}

		$id     = sanitize_key( $_POST['id'] );
		$type   = is_numeric( $id ) ? 'feed' : 'events';
		$option = $this->get_option();

		$option['dismissed'][] = $id;
		$option['dismissed']   = array_unique( $option['dismissed'] );

		// Remove notification.
		if ( is_array( $option[ $type ] ) && ! empty( $option[ $type ] ) ) {
			foreach ( $option[ $type ] as $key => $notification ) {
				if ( (string) $notification['id'] === (string) $id ) {
					unset( $option[ $type ][ $key ] );

					break;
				}
			}
		}

		update_option( 'wpforms_notifications', $option );

		wp_send_json_success();
	}

	/**
	 * Prepare button URL.
	 *
	 * @since 1.7.5
	 *
	 * @param array $btn Button data.
	 *
	 * @return string
	 */
	private function prepare_btn_url( $btn ) {

		if ( empty( $btn['url'] ) ) {
			return '';
		}

		$replace_tags = [
			'{admin_url}'   => admin_url(),
			'{license_key}' => wpforms_get_license_key(),
		];

		return str_replace( array_keys( $replace_tags ), array_values( $replace_tags ), $btn['url'] );
	}

	/**
	 * Get the notification's video badge HTML.
	 *
	 * @since 1.7.5
	 *
	 * @param string $video_url Valid video URL.
	 *
	 * @return string
	 */
	private function get_video_badge_html( $video_url ) {

		$video_url = wp_http_validate_url( $video_url );

		if ( empty( $video_url ) ) {
			return '';
		}

		$data_attr_lity = wp_is_mobile() ? '' : 'data-lity';

		return sprintf(
			'<a class="wpforms-notifications-badge" href="%1$s" %2$s><i class="fa fa-youtube-play" aria-hidden="true"></i>%3$s</a>',
			esc_url( $video_url ),
			esc_attr( $data_attr_lity ),
			esc_html__( 'Watch Video', 'wpforms-lite' )
		);
	}
}

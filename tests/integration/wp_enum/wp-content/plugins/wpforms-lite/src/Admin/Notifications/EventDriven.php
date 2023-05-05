<?php

namespace WPForms\Admin\Notifications;

/**
 * Class EventDriven.
 *
 * @since 1.7.5
 */
class EventDriven {

	/**
	 * WPForms version when the Event Driven feature has been introduced.
	 *
	 * @since 1.7.5
	 *
	 * @var string
	 */
	const FEATURE_INTRODUCED = '1.7.5';

	/**
	 * Expected date format for notifications.
	 *
	 * @since 1.7.5
	 *
	 * @var string
	 */
	const DATE_FORMAT = 'Y-m-d H:i:s';

	/**
	 * Common UTM parameters.
	 *
	 * @since 1.7.5
	 *
	 * @var array
	 */
	const UTM_PARAMS = [
		'utm_source' => 'WordPress',
		'utm_medium' => 'Event Notification',
	];

	/**
	 * Common targets for date logic.
	 *
	 * Available items:
	 *  - upgraded (upgraded to a latest version)
	 *  - activated
	 *  - forms_first_created
	 *  - X.X.X.X (upgraded to a specific version)
	 *  - pro (activated/installed)
	 *  - lite (activated/installed)
	 *
	 * @since 1.7.5
	 *
	 * @var array
	 */
	const DATE_LOGIC = [ 'upgraded', 'activated', 'forms_first_created' ];

	/**
	 * Timestamps.
	 *
	 * @since 1.7.5
	 *
	 * @var array
	 */
	private $timestamps = [];

	/**
	 * Initialize class.
	 *
	 * @since 1.7.5
	 */
	public function init() {

		if ( ! $this->allow_load() ) {
			return;
		}

		$this->hooks();
	}

	/**
	 * Indicate if this is allowed to load.
	 *
	 * @since 1.7.5
	 *
	 * @return bool
	 */
	private function allow_load() {

		return wpforms()->get( 'notifications' )->has_access() || wp_doing_cron();
	}

	/**
	 * Hooks.
	 *
	 * @since 1.7.5
	 */
	private function hooks() {

		add_filter( 'wpforms_admin_notifications_update_data', [ $this, 'update_events' ] );
	}

	/**
	 * Add Event Driven notifications before saving them in database.
	 *
	 * @since 1.7.5
	 *
	 * @param array $data Notification data.
	 *
	 * @return array
	 */
	public function update_events( $data ) {

		$updated = [];

		/**
		 * Allow developers to turn on debug mode: store all notifications and then show all of them.
		 *
		 * @since 1.7.5
		 *
		 * @param bool $is_debug True if it's a debug mode. Default: false.
		 */
		$is_debug = (bool) apply_filters( 'wpforms_admin_notifications_event_driven_update_events_debug', false );

		$wpforms_notifications = wpforms()->get( 'notifications' );

		foreach ( $this->get_notifications() as $slug => $notification ) {

			$is_processed      = ! empty( $data['events'][ $slug ]['start'] );
			$is_conditional_ok = ! ( isset( $notification['condition'] ) && $notification['condition'] === false );

			// If it's a debug mode OR valid notification has been already processed - skip running logic checks and save it.
			if (
				$is_debug ||
				( $is_processed && $is_conditional_ok && $wpforms_notifications->is_valid( $data['events'][ $slug ] ) )
			) {
				unset( $notification['date_logic'], $notification['offset'], $notification['condition'] );

				// phpcs:ignore WordPress.DateTime.RestrictedFunctions.date_date
				$notification['start'] = $is_debug ? date( self::DATE_FORMAT ) : $data['events'][ $slug ]['start'];
				$updated[ $slug ]      = $notification;

				continue;
			}

			// Ignore if a condition is not passed conditional checks.
			if ( ! $is_conditional_ok ) {
				continue;
			}

			$timestamp = $this->get_timestamp_by_date_logic(
				$this->prepare_date_logic( $notification )
			);

			if ( empty( $timestamp ) ) {
				continue;
			}

			// Probably, notification should be visible after some time.
			$offset = empty( $notification['offset'] ) ? 0 : absint( $notification['offset'] );

			// Set a start date when notification will be shown.
			// phpcs:ignore WordPress.DateTime.RestrictedFunctions.date_date
			$notification['start'] = date( self::DATE_FORMAT, $timestamp + $offset );

			// Ignore if notification data is not valid.
			if ( ! $wpforms_notifications->is_valid( $notification ) ) {
				continue;
			}

			// Remove unnecessary values, mark notification as active, and save it.
			unset( $notification['date_logic'], $notification['offset'], $notification['condition'] );
			$updated[ $slug ] = $notification;
		}

		$data['events'] = $updated;

		return $data;
	}

	/**
	 * Prepare and retrieve date logic.
	 *
	 * @since 1.7.5
	 *
	 * @param array $notification Notification data.
	 *
	 * @return array
	 */
	private function prepare_date_logic( $notification ) {

		$date_logic = empty( $notification['date_logic'] ) || ! is_array( $notification['date_logic'] ) ? self::DATE_LOGIC : $notification['date_logic'];

		return array_filter( array_filter( $date_logic, 'is_string' ) );
	}

	/**
	 * Retrieve a notification timestamp based on date logic.
	 *
	 * @since 1.7.5
	 *
	 * @param array $args Date logic.
	 *
	 * @return int
	 */
	private function get_timestamp_by_date_logic( $args ) {

		foreach ( $args as $target ) {

			if ( ! empty( $this->timestamps[ $target ] ) ) {
				return $this->timestamps[ $target ];
			}

			$timestamp = call_user_func(
				$this->get_timestamp_callback( $target ),
				$target
			);

			if ( ! empty( $timestamp ) ) {
				$this->timestamps[ $target ] = $timestamp;

				return $timestamp;
			}
		}

		return 0;
	}

	/**
	 * Retrieve a callback that determines needed timestamp.
	 *
	 * @since 1.7.5
	 *
	 * @param string $target Date logic target.
	 *
	 * @return callable
	 */
	private function get_timestamp_callback( $target ) {

		$raw_target = $target;

		// As $target should be a part of name for callback method,
		// this regular expression allow lowercase characters, numbers, and underscore.
		$target = strtolower( preg_replace( '/[^a-z0-9_]/', '', $target ) );

		// Basic callback.
		$callback = [ $this, 'get_timestamp_' . $target ];

		// Determine if a special version number is passed.
		// Uses the regular expression to check a SemVer string.
		// @link https://semver.org/#is-there-a-suggested-regular-expression-regex-to-check-a-semver-string.
		if ( preg_match( '/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:\.([1-9\d*]))?(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$/', $raw_target ) ) {
			$callback = [ $this, 'get_timestamp_upgraded' ];
		}

		// If callback is callable, return it. Otherwise, return fallback.
		return is_callable( $callback ) ? $callback : '__return_zero';
	}

	/**
	 * Retrieve a timestamp when WPForms was upgraded.
	 *
	 * @since 1.7.5
	 *
	 * @param string $version WPForms version.
	 *
	 * @return int|false Unix timestamp. False on failure.
	 */
	private function get_timestamp_upgraded( $version ) {

		if ( $version === 'upgraded' ) {
			$version = WPFORMS_VERSION;
		}

		$timestamp = wpforms_get_upgraded_timestamp( $version );

		if ( $timestamp === false ) {
			return false;
		}

		// Return a current timestamp if no luck to return a migration's timestamp.
		return $timestamp <= 0 ? time() : $timestamp;
	}

	/**
	 * Retrieve a timestamp when WPForms was first installed/activated.
	 *
	 * @since 1.7.5
	 *
	 * @return int|false Unix timestamp. False on failure.
	 */
	private function get_timestamp_activated() {

		return wpforms_get_activated_timestamp();
	}

	/**
	 * Retrieve a timestamp when Lite was first installed.
	 *
	 * @since 1.7.5
	 *
	 * @return int|false Unix timestamp. False on failure.
	 */
	private function get_timestamp_lite() {

		$activated = (array) get_option( 'wpforms_activated', [] );

		return ! empty( $activated['lite'] ) ? absint( $activated['lite'] ) : false;
	}

	/**
	 * Retrieve a timestamp when Pro was first installed.
	 *
	 * @since 1.7.5
	 *
	 * @return int|false Unix timestamp. False on failure.
	 */
	private function get_timestamp_pro() {

		$activated = (array) get_option( 'wpforms_activated', [] );

		return ! empty( $activated['pro'] ) ? absint( $activated['pro'] ) : false;
	}

	/**
	 * Retrieve a timestamp when a first form was created.
	 *
	 * @since 1.7.5
	 *
	 * @return int|false Unix timestamp. False on failure.
	 */
	private function get_timestamp_forms_first_created() {

		$timestamp = get_option( 'wpforms_forms_first_created' );

		return ! empty( $timestamp ) ? absint( $timestamp ) : false;
	}

	/**
	 * Retrieve a number of entries.
	 *
	 * @since 1.7.5
	 *
	 * @return int
	 */
	private function get_entry_count() {

		static $count;

		if ( is_int( $count ) ) {
			return $count;
		}

		global $wpdb;

		$count              = 0;
		$entry_handler      = wpforms()->get( 'entry' );
		$entry_meta_handler = wpforms()->get( 'entry_meta' );

		if ( ! $entry_handler || ! $entry_meta_handler ) {
			return $count;
		}

		$query = "SELECT COUNT({$entry_handler->primary_key})
				FROM {$entry_handler->table_name}
				WHERE {$entry_handler->primary_key}
				NOT IN (
					SELECT entry_id
					FROM {$entry_meta_handler->table_name}
					WHERE type = 'backup_id'
				);";

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared
		$count = (int) $wpdb->get_var( $query );

		return $count;
	}

	/**
	 * Retrieve forms.
	 *
	 * @since 1.7.5
	 *
	 * @param int $posts_per_page Number of form to return.
	 *
	 * @return array
	 */
	private function get_forms( $posts_per_page ) {

		$forms = wpforms()->get( 'form' )->get(
			'',
			[
				'posts_per_page'         => (int) $posts_per_page,
				'nopaging'               => false,
				'update_post_meta_cache' => false,
				'update_post_term_cache' => false,
				'cap'                    => false,
			]
		);

		return ! empty( $forms ) ? (array) $forms : [];
	}

	/**
	 * Determine if the user has at least 1 form.
	 *
	 * @since 1.7.5
	 *
	 * @return bool
	 */
	private function has_form() {

		return ! empty( $this->get_forms( 1 ) );
	}

	/**
	 * Determine if it is a new user.
	 *
	 * @since 1.7.5
	 *
	 * @return bool
	 */
	private function is_new_user() {

		// Check if this is an update or first install.
		return ! get_option( 'wpforms_version_upgraded_from' );
	}

	/**
	 * Determine if it's an English site.
	 *
	 * @since 1.7.5
	 *
	 * @return bool
	 */
	private function is_english_site() {

		static $result;

		if ( is_bool( $result ) ) {
			return $result;
		}

		$locales = array_unique(
			array_map(
				[ $this, 'language_to_iso' ],
				[ get_locale(), get_user_locale() ]
			)
		);
		$result  = count( $locales ) === 1 && $locales[0] === 'en';

		return $result;
	}

	/**
	 * Convert language to ISO.
	 *
	 * @since 1.7.5
	 *
	 * @param string $lang Language value.
	 *
	 * @return string
	 */
	private function language_to_iso( $lang ) {

		return $lang === '' ? $lang : explode( '_', $lang )[0];
	}

	/**
	 * Retrieve a modified URL query string.
	 *
	 * @since 1.7.5
	 *
	 * @param array  $args An associative array of query variables.
	 * @param string $url  A URL to act upon.
	 *
	 * @return string
	 */
	private function add_query_arg( $args, $url ) {

		return add_query_arg(
			array_merge( $this->get_utm_params(), array_map( 'rawurlencode', $args ) ),
			$url
		);
	}

	/**
	 * Retrieve UTM parameters for Event Driven notifications links.
	 *
	 * @since 1.7.5
	 *
	 * @return array
	 */
	private function get_utm_params() {

		static $utm_params;

		if ( ! $utm_params ) {
			$utm_params = [
				'utm_source'   => self::UTM_PARAMS['utm_source'],
				'utm_medium'   => rawurlencode( self::UTM_PARAMS['utm_medium'] ),
				'utm_campaign' => wpforms()->is_pro() ? 'plugin' : 'liteplugin',
			];
		}

		return $utm_params;
	}

	/**
	 * Retrieve Event Driven notifications.
	 *
	 * @since 1.7.5
	 *
	 * @return array
	 */
	private function get_notifications() {

		return [
			'welcome-message'        => [
				'id'        => 'welcome-message',
				'title'     => esc_html__( 'Welcome to WPForms!', 'wpforms-lite' ),
				'content'   => esc_html__( 'We’re grateful that you chose WPForms for your website! Now that you’ve installed the plugin, you’re less than 5 minutes away from publishing your first form. To make it easy, we’ve got 600+ form templates to get you started!', 'wpforms-lite' ),
				'btns'      => [
					'main' => [
						'url'  => admin_url( 'admin.php?page=wpforms-builder' ),
						'text' => esc_html__( 'Start Building', 'wpforms-lite' ),
					],
					'alt'  => [
						'url'  => $this->add_query_arg(
							[ 'utm_content' => 'Welcome Read the Guide' ],
							'https://wpforms.com/docs/creating-first-form/'
						),
						'text' => esc_html__( 'Read the Guide', 'wpforms-lite' ),
					],
				],
				'type'      => [
					'lite',
					'basic',
					'plus',
					'pro',
					'agency',
					'elite',
					'ultimate',
				],
				// Immediately after activation (new users only, not upgrades).
				'condition' => $this->is_new_user(),
			],
			'wp-mail-smtp-education' => [
				'id'        => 'wp-mail-smtp-education',
				'title'     => esc_html__( 'Don’t Miss Your Form Notification Emails!', 'wpforms-lite' ),
				'content'   => esc_html__( 'Did you know that many WordPress sites are not properly configured to send emails? With the free WP Mail SMTP plugin, you can easily optimize your site to send emails, avoid the spam folder, and make sure your emails land in the recipient’s inbox every time.', 'wpforms-lite' ),
				'btns'      => [
					'main' => [
						'url'  => admin_url( 'admin.php?page=wpforms-smtp' ),
						'text' => esc_html__( 'Install Now', 'wpforms-lite' ),
					],
					'alt'  => [
						'url'  => $this->add_query_arg(
							[ 'utm_content' => 'WP Mail SMTP Learn More' ],
							'https://wpforms.com/docs/how-to-set-up-smtp-using-the-wp-mail-smtp-plugin/'
						),
						'text' => esc_html__( 'Learn More', 'wpforms-lite' ),
					],
				],
				// 3 days after activation/upgrade.
				'offset'    => 3 * DAY_IN_SECONDS,
				'condition' => ! function_exists( 'wp_mail_smtp' ),
			],
			'join-vip-circle'        => [
				'id'      => 'join-vip-circle',
				'title'   => esc_html__( 'Want to Be a VIP? Join Now!', 'wpforms-lite' ),
				'content' => esc_html__( 'Running a WordPress site can be challenging. But help is just around the corner! Our Facebook group contains tons of tips and help to get your business growing! When you join our VIP Circle, you’ll get instant access to tips, tricks, and answers from a community of loyal WPForms users. Best of all, membership is 100% free!', 'wpforms-lite' ),
				'btns'    => [
					'main' => [
						'url'  => 'https://www.facebook.com/groups/wpformsvip/',
						'text' => esc_html__( 'Join Now', 'wpforms-lite' ),
					],
				],
				// 30 days after activation/upgrade.
				'offset'  => 30 * DAY_IN_SECONDS,
			],
			'survey-reports'         => [
				'id'        => 'survey-reports',
				'title'     => esc_html__( 'Want to Know What Your Customers Really Think?', 'wpforms-lite' ),
				'content'   => esc_html__( 'Nothing beats real feedback from your customers and visitors. That’s why many small businesses love our awesome Surveys and Polls addon. Instantly unlock full survey reporting right in your WordPress dashboard. And don’t forget: building a survey is easy with our pre-made templates, so you could get started within a few minutes!', 'wpforms-lite' ),
				'btns'      => [
					'main' => [
						'license' => [
							'lite'  => [
								'url'  => $this->add_query_arg(
									[
										'utm_content' => 'Surveys and Polls Upgrade Lite',
										'utm_locale'  => wpforms_sanitize_key( get_locale() ),
									],
									'https://wpforms.com/lite-upgrade/'
								),
								'text' => esc_html__( 'Upgrade Now', 'wpforms-lite' ),
							],
							'basic' => [
								'url'  => $this->add_query_arg(
									[ 'utm_content' => 'Surveys and Polls Upgrade Basic' ],
									'https://wpforms.com/account/licenses/'
								),
								'text' => esc_html__( 'Upgrade Now', 'wpforms-lite' ),
							],
							'plus'  => [
								'url'  => $this->add_query_arg(
									[ 'utm_content' => 'Surveys and Polls Upgrade Basic' ],
									'https://wpforms.com/account/licenses/'
								),
								'text' => esc_html__( 'Upgrade Now', 'wpforms-lite' ),
							],
							'pro'   => [
								'url'  => admin_url( 'admin.php?page=wpforms-addons' ),
								'text' => esc_html__( 'Install Now', 'wpforms-lite' ),
							],
							'elite' => [
								'url'  => admin_url( 'admin.php?page=wpforms-addons' ),
								'text' => esc_html__( 'Install Now', 'wpforms-lite' ),
							],
						],
					],
					'alt'  => [
						'url'  => $this->add_query_arg(
							[ 'utm_content' => 'Surveys and Polls Learn More' ],
							'https://wpforms.com/docs/how-to-install-and-use-the-surveys-and-polls-addon/'
						),
						'text' => esc_html__( 'Learn More', 'wpforms-lite' ),
					],
				],
				// 45 days after activation/upgrade.
				'offset'    => 45 * DAY_IN_SECONDS,
				'condition' => ! defined( 'WPFORMS_SURVEYS_POLLS_VERSION' ),
			],
			'form-abandonment'       => [
				'id'        => 'form-abandonment',
				'title'     => esc_html__( 'Get More Leads From Your Forms!', 'wpforms-lite' ),
				'content'   => esc_html__( 'Are your forms converting fewer visitors than you hoped? Often, visitors quit forms partway through. That can prevent you from getting all the leads you deserve to capture. With our Form Abandonment addon, you can capture partial entries even if your visitor didn’t hit Submit! From there, it’s easy to follow up with leads and turn them into loyal customers.', 'wpforms-lite' ),
				'btns'      => [
					'main' => [
						'license' => [
							'lite'  => [
								'url'  => $this->add_query_arg(
									[
										'utm_content' => 'Form Abandonment Upgrade Lite',
										'utm_locale'  => wpforms_sanitize_key( get_locale() ),
									],
									'https://wpforms.com/lite-upgrade/'
								),
								'text' => esc_html__( 'Upgrade Now', 'wpforms-lite' ),
							],
							'basic' => [
								'url'  => $this->add_query_arg(
									[ 'utm_content' => 'Form Abandonment Upgrade Basic' ],
									'https://wpforms.com/account/licenses/'
								),
								'text' => esc_html__( 'Upgrade Now', 'wpforms-lite' ),
							],
							'plus'  => [
								'url'  => $this->add_query_arg(
									[ 'utm_content' => 'Form Abandonment Upgrade Basic' ],
									'https://wpforms.com/account/licenses/'
								),
								'text' => esc_html__( 'Upgrade Now', 'wpforms-lite' ),
							],
							'pro'   => [
								'url'  => admin_url( 'admin.php?page=wpforms-addons' ),
								'text' => esc_html__( 'Install Now', 'wpforms-lite' ),
							],
							'elite' => [
								'url'  => admin_url( 'admin.php?page=wpforms-addons' ),
								'text' => esc_html__( 'Install Now', 'wpforms-lite' ),
							],
						],
					],
					'alt'  => [
						'url'  => $this->add_query_arg(
							[ 'utm_content' => 'Form Abandonment Learn More' ],
							'https://wpforms.com/docs/how-to-install-and-use-form-abandonment-with-wpforms/'
						),
						'text' => esc_html__( 'Learn More', 'wpforms-lite' ),
					],
				],
				// 60 days after activation/upgrade.
				'offset'    => 60 * DAY_IN_SECONDS,
				'condition' => ! defined( 'WPFORMS_FORM_ABANDONMENT_VERSION' ),
			],
			'ideas'                  => [
				'id'        => 'ideas',
				'title'     => esc_html__( 'What’s Your Dream WPForms Feature?', 'wpforms-lite' ),
				'content'   => esc_html__( 'If you could add just one feature to WPForms, what would it be? We want to know! Our team is busy surveying valued customers like you as we plan the year ahead. We’d love to know which features would take your business to the next level! Do you have a second to share your idea with us?', 'wpforms-lite' ),
				'btns'      => [
					'main' => [
						'url'  => 'https://wpforms.com/share-your-idea/',
						'text' => esc_html__( 'Share Your Idea', 'wpforms-lite' ),
					],
				],
				// 120 days after activation/upgrade.
				'offset'    => 120 * DAY_IN_SECONDS,
				'condition' => $this->has_form(),
			],
			'user-insights'          => [
				'id'        => 'user-insights',
				'title'     => esc_html__( 'Congratulations! You Just Got Your 100th Form Entry!', 'wpforms-lite' ),
				'content'   => esc_html__( 'You just hit 100 entries&hellip; and this is just the beginning! Now it’s time to dig into the data and figure out what makes your visitors tick. The User Journey addon shows you what your visitors looked at before submitting your form. Now you can easily find which areas of your site are triggering form conversions.', 'wpforms-lite' ),
				'btns'      => [
					'main' => [
						'license' => [
							'lite'  => [
								'url'  => $this->add_query_arg(
									[
										'utm_content' => 'User Journey Upgrade Lite',
										'utm_locale'  => wpforms_sanitize_key( get_locale() ),
									],
									'https://wpforms.com/lite-upgrade/'
								),
								'text' => esc_html__( 'Upgrade Now', 'wpforms-lite' ),
							],
							'basic' => [
								'url'  => $this->add_query_arg(
									[ 'utm_content' => 'User Journey Upgrade Basic' ],
									'https://wpforms.com/account/licenses/'
								),
								'text' => esc_html__( 'Upgrade Now', 'wpforms-lite' ),
							],
							'plus'  => [
								'url'  => $this->add_query_arg(
									[ 'utm_content' => 'User Journey Upgrade Basic' ],
									'https://wpforms.com/account/licenses/'
								),
								'text' => esc_html__( 'Upgrade Now', 'wpforms-lite' ),
							],
							'pro'   => [
								'url'  => admin_url( 'admin.php?page=wpforms-addons' ),
								'text' => esc_html__( 'Install Now', 'wpforms-lite' ),
							],
							'elite' => [
								'url'  => admin_url( 'admin.php?page=wpforms-addons' ),
								'text' => esc_html__( 'Install Now', 'wpforms-lite' ),
							],
						],
					],
				],
				'condition' => ! defined( 'WPFORMS_USER_JOURNEY_VERSION' ) && $this->get_entry_count() >= 100,
			],
		];
	}
}

<?php
/**
 * Milestone Countdown Widget
 *
 * @package automattic/jetpack
 */

use Automattic\Jetpack\Assets;

/**
 * Class Milestone_Widget
 */
class Milestone_Widget extends WP_Widget {
	/**
	 * Holding array for widget configuration and localization.
	 *
	 * @var array
	 */
	private static $config_js = array();

	/**
	 * Available time units sorted in descending order.
	 *
	 * @var Array
	 */
	protected $available_units = array(
		'years',
		'months',
		'days',
		'hours',
		'minutes',
		'seconds',
	);

	/**
	 * Milestone_Widget constructor.
	 */
	public function __construct() {
		$widget = array(
			'classname'   => 'milestone-widget',
			'description' => __( 'Display a countdown to a certain date.', 'jetpack' ),
		);

		parent::__construct(
			'Milestone_Widget',
			/** This filter is documented in modules/widgets/facebook-likebox.php */
			apply_filters( 'jetpack_widget_name', __( 'Milestone', 'jetpack' ) ),
			$widget
		);

		add_action( 'wp_enqueue_scripts', array( __CLASS__, 'enqueue_template' ) );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'enqueue_admin' ) );
		add_action( 'wp_footer', array( $this, 'localize_script' ) );

		if ( is_active_widget( false, false, $this->id_base, true ) || is_active_widget( false, false, 'monster', true ) || is_customize_preview() ) {
			add_action( 'wp_head', array( __CLASS__, 'styles_template' ) );
		}
	}

	/**
	 * Enqueue admin assets.
	 *
	 * @param string $hook_suffix Hook suffix provided by WordPress.
	 */
	public static function enqueue_admin( $hook_suffix ) {
		if ( 'widgets.php' === $hook_suffix ) {
			wp_enqueue_style( 'milestone-admin', plugin_dir_url( __FILE__ ) . 'style-admin.css', array(), '20201113' );
			wp_enqueue_script(
				'milestone-admin-js',
				Assets::get_file_url_for_environment(
					'_inc/build/widgets/milestone/admin.min.js',
					'modules/widgets/milestone/admin.js'
				),
				array( 'jquery' ),
				'20201113',
				true
			);
		}
	}

	/**
	 * Enqueue the frontend JS.
	 */
	public static function enqueue_template() {
		if ( class_exists( 'Jetpack_AMP_Support' ) && Jetpack_AMP_Support::is_amp_request() ) {
			return;
		}

		wp_enqueue_script(
			'milestone',
			Assets::get_file_url_for_environment(
				'_inc/build/widgets/milestone/milestone.min.js',
				'modules/widgets/milestone/milestone.js'
			),
			array(),
			'20201113',
			true
		);
	}

	/**
	 * Output the frontend styling.
	 */
	public static function styles_template() {
		global $themecolors;
		$colors = wp_parse_args(
			$themecolors,
			array(
				'bg'     => 'ffffff',
				'border' => 'cccccc',
				'text'   => '333333',
			)
		);
		?>
<style>
.milestone-widget {
	--milestone-text-color: <?php echo self::sanitize_color_hex( $colors['text'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>;
	--milestone-bg-color: <?php echo self::sanitize_color_hex( $colors['bg'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>;
	--milestone-border-color:<?php echo self::sanitize_color_hex( $colors['border'] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>;
}
</style>
		<?php
	}

	/**
	 * Ensure that a string representing a color in hexadecimal
	 * notation is safe for use in css and database saves.
	 *
	 * @param string $hex Hexademical code to sanitize.
	 * @param string $prefix Prefix for the hex code.
	 *
	 * @return string Color in hexadecimal notation on success - the string "transparent" otherwise.
	 */
	public static function sanitize_color_hex( $hex, $prefix = '#' ) {
		$hex = trim( $hex );

		/* Strip recognized prefixes. */
		if ( 0 === strpos( $hex, '#' ) ) {
			$hex = substr( $hex, 1 );
		} elseif ( 0 === strpos( $hex, '%23' ) ) {
			$hex = substr( $hex, 3 );
		}

		if ( 0 !== preg_match( '/^[0-9a-fA-F]{6}$/', $hex ) ) {
			return $prefix . $hex;
		}

		return 'transparent';
	}

	/**
	 * Localize Front-end Script.
	 *
	 * Print the javascript configuration array only if the
	 * current template has an instance of the widget that
	 * is still counting down. In all other cases, this
	 * function will dequeue milestone.js.
	 *
	 * Hooks into the "wp_footer" action.
	 */
	public function localize_script() {
		if ( class_exists( 'Jetpack_AMP_Support' ) && Jetpack_AMP_Support::is_amp_request() ) {
			return;
		}

		if ( empty( self::$config_js['instances'] ) ) {
			wp_dequeue_script( 'milestone' );
			return;
		}
		self::$config_js['api_root'] = esc_url_raw( rest_url() );
		wp_localize_script( 'milestone', 'MilestoneConfig', self::$config_js );
	}

	/**
	 * Return an associative array of default values
	 *
	 * These values are used in new widgets.
	 *
	 * @return array Array of default values for the Widget's options.
	 */
	public function defaults() {
		$now           = current_datetime();
		$now_timestamp = $now->getTimestamp();

		return array(
			'title'   => '',
			'event'   => __( 'The Big Day', 'jetpack' ),
			'unit'    => 'automatic',
			'type'    => 'until',
			'message' => __( 'The big day is here.', 'jetpack' ),
			'day'     => gmdate( 'd', $now_timestamp ),
			'month'   => gmdate( 'm', $now_timestamp ),
			'year'    => gmdate( 'Y', $now_timestamp ),
			'hour'    => 0,
			'min'     => 0,
		);
	}

	/**
	 * Widget
	 *
	 * @param array $args Widget args.
	 * @param array $instance Widget instance.
	 */
	public function widget( $args, $instance ) {
		$instance = wp_parse_args( $instance, $this->defaults() );

		$this->enqueue_scripts();

		echo $args['before_widget']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped

		/** This filter is documented in wp-includes/widgets/class-wp-widget-pages.php */
		$title = apply_filters( 'widget_title', $instance['title'] );
		if ( ! empty( $title ) ) {
			echo $args['before_title'] . $title . $args['after_title']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		}

		$widget_id = ! empty( $args['widget_id'] ) ? $args['widget_id'] : 'milestone_widget';
		$data      = $this->get_widget_data( $instance );
		$config    = array(
			'id'      => $widget_id,
			'message' => $data['message'],
			'refresh' => $data['refresh'],
		);

		/*
		 * Sidebars may be configured to not expose the `widget_id`. Example: `twentytwenty` footer areas.
		 *
		 * We need our own unique identifier.
		 */
		$config['content_id'] = $widget_id . '-content';

		self::$config_js['instances'][] = $config;

		echo sprintf( '<div id="%s" class="milestone-content">', esc_html( $config['content_id'] ) );

		echo '<div class="milestone-header">';
		echo '<strong class="event">' . esc_html( $instance['event'] ) . '</strong>';
		echo '<span class="date">' . esc_html( date_i18n( get_option( 'date_format' ), $data['milestone'] ) ) . '</span>';
		echo '</div>';

		echo wp_kses_post( $data['message'] );

		echo '</div><!--milestone-content-->';

		echo $args['after_widget']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped

		/** This action is documented in modules/widgets/gravatar-profile.php */
		do_action( 'jetpack_stats_extra', 'widget_view', 'milestone' );
	}

	/**
	 * Enqueue widget styles
	 */
	public function enqueue_scripts() {
		wp_enqueue_style(
			'milestone-widget',
			plugins_url( 'milestone-widget.css', __FILE__ ),
			array(),
			JETPACK__VERSION
		);
	}

	/**
	 * Getter for the widget data.
	 *
	 * @param array $instance Widget instance.
	 *
	 * @return array
	 */
	public function get_widget_data( $instance ) {
		$data = array();

		$instance = $this->sanitize_instance( $instance );

		$milestone = mktime( $instance['hour'], $instance['min'], 0, $instance['month'], $instance['day'], $instance['year'] );
		$now       = (int) current_time( 'timestamp' ); // phpcs:ignore WordPress.DateTime.CurrentTimeTimestamp.Requested
		$type      = $instance['type'];

		if ( 'since' === $type ) {
			$diff = (int) floor( $now - $milestone );
		} else {
			$diff = (int) floor( $milestone - $now );
		}

		$data['diff'] = $diff;
		$data['unit'] = $this->get_unit( $diff, $instance['unit'] );

		// Setting the refresh counter to equal the number of seconds it takes to flip a unit.
		$refresh_intervals = array(
			0, // should be YEAR_IN_SECONDS, but doing setTimeout for a year doesn't seem to be logical.
			0, // same goes for MONTH_IN_SECONDS.
			DAY_IN_SECONDS,
			HOUR_IN_SECONDS,
			MINUTE_IN_SECONDS,
			1,
		);

		$data['refresh']   = $refresh_intervals[ array_search( $data['unit'], $this->available_units, true ) ];
		$data['milestone'] = $milestone;

		if ( ( 1 > $diff ) && ( 'until' === $type ) ) {
			$data['message'] = '<div class="milestone-message">' . $instance['message'] . '</div>';
			$data['refresh'] = 0; // No need to refresh, the milestone has been reached.
		} else {
			$interval_text = $this->get_interval_in_units( $diff, $data['unit'] );
			$interval      = (int) $interval_text;

			if ( 'since' === $type ) {

				switch ( $data['unit'] ) {
					case 'years':
						$data['message'] = sprintf(
							/* translators: %s is the number of year(s). */
							_n(
								'<span class="difference">%s</span> <span class="label">year ago.</span>',
								'<span class="difference">%s</span> <span class="label">years ago.</span>',
								$interval,
								'jetpack'
							),
							$interval_text
						);
						break;
					case 'months':
						$data['message'] = sprintf(
							/* translators: %s is the number of month(s). */
							_n(
								'<span class="difference">%s</span> <span class="label">month ago.</span>',
								'<span class="difference">%s</span> <span class="label">months ago.</span>',
								$interval,
								'jetpack'
							),
							$interval_text
						);
						break;
					case 'days':
						$data['message'] = sprintf(
							/* translators: %s is the number of days(s). */
							_n(
								'<span class="difference">%s</span> <span class="label">day ago.</span>',
								'<span class="difference">%s</span> <span class="label">days ago.</span>',
								$interval,
								'jetpack'
							),
							$interval_text
						);
						break;
					case 'hours':
						$data['message'] = sprintf(
							/* translators: %s is the number of hours(s). */
							_n(
								'<span class="difference">%s</span> <span class="label">hour ago.</span>',
								'<span class="difference">%s</span> <span class="label">hours ago.</span>',
								$interval,
								'jetpack'
							),
							$interval_text
						);
						break;
					case 'minutes':
						$data['message'] = sprintf(
							/* translators: %s is the number of minutes(s). */
							_n(
								'<span class="difference">%s</span> <span class="label">minute ago.</span>',
								'<span class="difference">%s</span> <span class="label">minutes ago.</span>',
								$interval,
								'jetpack'
							),
							$interval_text
						);
						break;
					case 'seconds':
						$data['message'] = sprintf(
							/* translators: %s is the number of second(s). */
							_n(
								'<span class="difference">%s</span> <span class="label">second ago.</span>',
								'<span class="difference">%s</span> <span class="label">seconds ago.</span>',
								$interval,
								'jetpack'
							),
							$interval_text
						);
						break;
				}
			} else {
				switch ( $this->get_unit( $diff, $instance['unit'] ) ) {
					case 'years':
						$data['message'] = sprintf(
							/* translators: %s is the number of year(s). */
							_n(
								'<span class="difference">%s</span> <span class="label">year to go.</span>',
								'<span class="difference">%s</span> <span class="label">years to go.</span>',
								$interval,
								'jetpack'
							),
							$interval_text
						);
						break;
					case 'months':
						$data['message'] = sprintf(
							/* translators: %s is the number of month(s). */
							_n(
								'<span class="difference">%s</span> <span class="label">month to go.</span>',
								'<span class="difference">%s</span> <span class="label">months to go.</span>',
								$interval,
								'jetpack'
							),
							$interval_text
						);
						break;
					case 'days':
						$data['message'] = sprintf(
							/* translators: %s is the number of days(s). */
							_n(
								'<span class="difference">%s</span> <span class="label">day to go.</span>',
								'<span class="difference">%s</span> <span class="label">days to go.</span>',
								$interval,
								'jetpack'
							),
							$interval_text
						);
						break;
					case 'hours':
						$data['message'] = sprintf(
							/* translators: %s is the number of hour(s). */
							_n(
								'<span class="difference">%s</span> <span class="label">hour to go.</span>',
								'<span class="difference">%s</span> <span class="label">hours to go.</span>',
								$interval,
								'jetpack'
							),
							$interval_text
						);
						break;
					case 'minutes':
						$data['message'] = sprintf(
							/* translators: %s is the number of minute(s). */
							_n(
								'<span class="difference">%s</span> <span class="label">minute to go.</span>',
								'<span class="difference">%s</span> <span class="label">minutes to go.</span>',
								$interval,
								'jetpack'
							),
							$interval_text
						);
						break;
					case 'seconds':
						$data['message'] = sprintf(
							/* translators: %s is the number of second(s). */
							_n(
								'<span class="difference">%s</span> <span class="label">second to go.</span>',
								'<span class="difference">%s</span> <span class="label">seconds to go.</span>',
								$interval,
								'jetpack'
							),
							$interval_text
						);
						break;
				}
			}
			$data['message'] = '<div class="milestone-countdown">' . $data['message'] . '</div>';
		}

		return $data;
	}

	/**
	 * Return the largest possible time unit that the difference will be displayed in.
	 *
	 * @param Integer $seconds the interval in seconds.
	 * @param String  $maximum_unit the maximum unit that will be used. Optional.
	 * @return String $calculated_unit
	 */
	protected function get_unit( $seconds, $maximum_unit = 'automatic' ) {
		$unit = '';

		if ( $seconds >= YEAR_IN_SECONDS * 2 ) {
			// more than 2 years - show in years, one decimal point.
			$unit = 'years';

		} elseif ( $seconds >= YEAR_IN_SECONDS ) {
			if ( 'years' === $maximum_unit ) {
				$unit = 'years';
			} else {
				// automatic mode - showing months even if it's between one and two years.
				$unit = 'months';
			}
		} elseif ( $seconds >= MONTH_IN_SECONDS * 3 ) {
			// fewer than 2 years - show in months.
			$unit = 'months';

		} elseif ( $seconds >= MONTH_IN_SECONDS ) {
			if ( 'months' === $maximum_unit ) {
				$unit = 'months';
			} else {
				// automatic mode - showing days even if it's between one and three months.
				$unit = 'days';
			}
		} elseif ( $seconds >= DAY_IN_SECONDS - 1 ) {
			// fewer than a month - show in days.
			$unit = 'days';

		} elseif ( $seconds >= HOUR_IN_SECONDS - 1 ) {
			// less than 1 day - show in hours.
			$unit = 'hours';

		} elseif ( $seconds >= MINUTE_IN_SECONDS - 1 ) {
			// less than 1 hour - show in minutes.
			$unit = 'minutes';

		} else {
			// less than 1 minute - show in seconds.
			$unit = 'seconds';
		}

		$maximum_unit_index = array_search( $maximum_unit, $this->available_units, true );
		$unit_index         = array_search( $unit, $this->available_units, true );

		if (
			false === $maximum_unit_index // the maximum unit parameter is automatic.
			|| $unit_index > $maximum_unit_index // there is not enough seconds for even one maximum time unit.
		) {
			return $unit;
		}
		return $maximum_unit;
	}

	/**
	 * Returns a time difference value in specified units.
	 *
	 * @param int    $seconds Number of seconds.
	 * @param string $units Unit.
	 * @return int $time_in_units.
	 */
	protected function get_interval_in_units( $seconds, $units ) {
		switch ( $units ) {
			case 'years':
				$years    = $seconds / YEAR_IN_SECONDS;
				$decimals = abs( round( $years, 1 ) - round( $years ) ) > 0 ? 1 : 0;
				return number_format_i18n( $years, $decimals );
			case 'months':
				return (int) ( $seconds / 60 / 60 / 24 / 30 );
			case 'days':
				return (int) ( $seconds / 60 / 60 / 24 + 1 );
			case 'hours':
				return (int) ( $seconds / 60 / 60 );
			case 'minutes':
				return (int) ( $seconds / 60 + 1 );
			default:
				return $seconds;
		}
	}

	/**
	 * Update widget.
	 *
	 * @param array $new_instance New instance of the widget being saved.
	 * @param array $old_instance Previous instance being saved over.
	 *
	 * @return array
	 */
	public function update( $new_instance, $old_instance ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		return $this->sanitize_instance( $new_instance );
	}

	/**
	 * Make sure that a number is within a certain range.
	 * If the number is too small it will become the possible lowest value.
	 * If the number is too large it will become the possible highest value.
	 *
	 * @param int $n The number to check.
	 * @param int $floor The lowest possible value.
	 * @param int $ceil The highest possible value.
	 */
	public function sanitize_range( $n, $floor, $ceil ) {
		$n = (int) $n;
		if ( $n < $floor ) {
			$n = $floor;
		} elseif ( $n > $ceil ) {
			$n = $ceil;
		}
		return $n;
	}

	/**
	 * Sanitize an instance of this widget.
	 *
	 * Date ranges match the documentation for mktime in the php manual.
	 *
	 * @see https://php.net/manual/en/function.mktime.php#refsect1-function.mktime-parameters
	 *
	 * @uses Milestone_Widget::sanitize_range().
	 *
	 * @param array $dirty Unsantized data for the widget.
	 *
	 * @return array Santized data.
	 */
	public function sanitize_instance( $dirty ) {
		$dirty = wp_parse_args(
			$dirty,
			$this->defaults()
		);

		$allowed_tags = array(
			'a'      => array(
				'title'  => array(),
				'href'   => array(),
				'target' => array(),
			),
			'em'     => array( 'title' => array() ),
			'strong' => array( 'title' => array() ),
		);

		$clean = array(
			'title'   => trim( wp_strip_all_tags( stripslashes( $dirty['title'] ) ) ),
			'event'   => trim( wp_strip_all_tags( stripslashes( $dirty['event'] ) ) ),
			'unit'    => $dirty['unit'],
			'type'    => $dirty['type'],
			'message' => wp_kses( $dirty['message'], $allowed_tags ),
			'year'    => $this->sanitize_range( $dirty['year'], 1901, 2037 ),
			'month'   => $this->sanitize_range( $dirty['month'], 1, 12 ),
			'hour'    => $this->sanitize_range( $dirty['hour'], 0, 23 ),
			'min'     => zeroise( $this->sanitize_range( $dirty['min'], 0, 59 ), 2 ),
		);

		$clean['day'] = $this->sanitize_range( $dirty['day'], 1, gmdate( 't', mktime( 0, 0, 0, $clean['month'], 1, $clean['year'] ) ) );

		return $clean;
	}

	/**
	 * Form
	 *
	 * @param array $instance Widget instance.
	 */
	public function form( $instance ) {
		$instance = $this->sanitize_instance( $instance );

		$units = array(
			'automatic' => _x( 'Automatic', 'Milestone widget: mode in which the date unit is determined automatically', 'jetpack' ),
			'years'     => _x( 'Years', 'Milestone widget: mode in which the date unit is set to years', 'jetpack' ),
			'months'    => _x( 'Months', 'Milestone widget: mode in which the date unit is set to months', 'jetpack' ),
			'days'      => _x( 'Days', 'Milestone widget: mode in which the date unit is set to days', 'jetpack' ),
			'hours'     => _x( 'Hours', 'Milestone widget: mode in which the date unit is set to hours', 'jetpack' ),
		);
		?>
		<div class="milestone-widget">
			<p>
				<label for="<?php echo esc_attr( $this->get_field_id( 'title' ) ); ?>"><?php esc_html_e( 'Title', 'jetpack' ); ?></label>
				<input class="widefat" id="<?php echo esc_attr( $this->get_field_id( 'title' ) ); ?>" name="<?php echo esc_attr( $this->get_field_name( 'title' ) ); ?>" type="text" value="<?php echo esc_attr( $instance['title'] ); ?>" />
			</p>

			<p>
				<label for="<?php echo esc_attr( $this->get_field_id( 'event' ) ); ?>"><?php esc_html_e( 'Description', 'jetpack' ); ?></label>
				<input class="widefat" id="<?php echo esc_attr( $this->get_field_id( 'event' ) ); ?>" name="<?php echo esc_attr( $this->get_field_name( 'event' ) ); ?>" type="text" value="<?php echo esc_attr( $instance['event'] ); ?>" />
			</p>

			<fieldset class="jp-ms-data-time">
				<legend><?php esc_html_e( 'Date', 'jetpack' ); ?></legend>

				<label for="<?php echo esc_attr( $this->get_field_id( 'month' ) ); ?>" class="assistive-text"><?php esc_html_e( 'Month', 'jetpack' ); ?></label>
				<select id="<?php echo esc_attr( $this->get_field_id( 'month' ) ); ?>" class="month" name="<?php echo esc_attr( $this->get_field_name( 'month' ) ); ?>">
					<?php
								global $wp_locale;
					for ( $i = 1; $i < 13; $i++ ) {
						$monthnum = zeroise( $i, 2 );
						printf(
							'<option value="%s" %s>%s-%s</option>',
							esc_attr( $monthnum ),
							selected( $i, $instance['month'], false ),
							esc_attr( $monthnum ),
							esc_attr( $wp_locale->get_month_abbrev( $wp_locale->get_month( $i ) ) )
						);
					}
					?>
				</select>

				<label for="<?php echo esc_attr( $this->get_field_id( 'day' ) ); ?>" class="assistive-text"><?php esc_html_e( 'Day', 'jetpack' ); ?></label>
				<input id="<?php echo esc_attr( $this->get_field_id( 'day' ) ); ?>" class="day" name="<?php echo esc_attr( $this->get_field_name( 'day' ) ); ?>" type="text" value="<?php echo esc_attr( $instance['day'] ); ?>">,

				<label for="<?php echo esc_attr( $this->get_field_id( 'year' ) ); ?>" class="assistive-text"><?php esc_html_e( 'Year', 'jetpack' ); ?></label>
				<input id="<?php echo esc_attr( $this->get_field_id( 'year' ) ); ?>" class="year" name="<?php echo esc_attr( $this->get_field_name( 'year' ) ); ?>" type="text" value="<?php echo esc_attr( $instance['year'] ); ?>">
			</fieldset>

			<fieldset class="jp-ms-data-time">
				<legend><?php esc_html_e( 'Time', 'jetpack' ); ?></legend>

				<label for="<?php echo esc_attr( $this->get_field_id( 'hour' ) ); ?>" class="assistive-text"><?php esc_html_e( 'Hour', 'jetpack' ); ?></label>
				<input id="<?php echo esc_attr( $this->get_field_id( 'hour' ) ); ?>" class="hour" name="<?php echo esc_attr( $this->get_field_name( 'hour' ) ); ?>" type="text" value="<?php echo esc_attr( $instance['hour'] ); ?>">

				<label for="<?php echo esc_attr( $this->get_field_id( 'min' ) ); ?>" class="assistive-text"><?php esc_html_e( 'Minutes', 'jetpack' ); ?></label>

				<span class="time-separator">:</span>

				<input id="<?php echo esc_attr( $this->get_field_id( 'min' ) ); ?>" class="minutes" name="<?php echo esc_attr( $this->get_field_name( 'min' ) ); ?>" type="text" value="<?php echo esc_attr( $instance['min'] ); ?>">
			</fieldset>

			<fieldset class="jp-ms-data-unit">
				<legend><?php esc_html_e( 'Time Unit', 'jetpack' ); ?></legend>

				<label for="<?php echo esc_attr( $this->get_field_id( 'unit' ) ); ?>" class="assistive-text">
					<?php esc_html_e( 'Time Unit', 'jetpack' ); ?>
				</label>

				<select id="<?php echo esc_attr( $this->get_field_id( 'unit' ) ); ?>" class="unit" name="<?php echo esc_attr( $this->get_field_name( 'unit' ) ); ?>">
					<?php
					foreach ( $units as $key => $unit ) {
						printf(
							'<option value="%s" %s>%s</option>',
							esc_attr( $key ),
							selected( $key, $instance['unit'], false ),
							esc_html( $unit )
						);
					}
					?>
				</select>
			</fieldset>

			<ul class="milestone-type">
				<li>
					<label>
						<input
								<?php checked( $instance['type'], 'until' ); ?>
								name="<?php echo esc_attr( $this->get_field_name( 'type' ) ); ?>"
								type="radio"
								value="until"
						/>
						<?php esc_html_e( 'Until your milestone', 'jetpack' ); ?>
					</label>
				</li>

				<li>
					<label>
						<input
								<?php checked( $instance['type'], 'since' ); ?>
								name="<?php echo esc_attr( $this->get_field_name( 'type' ) ); ?>"
								type="radio"
								value="since"
						/>
						<?php esc_html_e( 'Since your milestone', 'jetpack' ); ?>
					</label>
				</li>
			</ul>

			<p class="milestone-message-wrapper">
				<label for="<?php echo esc_attr( $this->get_field_id( 'message' ) ); ?>"><?php esc_html_e( 'Milestone Reached Message', 'jetpack' ); ?></label>
				<textarea id="<?php echo esc_attr( $this->get_field_id( 'message' ) ); ?>" name="<?php echo esc_attr( $this->get_field_name( 'message' ) ); ?>" class="widefat" rows="3"><?php echo esc_textarea( $instance['message'] ); ?></textarea>
			</p>
		</div>

		<?php
	}
}

<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

// phpcs:disable Universal.Files.SeparateFunctionsFromOO.Mixed -- TODO: Move classes to appropriately-named class files.

/**
 * Jetpack_Internet_Defense_League_Widget main class.
 */
class Jetpack_Internet_Defense_League_Widget extends WP_Widget {
	/**
	 * Default widget settings.
	 *
	 * @var array
	 */
	public $defaults = array();

	/**
	 * Selected display variant.
	 *
	 * @var string
	 */
	public $variant;
	/**
	 * Display variants.
	 *
	 * @var array
	 */
	public $variants = array();

	/**
	 * Selected campaign.
	 *
	 * @var string
	 */
	public $campaign;
	/**
	 * Campaign options.
	 *
	 * @var array
	 */
	public $campaigns = array();
	/**
	 * False when enabling campaigns other than 'none' or empty.
	 *
	 * @var bool
	 */
	public $no_current = true;

	/**
	 * Selected badge to display.
	 *
	 * @var string
	 */
	public $badge;
	/**
	 * Badge display options.
	 *
	 * @var array
	 */
	public $badges = array();

	/**
	 * Jetpack_Internet_Defense_League_Widget constructor.
	 */
	public function __construct() {
		parent::__construct(
			'internet_defense_league_widget',
			/** This filter is documented in modules/widgets/facebook-likebox.php */
			apply_filters( 'jetpack_widget_name', esc_html__( 'Internet Defense League', 'jetpack' ) ),
			array(
				'description'                 => esc_html__( 'Show your support for the Internet Defense League.', 'jetpack' ),
				'customize_selective_refresh' => true,
			)
		);

		// When enabling campaigns other than 'none' or empty, change $no_current to false above.
		$this->campaigns = array(
			''     => esc_html__( 'All current and future campaigns', 'jetpack' ),
			'none' => esc_html__( 'None, just display the badge please', 'jetpack' ),
		);

		$this->variants = array(
			'banner' => esc_html__( 'Banner at the top of my site', 'jetpack' ),
			'modal'  => esc_html__( 'Modal (Overlay Box)', 'jetpack' ),
		);

		$this->badges = array(
			'shield_badge'   => esc_html__( 'Shield Badge', 'jetpack' ),
			'super_badge'    => esc_html__( 'Super Badge', 'jetpack' ),
			'side_bar_badge' => esc_html__( 'Red Cat Badge', 'jetpack' ),
		);

		if ( false === $this->no_current ) {
			$this->badges['none'] = esc_html__( 'Don\'t display a badge (just the campaign)', 'jetpack' );
		}

		$this->defaults = array(
			'campaign' => key( $this->campaigns ),
			'variant'  => key( $this->variants ),
			'badge'    => key( $this->badges ),
		);

		add_filter( 'widget_types_to_hide_from_legacy_widget_block', array( $this, 'hide_widget_in_block_editor' ) );
	}

	/**
	 * Remove the "Internet Defense League" widget from the Legacy Widget block
	 *
	 * @param array $widget_types List of widgets that are currently removed from the Legacy Widget block.
	 * @return array $widget_types New list of widgets that will be removed.
	 */
	public function hide_widget_in_block_editor( $widget_types ) {
		$widget_types[] = 'internet_defense_league_widget';
		return $widget_types;
	}

	/**
	 * Display the Widget.
	 *
	 * @see WP_Widget::widget()
	 *
	 * @param array $args     Display arguments.
	 * @param array $instance The settings for the particular instance of the widget.
	 */
	public function widget( $args, $instance ) {
		$instance = wp_parse_args( $instance, $this->defaults );

		if ( 'none' !== $instance['badge'] ) {
			if ( ! isset( $this->badges[ $instance['badge'] ] ) ) {
				$instance['badge'] = $this->defaults['badge'];
			}
			$badge_url        = esc_url( 'https://www.internetdefenseleague.org/images/badges/final/' . $instance['badge'] . '.png' );
			$photon_badge_url = jetpack_photon_url( $badge_url );
			$alt_text         = esc_html__( 'Member of The Internet Defense League', 'jetpack' );
			echo $args['before_widget']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			echo '<p><a href="https://www.internetdefenseleague.org/"><img src="' . esc_url( $photon_badge_url ) . '" alt="' . esc_attr( $alt_text ) . '" style="max-width: 100%; height: auto;" /></a></p>';
			echo $args['after_widget']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		}

		if ( 'none' !== $instance['campaign'] ) {
			$this->campaign = $instance['campaign'];
			$this->variant  = $instance['variant'];
			add_action( 'wp_footer', array( $this, 'footer_script' ) );
		}

		/** This action is already documented in modules/widgets/gravatar-profile.php */
		do_action( 'jetpack_stats_extra', 'widget_view', 'internet_defense_league' );
	}

	/**
	 * Inline footer script.
	 */
	public function footer_script() {
		if ( ! isset( $this->campaigns[ $this->campaign ] ) ) {
			$this->campaign = $this->defaults['campaign'];
		}

		if ( ! isset( $this->variants[ $this->variant ] ) ) {
			$this->variant = $this->defaults['variant'];
		}

		// On AMP endpoints, prevent a validation error from the inline script.
		if ( class_exists( 'Jetpack_AMP_Support' ) && Jetpack_AMP_Support::is_amp_request() ) {
			return;
		}

		?>
		<script type="text/javascript">
			window._idl = {};
			_idl.campaign = "<?php echo esc_js( $this->campaign ); ?>";
			_idl.variant = "<?php echo esc_js( $this->variant ); ?>";
			(function() {
				var idl = document.createElement('script');
				idl.async = true;
				idl.src = 'https://members.internetdefenseleague.org/include/?url=' + (_idl.url || '') + '&campaign=' + (_idl.campaign || '') + '&variant=' + (_idl.variant || 'banner');
				document.getElementsByTagName('body')[0].appendChild(idl);
			})();
		</script>
		<?php
	}

	/**
	 * Widget form in the dashboard.
	 *
	 * @see WP_Widget::form()
	 *
	 * @param array $instance Previously saved values from database.
	 */
	public function form( $instance ) {
		$instance = wp_parse_args( $instance, $this->defaults );

		// Hide first two form fields if no current campaigns.
		if ( false === $this->no_current ) {
			echo '<p><label>';
			echo esc_html__( 'Which Internet Defense League campaign do you want to participate in?', 'jetpack' ) . '<br />';
			$this->select( 'campaign', $this->campaigns, $instance['campaign'] );
			echo '</label></p>';

			echo '<p><label>';
			echo esc_html__( 'How do you want to promote the campaign?', 'jetpack' ) . '<br />';
			$this->select( 'variant', $this->variants, $instance['variant'] );
			echo '</label></p>';
		}

		echo '<p><label>';
		echo esc_html__( 'Which badge would you like to display?', 'jetpack' ) . '<br />';
		$this->select( 'badge', $this->badges, $instance['badge'] );
		echo '</label></p>';

		echo '<p>' . wp_kses(
			sprintf(
				/* translators: %s is an HTML link to the website of an internet campaign called the "Internet Defense League" */
				_x( 'Learn more about the %s', 'the Internet Defense League', 'jetpack' ),
				'<a href="https://www.internetdefenseleague.org/">Internet Defense League</a>'
			),
			array(
				'a' => array(
					'href' => array(),
				),
			)
		) . '</p>';
	}

	/**
	 * Display a select form field.
	 *
	 * @param string $field_name Name of the field.
	 * @param array  $options Array of options.
	 * @param string $default Default option.
	 */
	public function select( $field_name, $options, $default = null ) {
		echo '<select class="widefat" name="' . esc_attr( $this->get_field_name( $field_name ) ) . '">';
		foreach ( $options as $option_slug => $option_name ) {
			echo '<option value="' . esc_attr( $option_slug ) . '"' . selected( $option_slug, $default, false ) . '>' . esc_html( $option_name ) . '</option>';
		}
		echo '</select>';
	}

	/**
	 * Update widget.
	 *
	 * @see WP_Widget::update()
	 *
	 * @param array $new_instance New widget instance data.
	 * @param array $old_instance Old widget instance data.
	 */
	public function update( $new_instance, $old_instance ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		$instance = array();

		$instance['campaign'] = ( isset( $new_instance['campaign'] ) && isset( $this->campaigns[ $new_instance['campaign'] ] ) ) ? $new_instance['campaign'] : $this->defaults['campaign'];
		$instance['variant']  = ( isset( $new_instance['variant'] ) && isset( $this->variants[ $new_instance['variant'] ] ) ) ? $new_instance['variant'] : $this->defaults['variant'];
		$instance['badge']    = ( isset( $new_instance['badge'] ) && isset( $this->badges[ $new_instance['badge'] ] ) ) ? $new_instance['badge'] : $this->defaults['badge'];

		return $instance;
	}
}

/**
 * Register the widget.
 */
function jetpack_internet_defense_league_init() {
	register_widget( 'Jetpack_Internet_Defense_League_Widget' );
}

add_action( 'widgets_init', 'jetpack_internet_defense_league_init' );

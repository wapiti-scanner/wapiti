<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName

use Automattic\Jetpack\Assets;

// Exit if file is accessed directly.
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Class to include elements to modify Related Posts look in Customizer.
 *
 * @since 4.4.0
 */
class Jetpack_Related_Posts_Customize {

	/**
	 * Key for panel, section and prefix for options. Same option name than in Options > Reading.
	 *
	 * @var string
	 */
	public $prefix = 'jetpack_relatedposts';

	/**
	 * Control to focus when customizer loads
	 *
	 * @var string
	 */
	public $focus = '';

	/**
	 * Class initialization.
	 *
	 * @since 4.4.0
	 */
	public function __construct() {
		add_action( 'customize_register', array( $this, 'customize_register' ) );
		add_action( 'customize_controls_enqueue_scripts', array( $this, 'customize_controls_enqueue_scripts' ) );
	}

	/**
	 * Initialize Customizer controls.
	 *
	 * @since 4.4.0
	 *
	 * @param WP_Customize_Manager $wp_customize Customizer instance.
	 */
	public function customize_register( $wp_customize ) {

		$wp_customize->add_section(
			$this->prefix,
			array(
				'title'       => esc_html__( 'Related Posts', 'jetpack' ),
				'description' => '',
				'capability'  => 'edit_theme_options',
				'priority'    => 200,
			)
		);

		$selective_options = array();

		foreach ( $this->get_options( $wp_customize ) as $key => $field ) {
			$control_id          = "$this->prefix[$key]";
			$selective_options[] = $control_id;
			$wp_customize->add_setting(
				$control_id,
				array(
					'default'    => isset( $field['default'] ) ? $field['default'] : '',
					'type'       => isset( $field['setting_type'] ) ? $field['setting_type'] : 'option',
					'capability' => isset( $field['capability'] ) ? $field['capability'] : 'edit_theme_options',
					'transport'  => isset( $field['transport'] ) ? $field['transport'] : 'postMessage',
				)
			);
			$control_settings = array(
				'label'           => isset( $field['label'] ) ? $field['label'] : '',
				'description'     => isset( $field['description'] ) ? $field['description'] : '',
				'settings'        => $control_id,
				'type'            => isset( $field['control_type'] ) ? $field['control_type'] : 'text',
				'section'         => $this->prefix,
				'priority'        => 10,
				'active_callback' => isset( $field['active_callback'] ) ? $field['active_callback'] : __CLASS__ . '::is_single',
			);
			switch ( $field['control_type'] ) {
				case 'text':
				case 'checkbox':
				default:
					$wp_customize->add_control( new WP_Customize_Control( $wp_customize, $control_id, $control_settings ) );
					break;
				case 'select':
					if ( isset( $field['choices'] ) ) {
						$control_settings['choices'] = $field['choices'];
						$wp_customize->add_control( new WP_Customize_Control( $wp_customize, $control_id, $control_settings ) );
					}
					break;
				case 'message':
					$wp_customize->add_control( new Jetpack_Message_Control( $wp_customize, $control_id, $control_settings ) );
					break;
			}
		}

		// If selective refresh is available, implement it.
		if ( isset( $wp_customize->selective_refresh ) ) {
			$wp_customize->selective_refresh->add_partial(
				"$this->prefix",
				array(
					'selector'            => '.jp-relatedposts:not(.jp-relatedposts-block)',
					'settings'            => $selective_options,
					'render_callback'     => __CLASS__ . '::render_callback',
					'container_inclusive' => false,
				)
			);
		}
	}

	/**
	 * Callback that outputs the headline based on user choice.
	 *
	 * @since 4.4.0
	 */
	public static function render_callback() {
		echo Jetpack_RelatedPosts::init()->get_headline(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- content escaped in get_headline method
	}

	/**
	 * Check whether the current post contains a Related Posts block.
	 *
	 * @since 6.9.0
	 *
	 * @return bool
	 */
	public static function contains_related_posts_block() {
		if ( has_block( 'jetpack/related-posts' ) ) {
			return true;
		}

		return false;
	}

	/**
	 * Check that we're in a single post view.
	 * Will return `false` if the current post contains a Related Posts block,
	 * because in that case we want to hide the Customizer controls.
	 *
	 * @since 4.4.0
	 *
	 * @return bool
	 */
	public static function is_single() {
		if ( self::contains_related_posts_block() ) {
			return false;
		}
		return is_single();
	}

	/**
	 * Check that we're not in a single post view.
	 * Will return `false` if the current post contains a Related Posts block,
	 * because in that case we want to hide the Customizer controls.
	 *
	 * @since 4.4.0
	 *
	 * @return bool
	 */
	public static function is_not_single() {
		if ( self::contains_related_posts_block() ) {
			return false;
		}
		return ! is_single();
	}

	/**
	 * Return list of options to modify.
	 *
	 * @since 4.4.0
	 *
	 * @param object $wp_customize Instance of WP Customizer.
	 *
	 * @return mixed|void
	 */
	public function get_options( $wp_customize ) {
		$transport = isset( $wp_customize->selective_refresh ) ? 'postMessage' : 'refresh';

		$switched_locale = switch_to_locale( get_user_locale() );
		$headline        = __( 'Related', 'jetpack' );
		if ( $switched_locale ) {
			restore_previous_locale();
		}

		/**
		 * The filter allows you to change the options used to display Related Posts in the Customizer.
		 *
		 * @module related-posts
		 *
		 * @since 4.4.0
		 *
		 * @param array $options Array of options used to display Related Posts in the Customizer.
		 */
		return apply_filters(
			'jetpack_related_posts_customize_options',
			array(
				'enabled'          => array(
					'control_type' => 'hidden',
					'default'      => 1,
					'setting_type' => 'option',
					'transport'    => $transport,
				),
				'show_headline'    => array(
					'label'        => esc_html__( 'Show a headline', 'jetpack' ),
					'description'  => esc_html__( 'This helps to clearly separate the related posts from post content.', 'jetpack' ),
					'control_type' => 'checkbox',
					'default'      => 1,
					'setting_type' => 'option',
					'transport'    => $transport,
				),
				'headline'         => array(
					'label'        => '',
					'description'  => esc_html__( 'Enter text to use as headline.', 'jetpack' ),
					'control_type' => 'text',
					'default'      => esc_html( $headline ),
					'setting_type' => 'option',
					'transport'    => $transport,
				),
				'show_thumbnails'  => array(
					'label'        => esc_html__( 'Show thumbnails', 'jetpack' ),
					'description'  => esc_html__( 'Show a thumbnail image where available.', 'jetpack' ),
					'control_type' => 'checkbox',
					'default'      => 1,
					'setting_type' => 'option',
					'transport'    => $transport,
				),
				'show_date'        => array(
					'label'        => esc_html__( 'Show date', 'jetpack' ),
					'description'  => esc_html__( 'Display date when entry was published.', 'jetpack' ),
					'control_type' => 'checkbox',
					'default'      => 1,
					'setting_type' => 'option',
					'transport'    => $transport,
				),
				'show_context'     => array(
					'label'        => esc_html__( 'Show context', 'jetpack' ),
					'description'  => esc_html__( "Display entry's category or tag.", 'jetpack' ),
					'control_type' => 'checkbox',
					'default'      => 1,
					'setting_type' => 'option',
					'transport'    => $transport,
				),
				'layout'           => array(
					'label'        => esc_html__( 'Layout', 'jetpack' ),
					'description'  => esc_html__( 'Arrange entries in different layouts.', 'jetpack' ),
					'control_type' => 'select',
					'choices'      => array(
						'grid' => esc_html__( 'Grid', 'jetpack' ),
						'list' => esc_html__( 'List', 'jetpack' ),
					),
					'default'      => 'grid',
					'setting_type' => 'option',
					'transport'    => $transport,
				),
				'msg_go_to_single' => array(
					'description'     => esc_html__( 'Please visit a single post view to reveal the customization options.', 'jetpack' ),
					'control_type'    => 'message',
					'active_callback' => __CLASS__ . '::is_not_single',
				),
				'msg_example'      => array(
					'description'  => esc_html__( 'Please note that the related posts displayed now are only for previewing purposes.', 'jetpack' ),
					'control_type' => 'message',
				),
			)
		);
	}

	/**
	 * Enqueue assets for Customizer controls.
	 *
	 * @since 4.4.0
	 */
	public function customize_controls_enqueue_scripts() {
		wp_enqueue_script(
			'jetpack_related-posts-customizer',
			Assets::get_file_url_for_environment(
				'_inc/build/related-posts/related-posts-customizer.min.js',
				'modules/related-posts/related-posts-customizer.js'
			),
			array( 'customize-controls' ),
			JETPACK__VERSION,
			false
		);
	}

} // class end

/**
 * Control that displays a message in Customizer.
 *
 * @since 4.4.0
 * @todo break this out into its own file.
 */
class Jetpack_Message_Control extends WP_Customize_Control { // phpcs:ignore

	/**
	 * Render the message.
	 *
	 * @since 4.4.0
	 */
	public function render_content() {
		echo '<p class="description">' . esc_html( $this->description ) . '</p>';
	}
} // class end

// Initialize controls.
new Jetpack_Related_Posts_Customize();

<?php // phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * MailChimp popup widget.
 * It acts as a wrapper for the mailchimp_subscriber_popup shortcode.
 *
 * @package automattic/jetpack
 */

// phpcs:disable Universal.Files.SeparateFunctionsFromOO.Mixed -- TODO: Move classes to appropriately-named class files.

if ( ! class_exists( 'Jetpack_MailChimp_Subscriber_Popup_Widget' ) ) {

	if ( ! class_exists( 'MailChimp_Subscriber_Popup' ) ) {
		include_once JETPACK__PLUGIN_DIR . 'modules/shortcodes/mailchimp.php';
	}

	/**
	 * Register MailChimp Subscriber Popup widget.
	 */
	function jetpack_mailchimp_subscriber_popup_widget_init() {
		register_widget( 'Jetpack_MailChimp_Subscriber_Popup_Widget' );
	}

	add_action( 'widgets_init', 'jetpack_mailchimp_subscriber_popup_widget_init' );

	/**
	 * Add a MailChimp subscription form.
	 */
	class Jetpack_MailChimp_Subscriber_Popup_Widget extends WP_Widget {

		/**
		 * Constructor
		 */
		public function __construct() {
			parent::__construct(
				'widget_mailchimp_subscriber_popup',
				/** This filter is documented in modules/widgets/facebook-likebox.php */
				apply_filters( 'jetpack_widget_name', __( 'MailChimp Subscriber Popup', 'jetpack' ) ),
				array(
					'classname'                   => 'widget_mailchimp_subscriber_popup',
					'description'                 => __( 'Allows displaying a popup subscription form to visitors.', 'jetpack' ),
					'customize_selective_refresh' => true,
				)
			);

			add_filter( 'widget_types_to_hide_from_legacy_widget_block', array( $this, 'hide_widget_in_block_editor' ) );
		}

		/**
		 * Remove the "Mailchimp Subscriber Popup" widget from the Legacy Widget block
		 *
		 * @param array $widget_types List of widgets that are currently removed from the Legacy Widget block.
		 * @return array $widget_types New list of widgets that will be removed.
		 */
		public function hide_widget_in_block_editor( $widget_types ) {
			$widget_types[] = 'widget_mailchimp_subscriber_popup';
			return $widget_types;
		}

		/**
		 * Outputs the HTML for this widget.
		 *
		 * @param array $args     An array of standard parameters for widgets in this theme.
		 * @param array $instance An array of settings for this widget instance.
		 *
		 * @return void Echoes it's output
		 */
		public function widget( $args, $instance ) {
			$instance = wp_parse_args( $instance, array( 'code' => '' ) );

			// Regular expresion that will match maichimp shortcode.
			$regex = '(\[mailchimp_subscriber_popup[^\]]+\])';

			// Check if the shortcode exists.
			preg_match( $regex, $instance['code'], $matches );

			// Process the shortcode only, if exists.
			if ( ! empty( $matches[0] ) ) {
				echo do_shortcode( $matches[0] );
			}

			/** This action is documented in modules/widgets/gravatar-profile.php */
			do_action( 'jetpack_stats_extra', 'widget_view', 'mailchimp_subscriber_popup' );
		}

		/**
		 * Deals with the settings when they are saved by the admin.
		 *
		 * @param array $new_instance New configuration values.
		 * @param array $old_instance Old configuration values.
		 *
		 * @return array
		 */
		public function update( $new_instance, $old_instance ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
			$instance         = array();
			$instance['code'] = MailChimp_Subscriber_Popup::reversal( $new_instance['code'] );

			return $instance;
		}

		/**
		 * Displays the form for this widget on the Widgets page of the WP Admin area.
		 *
		 * @param array $instance Instance configuration.
		 *
		 * @return void
		 */
		public function form( $instance ) {
			$instance = wp_parse_args( $instance, array( 'code' => '' ) );

			$label = sprintf(
				wp_kses(
					/* Translators: %s is a link to the MailChimp support docs. */
					__( 'Code: <a href="%s" target="_blank">( ? )</a>', 'jetpack' ),
					array(
						'a' => array(
							'href'   => array(),
							'target' => array(),
						),
					)
				),
				'https://en.support.wordpress.com/mailchimp/'
			);

			printf(
				'<p><label for="%1$s">%4$s</label><textarea class="widefat" id="%1$s" name="%2$s" rows="3">%3$s</textarea></p>',
				esc_attr( $this->get_field_id( 'code' ) ),
				esc_attr( $this->get_field_name( 'code' ) ),
				esc_textarea( $instance['code'] ),
				$label // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped above.
			);
		}
	}
}

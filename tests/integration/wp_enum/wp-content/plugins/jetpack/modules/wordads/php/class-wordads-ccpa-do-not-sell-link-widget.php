<?php
/**
 * CCPA Do Not Sell Widget
 *
 * @package automattic/jetpack
 */

/**
 * Class WordAds_Ccpa_Do_Not_Sell_Link_Widget
 */
class WordAds_Ccpa_Do_Not_Sell_Link_Widget extends WP_Widget {

	/**
	 * WordAds_Ccpa_Do_Not_Sell_Link_Widget constructor.
	 */
	public function __construct() {
		parent::__construct(
			'wordads_ccpa_do_not_sell_link_widget',
			/** This filter is documented in modules/widgets/facebook-likebox.php */
			apply_filters( 'jetpack_widget_name', __( 'Do Not Sell Link (US Privacy)', 'jetpack' ) ),
			array(
				'description'                 => __( 'Inserts "Do Not Sell or Share My Personal Information" link required by some US states to opt-out of targeted advertising', 'jetpack' ),
				'customize_selective_refresh' => true,
			)
		);
	}

	/**
	 * Widget outputter.
	 *
	 * @param array $args Widget args.
	 * @param array $instance Widget instance.
	 */
	public function widget( $args, $instance ) { // phpcs:ignore VariableAnalysis.CodeAnalysis.VariableAnalysis.UnusedVariable
		echo $args['before_widget']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		echo do_shortcode( '[privacy-do-not-sell-link]' );
		echo $args['after_widget']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
	}
}

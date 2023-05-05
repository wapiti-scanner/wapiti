<?php
/**
 * Widget for adding ads to a sidebar.
 *
 * @package automattic/jetpack
 */

/**
 * Widget for inserting an ad into your sidebar
 *
 * @since 4.5.0
 */
class WordAds_Sidebar_Widget extends WP_Widget {

	/**
	 * Allowed tags.
	 *
	 * @var string[]
	 */
	private static $allowed_tags = array( 'mrec', 'wideskyscraper', 'leaderboard' );

	/**
	 * Number of widgets.
	 *
	 * @var int
	 */
	private static $num_widgets = 0;

	/**
	 * WordAds_Sidebar_Widget constructor.
	 */
	public function __construct() {
		parent::__construct(
			'wordads_sidebar_widget',
			/** This filter is documented in modules/widgets/facebook-likebox.php */
			apply_filters( 'jetpack_widget_name', 'Ads' ),
			array(
				'description'                 => __( 'Insert an ad unit wherever you can place a widget.', 'jetpack' ),
				'customize_selective_refresh' => true,
			)
		);

		add_filter( 'widget_types_to_hide_from_legacy_widget_block', array( $this, 'hide_widget_in_block_editor' ) );
	}

	/**
	 * Remove the Ad widget from the Legacy Widget block
	 *
	 * @param array $widget_types List of widgets that are currently removed from the Legacy Widget block.
	 *
	 * @return array $widget_types New list of widgets that will be removed.
	 */
	public function hide_widget_in_block_editor( $widget_types ) {
		$widget_types[] = 'wordads_sidebar_widget';
		return $widget_types;
	}

	/**
	 * The Widget outputter.
	 *
	 * @param array $args Widget args.
	 * @param array $instance The Widget instance.
	 *
	 * @return bool|void
	 */
	public function widget( $args, $instance ) {
		global $wordads;
		if ( $wordads->should_bail() ) {
			return false;
		}

		if ( ! isset( $instance['unit'] ) ) {
			$instance['unit'] = 'mrec';
		}

		++self::$num_widgets;
		$about      = __( 'Advertisements', 'jetpack' );
		$width      = WordAds::$ad_tag_ids[ $instance['unit'] ]['width'];
		$height     = WordAds::$ad_tag_ids[ $instance['unit'] ]['height'];
		$unit_id    = 1 === self::$num_widgets ? 3 : self::$num_widgets + 3; // 2nd belowpost is '4'
		$section_id = 0 === $wordads->params->blog_id ?
			WORDADS_API_TEST_ID :
			$wordads->params->blog_id . $unit_id;

		$snippet = '';
		if ( $wordads->option( 'wordads_house', true ) ) {
			$unit = 'mrec';
			if ( 'leaderboard' === $instance['unit'] && ! $this->params->mobile_device ) {
				$unit = 'leaderboard';
			} elseif ( 'wideskyscraper' === $instance['unit'] ) {
				$unit = 'widesky';
			}

			$snippet = $wordads->get_house_ad( $unit );
		} else {
			// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
			echo $wordads->get_ad_snippet( $section_id, $height, $width, 'widget' );
			return;
		}

		?>
		<div class="wpcnt">
			<div class="wpa">
				<span class="wpa-about"><?php echo esc_html( $about ); ?></span>
				<div class="u <?php echo esc_attr( $instance['unit'] ); ?>">
					<?php echo $snippet; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * The widget settings form.
	 *
	 * @param array $instance Widget instance.
	 *
	 * @return string|void
	 */
	public function form( $instance ) {
		// ad unit type.
		if ( isset( $instance['unit'] ) ) {
			$unit = $instance['unit'];
		} else {
			$unit = 'mrec';
		}
		?>
		<p>
			<label for="<?php echo esc_attr( $this->get_field_id( 'unit' ) ); ?>"><?php esc_html_e( 'Tag Dimensions:', 'jetpack' ); ?></label>
			<select class="widefat" id="<?php echo esc_attr( $this->get_field_id( 'unit' ) ); ?>" name="<?php echo esc_attr( $this->get_field_name( 'unit' ) ); ?>">
		<?php
		foreach ( WordAds::$ad_tag_ids as $ad_unit => $properties ) {
			if ( ! in_array( $ad_unit, self::$allowed_tags, true ) ) {
				continue;
			}

				$splits      = explode( '_', $properties['tag'] );
				$unit_pretty = "{$splits[0]} {$splits[1]}";
				$selected    = selected( $ad_unit, $unit, false );
				echo "<option value='", esc_attr( $ad_unit ) ,"' ", esc_attr( $selected ), '>', esc_html( $unit_pretty ) , '</option>';
		}
		?>
			</select>
		</p>
		<?php
	}

	/**
	 * The Widget updater.
	 *
	 * @param array $new_instance The revised instance.
	 * @param array $old_instance Original instance.
	 *
	 * @return array
	 */
	public function update( $new_instance, $old_instance ) {
		$instance = $old_instance;

		if ( in_array( $new_instance['unit'], self::$allowed_tags, true ) ) {
			$instance['unit'] = $new_instance['unit'];
		} else {
			$instance['unit'] = 'mrec';
		}

		return $instance;
	}
}

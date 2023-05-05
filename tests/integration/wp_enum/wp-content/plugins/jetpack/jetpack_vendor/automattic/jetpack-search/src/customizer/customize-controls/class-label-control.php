<?php
/**
 * A label-only Customizer control for use with Jetpack Search configuration
 *
 * @package automattic/jetpack
 * @since 8.6.0
 */

namespace Automattic\Jetpack\Search;

use WP_Customize_Control;

if ( ! class_exists( 'WP_Customize_Control' ) ) {
	return;
}
/**
 * Label Control class.
 */
class Label_Control extends WP_Customize_Control {
	/**
	 * Override rendering for custom class name; omit element ID.
	 */
	protected function render() {
		echo '<li class="customize-control customize-label-control">';
		$this->render_content();
		echo '</li>';
	}

	/**
	 * Override content rendering.
	 */
	protected function render_content() {
		if ( ! empty( $this->label ) ) : ?>
			<label class="customize-control-title">
				<?php echo esc_html( $this->label ); ?>
			</label>
		<?php endif; ?>
		<?php if ( ! empty( $this->description ) ) : ?>
			<span class="description customize-control-description">
				<?php echo esc_html( $this->description ); ?>
			</span>
			<?php
		endif;
	}
}

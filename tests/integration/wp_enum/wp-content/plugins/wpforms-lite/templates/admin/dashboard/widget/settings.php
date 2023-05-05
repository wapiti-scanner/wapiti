<?php
/**
 * Dashboard widget settings gear icon template.
 *
 * @since 1.7.4
 *
 * @var int  $graph_style  Graph style, value 1 for Bar style, 2 for Line style.
 * @var int  $color_scheme Color scheme, value 1 for WPForms color scheme, 2 for for WordPress color scheme.
 * @var bool $enabled      If form fields should be enabled.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$disabled = ! $enabled;

?>
<div class="wpforms-dash-widget-settings-container">
	<button id="wpforms-dash-widget-settings-button" class="wpforms-dash-widget-settings-button button" type="button">
		<span class="dashicons dashicons-admin-generic"></span>
	</button>
	<div class="wpforms-dash-widget-settings-menu <?php echo $disabled ? 'disabled' : ''; ?>">
		<div class="wpforms-dash-widget-settings-menu-wrap">
			<h4><?php esc_html_e( 'Graph Style', 'wpforms-lite' ); ?></h4>
			<div>
				<div class="wpforms-dash-widget-settings-menu-item">
					<input type="radio" id="wpforms-dash-widget-settings-style-bar" name="wpforms-style" value="1" <?php checked( '1', $graph_style ); ?> <?php disabled( $disabled ); ?>>
					<label for="wpforms-dash-widget-settings-style-bar" <?php disabled( $disabled ); ?>><?php esc_html_e( 'Bar', 'wpforms-lite' ); ?></label>
				</div>
				<div class="wpforms-dash-widget-settings-menu-item">
					<input type="radio" id="wpforms-dash-widget-settings-style-line" name="wpforms-style" value="2" <?php checked( '2', $graph_style ); ?> <?php disabled( $disabled ); ?>>
					<label for="wpforms-dash-widget-settings-style-line" <?php disabled( $disabled ); ?>><?php esc_html_e( 'Line', 'wpforms-lite' ); ?></label>
				</div>
			</div>
		</div>
		<div class="wpforms-dash-widget-settings-menu-wrap color-scheme">
			<h4><?php esc_html_e( 'Color Scheme', 'wpforms-lite' ); ?></h4>
			<div>
				<div class="wpforms-dash-widget-settings-menu-item">
					<input type="radio" id="wpforms-dash-widget-settings-color-wpforms" name="wpforms-color" value="1" <?php checked( '1', $color_scheme ); ?> <?php disabled( $disabled ); ?>>
					<label for="wpforms-dash-widget-settings-color-wpforms" <?php disabled( $disabled ); ?>><?php esc_html_e( 'WPForms', 'wpforms-lite' ); ?></label>
				</div>
				<div class="wpforms-dash-widget-settings-menu-item">
					<input type="radio" id="wpforms-dash-widget-settings-color-wp" name="wpforms-color" value="2" <?php checked( '2', $color_scheme ); ?> <?php disabled( $disabled ); ?>>
					<label for="wpforms-dash-widget-settings-color-wp" <?php disabled( $disabled ); ?>><?php esc_html_e( 'WordPress', 'wpforms-lite' ); ?></label>
				</div>
			</div>
		</div>
		<button type="button" class="button wpforms-dash-widget-settings-menu-save" <?php disabled( $disabled ); ?>><?php esc_html_e( 'Save Changes', 'wpforms-lite' ); ?></button>
	</div>
</div>

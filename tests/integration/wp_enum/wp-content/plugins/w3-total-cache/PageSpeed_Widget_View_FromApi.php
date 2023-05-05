<?php
/**
 * File: PageSpeed_Widget_View_FromApi.php
 *
 * Template file for PageSpeed dashboard widget.
 *
 * @since 2.3.0 Update to utilize OAuth2.0 and overhaul of feature.
 *
 * @package W3TC
 */

namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}

?>
<div class="metabox-holder">
	<?php
	if ( isset( $api_response_error['error'] ) && ! empty( $api_response_error['error'] ) ) {
		?>
		<div class="w3tcps_feedback">
			<div class="notice notice-error inline w3tcps_error">
				<p><?php echo wp_kses( $api_response_error['error'], Util_PageSpeed::get_allowed_tags() ); ?></p>
			</div>
		</div>
		<?php
	} elseif ( ! empty( $api_response['mobile']['error'] ) || ! empty( $api_response['desktop']['error'] ) ) {
		?>
		<div class="w3tcps_feedback">
			<div class="notice notice-error inline w3tcps_error">
				<p><?php esc_html_e( 'An error has occured!', 'w3-total-cache' ); ?></p>
				<p><?php esc_html_e( 'Mobile: ', 'w3-total-cache' ) . esc_html( $api_response['mobile']['error'] ); ?></p>
				<p><?php esc_html_e( 'Desktop: ', 'w3-total-cache' ) . esc_html( $api_response['desktop']['error'] ); ?></p>
			</div>
		</div>
		<?php
	} else {
		?>
		<div id="w3tcps_legend">
			<div class="w3tcps_gages">
				<div class="w3tcps_gauge_desktop">
					<?php Util_PageSpeed::print_gauge( $api_response['desktop'], 'desktop' ); ?>
				</div>
				<div class="w3tcps_gauge_mobile">
					<?php Util_PageSpeed::print_gauge( $api_response['mobile'], 'smartphone' ); ?>
				</div>
			</div>
			<?php
			echo wp_kses(
				sprintf(
					// translators: 1 opening HTML span tag, 2 opening HTML a tag to web.dev/performance-soring, 3 closing HTML a tag,
					// translators: 4 opening HTML a tag to googlechrome.github.io Lighthouse Score Calculator, 5 closing HTML a tag,
					// translators: 6 closing HTML p tag.
					__(
						'%1$sValues are estimated and may vary. The %2$sperformance score is calculated%3$s directly from these metrics. %4$sSee calculator.%5$s%6$s',
						'w3-total-cache'
					),
					'<p class="w3tcps_legend_description">',
					'<a rel="noopener" target="_blank" href="' . esc_url( 'https://web.dev/performance-scoring/?utm_source=lighthouse&amp;utm_medium=lr' ) . '">',
					'</a>',
					'<a target="_blank" href="' . esc_url( 'https://googlechrome.github.io/lighthouse/scorecalc/#FCP=1028&amp;TTI=1119&amp;SI=1028&amp;TBT=18&amp;LCP=1057&amp;CLS=0&amp;FMP=1028&amp;device=desktop&amp;version=9.0.0' ) . '">',
					'</a>',
					'</p>'
				),
				Util_PageSpeed::get_allowed_tags()
			);
			?>
			<div class="w3tcps_ranges">
				<span class="w3tcps_range w3tcps_fail"><?php esc_html_e( '0–49', 'w3-total-cache' ); ?></span>
				<span class="w3tcps_range w3tcps_average"><?php esc_html_e( '50–89', 'w3-total-cache' ); ?></span>
				<span class="w3tcps_range w3tcps_pass"><?php esc_html_e( '90–100', 'w3-total-cache' ); ?></span>
			</div>
		</div>
		<div id="w3tcps_widget_metrics_container" class="tab-content w3tcps_content">
			<div class="w3tcps_widget_metrics">
				<?php Util_PageSpeed::print_bar_combined_with_icon( $api_response, 'first-contentful-paint', 'First Contentful Paint' ); ?>
				<?php Util_PageSpeed::print_bar_combined_with_icon( $api_response, 'speed-index', 'Speed Index' ); ?>
				<?php Util_PageSpeed::print_bar_combined_with_icon( $api_response, 'largest-contentful-paint', 'Largest Contentful Paint' ); ?>
				<?php Util_PageSpeed::print_bar_combined_with_icon( $api_response, 'interactive', 'Time to Interactive' ); ?>
				<?php Util_PageSpeed::print_bar_combined_with_icon( $api_response, 'total-blocking-time', 'Total Blocking Time' ); ?>
				<?php Util_PageSpeed::print_bar_combined_with_icon( $api_response, 'cumulative-layout-shift', 'Cumulative Layout Shift' ); ?>
			</div>
		</div>
		<?php
	}
	?>
</div>

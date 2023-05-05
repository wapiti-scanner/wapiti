<?php
/**
 * File: PageSpeed_Page_View_FromAPI.php
 *
 * Template file for PageSpeed page.
 *
 * @since 2.3.0 Update to utilize OAuth2.0 and overhaul of feature.
 *
 * @package W3TC
 */

namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}

/**
 * Get the active tab and icon from the $_GET param.
 *
 * @var string
 */
$current_tab = ( ! empty( $_GET['tab'] ) ? Util_Request::get( 'tab' ) : 'mobile' );

?>
<div id="w3tcps_container">
	<div class="w3tcps_content">
		<div id="w3tcps_home">
			<div class="page_post">
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
							<p><?php echo esc_html( $api_response['mobile']['error'] ); ?></p>
							<p><?php echo esc_html( $api_response['desktop']['error'] ); ?></p>
						</div>
					</div>
					<?php
				} else {
					?>
					<div id="w3tc" class="wrap">
						<nav class="nav-tab-wrapper">
							<a href="#" id="w3tcps_control_mobile" class="nav-tab <?php echo ( 'mobile' === $current_tab ? 'nav-tab-active' : '' ); ?>"><?php esc_html_e( 'Mobile', 'w3-total-cache' ); ?></a>
							<a href="#" id="w3tcps_control_desktop" class="nav-tab <?php echo ( 'desktop' === $current_tab ? 'nav-tab-active' : '' ); ?>"><?php esc_html_e( 'Desktop', 'w3-total-cache' ); ?></a>
						</nav>
						<div class="metabox-holder">
							<?php
							$analysis_types = array(
								'desktop' => 'desktop',
								'mobile'  => 'smartphone',
							);
							foreach ( $analysis_types as $analysis_type => $icon ) {
								?>
								<div id="w3tcps_<?php echo esc_attr( $analysis_type ); ?>" class="tab-content w3tcps_content">
									<div id="w3tcps_legend_<?php echo esc_attr( $analysis_type ); ?>">
										<?php Util_Ui::postbox_header( __( 'Legend', 'w3-total-cache' ), '', 'w3tcps-legend' ); ?>
										<div class="w3tcps_gauge_<?php echo esc_attr( $analysis_type ); ?>">
											<?php Util_PageSpeed::print_gauge( $api_response[ $analysis_type ], $icon ); ?>
										</div>
										<?php
										echo wp_kses(
											sprintf(
												// translators: 1 opening HTML p tag, 2 opening HTML a tag to web.dev/performance-soring, 3 closing HTML a tag,
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
										<?php Util_Ui::postbox_footer(); ?>
									</div>
									<div class="w3tcps_metrics_<?php echo esc_attr( $analysis_type ); ?>">
										<?php Util_Ui::postbox_header( __( 'Core Metrics', 'w3-total-cache' ), '', 'w3tcps-core-metrics' ); ?>
										<?php Util_PageSpeed::print_bar_single_no_icon( $api_response[ $analysis_type ], 'first-contentful-paint', 'First Contentful Paint' ); ?>
										<?php Util_PageSpeed::print_bar_single_no_icon( $api_response[ $analysis_type ], 'speed-index', 'Speed Index' ); ?>
										<?php Util_PageSpeed::print_bar_single_no_icon( $api_response[ $analysis_type ], 'largest-contentful-paint', 'Largest Contentful Paint' ); ?>
										<?php Util_PageSpeed::print_bar_single_no_icon( $api_response[ $analysis_type ], 'interactive', 'Time to Interactive' ); ?>
										<?php Util_PageSpeed::print_bar_single_no_icon( $api_response[ $analysis_type ], 'total-blocking-time', 'Total Blocking Time' ); ?>
										<?php Util_PageSpeed::print_bar_single_no_icon( $api_response[ $analysis_type ], 'cumulative-layout-shift', 'Cumulative Layout Shift' ); ?>
										<?php Util_Ui::postbox_footer(); ?>
									</div>
									<div class="w3tcps_screenshots_<?php echo esc_attr( $analysis_type ); ?>">
										<?php Util_Ui::postbox_header( __( 'Screenshots', 'w3-total-cache' ), '', 'w3tcps-screenshots' ); ?>
										<div class="w3tcps_screenshots_other_<?php echo esc_attr( $analysis_type ); ?>">
											<h3 class="w3tcps_metric_title"><?php esc_html_e( 'Pageload Thumbnails', 'w3-total-cache' ); ?></h3>
											<div class="w3tcps_other_screenshot_container"><?php Util_PageSpeed::print_screenshots( $api_response[ $analysis_type ] ); ?></div>
										</div>
										<div class="w3tcps_screenshots_final_<?php echo esc_attr( $analysis_type ); ?>">
											<h3 class="w3tcps_metric_title"><?php esc_html_e( 'Final Screenshot', 'w3-total-cache' ); ?></h3>
											<div class="w3tcps_final_screenshot_container"><?php Util_PageSpeed::print_final_screenshot( $api_response[ $analysis_type ] ); ?></div>
										</div>
										<?php Util_Ui::postbox_footer(); ?>
									</div>
									<div class="w3tcps_breakdown w3tcps_breakdown_<?php echo esc_attr( $analysis_type ); ?>">
										<?php Util_Ui::postbox_header( __( 'Audit Results', 'w3-total-cache' ), '', 'w3tcps-audit-results' ); ?>
										<div id="w3tcps_audit_filters_<?php echo esc_attr( $analysis_type ); ?>" class="nav-tab-wrapper">
											<a href="#" title="<?php esc_attr_e( 'ALL', 'w3-total-cache' ); ?>" class="w3tcps_audit_filter nav-tab nav-tab-active"><?php esc_html_e( 'ALL', 'w3-total-cache' ); ?></a>
											<a href="#" title="<?php esc_attr_e( 'First Contentful Paint', 'w3-total-cache' ); ?>" class="w3tcps_audit_filter nav-tab"><?php esc_html_e( 'FCP', 'w3-total-cache' ); ?></a>
											<a href="#" title="<?php esc_attr_e( 'Total Blocking Time', 'w3-total-cache' ); ?>" class="w3tcps_audit_filter nav-tab"><?php esc_html_e( 'TBT', 'w3-total-cache' ); ?></a>
											<a href="#" title="<?php esc_attr_e( 'Largest Contentful Paint', 'w3-total-cache' ); ?>" class="w3tcps_audit_filter nav-tab"><?php esc_html_e( 'LCP', 'w3-total-cache' ); ?></a>
											<a href="#" title="<?php esc_attr_e( 'Cumulative Layout Shift', 'w3-total-cache' ); ?>" class="w3tcps_audit_filter nav-tab"><?php esc_html_e( 'CLS', 'w3-total-cache' ); ?></a>
										</div>
										<?php Util_PageSpeed::print_breakdown( $api_response[ $analysis_type ] ); ?>
										<?php Util_Ui::postbox_footer(); ?>
									</div>
								</div>
								<?php
							}
							?>
						</div>
					</div>
					<?php
				}
				?>
			</div>
		</div>
	</div>
</div>

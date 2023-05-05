<?php
/**
 * Form Builder Help Screen template.
 *
 * @since 1.6.3
 *
 * @var array $settings Help Screen settings.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$times_svg      = '<svg width="1792" height="1792" viewBox="0 0 1792 1792" xmlns="http://www.w3.org/2000/svg"><path d="M1490 1322q0 40-28 68l-136 136q-28 28-68 28t-68-28l-294-294-294 294q-28 28-68 28t-68-28l-136-136q-28-28-28-68t28-68l294-294-294-294q-28-28-28-68t28-68l136-136q28-28 68-28t68 28l294 294 294-294q28-28 68-28t68 28l136 136q28 28 28 68t-28 68l-294 294 294 294q28 28 28 68z"/></svg>';
$url_parameters = add_query_arg(
	[
		'utm_campaign' => wpforms()->is_pro() ? 'plugin' : 'liteplugin',
		'utm_source'   => 'WordPress',
		'utm_medium'   => rawurlencode( 'Builder Help Modal' ),
		'utm_content'  => '',
	],
	''
);

$links_utm_medium = 'Builder Help Modal';

?>
<div id="wpforms-builder-help" style="display: none; opacity: 0;" class="wpforms-admin-page">

	<img id="wpforms-builder-help-logo"
		src="<?php echo esc_url( WPFORMS_PLUGIN_URL . 'assets/images/sullie-alt.png' ); ?>"
		title="<?php esc_attr_e( 'Sullie the WPForms mascot', 'wpforms-lite' ); ?>"
		alt="WPForms Logo">

	<div id="wpforms-builder-help-close" title="<?php esc_attr_e( 'Close', 'wpforms-lite' ); ?>">
		<?php echo $times_svg; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
	</div>

	<div id="wpforms-builder-help-content">

		<div id="wpforms-builder-help-search">
			<input type="text" placeholder="<?php esc_attr_e( 'Ask a question or search the docs...', 'wpforms-lite' ); ?>">
			<div id="wpforms-builder-help-search-clear" title="<?php esc_attr_e( 'Clear', 'wpforms-lite' ); ?>">
				<?php echo $times_svg; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
			</div>
		</div>

		<div id="wpforms-builder-help-no-result" style="display: none;">
			<ul class="wpforms-builder-help-docs">
				<li>
					<i class="fa fa-info-circle"></i><span><?php esc_html_e( 'No docs found', 'wpforms-lite' ); ?></span>
				</li>
			</ul>
		</div>
		<div id="wpforms-builder-help-result"></div>
		<div id="wpforms-builder-help-categories"></div>

		<div id="wpforms-builder-help-footer">

			<div class="wpforms-builder-help-footer-block">
				<i class="fa fa-file-text-o"></i>
				<h3><?php esc_html_e( 'View Documentation', 'wpforms-lite' ); ?></h3>
				<p><?php esc_html_e( 'Browse documentation, reference material, and tutorials for WPForms.', 'wpforms-lite' ); ?></p>
				<a href="<?php echo esc_url( wpforms_utm_link( $settings['docs_url'], $links_utm_medium, 'View Documentation' ) ); ?>"
					class="wpforms-btn wpforms-btn-md wpforms-btn-light-grey"
					rel="noopener noreferrer"
					target="_blank">
						<?php esc_html_e( 'View All Documentation', 'wpforms-lite' ); ?>
				</a>
			</div>

			<div class="wpforms-builder-help-footer-block">
				<i class="fa fa-support"></i>
				<h3><?php esc_html_e( 'Get Support', 'wpforms-lite' ); ?></h3>

				<?php if ( wpforms()->is_pro() ) { ?>
					<p><?php esc_html_e( 'Submit a ticket and our world class support team will be in touch soon.', 'wpforms-lite' ); ?></p>
					<a href="<?php echo esc_url( wpforms_utm_link( $settings['support_ticket_url'], $links_utm_medium, 'Contact Support' ) ); ?>"
						class="wpforms-btn wpforms-btn-md wpforms-btn-light-grey"
						rel="noopener noreferrer"
						target="_blank">
							<?php esc_html_e( 'Submit a Support Ticket', 'wpforms-lite' ); ?>
					</a>

				<?php } else { ?>
					<p><?php esc_html_e( 'Upgrade to WPForms Pro to access our world class customer support.', 'wpforms-lite' ); ?></p>
					<a href="<?php echo esc_url( wpforms_utm_link( $settings['upgrade_url'], $links_utm_medium, 'Upgrade For Support' ) ); ?>"
						class="wpforms-btn wpforms-btn-md wpforms-btn-orange"
						rel="noopener noreferrer"
						target="_blank">
							<?php esc_html_e( 'Upgrade to WPForms Pro', 'wpforms-lite' ); ?>
					</a>

				<?php } ?>
			</div>

		</div>
	</div>
</div>

<script type="text/html" id="tmpl-wpforms-builder-help-categories">
	<ul class="wpforms-builder-help-categories-toggle">
		<# _.each( data.categories, function( categoryTitle, categorySlug ) { #>
		<li class="wpforms-builder-help-category">
			<header>
				<i class="fa fa-folder-open-o wpforms-folder"></i>
				<span>{{{ categoryTitle }}}</span>
				<i class="fa fa-angle-right wpforms-arrow"></i>
			</header>
			<ul class="wpforms-builder-help-docs" style="display: none;">
				<# _.each( data.docs[ categorySlug ], function( doc, index ) {
					utmContent = encodeURIComponent( doc.title ); #>
				<li>
					<i class="fa fa-file-text-o"></i><a href="{{ doc.url }}<?php echo esc_url( $url_parameters ); ?>={{ utmContent }}" rel="noopener noreferrer" target="_blank">{{{ doc.title }}}</a>
				</li>
					<# if ( index === 4 && data.docs[ categorySlug ].length > 4 ) { #>
						<div style="display: none;">
					<# } #>
				<# } ) #>
				<# if ( data.docs[ categorySlug ].length > 4 ) { #>
					</div>
					<button class="wpforms-btn wpforms-btn-md wpforms-btn-light-grey viewall" type="button"><?php esc_html_e( 'View All', 'wpforms-lite' ); ?> {{{ categoryTitle }}} <?php esc_html_e( 'Docs', 'wpforms-lite' ); ?></button>
				<# } #>
			</ul>
		</li>
		<# } ) #>
	</ul>
</script>

<script type="text/html" id="tmpl-wpforms-builder-help-categories-error">
	<h4 class="wpforms-builder-help-error">
		<?php esc_html_e( 'Unfortunately the error occurred while downloading help data.', 'wpforms-lite' ); ?>
	</h4>
</script>

<script type="text/html" id="tmpl-wpforms-builder-help-docs">
	<ul class="wpforms-builder-help-docs">
		<# _.each( data.docs, function( doc, index ) {
			utmContent = encodeURIComponent( doc.title ); #>
		<li>
			<i class="fa fa-file-text-o"></i><a href="{{ doc.url }}<?php echo esc_url( $url_parameters ); ?>={{ utmContent }}" rel="noopener noreferrer" target="_blank">{{{ doc.title }}}</a>
		</li>
		<# } ) #>
	</ul>
</script>

<?php
/**
 * Form Embed Wizard.
 * Embed popup HTML template.
 *
 * @since 1.6.2
 */

if ( ! \defined( 'ABSPATH' ) ) {
	exit;
}
$pages_exists = ! empty( $args['dropdown_pages'] ) ? 1 : 0;
?>

<div id="wpforms-admin-form-embed-wizard-container" class="wpforms-admin-popup-container">
	<div id="wpforms-admin-form-embed-wizard" class="wpforms-admin-popup" data-pages-exists="<?php echo esc_attr( $pages_exists ); ?>">
		<div class="wpforms-admin-popup-content">
			<h3><?php esc_html_e( 'Embed in a Page', 'wpforms-lite' ); ?></h3>
			<div id="wpforms-admin-form-embed-wizard-content-initial">
				<p class="no-gap"><b><?php esc_html_e( 'We can help embed your form with just a few clicks!', 'wpforms-lite' ); ?></b></p>

				<?php if ( ! empty( $args['user_can_edit_pages'] ) ) : ?>
					<p><?php esc_html_e( 'Would you like to embed your form in an existing page, or create a new one?', 'wpforms-lite' ); ?></p>
				<?php endif; ?>
			</div>

			<?php if ( ! empty( $args['user_can_edit_pages'] ) ) : ?>
				<div id="wpforms-admin-form-embed-wizard-content-select-page" style="display: none;">
					<p><?php esc_html_e( 'Select the page you would like to embed your form in.', 'wpforms-lite' ); ?></p>
				</div>
				<div id="wpforms-admin-form-embed-wizard-content-create-page" style="display: none;">
					<p><?php esc_html_e( 'What would you like to call the new page?', 'wpforms-lite' ); ?></p>
				</div>
				<div id="wpforms-admin-form-embed-wizard-section-btns" class="wpforms-admin-popup-bottom">
					<button type="button" data-action="select-page" class="wpforms-admin-popup-btn"><?php esc_html_e( 'Select Existing Page', 'wpforms-lite' ); ?></button>
					<button type="button" data-action="create-page" class="wpforms-admin-popup-btn"><?php esc_html_e( 'Create New Page', 'wpforms-lite' ); ?></button>
				</div>
				<div id="wpforms-admin-form-embed-wizard-section-go" class="wpforms-admin-popup-bottom wpforms-admin-popup-flex" style="display: none;">
					<?php echo $args['dropdown_pages']; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
					<input type="text" id="wpforms-admin-form-embed-wizard-new-page-title" value="" placeholder="<?php esc_attr_e( 'Name Your Page', 'wpforms-lite' ); ?>">
					<button type="button" data-action="go" class="wpforms-admin-popup-btn"><?php esc_html_e( 'Let’s Go!', 'wpforms-lite' ); ?></button>
				</div>
			<?php endif; ?>
			<div id="wpforms-admin-form-embed-wizard-section-toggles" class="wpforms-admin-popup-bottom">
				<p class="secondary">
					<?php
					printf(
						wp_kses( /* translators: %1$s - Video tutorial toggle CSS classes, %2$s - shortcode toggle CSS classes. */
							__( 'You can also <a href="#" class="%1$s">embed your form manually</a> or <a href="#" class="%2$s">use a shortcode</a>', 'wpforms-lite' ),
							[
								'a' => [
									'href'  => [],
									'class' => [],
								],
							]
						),
						'tutorial-toggle wpforms-admin-popup-toggle',
						'shortcode-toggle wpforms-admin-popup-toggle'
					);
					?>
				</p>
				<iframe style="display: none;" src="about:blank" frameborder="0" id="wpforms-admin-form-embed-wizard-tutorial" allowfullscreen width="450" height="256"></iframe>
				<div id="wpforms-admin-form-embed-wizard-shortcode-wrap" style="display: none;">
					<input type="text" id="wpforms-admin-form-embed-wizard-shortcode" class="wpforms-admin-popup-shortcode" disabled />
					<span id="wpforms-admin-form-embed-wizard-shortcode-copy" title="<?php esc_attr_e( 'Copy embed code to clipboard', 'wpforms-lite' ); ?>">
						<i class="fa fa-files-o" aria-hidden="true"></i>
					</span>
				</div>
			</div>
			<div id="wpforms-admin-form-embed-wizard-section-goback" class="wpforms-admin-popup-bottom" style="display: none;">
				<p class="secondary">
					<a href="#" class="wpforms-admin-popup-toggle initialstate-toggle">« <?php esc_html_e( 'Go back', 'wpforms-lite' ); ?></a>
				</p>
			</div>
		</div>
		<i class="fa fa-times wpforms-admin-popup-close"></i>
	</div>
</div>

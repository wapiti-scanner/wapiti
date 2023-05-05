<?php
/**
 * File: cdn.php
 *
 * @package W3TC
 */

namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}

// when separate config is used - each blog has own uploads
// so nothing to upload from network admin.
$upload_blogfiles_enabled = $cdn_mirror || ! is_network_admin() || ! Util_Environment::is_using_master_config();

?>
<?php require W3TC_INC_DIR . '/options/common/header.php'; ?>
<p id="w3tc-options-menu">
	<?php esc_html_e( 'Jump to:', 'w3-total-cache' ); ?>
	<a href="#toplevel_page_w3tc_general"><?php esc_html_e( 'Main Menu', 'w3-total-cache' ); ?></a> |
	<a href="#general"><?php esc_html_e( 'General', 'w3-total-cache' ); ?></a> |
	<a href="#configuration"><?php esc_html_e( 'Configuration', 'w3-total-cache' ); ?></a> |
	<a href="#advanced"><?php esc_html_e( 'Advanced', 'w3-total-cache' ); ?></a> |
	<a href="#notes"><?php esc_html_e( 'Note(s)', 'w3-total-cache' ); ?></a>
</p>

<p>
	<?php
	echo wp_kses(
		sprintf(
			// translators: 1 HTML strong tag containing CDN Engine value, 2 HTML span tag containing CDN Engine enabled/disabled value.
			__(
				'Content Delivery Network support via %1$s is currently %2$s.',
				'w3-total-cache'
			),
			'<strong>' . Cache::engine_name( $this->_config->get_string( 'cdn.engine' ) ) . '</strong>',
			'<span class="w3tc-' . ( $cdn_enabled ? 'enabled">' . esc_html__( 'enabled', 'w3-total-cache' ) : 'disabled">' . esc_html__( 'disabled', 'w3-total-cache' ) ) . '</span>'
		),
		array(
			'strong' => array(),
			'span'   => array(
				'class' => array(),
			),
		)
	);
	?>
</p>
<form id="w3tc_cdn" action="admin.php?page=<?php echo esc_attr( $this->_page ); ?>" method="post">
	<p>
		<?php if ( $cdn_mirror ) : ?>
			Maximize <acronym title="Content Delivery Network">CDN</acronym> usage by <input id="cdn_rename_domain" class="button {nonce: '<?php echo esc_attr( wp_create_nonce( 'w3tc' ) ); ?>'}" type="button" value="modify attachment URLs" /> or
			<input id="cdn_import_library" class="button {nonce: '<?php echo esc_attr( wp_create_nonce( 'w3tc' ) ); ?>'}" type="button" value="importing attachments into the Media Library" />.
			<?php if ( Cdn_Util::can_purge( $cdn_engine ) ) : ?>
				<input id="cdn_purge" class="button {nonce: '<?php echo esc_attr( wp_create_nonce( 'w3tc' ) ); ?>'}" type="button" value="Purge" /> objects from the <acronym title="Content Delivery Network">CDN</acronym> using this tool
			<?php endif; ?>
			<?php if ( $cdn_mirror_purge_all ) : ?>
				or <input class="button" type="submit" name="w3tc_flush_cdn" value="purge CDN completely" />
			<?php endif; ?>
			<?php if ( Cdn_Util::can_purge( $cdn_engine ) ) : ?>
				.
			<?php endif; ?>
		<?php else : ?>
			<?php
			echo wp_kses(
				sprintf(
					// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
					__(
						'Prepare the %1$sCDN%2$s by:',
						'w3-total-cache'
					),
					'<acronym title="' . esc_attr__( 'Content Delivery Network', 'w3-total-cache' ) . '">',
					'</acronym>'
				),
				array(
					'acronym' => array(
						'title' => array(),
					),
				)
			);
			?>
			<input id="cdn_import_library" class="button {nonce: '<?php echo esc_attr( wp_create_nonce( 'w3tc' ) ); ?>'}" type="button" value="<?php esc_attr_e( 'importing attachments into the Media Library', 'w3-total-cache' ); ?>" />.
			Check <input id="cdn_queue" class="button {nonce: '<?php echo esc_attr( wp_create_nonce( 'w3tc' ) ); ?>'}" type="button" value="<?php esc_attr_e( 'unsuccessful file transfers', 'w3-total-cache' ); ?>" /> <?php esc_html_e( 'if some objects appear to be missing.', 'w3-total-cache' ); ?>
			<?php if ( Cdn_Util::can_purge( $cdn_engine ) ) : ?>
				<input id="cdn_purge" class="button {nonce: '<?php echo esc_attr( wp_create_nonce( 'w3tc' ) ); ?>'}" type="button" value="<?php esc_attr_e( 'Purge', 'w3-total-cache' ); ?>" />
					<?php
					echo wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
							__(
								' objects from the %1$sCDN%2$s if needed.',
								'w3-total-cache'
							),
							'<acronym title="' . esc_attr__( 'Content Delivery Network', 'w3-total-cache' ) . '">',
							'</acronym>'
						),
						array(
							'acronym' => array(
								'title' => array(),
							),
						)
					);
					?>
			<?php endif; ?>
			<input id="cdn_rename_domain" class="button {nonce: '<?php echo esc_attr( wp_create_nonce( 'w3tc' ) ); ?>'}" type="button" value="Modify attachment URLs" /> <?php esc_html_e( 'if the domain name of your site has ever changed.', 'w3-total-cache' ); ?>
		<?php endif; ?>
		<?php
		echo wp_kses(
			Util_Ui::nonce_field( 'w3tc' ),
			array(
				'input' => array(
					'type'  => array(),
					'name'  => array(),
					'value' => array(),
				),
			)
		);
		?>
		<input type="submit" name="w3tc_flush_browser_cache" value="<?php esc_attr_e( 'Update media query string', 'w3-total-cache' ); ?>" <?php disabled( ! ( $browsercache_enabled && $browsercache_update_media_qs ) ); ?> class="button" /> <?php esc_html_e( 'to make existing file modifications visible to visitors with a primed cache.', 'w3-total-cache' ); ?>
	</p>
</form>
<form id="cdn_form" action="admin.php?page=<?php echo esc_attr( $this->_page ); ?>" method="post">
	<div class="metabox-holder">
		<?php Util_Ui::postbox_header( esc_html__( 'General', 'w3-total-cache' ), '', 'general' ); ?>
		<table class="form-table">
			<tr>
				<th <?php echo $cdn_mirror ? 'colspan="2"' : 'style="width: 300px;"'; ?>>
					<?php
					$force_value = ( $upload_blogfiles_enabled ? null : false );
					$this->checkbox(
						'cdn.uploads.enable',
						! $upload_blogfiles_enabled,
						'',
						true,
						$force_value
					);
					?>
					<?php Util_Ui::e_config_label( 'cdn.uploads.enable' ); ?></label>
					<p class="description">
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
								__(
									'If checked, all attachments will be hosted with the %1$sCDN%2$s.',
									'w3-total-cache'
								),
								'<acronym title="' . esc_attr__( 'Content Delivery Network', 'w3-total-cache' ) . '">',
								'</acronym>'
							),
							array(
								'acronym' => array(
									'title' => array(),
								),
							)
						);
						if ( ! $upload_blogfiles_enabled ) :
							echo wp_kses(
								sprintf(
									// translators: 1 HTML line break.
									__(
										'%1$sTo enable that, switch off "Use single network configuration file for all sites" option at General settings page and use specific settings for each blog.',
										'w3-total-cache'
									),
									'<br />'
								),
								array(
									'br' => array(),
								)
							);
						endif;
						?>
					</p>
				</th>
				<?php if ( ! $cdn_mirror ) : ?>
					<td>
						<input id="cdn_export_library" class="button {nonce: '<?php echo esc_attr( wp_create_nonce( 'w3tc' ) ); ?>'}"
							type="button" value="<?php esc_attr_e( 'Upload attachments', 'w3-total-cache' ); ?>"
							<?php disabled( ! $upload_blogfiles_enabled ); ?> />
					</td>
				<?php endif; ?>
			</tr>
			<tr>
				<th <?php echo $cdn_mirror ? 'colspan="2"' : ''; ?>>
					<?php $this->checkbox( 'cdn.includes.enable' ); ?> <?php Util_Ui::e_config_label( 'cdn.includes.enable' ); ?></label>
					<p class="description">
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
								__(
									'If checked, WordPress static core file types specified in the "wp-includes file types to upload" field below will be hosted with the %1$sCDN%2$s.',
									'w3-total-cache'
								),
								'<acronym title="' . esc_attr__( 'Content Delivery Network', 'w3-total-cache' ) . '">',
								'</acronym>'
							),
							array(
								'acronym' => array(
									'title' => array(),
								),
							)
						);
						?>
					</p>
				</th>
				<?php if ( ! $cdn_mirror ) : ?>
					<td>
						<input class="button cdn_export {type: 'includes', nonce: '<?php echo esc_attr( wp_create_nonce( 'w3tc' ) ); ?>'}"
							type="button" value="<?php esc_attr_e( 'Upload includes files', 'w3-total-cache' ); ?>" />
					</td>
				<?php endif; ?>
			</tr>
			<tr>
				<th <?php echo $cdn_mirror ? 'colspan="2"' : ''; ?>>
					<?php $this->checkbox( 'cdn.theme.enable' ); ?> <?php Util_Ui::e_config_label( 'cdn.theme.enable' ); ?></label>
					<p class="description">
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
								__(
									'If checked, all theme file types specified in the "theme file types to upload" field below will be hosted with the %1$sCDN%2$s.',
									'w3-total-cache'
								),
								'<acronym title="' . esc_attr__( 'Content Delivery Network', 'w3-total-cache' ) . '">',
								'</acronym>'
							),
							array(
								'acronym' => array(
									'title' => array(),
								),
							)
						);
						?>
					</p>
				</th>
				<?php if ( ! $cdn_mirror ) : ?>
					<td>
						<input class="button cdn_export {type: 'theme', nonce: '<?php echo esc_attr( wp_create_nonce( 'w3tc' ) ); ?>'}"
							type="button" value="<?php esc_attr_e( 'Upload theme files', 'w3-total-cache' ); ?>"
							/>
					</td>
				<?php endif; ?>
			</tr>
			<tr>
				<th <?php echo $cdn_mirror ? 'colspan="2"' : ''; ?>>
					<?php $this->checkbox( 'cdn.minify.enable', ! $minify_enabled ); ?> <?php Util_Ui::e_config_label( 'cdn.minify.enable' ); ?></label>
					<p class="description">
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag,
								// translators: 3 opening HTML acronym tag, 4 closing HTML acronym tag,
								// translators: 5 opening HTML acronym tag, 6 closing HTML acronym tag.
								__(
									'If checked, minified %1$sCSS%2$s and %3$sJS%4$s files will be hosted with the %5$sCDN%6$s.',
									'w3-total-cache'
								),
								'<acronym title="' . esc_attr__( 'Cascading Style Sheet', 'w3-total-cache' ) . '">',
								'</acronym>',
								'<acronym title="' . esc_attr__( 'JavaScript', 'w3-total-cache' ) . '">',
								'</acronym>',
								'<acronym title="' . esc_attr__( 'Content Delivery Network', 'w3-total-cache' ) . '">',
								'</acronym>'
							),
							array(
								'acronym' => array(
									'title' => array(),
								),
							)
						);
						?>
					</p>
				</th>
				<?php if ( ! $cdn_mirror ) : ?>
					<td>
						<input class="button cdn_export {type: 'minify', nonce: '<?php echo esc_attr( wp_create_nonce( 'w3tc' ) ); ?>'}"
							type="button" value="<?php esc_attr_e( 'Upload minify files', 'w3-total-cache' ); ?>"
							<?php disabled( ! $minify_enabled ); ?> />
					</td>
				<?php endif; ?>
			</tr>
			<tr>
				<th <?php echo $cdn_mirror ? 'colspan="2"' : ''; ?>>
					<?php $this->checkbox( 'cdn.custom.enable' ); ?> <?php Util_Ui::e_config_label( 'cdn.custom.enable' ); ?></label>
					<p class="description">
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
								__(
									'If checked, any file names or paths specified in the "custom file list" field below will be hosted with the %1$sCDN%2$s.',
									'w3-total-cache'
								),
								'<acronym title="' . esc_attr__( 'Content Delivery Network', 'w3-total-cache' ) . '">',
								'</acronym>'
							),
							array(
								'acronym' => array(
									'title' => array(),
								),
							)
						);
						?>
					</p>
				</th>
				<?php if ( ! $cdn_mirror ) : ?>
					<td>
						<input class="button cdn_export {type: 'custom', nonce: '<?php echo esc_attr( wp_create_nonce( 'w3tc' ) ); ?>'}"
							type="button" value="<?php esc_attr_e( 'Upload custom files', 'w3-total-cache' ); ?>"
							<?php disabled( ! $upload_blogfiles_enabled ); ?> />
					</td>
				<?php endif; ?>
			</tr>
			<?php if ( ! $cdn_mirror ) : ?>
				<tr>
					<th colspan="2">
						<?php $this->checkbox( 'cdn.force.rewrite' ); ?> <?php Util_Ui::e_config_label( 'cdn.force.rewrite' ); ?></label>
						<p class="description"><?php esc_html_e( 'If modified files are not always detected and replaced, use this option to over-write them.', 'w3-total-cache' ); ?></p>
					</th>
				</tr>
			<?php endif; ?>

			<?php if ( $cdn_supports_header ) : ?>
				<tr>
					<th colspan="2">
						<?php $this->checkbox( 'cdn.canonical_header' ); ?> <?php Util_Ui::e_config_label( 'cdn.canonical_header' ); ?></label>
						<p class="description">
							<?php
							echo wp_kses(
								sprintf(
									// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
									__(
										'Adds canonical %1$sHTTP%2$s header to assets files.',
										'w3-total-cache'
									),
									'<acronym title="' . esc_attr__( 'Hypertext Transfer Protocol', 'w3-total-cache' ) . '">',
									'</acronym>'
								),
								array(
									'acronym' => array(
										'title' => array(),
									),
								)
							);
							?>
						</p>
					</th>
				</tr>
			<?php endif; ?>
		</table>

		<?php Util_Ui::button_config_save( 'cdn_general' ); ?>
		<?php Util_Ui::postbox_footer(); ?>

		<?php Util_Ui::postbox_header( esc_html__( 'Configuration: Objects', 'w3-total-cache' ), '', 'configuration' ); ?>
		<table class="form-table">
			<?php
			if ( 'google_drive' === $cdn_engine ||
				'highwinds' === $cdn_engine ||
				'limelight' === $cdn_engine ||
				'rackspace_cdn' === $cdn_engine ||
				'rscf' === $cdn_engine ||
				'stackpath' === $cdn_engine ||
				'stackpath2' === $cdn_engine ) {
				do_action( 'w3tc_settings_cdn_boxarea_configuration' );
			} elseif ( Cdn_Util::is_engine( $cdn_engine ) ) {
				include W3TC_INC_DIR . '/options/cdn/' . $cdn_engine . '.php';
			}
			?>
		</table>

		<?php Util_Ui::button_config_save( 'cdn_configuration' ); ?>
		<?php Util_Ui::postbox_footer(); ?>

		<?php do_action( 'w3tc_settings_box_cdnfsd' ); ?>

		<?php Util_Ui::postbox_header( esc_html__( 'Advanced', 'w3-total-cache' ), '', 'advanced' ); ?>
		<table class="form-table">

			<tr>
				<th colspan="2">
					<?php
					$this->checkbox( 'cdn.flush_manually' );
					echo wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
							__(
								'Only purge %1$sCDN%2$s manually',
								'w3-total-cache'
							),
							'<acronym title="' . esc_attr__( 'Content Delivery Network', 'w3-total-cache' ) . '">',
							'</acronym>'
						),
						array(
							'acronym' => array(
								'title' => array(),
							),
						)
					);
					?>
					<p class="description">
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
								__(
									'Purge %1$sCDN%2$s only if explicit purge button is clicked.',
									'w3-total-cache'
								),
								'<acronym title="' . esc_attr__( 'Content Delivery Network', 'w3-total-cache' ) . '">',
								'</acronym>'
							),
							array(
								'acronym' => array(
									'title' => array(),
								),
							)
						);
						?>
						<div class="hidden" id="cdn-flushmanually-warning">
								<div class="notice notice-warning inline"><p>
							<?php
							echo wp_kses(
								sprintf(
									// translators: 1: HTML break, 2: HTML anchor open tag, 3: HTML anchor close tag.
									__(
										'Please see %2$sAmazon\'s CloudFront documentation -- Paying for file invalidation%3$s:%1$sThe first 1,000 invalidation paths that you submit per month are free; you pay for each invalidation path over 1,000 in a month.%1$sYou can disable automatic purging by enabling "Only purge CDN manually".',
										'w3-total-cache'
									),
									'<br />',
									'<a target="_blank" href="https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/Invalidation.html#PayingForInvalidation">',
									'</a>'
								),
								array(
									'a'  => array(
										'target' => array(),
										'href'   => array(),
									),
									'br' => array(),
								)
							);
							?>
							</p></div>
						</div>
					</p>
				</th>
			</tr>

			<tr>
				<th colspan="2">
					<?php $this->checkbox( 'cdn.reject.ssl' ); ?> <?php Util_Ui::e_config_label( 'cdn.reject.ssl' ); ?></label>
					<p class="description">
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag,
								// translators: 3 opening HTML acronym tag, 4 closing HTML acronym tag,
								// translators: 5 opening HTML acronym tag, 6 closing HTML acronym tag.
								__(
									'When %1$sSSL%2$s pages are returned no %3$sCDN%4$s %5$sURL%6$ss will appear in HTML pages.',
									'w3-total-cache'
								),
								'<acronym title="' . esc_attr__( 'Secure Sockets Layer', 'w3-total-cache' ) . '">',
								'</acronym>',
								'<acronym title="' . esc_attr__( 'Content Delivery Network', 'w3-total-cache' ) . '">',
								'</acornym>',
								'<acronym title="' . esc_attr__( 'Uniform Resource Indicator', 'w3-total-cache' ) . '">',
								'</acornym>'
							),
							array(
								'acronym' => array(
									'title' => array(),
								),
							)
						);
						?>
					</p>
				</th>
			</tr>
			<tr>
				<th colspan="2">
					<?php $this->checkbox( 'cdn.admin.media_library' ); ?> <?php Util_Ui::e_config_label( 'cdn.admin.media_library' ); ?></label>
					<p class="description">
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
								__(
									'All Media Library content will use %1$sCDN%2$s links on administration pages.',
									'w3-total-cache'
								),
								'<acronym title="' . esc_attr__( 'Content Delivery Network', 'w3-total-cache' ) . '">',
								'</acronym>'
							),
							array(
								'acronym' => array(
									'title' => array(),
								),
							)
						);
						?>
					</p>
				</th>
			</tr>
			<tr>
				<th colspan="2">
					<?php $this->checkbox( 'cdn.cors_header' ); ?> Add <acronym title="Access-Control-Allow-Origin">CORS</acronym> header</label>
					<p class="description">
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
								__(
									'Add %1$sCORS%2$s headers to allow cross-domain assets usage.',
									'w3-total-cache'
								),
								'<acronym title="' . esc_attr__( 'Access-Control-Allow-Origin', 'w3-total-cache' ) . '">',
								'</acronym>'
							),
							array(
								'acronym' => array(
									'title' => array(),
								),
							)
						);
						?>
					</p>
				</th>
			</tr>

			<tr>
				<th colspan="2">
					<?php $this->checkbox( 'cdn.reject.logged_roles' ); ?> <?php Util_Ui::e_config_label( 'cdn.reject.logged_roles' ); ?></label>
					<p class="description"><?php esc_html_e( 'Select user roles that will use the origin server exclusively:', 'w3-total-cache' ); ?></p>

					<div id="cdn_reject_roles" class="w3tc_reject_roles">
						<?php $saved_roles = $this->_config->get_array( 'cdn.reject.roles' ); ?>
						<input type="hidden" name="cdn__reject__roles" value="" /><br />
						<?php foreach ( get_editable_roles() as $role_name => $role_data ) : ?>
							<input type="checkbox" name="cdn__reject__roles[]" value="<?php echo esc_attr( $role_name ); ?>" <?php checked( in_array( $role_name, $saved_roles, true ) ); ?> id="role_<?php echo esc_attr( $role_name ); ?>" />
							<label for="role_<?php echo esc_attr( $role_name ); ?>"><?php echo esc_html( $role_data['name'] ); ?></label>
						<?php endforeach; ?>
					</div>
				</th>
			</tr>
			<?php if ( ! $cdn_mirror ) : ?>
			<tr>
				<th><label for="cdn_reject_uri"><?php Util_Ui::e_config_label( 'cdn.reject.uri' ); ?></label></th>
				<td>
					<textarea id="cdn_reject_uri" name="cdn__reject__uri"
						<?php Util_Ui::sealing_disabled( 'cdn.' ); ?>
							cols="40" rows="5"><?php echo esc_textarea( implode( "\r\n", $this->_config->get_array( 'cdn.reject.uri' ) ) ); ?></textarea>
					<p class="description">
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML a tag to W3TC FAQ admin page, 2 opening HTML acronym tag,
								// translators: 3 closing HTML acronym tag, 4 closing HTML a tag.
								__(
									'Always ignore the specified pages / directories. Supports regular expression (See %1$s%2$sFAQ%3$s%4$s)'
								),
								'<a href="' . esc_url( network_admin_url( 'admin.php?page=w3tc_faq' ) ) . '">',
								'<acronym title="' . esc_attr__( 'Frequently Asked Questions', 'w3-total-cache' ) . '">',
								'</acronym>',
								'</a>'
							),
							array(
								'a'       => array(
									'href' => array(),
								),
								'acronym' => array(
									'title' => array(),
								),
							)
						);
						?>
					</p>
				</td>
			</tr>
			<tr>
				<th colspan="2">
					<?php $this->checkbox( 'minify.upload', $this->_config->get_boolean( 'minify.auto' ) ); ?> <?php esc_html_e( 'Automatically upload minify files', 'w3-total-cache' ); ?></label>
					<p class="description">
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
								__(
									'If %1$sCDN%2$s is enabled (and not using the origin pull method), your minified files will be automatically uploaded.',
									'w3-total-cache'
								),
								'<acronym title="' . esc_attr__( 'Content Delivery Network', 'w3-total-cache' ) . '">',
								'</acronym>'
							),
							array(
								'acronym' => array(
									'title' => array(),
								),
							)
						);
						?>
					</p>
				</th>
			</tr>
			<tr>
				<th colspan="2">
					<?php
					$disabled    = false;
					$force_value = null;

					if ( 'google_drive' === $this->_config->get_string( 'cdn.engine' ) ) {
						$disabled    = true;
						$force_value = false;
					}

					$this->checkbox(
						'cdn.autoupload.enabled',
						$disabled,
						'',
						true,
						$force_value
					);
					?>
					<?php Util_Ui::e_config_label( 'cdn.autoupload.enabled' ); ?></label>
					<p class="description"><?php esc_html_e( 'Automatically attempt to find and upload changed files.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
			<tr>
				<th><label for="cdn_autoupload_interval"><?php Util_Ui::e_config_label( 'cdn.autoupload.interval' ); ?></label></th>
				<td>
					<input id="cdn_autoupload_interval" type="text"
						name="cdn__autoupload__interval"
						<?php Util_Ui::sealing_disabled( 'cdn.' ); ?>
						value="<?php echo esc_attr( $this->_config->get_integer( 'cdn.autoupload.interval' ) ); ?>" size="8" /> <?php esc_html_e( 'seconds', 'w3-total-cache' ); ?>
					<p class="description"><?php esc_html_e( 'Specify the interval between upload of changed files.', 'w3-total-cache' ); ?></p>
				</td>
			</tr>
			<tr>
				<th><label for="cdn_limit_interval"><?php Util_Ui::e_config_label( 'cdn.queue.interval' ); ?></label></th>
				<td>
					<input id="cdn_limit_interval" type="text"
						<?php Util_Ui::sealing_disabled( 'cdn.' ); ?>
						name="cdn__queue__interval" value="<?php echo esc_attr( $this->_config->get_integer( 'cdn.queue.interval' ) ); ?>" size="10" /> <?php esc_html_e( 'seconds', 'w3-total-cache' ); ?>
					<p class="description"><?php esc_html_e( 'The number of seconds to wait before upload attempt.', 'w3-total-cache' ); ?></p>
				</td>
			</tr>
			<tr>
				<th><label for="cdn_limit_queue"><?php Util_Ui::e_config_label( 'cdn.queue.limit' ); ?></label></th>
				<td>
					<input id="cdn_limit_queue" type="text"
						<?php Util_Ui::sealing_disabled( 'cdn.' ); ?>
						name="cdn__queue__limit" value="<?php echo esc_attr( $this->_config->get_integer( 'cdn.queue.limit' ) ); ?>" size="10" />
					<p class="description"><?php esc_html_e( 'Number of files processed per upload attempt.', 'w3-total-cache' ); ?></p>
				</td>
			</tr>
			<?php endif ?>
			<tr>
				<th style="width: 300px;"><label for="cdn_includes_files"><?php Util_Ui::e_config_label( 'cdn.includes.files' ); ?></label></th>
				<td>
					<input id="cdn_includes_files" type="text"
						<?php Util_Ui::sealing_disabled( 'cdn.' ); ?>
						name="cdn__includes__files" value="<?php echo esc_attr( $this->_config->get_string( 'cdn.includes.files' ) ); ?>" size="100" />
					<p class="description">
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
								__(
									'Specify the file types within the WordPress core to host with the %1$sCDN%2$s.',
									'w3-total-cache'
								),
								'<acronym title="' . esc_attr__( 'Content Delivery Network', 'w3-total-cache' ) . '">',
								'</acronym>'
							),
							array(
								'acronym' => array(
									'title' => array(),
								),
							)
						);
						?>
					</p>
				</td>
			</tr>
			<tr>
				<th><label for="cdn_theme_files"><?php Util_Ui::e_config_label( 'cdn.theme.files' ); ?></label></th>
				<td>
					<input id="cdn_theme_files" type="text" name="cdn__theme__files"
						<?php Util_Ui::sealing_disabled( 'cdn.' ); ?>
						value="<?php echo esc_attr( $this->_config->get_string( 'cdn.theme.files' ) ); ?>" size="100" />
					<p class="description">
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
								__(
									'Specify the file types in the active theme to host with the %1$sCDN%2$s.',
									'w3-total-cache'
								),
								'<acronym title="' . esc_attr__( 'Content Delivery Network', 'w3-total-cache' ) . '">',
								'</acronym>'
							),
							array(
								'acronym' => array(
									'title' => array(),
								),
							)
						);
						?>
					</p>
				</td>
			</tr>
			<tr>
				<th><label for="cdn_import_files"><?php Util_Ui::e_config_label( 'cdn.import.files' ); ?></label></th>
				<td>
					<input id="cdn_import_files" type="text" name="cdn__import__files"
						<?php Util_Ui::sealing_disabled( 'cdn.' ); ?>
						value="<?php echo esc_attr( $this->_config->get_string( 'cdn.import.files' ) ); ?>" size="100" />
					<p class="description"><?php esc_html_e( 'Automatically import files hosted with 3rd parties of these types (if used in your posts / pages) to your media library.', 'w3-total-cache' ); ?></p>
				</td>
			</tr>
			<tr>
				<th><label for="cdn_custom_files"><?php Util_Ui::e_config_label( 'cdn.custom.files' ); ?></label></th>
				<td>
					<textarea id="cdn_custom_files" name="cdn__custom__files"
						<?php Util_Ui::sealing_disabled( 'cdn.' ); ?> cols="40"
						rows="5"><?php echo esc_textarea( implode( "\r\n", $this->_config->get_array( 'cdn.custom.files' ) ) ); ?></textarea>
					<p class="description">
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
								__(
									'Specify any files outside of theme or other common directories to host with the %1$sCDN%2$s.',
									'w3-total-cache'
								),
								'<acronym title="' . esc_attr__( 'Content Delivery Network', 'w3-total-cache' ) . '">',
								'</acronym>'
							),
							array(
								'acronym' => array(
									'title' => array(),
								),
							)
						);
						?>
						<?php if ( Util_Environment::is_wpmu() ) : ?>
							<br />
							<?php esc_html_e( 'To upload files in blogs.dir for current blog write wp-content/&lt;currentblog&gt;/.', 'w3-total-cache' ); ?>
						<?php endif ?>
					</p>
				</td>
			</tr>
			<tr>
				<th><label for="cdn_reject_ua"><?php Util_Ui::e_config_label( 'cdn.reject.ua' ); ?></label></th>
				<td>
					<textarea id="cdn_reject_ua" name="cdn__reject__ua" cols="40"
						<?php Util_Ui::sealing_disabled( 'cdn.' ); ?> rows="5"><?php echo esc_textarea( implode( "\r\n", $this->_config->get_array( 'cdn.reject.ua' ) ) ); ?></textarea>
					<p class="description">
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
								__(
									'Specify user agents that should not access files hosted with the %1$sCDN%2$s.',
									'w3-total-cache'
								),
								'<acronym title="' . esc_attr__( 'Content Delivery Network', 'w3-total-cache' ) . '">',
								'</acronym>'
							),
							array(
								'acronym' => array(
									'title' => array(),
								),
							)
						);
						?>
					</p>
				</td>
			</tr>
			<tr>
				<th><label for="cdn_reject_files"><?php Util_Ui::e_config_label( 'cdn.reject.files' ); ?></label></th>
				<td>
					<textarea id="cdn_reject_files" name="cdn__reject__files"
						<?php Util_Ui::sealing_disabled( 'cdn.' ); ?> cols="40" rows="5"><?php echo esc_textarea( implode( "\r\n", $this->_config->get_array( 'cdn.reject.files' ) ) ); ?></textarea>
					<p class="description">
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
								__(
									'Specify the path of files that should not use the %1$sCDN%2$s.',
									'w3-total-cache'
								),
								'<acronym title="' . esc_attr__( 'Content Delivery Network', 'w3-total-cache' ) . '">',
								'</acronym>'
							),
							array(
								'acronym' => array(
									'title' => array(),
								),
							)
						);
						?>
					</p>
				</td>
			</tr>
			<tr>
				<th colspan="2">
					<input type="hidden" name="set_cookie_domain_old" value="<?php echo (int) $set_cookie_domain; ?>" />
					<input type="hidden" name="set_cookie_domain_new" value="0" />
					<label><input type="checkbox" name="set_cookie_domain_new"
						<?php Util_Ui::sealing_disabled( 'cdn.' ); ?> value="1"<?php checked( $set_cookie_domain, true ); ?> />
						<?php
						echo esc_html(
							sprintf(
								// translators: 1 Cookie Domain.
								__(
									'Set cookie domain to "%1$s"',
									'w3-total-cache'
								),
								$cookie_domain
							)
						);
						?>
					</label>
					<p class="description">
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag,
								// translators: 3 opening HTML acronym tag, 4 closing HTML acronym tag.
								__(
									'If using subdomain for %1$sCDN%2$s functionality, this setting helps prevent new users from sending cookies in requests to the %3$sCDN%4$s subdomain.',
									'w3-total-cache'
								),
								'<acronym title="' . esc_attr__( 'Content Delivery Network', 'w3-total-cache' ) . '">',
								'</acronym>',
								'<acronym title="' . esc_attr__( 'Content Delivery Network', 'w3-total-cache' ) . '">',
								'</acronym>'
							),
							array(
								'acronym' => array(
									'title' => array(),
								),
							)
						);
						?>
					</p>
				</th>
			</tr>
		</table>

		<?php Util_Ui::button_config_save( 'cdn_advanced' ); ?>
		<?php Util_Ui::postbox_footer(); ?>

		<?php Util_Ui::postbox_header( esc_html__( 'Note(s):', 'w3-total-cache' ), '', 'notes' ); ?>
		<table class="form-table">
			<tr>
				<th colspan="2">
					<ul>
						<li><?php esc_html_e( 'You can use placeholders {wp_content_dir}, {plugins_dir}, {uploads_dir} instead of writing folder paths (wp-content, wp-content/plugins, wp-content/uploads).', 'w3-total-cache' ); ?></li>
						<li>
							<?php
							echo wp_kses(
								sprintf(
									// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag,
									// translators: 3 opening HTML acronym tag, 4 closing HTML acronym tag,
									// translators: 5 opening HTML a tag to W3TC BrowserCache admin page, 6 closing HTML a tag.
									__(
										'If using Amazon Web Services or Self-Hosted %1$sCDN%2$s types, enable %3$sHTTP%4$s compression in the "Media &amp; Other Files" section on %5$sBrowser Cache%6$s Settings tab.',
										'w3-total-cache'
									),
									'<acronym title="' . esc_attr__( 'Content Delivery Network', 'w3-total-cache' ) . '">',
									'</acronym>',
									'<acronym title="' . esc_attr__( 'Hypertext Transfer Protocol', 'w3-total-cache' ) . '">',
									'</acronym>',
									'<a href="' . esc_url( admin_url( 'admin.php?page=w3tc_browsercache' ) ) . '">',
									'</a>'
								),
								array(
									'a'       => array(
										'href' => array(),
									),
									'acronym' => array(
										'title' => array(),
									),
								)
							);
							?>
						</li>
					</ul>
				</th>
			</tr>
		</table>
		<?php Util_Ui::postbox_footer(); ?>
	</div>
</form>
<?php require W3TC_INC_DIR . '/options/common/footer.php'; ?>

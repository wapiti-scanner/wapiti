<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}

$security_session_values = array(
	''    => 'Default',
	'on'  => 'Enable',
	'off' => 'Disable',
);

?>
<?php require W3TC_INC_DIR . '/options/common/header.php'; ?>

<form action="admin.php?page=<?php echo esc_attr( $this->_page ); ?>" method="post">
	<p>
		<?php
		echo wp_kses(
			sprintf(
				// translators: 1 HTML span tag indicating Browsercache enabled/disabled.
				__(
					'Browser caching is currently %1$s.',
					'w3-total-cache'
				),
				'<span class="w3tc-' . ( $browsercache_enabled ? 'enabled">' . esc_html__( 'enabled', 'w3-total-cache' ) : 'disabled">' . esc_html__( 'disabled', 'w3-total-cache' ) ) . '</span>'
			),
			array(
				'span' => array(
					'class' => array(),
				),
			)
		);
		?>
	</p>
	<p>
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

		<?php
		echo wp_kses(
			sprintf(
				// translators: HTML input submit for updating media query string.
				__(
					'%1$s to make existing file modifications visible to visitors with a primed cache',
					'w3-total-cache'
				),
				'<input type="submit" name="w3tc_flush_browser_cache" value="' .
					esc_attr__( 'Update media query string', 'w3-total-cache' ) . '" ' .
					disabled( ! ( $browsercache_enabled && $browsercache_update_media_qs ), true, false ) .
					' class="button" />'
			),
			array(
				'input' => array(
					'type'     => array(),
					'name'     => array(),
					'value'    => array(),
					'disabled' => array(),
					'class'    => array(),
				),
			)
		);
		?>
	</p>
</form>
<form action="admin.php?page=<?php echo esc_attr( $this->_page ); ?>" method="post">
	<div class="metabox-holder">
		<?php Util_Ui::postbox_header( esc_html__( 'General', 'w3-total-cache' ), '', 'general' ); ?>
		<p><?php esc_html_e( 'Specify global browser cache policy.', 'w3-total-cache' ); ?></p>
		<table class="form-table">
			<tr>
				<th colspan="2">
					<label>
						<input id="browsercache_last_modified" type="checkbox" name="expires"
							<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?>
							value="1"<?php checked( $browsercache_last_modified, true ); ?> />
						<?php esc_html_e( 'Set Last-Modified header', 'w3-total-cache' ); ?>
					</label>
					<p class="description"><?php esc_html_e( 'Set the Last-Modified header to enable 304 Not Modified response.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
			<tr>
				<th colspan="2">
					<label>
						<input id="browsercache_expires" type="checkbox" name="expires"
							<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?>
							value="1"<?php checked( $browsercache_expires, true ); ?> /> <?php esc_html_e( 'Set expires header', 'w3-total-cache' ); ?></label>
					<p class="description"><?php esc_html_e( 'Set the expires header to encourage browser caching of files.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
			<tr>
				<th colspan="2">
					<label><input id="browsercache_cache_control" type="checkbox"
						<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> name="cache_control" value="1"<?php checked( $browsercache_cache_control, true ); ?> /> <?php esc_html_e( 'Set cache control header', 'w3-total-cache' ); ?></label>
					<p class="description"><?php esc_html_e( 'Set pragma and cache-control headers to encourage browser caching of files.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
			<tr>
				<th colspan="2">
					<label><input id="browsercache_etag" type="checkbox"
						<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?>
						name="etag" value="1"<?php checked( $browsercache_etag, true ); ?> /> <?php esc_html_e( 'Set entity tag (ETag)', 'w3-total-cache' ); ?></label>
					<p class="description"><?php esc_html_e( 'Set the ETag header to encourage browser caching of files.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
			<tr>
				<th colspan="2">
					<label><input id="browsercache_w3tc" type="checkbox" name="w3tc"
						<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?> value="1" <?php checked( $browsercache_w3tc, true ); ?> /> <?php esc_html_e( 'Set W3 Total Cache header', 'w3-total-cache' ); ?></label>
					<p class="description"><?php esc_html_e( 'Set this header to assist in identifying optimized files.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
			<tr>
				<th colspan="2">
					<label><input id="browsercache_compression" type="checkbox"
						<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?>
						name="compression"<?php checked( $browsercache_compression, true ); ?> value="1" />
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
								__(
									'Enable %1$sHTTP%2$s (gzip) compression',
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
					</label>
					<p class="description"><?php esc_html_e( 'Reduce the download time for text-based files.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
			<tr>
				<th colspan="2">
					<label><input id="browsercache_brotli" type="checkbox"
						<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?>
						<?php echo ! function_exists( 'brotli_compress' ) ? 'disabled="disabled"' : ''; ?>
						name="compression"<?php checked( $browsercache_brotli, true ); ?> value="1" />
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
								__(
									'Enable %1$sHTTP%2$s (brotli) compression',
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
					</label>
					<p class="description"><?php esc_html_e( 'Reduce the download time for text-based files.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
			<tr>
				<th colspan="2">
					<label><input id="browsercache_replace" type="checkbox"
						<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?>
						name="replace" value="1"<?php checked( $browsercache_replace, true ); ?> /> <?php esc_html_e( 'Prevent caching of objects after settings change', 'w3-total-cache' ); ?></label>
					<p class="description"><?php esc_html_e( 'Whenever settings are changed, a new query string will be generated and appended to objects allowing the new policy to be applied.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
			<tr>
				<th colspan="2">
					<label><input id="browsercache_querystring" type="checkbox"
						<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?>
						name="querystring" value="1"<?php checked( $browsercache_querystring, true ); ?> /> <?php esc_html_e( 'Remove query strings from static resources', 'w3-total-cache' ); ?></label>
					<p class="description">
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
								__(
									'Resources with a "?" in the %1$sURL%2$s are not cached by some proxy caching servers.',
									'w3-total-cache'
								),
								'<acronym title="' . esc_attr__( 'Uniform Resource Locator', 'w3-total-cache' ) . '">',
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
				<th><label for="browsercache_replace_exceptions"><?php Util_Ui::e_config_label( 'browsercache.replace.exceptions' ); ?></label></th>
				<td>
					<textarea id="browsercache_replace_exceptions"
						<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?>
							name="browsercache__replace__exceptions" cols="40" rows="5"><?php echo esc_textarea( implode( "\r\n", $this->_config->get_array( 'browsercache.replace.exceptions' ) ) ); ?></textarea>
					<p class="description">
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
								__(
									'Do not add the prevent caching query string to the specified %1$sURI%2$ss. Supports regular expressions.',
									'w3-total-cache'
								),
								'<acronym title="' . esc_attr__( 'Uniform Resource Identifier', 'w3-total-cache' ) . '">',
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
					<label><input id="browsercache_nocookies" type="checkbox"
						<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?>
						name="nocookies" value="1"<?php checked( $browsercache_nocookies, true ); ?> /> <?php esc_html_e( "Don't set cookies for static files", 'w3-total-cache' ); ?></label>
					<p class="description"><?php esc_html_e( 'Removes Set-Cookie header for responses.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
			<tr>
				<th colspan="2">
					<?php $this->checkbox( 'browsercache.no404wp', ! Util_Rule::can_check_rules() ); ?> <?php Util_Ui::e_config_label( 'browsercache.no404wp' ); ?></label>
					<p class="description"><?php esc_html_e( 'Reduce server load by allowing the web server to handle 404 (not found) errors for static files (images etc).', 'w3-total-cache' ); ?></p>
					<p class="description">
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
								__(
									'If enabled - you may get 404 File Not Found response for some files generated on-the-fly by WordPress plugins. You may add those file %1$sURI%2$ss to 404 error exception list below to avoid that.',
									'w3-total-cache'
								),
								'<acronym title="' . esc_attr__( 'Uniform Resource Identifier', 'w3-total-cache' ) . '">',
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
				<th><label for="browsercache_no404wp_exceptions"><?php Util_Ui::e_config_label( 'browsercache.no404wp.exceptions' ); ?></label></th>
				<td>
					<textarea id="browsercache_no404wp_exceptions"
						<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?>
						name="browsercache__no404wp__exceptions" cols="40" rows="5"><?php echo esc_textarea( implode( "\r\n", $this->_config->get_array( 'browsercache.no404wp.exceptions' ) ) ); ?></textarea>
					<p class="description">
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
								__(
									'Never process 404 (not found) events for the specified %1$sURI%2$ss.',
									'w3-total-cache'
								),
								'<acronym title="' . esc_attr__( 'Uniform Resource Identifier', 'w3-total-cache' ) . '">',
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
			<?php
			Util_Ui::config_item(
				array(
					'key'            => 'browsercache.rewrite',
					'disabled'       => Util_Ui::sealing_disabled( 'browsercache.' ),
					'control'        => 'checkbox',
					'checkbox_label' => wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
							__(
								'Rewrite %1$sURL%2$s structure of objects',
								'w3-total-cache'
							),
							'<acronym title="' . esc_attr__( 'Universal Resource Locator', 'w3-total-cache' ) . '">',
							'</acronym>'
						),
						array(
							'acronym' => array(
								'title' => array(),
							),
						)
					),
					'description'    => wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
							__(
								'Generate unique %1$sURI%2$s for each file protected from caching by browser.',
								'w3-total-cache'
							),
							'<acronym title="' . esc_attr__( 'Universal Resource Indicator', 'w3-total-cache' ) . '">',
							'</acronym>'
						),
						array(
							'acronym' => array(
								'title' => array(),
							),
						)
					),
					'label_class'    => 'w3tc_single_column',
				)
			);
			?>
		</table>

		<?php Util_Ui::button_config_save( 'browsercache_general' ); ?>
		<?php Util_Ui::postbox_footer(); ?>

		<?php
		Util_Ui::postbox_header(
			wp_kses(
				sprintf(
					// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag,
					// translators: 3 opening HTML acronym tag, 4 closing HTML acronym tag.
					__(
						'%1$sCSS%2$s &amp; %3$sJS%4$s',
						'w3-total-cache'
					),
					'<acronym title="' . esc_attr__( 'Cascading Style Sheet', 'w3-total-cache' ) . '">',
					'</acronym>',
					'<acronym title="' . esc_attr__( 'JavaScript', 'w3-total-cache' ) . '">',
					'</acronym>'
				),
				array(
					'acronym' => array(
						'title' => array(),
					),
				)
			),
			'',
			'css_js'
		);
		?>
		<p><?php esc_html_e( 'Specify browser cache policy for Cascading Style Sheets and JavaScript files.', 'w3-total-cache' ); ?></p>

		<table class="form-table">
			<tr>
				<th colspan="2">
					<?php $this->checkbox( 'browsercache.cssjs.last_modified' ); ?> <?php Util_Ui::e_config_label( 'browsercache.cssjs.last_modified' ); ?></label>
					<p class="description"><?php esc_html_e( 'Set the Last-Modified header to enable 304 Not Modified response.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
			<tr>
				<th colspan="2">
					<?php $this->checkbox( 'browsercache.cssjs.expires' ); ?> <?php Util_Ui::e_config_label( 'browsercache.cssjs.expires' ); ?></label>
					<p class="description"><?php esc_html_e( 'Set the expires header to encourage browser caching of files.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
			<tr>
				<th>
					<label for="browsercache_cssjs_lifetime"><?php Util_Ui::e_config_label( 'browsercache.cssjs.lifetime' ); ?></label>
				</th>
				<td>
					<input id="browsercache_cssjs_lifetime" type="text"
						<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?>
						name="browsercache__cssjs__lifetime" value="<?php echo esc_attr( $this->_config->get_integer( 'browsercache.cssjs.lifetime' ) ); ?>" size="8" /> <?php esc_html_e( 'seconds', 'w3-total-cache' ); ?>
				</td>
			</tr>
			<tr>
				<th colspan="2">
					<?php $this->checkbox( 'browsercache.cssjs.cache.control' ); ?> <?php Util_Ui::e_config_label( 'browsercache.cssjs.cache.control' ); ?></label>
					<p class="description"><?php esc_html_e( 'Set pragma and cache-control headers to encourage browser caching of files.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
			<tr>
				<th>
					<label for="browsercache_cssjs_cache_policy"><?php Util_Ui::e_config_label( 'browsercache.cssjs.cache.policy' ); ?></label>
				</th>
				<td>
					<select id="browsercache_cssjs_cache_policy"
						<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?>
						name="browsercache__cssjs__cache__policy">
						<?php
						$value         = $this->_config->get_string( 'browsercache.cssjs.cache.policy' );
						$cssjs_expires = $this->_config->get_boolean( 'browsercache.cssjs.expires' );
						?>
						<option value="cache"<?php selected( $value, 'cache' ); ?>>cache ("public")</option>
						<option value="cache_public_maxage"<?php selected( $value, 'cache_public_maxage' ); ?><?php disabled( $is_nginx && $cssjs_expires ); ?>><?php esc_html_e( 'cache with max-age ("public, max-age=EXPIRES_SECONDS")', 'w3-total-cache' ); ?></option>
						<option value="cache_validation"<?php selected( $value, 'cache_validation' ); ?>><?php esc_html_e( 'cache with validation ("public, must-revalidate, proxy-revalidate")', 'w3-total-cache' ); ?></option>
						<option value="cache_maxage"<?php selected( $value, 'cache_maxage' ); ?><?php disabled( $is_nginx && $cssjs_expires ); ?>><?php esc_html_e( 'cache with max-age and validation ("max-age=EXPIRES_SECONDS, public, must-revalidate, proxy-revalidate")', 'w3-total-cache' ); ?></option>
						<option value="cache_noproxy"<?php selected( $value, 'cache_noproxy' ); ?>><?php esc_html_e( 'cache without proxy ("private, must-revalidate")', 'w3-total-cache' ); ?></option>
						<option value="no_cache"<?php selected( $value, 'no_cache' ); ?>><?php esc_html_e( 'don\'t cache ("max-age=0, private, no-store, no-cache, must-revalidate")', 'w3-total-cache' ); ?></option>
					</select>
					<?php if ( $is_nginx && $cssjs_expires ) : ?>
						<p class="description"><?php esc_html_e( 'The Expires header already sets the max-age.', 'w3-total-cache' ); ?></p>
					<?php endif; ?>
				</td>
			</tr>
			<tr>
				<th colspan="2">
					<?php $this->checkbox( 'browsercache.cssjs.etag' ); ?> <?php Util_Ui::e_config_label( 'browsercache.cssjs.etag' ); ?></label>
					<p class="description"><?php esc_html_e( 'Set the ETag header to encourage browser caching of files.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
			<tr>
				<th colspan="2">
					<?php $this->checkbox( 'browsercache.cssjs.w3tc' ); ?> <?php Util_Ui::e_config_label( 'browsercache.cssjs.w3tc' ); ?></label>
					<p class="description"><?php esc_html_e( 'Set this header to assist in identifying optimized files.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
			<tr>
				<th colspan="2">
					<?php $this->checkbox( 'browsercache.cssjs.compression' ); ?> <?php Util_Ui::e_config_label( 'browsercache.cssjs.compression' ); ?>  </label>
					<p class="description"><?php esc_html_e( 'Reduce the download time for text-based files.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
			<tr>
				<th colspan="2">
					<?php $this->checkbox( 'browsercache.cssjs.brotli', ! function_exists( 'brotli_compress' ) ); ?> <?php Util_Ui::e_config_label( 'browsercache.cssjs.brotli' ); ?>  </label>
					<p class="description"><?php esc_html_e( 'Reduce the download time for text-based files.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
			<tr>
				<th colspan="2">
					<?php $this->checkbox( 'browsercache.cssjs.replace' ); ?> <?php Util_Ui::e_config_label( 'browsercache.cssjs.replace' ); ?></label>
					<p class="description"><?php esc_html_e( 'Whenever settings are changed, a new query string will be generated and appended to objects allowing the new policy to be applied.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
			<tr>
				<th colspan="2">
					<?php $this->checkbox( 'browsercache.cssjs.querystring' ); ?> <?php esc_html_e( 'Remove query strings from static resources', 'w3-total-cache' ); ?></label>
					<p class="description">
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
								__(
									'Resources with a "?" in the %1$sURL%2$s are not cached by some proxy caching servers.',
									'w3-total-cache'
								),
								'<acronym title="' . esc_attr__( 'Uniform Resource Locator', 'w3-total-cache' ) . '">',
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
					<?php $this->checkbox( 'browsercache.cssjs.nocookies' ); ?> <?php Util_Ui::e_config_label( 'browsercache.cssjs.nocookies' ); ?></label>
					<p class="description"><?php esc_html_e( 'Removes Set-Cookie header for responses.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
		</table>

		<?php Util_Ui::button_config_save( 'browsercache_css_js' ); ?>
		<?php Util_Ui::postbox_footer(); ?>

		<?php
		Util_Ui::postbox_header(
			wp_kses(
				sprintf(
					// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag,
					// translators: 3 opening HTML acronym tag, 4 closing HTML acronym tag.
					__(
						'%1$sHTML%2$s &amp; %3$sXML%4$s',
						'w3-total-cache'
					),
					'<acronym title="' . esc_attr__( 'Hypertext Markup Language', 'w3-total-cache' ) . '">',
					'</acronym>',
					'<acronym title="' . esc_attr__( 'Extensible Markup Language', 'w3-total-cache' ) . '">',
					'</acronym>'
				),
				array(
					'acronym' => array(
						'title' => array(),
					),
				)
			),
			'',
			'html_xml'
		);
		?>
		<p><?php esc_html_e( 'Specify browser cache policy for posts, pages, feeds and text-based files.', 'w3-total-cache' ); ?></p>

		<table class="form-table">
			<tr>
				<th colspan="2">
					<?php $this->checkbox( 'browsercache.html.last_modified' ); ?> <?php Util_Ui::e_config_label( 'browsercache.html.last_modified' ); ?></label>
					<p class="description"><?php esc_html_e( 'Set the Last-Modified header to enable 304 Not Modified response.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
			<tr>
				<th colspan="2">
					<?php $this->checkbox( 'browsercache.html.expires' ); ?> <?php Util_Ui::e_config_label( 'browsercache.html.expires' ); ?></label>
					<p class="description"><?php esc_html_e( 'Set the expires header to encourage browser caching of files.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
			<tr>
				<th style="width: 250px;">
					<label for="browsercache_html_lifetime"><?php Util_Ui::e_config_label( 'browsercache.html.lifetime' ); ?></label>
				</th>
				<td>
					<input id="browsercache_html_lifetime" type="text" name="browsercache__html__lifetime"
						<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?>
						value="<?php echo esc_attr( $this->_config->get_integer( 'browsercache.html.lifetime' ) ); ?>"
						size="8" /> <?php esc_html_e( 'seconds', 'w3-total-cache' ); ?>
				</td>
			</tr>
			<tr>
				<th colspan="2">
					<?php $this->checkbox( 'browsercache.html.cache.control' ); ?> <?php Util_Ui::e_config_label( 'browsercache.html.cache.control' ); ?></label>
					<p class="description"><?php esc_html_e( 'Set pragma and cache-control headers to encourage browser caching of files.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
			<tr>
				<th>
					<label for="browsercache_html_cache_policy"><?php Util_Ui::e_config_label( 'browsercache.html.cache.policy' ); ?></label>
				</th>
				<td>
					<select id="browsercache_html_cache_policy" name="browsercache__html__cache__policy"
						<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?>>
						<?php
						$value        = $this->_config->get_string( 'browsercache.html.cache.policy' );
						$html_expires = $this->_config->get_boolean( 'browsercache.html.expires' );
						?>
						<option value="cache"<?php selected( $value, 'cache' ); ?>>cache ("public")</option>
						<option value="cache_public_maxage"<?php selected( $value, 'cache_public_maxage' ); ?><?php disabled( $is_nginx && $html_expires ); ?>><?php esc_html_e( 'cache with max-age ("public, max-age=EXPIRES_SECONDS")', 'w3-total-cache' ); ?></option>
						<option value="cache_validation"<?php selected( $value, 'cache_validation' ); ?>><?php esc_html_e( 'cache with validation ("public, must-revalidate, proxy-revalidate")', 'w3-total-cache' ); ?></option>
						<option value="cache_maxage"<?php selected( $value, 'cache_maxage' ); ?><?php disabled( $is_nginx && $html_expires ); ?>><?php esc_html_e( 'cache with max-age and validation ("max-age=EXPIRES_SECONDS, public, must-revalidate, proxy-revalidate")', 'w3-total-cache' ); ?></option>
						<option value="cache_noproxy"<?php selected( $value, 'cache_noproxy' ); ?>><?php esc_html_e( 'cache without proxy ("private, must-revalidate")', 'w3-total-cache' ); ?></option>
						<option value="no_cache"<?php selected( $value, 'no_cache' ); ?>><?php esc_html_e( 'no-cache ("max-age=0, private, no-store, no-cache, must-revalidate")', 'w3-total-cache' ); ?></option>
					</select>
					<?php if ( $is_nginx && $html_expires ) : ?>
						<p class="description"><?php esc_html_e( 'The Expires header already sets the max-age.', 'w3-total-cache' ); ?></p>
					<?php endif; ?>
				</td>
			</tr>
			<tr>
				<th colspan="2">
					<?php $this->checkbox( 'browsercache.html.etag' ); ?> <?php Util_Ui::e_config_label( 'browsercache.html.etag' ); ?></label>
					<p class="description"><?php esc_html_e( 'Set the ETag header to encourage browser caching of files.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
			<tr>
				<th colspan="2">
					<?php $this->checkbox( 'browsercache.html.w3tc' ); ?> <?php Util_Ui::e_config_label( 'browsercache.html.w3tc' ); ?></label>
					<p class="description"><?php esc_html_e( 'Set this header to assist in identifying optimized files.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
			<tr>
				<th colspan="2">
					<?php $this->checkbox( 'browsercache.html.compression' ); ?> <?php Util_Ui::e_config_label( 'browsercache.html.compression' ); ?></label>
					<p class="description"><?php esc_html_e( 'Reduce the download time for text-based files.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
			<tr>
				<th colspan="2">
					<?php $this->checkbox( 'browsercache.html.brotli', ! function_exists( 'brotli_compress' ) ); ?> <?php Util_Ui::e_config_label( 'browsercache.html.brotli' ); ?></label>
					<p class="description"><?php esc_html_e( 'Reduce the download time for text-based files.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
		</table>

		<?php Util_Ui::button_config_save( 'browsercache_html_xml' ); ?>
		<?php Util_Ui::postbox_footer(); ?>

		<?php Util_Ui::postbox_header( esc_html__( 'Media &amp; Other Files', 'w3-total-cache' ), '', 'media' ); ?>
		<table class="form-table">
			<tr>
				<th colspan="2">
					<?php $this->checkbox( 'browsercache.other.last_modified' ); ?> <?php Util_Ui::e_config_label( 'browsercache.other.last_modified' ); ?></label>
					<p class="description"><?php esc_html_e( 'Set the Last-Modified header to enable 304 Not Modified response.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
			<tr>
				<th colspan="2">
					<?php $this->checkbox( 'browsercache.other.expires' ); ?> <?php Util_Ui::e_config_label( 'browsercache.other.expires' ); ?></label>
					<p class="description"><?php esc_html_e( 'Set the expires header to encourage browser caching of files.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
			<tr>
				<th style="width: 250px;">
					<label for="browsercache_other_lifetime"><?php Util_Ui::e_config_label( 'browsercache.other.lifetime' ); ?></label>
				</th>
				<td>
					<input id="browsercache_other_lifetime" type="text"
						<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?>
						name="browsercache__other__lifetime" value="<?php echo esc_attr( $this->_config->get_integer( 'browsercache.other.lifetime' ) ); ?>" size="8" /> <?php esc_html_e( 'seconds', 'w3-total-cache' ); ?>
				</td>
			</tr>
			<tr>
				<th colspan="2">
					<?php $this->checkbox( 'browsercache.other.cache.control' ); ?> <?php Util_Ui::e_config_label( 'browsercache.other.cache.control' ); ?></label>
					<p class="description"><?php esc_html_e( 'Set pragma and cache-control headers to encourage browser caching of files.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
			<tr>
				<th>
					<label for="browsercache_other_cache_policy"><?php Util_Ui::e_config_label( 'browsercache.other.cache.policy' ); ?></label>
				</th>
				<td>
					<select id="browsercache_other_cache_policy"
						<?php Util_Ui::sealing_disabled( 'browsercache.' ); ?>
						name="browsercache__other__cache__policy">
						<?php
						$value         = $this->_config->get_string( 'browsercache.other.cache.policy' );
						$other_expires = $this->_config->get_string( 'browsercache.other.expires' );
						?>
						<option value="cache"<?php selected( $value, 'cache' ); ?>><?php esc_html_e( 'cache ("public")' ); ?></option>
						<option value="cache_public_maxage"<?php selected( $value, 'cache_public_maxage' ); ?><?php disabled( $is_nginx && $other_expires ); ?>><?php esc_html_e( 'cache with max-age ("public, max-age=EXPIRES_SECONDS")', 'w3-total-cache' ); ?></option>
						<option value="cache_validation"<?php selected( $value, 'cache_validation' ); ?>><?php esc_html_e( 'cache with validation ("public, must-revalidate, proxy-revalidate")', 'w3-total-cache' ); ?></option>
						<option value="cache_maxage"<?php selected( $value, 'cache_maxage' ); ?><?php disabled( $is_nginx && $other_expires ); ?>><?php esc_html_e( 'cache with max-age and validation ("max-age=EXPIRES_SECONDS, public, must-revalidate, proxy-revalidate")', 'w3-total-cache' ); ?></option>
						<option value="cache_noproxy"<?php selected( $value, 'cache_noproxy' ); ?>><?php esc_html_e( 'cache without proxy ("private, must-revalidate")', 'w3-total-cache' ); ?></option>
						<option value="no_cache"<?php selected( $value, 'no_cache' ); ?>><?php esc_html_e( 'no-cache ("max-age=0, private, no-store, no-cache, must-revalidate")', 'w3-total-cache' ); ?></option>
					</select>
					<?php if ( $is_nginx && $other_expires ) : ?>
						<p class="description"><?php esc_html_e( 'The Expires header already sets the max-age.', 'w3-total-cache' ); ?></p>
					<?php endif; ?>
				</td>
			</tr>
			<tr>
				<th colspan="2">
					<?php $this->checkbox( 'browsercache.other.etag' ); ?> <?php Util_Ui::e_config_label( 'browsercache.other.etag' ); ?></label>
					<p class="description"><?php esc_html_e( 'Set the ETag header to encourage browser caching of files.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
			<tr>
				<th colspan="2">
					<?php $this->checkbox( 'browsercache.other.w3tc' ); ?> <?php Util_Ui::e_config_label( 'browsercache.other.w3tc' ); ?></label>
					<p class="description"><?php esc_html_e( 'Set this header to assist in identifying optimized files.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
			<tr>
				<th colspan="2">
					<?php $this->checkbox( 'browsercache.other.compression' ); ?> <?php Util_Ui::e_config_label( 'browsercache.other.compression' ); ?>
					<p class="description"><?php esc_html_e( 'Reduce the download time for text-based files.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
			<tr>
				<th colspan="2">
					<?php $this->checkbox( 'browsercache.other.brotli', ! function_exists( 'brotli_compress' ) ); ?> <?php Util_Ui::e_config_label( 'browsercache.other.brotli' ); ?>
					<p class="description"><?php esc_html_e( 'Reduce the download time for text-based files.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
			<tr>
				<th colspan="2">
					<?php $this->checkbox( 'browsercache.other.replace' ); ?> <?php Util_Ui::e_config_label( 'browsercache.other.replace' ); ?></label>
					<p class="description"><?php esc_html_e( 'Whenever settings are changed, a new query string will be generated and appended to objects allowing the new policy to be applied.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
			<tr>
				<th colspan="2">
					<?php $this->checkbox( 'browsercache.other.querystring' ); ?> <?php esc_html_e( 'Remove query strings from static resources', 'w3-total-cache' ); ?></label>
					<p class="description">
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
								__(
									'Resources with a "?" in the %1$sURL%2$s are not cached by some proxy caching servers.',
									'w3-total-cache'
								),
								'<acronym title="' . esc_attr__( 'Uniform Resource Locator', 'w3-total-cache' ) . '">',
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
					<?php $this->checkbox( 'browsercache.other.nocookies' ); ?> <?php Util_Ui::e_config_label( 'browsercache.other.nocookies' ); ?></label>
					<p class="description"><?php esc_html_e( 'Removes Set-Cookie header for responses.', 'w3-total-cache' ); ?></p>
				</th>
			</tr>
		</table>

		<?php Util_Ui::button_config_save( 'browsercache_media' ); ?>
		<?php Util_Ui::postbox_footer(); ?>

		<?php require W3TC_DIR . '/BrowserCache_Page_View_SectionSecurity.php'; ?>
	</div>
</form>

<?php require W3TC_INC_DIR . '/options/common/footer.php'; ?>

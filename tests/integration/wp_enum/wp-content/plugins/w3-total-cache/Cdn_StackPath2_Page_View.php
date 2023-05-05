<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<?php if ( ! $authorized ) : ?>
	<tr>
		<th style="width: 300px;"><label><?php esc_html_e( 'Create account:', 'w3-total-cache' ); ?></label></th>
		<td>
			<p class="notice notice-error">
				<?php
				w3tc_e(
					'cdn.stackpath.widget.v2.no_cdn',
					sprintf(
						// translators: 1 HTML acronym for Content Delivery Network (CDN).
						__( 'W3 Total Cache has detected that you do not have a %1$s configured', 'w3-total-cache' ),
						'<acronym title="' . __( 'Content Delivery Network', 'w3-total-cache' ) . '">' . __( 'CDN', 'w3-total-cache' ) . '</acronym>'
					)
				);
				?>
			</p>
			<p>
				<?php esc_html_e( 'Enhance your website Performance with StackPath\'s CDN services. StackPath works magically with W3 Total Cache to speed up your site around the world for as little as $10 a month.', 'w3-total-cache' ); ?>
			</p>
			<p>
				<a href="<?php echo esc_url( W3TC_STACKPATH_SIGNUP_URL ); ?>" target="_blank" id="stackpath-create-account" class="button-primary"><?php w3tc_e( 'cdn.stackpath2.signUpAndSave', __( 'Sign Up Now and save!', 'w3-total-cache' ) ); ?></a>
			</p>
			<p class="description">
				<?php
				w3tc_e(
					'cdn.stackpath2.signUpAndSave.description',
					__( 'StackPath is a service that lets you speed up your site even more with W3 Total Cache. Sign up now to recieve a special offer!', 'w3-total-cache' )
				);
				?>
			</p>
		</td>
	</tr>
<?php endif; ?>

<tr>
	<th style="width: 300px;">
		<label>
			<?php esc_html_e( 'Specify account credentials:', 'w3-total-cache' ); ?>
		</label>
	</th>
	<td>
		<p>
			<?php esc_html_e( 'If you\'re an existing StackPath customer, enable CDN and Authorize. If you need help configuring your CDN, we also offer Premium Services to assist you.', 'w3-total-cache' ); ?>
		</p>

		<p>
			<?php if ( $authorized ) : ?>
				<input class="w3tc_cdn_stackpath2_authorize button-primary"
					type="button"
					value="<?php esc_attr_e( 'Reauthorize', 'w3-total-cache' ); ?>" />
			<?php else : ?>
				<input class="w3tc_cdn_stackpath2_authorize button-primary"
					type="button"
					value="<?php esc_attr_e( 'Authorize', 'w3-total-cache' ); ?>" />
			<?php endif; ?>
			<a class="button" href="<?php echo esc_url( wp_nonce_url( Util_Ui::admin_url( 'admin.php?page=w3tc_support' ), 'w3tc' ) ); ?>"><?php esc_html_e( 'Premium Services', 'w3-total-cache' ); ?></a>
		</p>
	</td>
</tr>

<?php if ( $authorized ) : ?>
	<?php if ( ! is_null( $http_domain ) ) : ?>
		<tr>
			<th>
				<label>
					<?php
					echo wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag,
							// translators: 3 opening HTML acronym tag, 4 closing HTML acronym tag,
							// translators: 5 opening HTML acronym tag, 6 closing HTML acronym tag.
							__(
								'%1$sCDN%2$s %3$sHTTP%4$s %5$sCNAME%6$s:',
								'w3-total-cache'
							),
							'<acronym title="' . esc_attr__( 'Content Delivery Network', 'w3-total-cache' ) . '">',
							'</acronym>',
							'<acronym title="' . esc_attr__( 'HyperText Transfer Protocol', 'w3-total-cache' ) . '">',
							'</acronym>',
							'<acronym title="' . esc_attr__( 'Canonical Name', 'w3-total-cache' ) . '">',
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
			</th>
			<td class="w3tc_config_value_text">
				<?php echo esc_html( $http_domain ); ?>
				<p class="description">
					<?php
					echo wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag,
							// translators: 3 opening HTML acronym tag, 4 closing HTML acronym tag,
							// translators: 5 opening HTML acronym tag, 6 closing HTML acronym tag.
							__(
								'This website domain has to be %1$sCNAME%2$s pointing to this %3$sCDN%4$s domain for %5$sHTTP%6$s requests',
								'w3-total-cache'
							),
							'<acronym title="' . esc_attr__( 'Canonical Name', 'w3-total-cache' ) . '">',
							'</acronym>',
							'<acronym title="' . esc_attr__( 'Content Delivery Network', 'w3-total-cache' ) . '">',
							'</acronym>',
							'<acronym title="' . esc_attr__( 'HyperText Transfer Protocol', 'w3-total-cache' ) . '">',
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
	<?php endif; ?>

	<?php if ( ! is_null( $https_domain ) ) : ?>
		<tr>
			<th>
				<label>
					<?php
					echo wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag,
							// translators: 3 opening HTML acronym tag, 4 closing HTML acronym tag,
							// translators: 5 opening HTML acronym tag, 6 closing HTML acronym tag.
							__(
								'%1$sCDN%2$s %3$sHTTPS%4$s %5$sCNAME%6$s:',
								'w3-total-cache'
							),
							'<acronym title="' . esc_attr__( 'Content Delivery Network', 'w3-total-cache' ) . '">',
							'</acronym>',
							'<acronym title="' . esc_attr__( 'HyperText Transfer Protocol over SSL', 'w3-total-cache' ) . '">',
							'</acronym>',
							'<acronym title="' . esc_attr__( 'Canonical Name', 'w3-total-cache' ) . '">',
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
			</th>
			<td class="w3tc_config_value_text">
				<?php echo esc_html( $https_domain ); ?>
				<p class="description">
					<?php
					echo wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag,
							// translators: 3 opening HTML acronym tag, 4 closing HTML acronym tag,
							// translators: 5 opening HTML acronym tag, 6 closing HTML acronym tag.
							__(
								'This website domain has to be %1$sCNAME%2$s pointing to this %3$sCDN%4$s domain for %5$sHTTPS%6$s requests',
								'w3-total-cache'
							),
							'<acronym title="' . esc_attr__( 'Canonical Name', 'w3-total-cache' ) . '">',
							'</acronym>',
							'<acronym title="' . esc_attr__( 'Content Delivery Network', 'w3-total-cache' ) . '">',
							'</acronym>',
							'<acronym title="' . esc_attr__( 'HyperText Transfer Protocol over SSL', 'w3-total-cache' ) . '">',
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
	<?php endif; ?>

	<tr>
		<th>
			<label for="cdn_stackpath_ssl">
				<?php
				echo wp_kses(
					sprintf(
						// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
						__(
							'%1$sSSL%2$s support:',
							'w3-total-cache'
						),
						'<acronym title="' . esc_attr__( 'Secure Sockets Layer', 'w3-total-cache' ) . '">',
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
		</th>
		<td>
			<select id="cdn_stackpath_ssl" name="cdn__stackpath__ssl" <?php Util_Ui::sealing_disabled( 'cdn.' ); ?>>
				<option value="auto"<?php selected( $config->get_string( 'cdn.stackpath.ssl' ), 'auto' ); ?>>
					<?php esc_html_e( 'Auto (determine connection type automatically)', 'w3-total-cache' ); ?>
				</option>
				<option value="enabled"<?php selected( $config->get_string( 'cdn.stackpath.ssl' ), 'enabled' ); ?>>
					<?php
					echo wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
							__(
								'Enabled (always use %1$sSSL%2$s)',
								'w3-total-cache'
							),
							'<acronym title="' . esc_attr__( 'Secure Sockets Layer', 'w3-total-cache' ) . '">',
							'</acronym>'
						),
						array(
							'acronym' => array(
								'title' => array(),
							),
						)
					);
					?>
				</option>
				<option value="disabled"<?php selected( $config->get_string( 'cdn.stackpath.ssl' ), 'disabled' ); ?>>
					<?php
					echo wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
							__(
								'Disabled (always use %1$sHTTP%2$s)',
								'w3-total-cache'
							),
							'<acronym title="' . esc_attr__( 'HyperText Transfer Protocol', 'w3-total-cache' ) . '">',
							'</acronym>'
						),
						array(
							'acronym' => array(
								'title' => array(),
							),
						)
					);
					?>
				</option>
			</select>
			<p class="description">
				<?php
				echo wp_kses(
					sprintf(
						// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag,
						// translators: 3 opening HTML acronym tag, 4 closing HTML acronym tag.
						__(
							'Some %1$sCDN%2$s providers may or may not support %3$sSSL%4$s, contact your vendor for more information.',
							'w3-total-cache'
						),
						'<acronym title="' . esc_attr__( 'Content Delivery Network', 'w3-total-cache' ) . '">',
						'</acronym>',
						'<acronym title="' . esc_attr__( 'Secure Sockets Layer', 'w3-total-cache' ) . '">',
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
		<th><?php esc_html_e( 'Replace site\'s hostname with:', 'w3-total-cache' ); ?></th>
		<td>
			<?php
			$cnames = $config->get_array( 'cdn.stackpath2.domain' );
			include W3TC_INC_DIR . '/options/cdn/common/cnames.php';
			?>
			<p class="description">
				<?php
				echo wp_kses(
					sprintf(
						// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag,
						// translators: 3 opening HTML acronym tag, 4 closing HTML acronym tag.
						__(
							'Enter the hostname provided by your %1$sCDN%2$s provider, this value will replace your site\'s hostname in the %3$sHTML%4$s.',
							'w3-total-cache'
						),
						'<acronym title="' . esc_attr__( 'Content Delivery Network', 'w3-total-cache' ) . '">',
						'</acronym>',
						'<acronym title="' . esc_attr__( 'Hypertext Markup Language', 'w3-total-cache' ) . '">',
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
			<input id="cdn_test" class="button {type: 'stackpath', nonce: '<?php echo esc_attr( wp_create_nonce( 'w3tc' ) ); ?>'}" type="button" value="<?php esc_attr_e( 'Test StackPath', 'w3-total-cache' ); ?>" /> <span id="cdn_test_status" class="w3tc-status w3tc-process"></span>
		</th>
	</tr>

<?php endif; ?>

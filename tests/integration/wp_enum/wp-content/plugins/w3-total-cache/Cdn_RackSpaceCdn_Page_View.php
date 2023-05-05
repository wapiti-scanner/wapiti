<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}

?>
<tr>
	<th style="width: 300px;"><label><?php esc_html_e( 'Authorize:', 'w3-total-cache' ); ?></label></th>
	<td>
		<?php if ( $authorized ) : ?>
			<input class="w3tc_cdn_rackspace_authorize button" type="button"
				value="<?php esc_attr_e( 'Reauthorize', 'w3-total-cache' ); ?>" />
		<?php else : ?>
			<input class="w3tc_cdn_rackspace_authorize button" type="button"
				value="<?php esc_attr_e( 'Authorize', 'w3-total-cache' ); ?>" />
		<?php endif; ?>
	</td>
</tr>

<?php if ( $authorized ) : ?>
	<tr>
		<th><?php esc_html_e( 'Username:', 'w3-total-cache' ); ?></th>
		<td class="w3tc_config_value_text">
			<?php echo esc_html( $config->get_string( 'cdn.rackspace_cdn.user_name' ) ); ?>
		</td>
	</tr>
	<tr>
		<th><?php esc_html_e( 'Region:', 'w3-total-cache' ); ?></th>
		<td class="w3tc_config_value_text">
			<?php echo esc_html( $config->get_string( 'cdn.rackspace_cdn.region' ) ); ?>
		</td>
	</tr>
	<tr>
		<th><?php esc_html_e( 'Service:', 'w3-total-cache' ); ?></th>
		<td class="w3tc_config_value_text">
			<?php echo esc_html( $config->get_string( 'cdn.rackspace_cdn.service.name' ) ); ?>
		</td>
	</tr>
	<tr>
		<th>
			<label>
				<?php
				echo wp_kses(
					sprintf(
						// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag,
						// translators: 3 opening HTML acronym tag, 4 closing HTML acronym tag.
						__(
							'%1$sCDN%2$s host (%3$sCNAME%4$s target):',
							'w3-total-cache'
						),
						'<acronym title="' . esc_attr__( 'Content Delivery Network', 'w3-total-cache' ) . '">',
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
			<?php echo esc_html( $access_url_full ); ?>
		</td>
	</tr>
	<?php if ( $config->get_string( 'cdn.rackspace_cdn.service.protocol' ) === 'http' ) : ?>
		<tr>
			<th><?php esc_html_e( 'Replace site\'s hostname with:', 'w3-total-cache' ); ?></th>
			<td>
				<?php
				$cnames = $config->get_array( 'cdn.rackspace_cdn.domains' );
				include W3TC_INC_DIR . '/options/cdn/common/cnames-readonly.php';
				?>
				<input class="w3tc_cdn_rackspace_configure_domains button" type="button"
						value="<?php esc_attr_e( 'Configure CNAMEs', 'w3-total-cache' ); ?>" />
				<p class="description">
					<?php
					echo wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag,
							// translators: 3 opening HTML acronym tag, 4 closing HTML acronym tag.
							__(
								'Enter hostname mapped to %1$sCDN%2$s host, this value will replace your site\'s hostname in the %3$sHTML%4$s.',
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
	<?php else : ?>
		<tr>
			<th><?php esc_html_e( 'Replace site\'s hostname with:', 'w3-total-cache' ); ?></th>
			<td>
				<?php
				$cnames = $config->get_array( 'cdn.rackspace_cdn.domains' );
				include W3TC_INC_DIR . '/options/cdn/common/cnames-readonly.php';
				?>
				<input name="w3tc_cdn_rackspace_cdn_domains_reload"
						class="w3tc-button-save button" type="submit"
						value="
							<?php
							echo wp_kses(
								sprintf(
									// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
									__(
										'Reload %1$sCNAME%2$ss from RackSpace',
										'w3-total-cache'
									),
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
						" />
				<p class="description">
					<?php
					echo wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag,
							// translators: 3 opening HTML acronym tag, 4 closing HTML acronym tag.
							__(
								'Hostname(s) mapped to %1$sCDN%2$s host, this value will replace your site\'s hostname in the %3$sHTML%4$s. You can manage them from RackSpace management console and load here afterwards.',
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
	<?php endif; ?>
	<tr>
		<th colspan="2">
			<input id="cdn_test"
				class="button {type: 'rackspace_cdn', nonce: '<?php echo esc_attr( wp_create_nonce( 'w3tc' ) ); ?>'}"
				type="button"
				value="<?php esc_attr_e( 'Test', 'w3-total-cache' ); ?>" />
			<span id="cdn_test_status" class="w3tc-status w3tc-process"></span>
		</th>
	</tr>
<?php endif; ?>

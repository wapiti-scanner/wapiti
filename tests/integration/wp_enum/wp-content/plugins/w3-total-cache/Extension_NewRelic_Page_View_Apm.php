<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}

?>
<p>
	<?php esc_html_e( 'Jump to:', 'w3-total-cache' ); ?>
	<a href="admin.php?page=w3tc_general"><?php esc_html_e( 'Main Menu', 'w3-total-cache' ); ?></a> |
	<a href="admin.php?page=w3tc_extensions"><?php esc_html_e( 'Extensions', 'w3-total-cache' ); ?></a>
</p>
<p>
	<?php esc_html_e( 'NewRelic extension is currently', 'w3-total-cache' ); ?>
	<?php
	if ( $config->is_extension_active_frontend( 'newrelic' ) ) {
		echo '<span class="w3tc-enabled">' . esc_html__( 'enabled', 'w3-total-cache' ) . '</span>';
	} else {
		echo '<span class="w3tc-disabled">' . esc_html__( 'disabled', 'w3-total-cache' ) . '</span>';
	}
	?>
	.
<p>

<form action="admin.php?page=w3tc_monitoring" method="post">
	<div class="metabox-holder">
		<?php Util_Ui::postbox_header( esc_html__( 'Application Settings', 'w3-total-cache' ), '', 'application' ); ?>
		<?php if ( $application_settings ) : ?>
		<table class="form-table">
			<tr>
				<th>
					<label><?php esc_html_e( 'Application ID:', 'w3-total-cache' ); ?></label>
				</th>
				<td>
					<?php echo esc_html( $application_settings['application-id'] ); ?>
				</td>
			</tr>
			<tr>
				<th>
					<label><?php esc_html_e( 'Application name:', 'w3-total-cache' ); ?></label>
				</th>
				<td>
					<?php echo esc_html( $application_settings['name'] ); ?>
				</td>
			</tr>
			<tr>
				<th>
					<label for="alerts-enabled"><?php esc_html_e( 'Alerts enabled:', 'w3-total-cache' ); ?></label>
				</th>
				<td>
					<input name="alerts-enabled]" type="hidden" value="false" />
					<input id="alerts-enabled" name="application[alerts_enabled]"
						type="checkbox" value="1" <?php checked( $application_settings['alerts-enabled'], 'true' ); ?> <?php Util_Ui::sealing_disabled( 'newrelic' ); ?>/>
				</td>
			</tr>
			<tr>
				<th>
					<label for="app-apdex-t"><?php esc_html_e( 'Application ApDex Threshold:', 'w3-total-cache' ); ?></label>
				</th>
				<td>
					<input id="app-apdex-t" name="application[app_apdex_t]" type="text"
						value="<?php echo esc_attr( $application_settings['app-apdex-t'] ); ?>"
						<?php Util_Ui::sealing_disabled( 'newrelic' ); ?> />
				</td>
			</tr>
			<tr>
				<th>
					<label for="rum-apdex-t">
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
								__(
									'%1$sRUM%2$s ApDex Threshold:',
									'w3-total-cache'
								),
								'<acronym title="' . esc_attr__( 'Real User Monitoring', 'w3-total-cache' ) . '">',
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
					<input id="rum-apdex-t" name="application[rum_apdex_t]" type="text"
						value="<?php echo esc_attr( $application_settings['rum-apdex-t'] ); ?>"
						<?php Util_Ui::sealing_disabled( 'newrelic' ); ?>/>
				</td>
			</tr>
			<tr>
				<th>
					<label for="rum-enabled">
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
								__(
									'%1$sRUM%2$s enabled:',
									'w3-total-cache'
								),
								'<acronym title="' . esc_attr__( 'Real User Monitoring', 'w3-total-cache' ) . '">',
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
					<input name="application[rum_enabled]" type="hidden" value="false"
						<?php Util_Ui::sealing_disabled( 'newrelic' ); ?> />
					<input id="rum-enabled" name="application[rum_enabled]"
						type="checkbox" value="1"
						<?php checked( $application_settings['rum-enabled'], 'true' ); ?>
						<?php Util_Ui::sealing_disabled( 'newrelic' ); ?>/>
				</td>
			</tr>
		</table>
		<p class="submit">
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
			<input type="submit" name="w3tc_save_new_relic"
				class="w3tc-button-save button-primary"
				<?php Util_Ui::sealing_disabled( 'newrelic' ); ?>
				value="<?php esc_attr_e( 'Save New Relic settings', 'w3-total-cache' ); ?>" />
		</p>
		<?php elseif ( empty( $application_settings ) ) : ?>
		<p class="description">
			<?php
			echo wp_kses(
				sprintf(
					// translators: 1 opening HTML a tag to W3TC monitoring settings page, 2 closing HTML a tag.
					__(
						'Application settings could not be retrieved. New Relic may not be properly configured, %1$sreview the settings%2$s.',
						'w3-total-cache'
					),
					'<a href="' . esc_url( network_admin_url( 'admin.php?page=w3tc_general#monitoring' ) ) . '">',
					'</a>'
				),
				array(
					'a' => array(
						'href' => array(),
					),
				)
			);
			?>
		</p>
		<?php else : ?>
		<p><?php esc_html_e( 'Application settings are only visible when New Relic is enabled', 'w3-total-cache' ); ?></p>
		<?php endif; ?>
		<?php Util_Ui::postbox_footer(); ?>
	</form>
	<form action="admin.php?page=w3tc_monitoring" method="post">

	<?php Util_Ui::postbox_header( esc_html__( 'Dashboard Settings', 'w3-total-cache' ), '', 'dashboard' ); ?>
	<table class="form-table">
		<tr>
			<th>
				<label for="newrelic_cache_time">
					<?php esc_html_e( 'Cache time:', 'w3-total-cache' ); ?>
				</label>
			</th>
			<td><input id="newrelic_cache_time" name="extension__newrelic__cache_time"
				type="text" value="<?php echo esc_attr( $config->get_integer( array( 'newrelic', 'cache_time', 5 ) ) ); ?>"
				<?php Util_Ui::sealing_disabled( 'newrelic' ); ?> />
				<p class="description">
					<?php esc_html_e( 'How many minutes data retrieved from New Relic should be stored. Minimum is 1 minute.', 'w3-total-cache' ); ?>
				</p>
			</td>
		</tr>
	</table>
	<?php Util_Ui::button_config_save( 'extension_newrelic_dashboard' ); ?>
	<?php Util_Ui::postbox_footer(); ?>

	<?php Util_Ui::postbox_header( esc_html__( 'Behavior Settings', 'w3-total-cache' ), '', 'behavior' ); ?>
	<table  class="form-table">
		<tr>
			<th colspan="2">
				<?php
				Util_Ui::checkbox(
					'',
					Util_Ui::config_key_to_http_name( array( 'newrelic', 'accept.logged_roles' ) ),
					$config->get_boolean( array( 'newrelic', 'accept.logged_roles' ) ),
					$config->is_sealed( 'newrelic' )
				);
				echo wp_kses(
					sprintf(
						// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
						__(
							'Use %1$sRUM%2$s only for following user roles',
							'w3-total-cache'
						),
						'<acronym title="' . esc_attr__( 'Real User Monitoring', 'w3-total-cache' ) . '">',
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
				<p class="description">
					<?php
					echo wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
							__(
								'Select user roles that %1$sRUM%2$s should be enabled for:',
								'w3-total-cache'
							),
							'<acronym title="' . esc_attr__( 'Real User Monitoring', 'w3-total-cache' ) . '">',
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

				<div id="newrelic_accept_roles" class="w3tc_reject_roles">
					<?php $saved_roles = $config->get_array( array( 'newrelic', 'accept.roles' ) ); ?>
					<input type="hidden" name="newrelic___accept__roles" value="" /><br />
					<?php foreach ( get_editable_roles() as $role_name => $role_data ) : ?>
						<input type="checkbox" name="newrelic___accept__roles[]" value="<?php echo esc_attr( $role_name ); ?>"
							<?php checked( in_array( $role_name, $saved_roles, true ) ); ?>
							id="role_<?php echo esc_attr( $role_name ); ?>"
							<?php Util_Ui::sealing_disabled( 'newrelic' ); ?> />
						<label for="role_<?php echo esc_attr( $role_name ); ?>"><?php echo esc_html( $role_data['name'] ); ?></label>
					<?php endforeach; ?>
				</div>
			</th>
		</tr>
		<tr>
			<th>
				<label for="newrelic_include_rum">
					<?php
					wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
							__(
								'Include %1$sRUM%2$s in compressed or cached pages:',
								'w3-total-cache'
							),
							'<acronym title="' . esc_attr__( 'Real User Monitoring', 'w3-total-cache' ) . '">',
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
				<input name="extension__newrelic__include_rum" type="hidden" value="0"
					<?php Util_Ui::sealing_disabled( 'newrelic' ); ?> />
				<input id="newrelic_include_rum" name="extension__newrelic__include_rum"
					type="checkbox" value="1"
					<?php checked( $config->get_boolean( array( 'newrelic', 'include_rum' ) ) ); ?>
					<?php Util_Ui::sealing_disabled( 'newrelic' ); ?> />
				<p class="description">
					<?php
					echo wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
							__(
								'This enables inclusion of %1$sRUM%2$s when using Page Cache together with Browser Cache gzip or when using Page Cache with Disc: Enhanced',
								'w3-total-cache'
							),
							'<acronym title="' . esc_attr__( 'Real User Monitoring', 'w3-total-cache' ) . '">',
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
			<th>
				<label for="newrelic_use_php_function">
					<?php
					echo wp_kses(
						sprintf(
							// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
							__(
								'Use %1$sPHP%2$s function to set application name:',
								'w3-total-cache'
							),
							'<acronym title="' . esc_attr__( 'Hypertext Preprocessor', 'w3-total-cache' ) . '">',
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
				<?php if ( Util_Environment::is_wpmu() ) : ?>
				<input id="newrelic_use_php_function" name="extension__newrelic__use_php_function" type="checkbox" value="1" checked="checked" disabled="disabled" />
					<p class="description">
						<?php esc_html_e( 'This is required when using New Relic on a network install to set the proper names for sites.', 'w3-total-cache' ); ?>
					</p>
				<?php else : ?>
				<input name="extension__newrelic__use_php_function" type="hidden" value="0" />
				<input id="newrelic_use_php_function" name="extension__newrelic__use_php_function" type="checkbox" value="1" <?php checked( $config->get_boolean( array( 'newrelic', 'use_php_function' ) ) ); ?>/>
					<p class="description">
						<?php
						echo wp_kses(
							sprintf(
								// translators: 1 opening HTML a tag to NewRelic per directory settings documentation, 2 closing HTML a tag.
								__(
									'Enable this to dynamically set proper application name. (See New Relic %1$sPer-directory settings%2$s for other methods.',
									'w3-total-cache'
								),
								'<a href="https://newrelic.com/docs/php/per-directory-settings">',
								'</a>'
							),
							array(
								'a' => array(
									'href' => array(),
								),
							)
						);
						?>
					</p>
				<?php endif ?>
			</td>
		</tr>
		<tr>
			<th>
				<label for="newrelic_enable_xmit">
					<?php
					esc_html_e( 'Enable XMIT:', 'w3-total-cache' )
					?>
				</label>
			</th>
			<td><input name="" type="hidden" value="0" />
			<input id="newrelic_enable_xmit" name="extension__newrelic__enable_xmit" type="checkbox" value="1" <?php checked( $config->get_boolean( array( 'newrelic', 'enable_xmit' ) ) ); ?> <?php Util_Ui::sealing_disabled( 'newrelic' ); ?>/>
				<p class="description">
					<?php
					echo wp_kses(
						sprintf(
							// translators: 1 opening HTML em tag, 2 opening HTML a tag to NewRelic PHP API documentation,
							// translators: 3 closing HTML a tag, 4 closing HTML em tag.
							__(
								'Enable this if you want to record the metric and transaction data (until the name is changed using PHP function), specify a value of true for this argument to make the agent send the transaction to the daemon. There is a slight performance impact as it takes a few milliseconds for the agent to dump its data. %1$sFrom %2$sNew Relic PHP API doc%3$s%4$s',
								'w3-total-cache'
							),
							'<em>',
							'<a href="https://newrelic.com/docs/php/the-php-api">',
							'</a>',
							'</em>'
						),
						array(
							'a'  => array(
								'href' => array(),
							),
							'em' => array(),
						)
					);
					?>
				</p>
			</td>
		</tr>
	</table>
	<?php Util_Ui::button_config_save( 'extension_newrelic_behaviour' ); ?>
	<?php Util_Ui::postbox_footer(); ?>
	</div>
</form>
<?php if ( $view_metric ) : ?>
<table>
	<?php foreach ( $metric_names as $metric ) : ?>
	<tr>
		<th style="text-align: right"><strong><?php echo esc_html( $metric->name ); ?></strong></th>
		<td><?php echo esc_html( implode( ', ', $metric->fields ) ); ?></td>
	</tr>
	<?php endforeach; ?>
</table>
<?php endif; ?>

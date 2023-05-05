<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<?php
Util_Ui::postbox_header( esc_html__( 'Monitoring', 'w3-total-cache' ), '', 'monitoring' );
Util_Ui::config_overloading_button( array( 'key' => 'newrelic.configuration_overloaded' ) );
?>

<?php if ( ! $new_relic_installed ) : ?>
	<p>
		<?php
		echo wp_kses(
			sprintf(
				// translators: 1 opening HTML a tag to W3TC NewRelic Signup page, 2 closing HTML a tag,
				// translators: 3 opening HTML a tag to NewRelic documentation for PHP, 4 closing HTML a tag.
				__(
					'New Relic may not be installed or not active on this server. %1$sSign up for a (free) account%2$s. Visit %3$sNew Relic%4$s for installation instructions.',
					'w3-total-cache'
				),
				'<a href="' . esc_url( W3TC_NEWRELIC_SIGNUP_URL ) . '" target="_blank">',
				'</a>',
				'<a href="' . esc_url( 'https://newrelic.com/docs/php/new-relic-for-php' ) . '" target="_blank">',
				'</a>'
			),
			array(
				'a' => array(
					'href'   => array(),
					'target' => array(),
				),
			)
		);
		?>
	</p>
<?php endif; ?>

<table class="form-table">
	<tr>
		<th>
			<label for="newrelic_api_key">
				<?php
				echo wp_kses(
					sprintf(
						// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
						__(
							'%1$sAPI%2$s key:',
							'w3-total-cache'
						),
						'<acronym title="' . esc_attr__( 'Application Programming Interface', 'w3-total-cache' ) . '">',
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
		<td class="w3tc-td-with-button">
			<?php echo esc_html( $config->get_string( array( 'newrelic', 'api_key' ) ) ); ?>
			<input type="button" class="button w3tcnr_configure" value="Configure"
				<?php Util_Ui::sealing_disabled( 'newrelic' ); ?> />
		</td>
	</tr>
	<tr>
		<th>
			<label><?php esc_html_e( 'Application name:', 'w3-total-cache' ); ?></label>
		</th>
		<td class="w3tc-td-with-button">
			<?php
			if ( 'browser' === $config->get_string( array( 'newrelic', 'monitoring_type' ) ) ) {
				echo '(browser) ';
			}

			echo esc_html( $effective_appname );
			?>
		</td>
	</tr>
</table>
<?php Util_Ui::button_config_save( 'general_newrelic' ); ?>
<?php Util_Ui::postbox_footer(); ?>

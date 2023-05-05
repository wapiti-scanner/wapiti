<?php
/**
 * File: Cdn_GeneralPage_View.php
 *
 * @package W3TC
 */

namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}

Util_Ui::postbox_header(
	wp_kses(
		sprintf(
			// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
			__(
				'%1$sCDN%2$s',
				'w3-total-cache'
			),
			'<acronym title="' . __( 'Content Delivery Network', 'w3-total-cache' ) . '">',
			'</acronym>'
		),
		array(
			'acronym' => array(
				'title' => array(),
			),
		)
	),
	'',
	'cdn'
);
Util_Ui::config_overloading_button(
	array(
		'key' => 'cdn.configuration_overloaded',
	)
);
?>
<p>
	<?php
	w3tc_e(
		'cdn.general.header',
		wp_kses(
			sprintf(
				// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
				__(
					'Host static files with your %1$sCDN%2$s to reduce page load time.',
					'w3-total-cache'
				),
				'<acronym title="' . __( 'Content Delivery Network', 'w3-total-cache' ) . '">',
				'</acronym>'
			),
			array(
				'acronym' => array(
					'title' => array(),
				),
			)
		)
	);

	if ( ! $cdn_enabled ) {
		echo '&nbsp;' . wp_kses(
			sprintf(
				// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag,
				// translators: 3 opening HTML a tag, 4 closing HTML a tag.
				__(
					'If you do not have a %1$sCDN%2$s provider try StackPath. %3$sSign up now to enjoy a special offer!%4$s.',
					'w3-total-cache'
				),
				'<acronym title="' . __( 'Content Delivery Network', 'w3-total-cache' ) . '">',
				'</acronym>',
				'<a href="' . esc_url( wp_nonce_url( Util_Ui::admin_url( 'admin.php?page=w3tc_dashboard&w3tc_cdn_stackpath_signup' ), 'w3tc' ) ) . '" target="_blank">',
				'</a>'
			),
			array(
				'acronym' => array(
					'title' => array(),
				),
				'a'       => array(
					'href'   => array(),
					'target' => array(),
				),
			)
		);
	}
	?>
</p>
<table class="form-table">
	<?php
	Util_Ui::config_item(
		array(
			'key'            => 'cdn.enabled',
			'control'        => 'checkbox',
			'checkbox_label' => __( 'Enable', 'w3-total-cache' ),
			'description'    => wp_kses(
				sprintf(
					// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag,
					// translators: 3 opening HTML acronym tag, 4 closing acronym tag.
					__(
						'Theme files, media library attachments, %1$sCSS%2$s, %3$sJS%4$s files etc will quickly for site visitors.',
						'w3-total-cache'
					),
					'<acronym title="' . __( 'Cascading Style Sheet', 'w3-total-cache' ) . '">',
					'</acronym>',
					'<acronym title="' . __( 'JavaScript', 'w3-total-cache' ) . '">',
					'</acronym>'
				),
				array(
					'acronym' => array(
						'title' => array(),
					),
				)
			),
		)
	);

	Util_Ui::config_item(
		array(
			'key'                 => 'cdn.engine',
			'control'             => 'selectbox',
			'selectbox_values'    => $engine_values,
			'selectbox_optgroups' => $engine_optgroups,
			'description'         => wp_kses(
				sprintf(
					// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag.
					__(
						'Select the %1$sCDN%2$s type you wish to use.',
						'w3-total-cache'
					),
					'<acronym title="' . __( 'Content Delivery Network', 'w3-total-cache' ) . '">',
					'</acronym>'
				),
				array(
					'acronym' => array(
						'title' => array(),
					),
				)
			),
		)
	);
	?>
</table>

<?php
do_action( 'w3tc_settings_general_boxarea_cdn_footer' );

Util_Ui::button_config_save(
	'general_cdn',
	'<input id="cdn_purge" type="button" value="' . __( 'Empty cache', 'w3-total-cache' ) .
		'" ' . ( $cdn_enabled && Cdn_Util::can_purge_all( $config->get_string( 'cdn.engine' ) ) ? '' : ' disabled="disabled" ' ) .
		' class="button {nonce: \'' . wp_create_nonce( 'w3tc' ) . '\'}" />'
);
?>
<?php Util_Ui::postbox_footer(); ?>

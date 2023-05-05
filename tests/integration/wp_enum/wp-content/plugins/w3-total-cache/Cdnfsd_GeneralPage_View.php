<?php
/**
 * File: Cdnfsd_GeneralPage_View.php
 *
 * @package W3TC
 */

namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}
?>
<p>
	<?php
	w3tc_e(
		'cdnfsd.general.header',
		sprintf(
			// translators: 1 HTML acronym for Content Delivery Network (CDN).
			__( 'Host the entire website with your compatible %1$s provider to reduce page load time.', 'w3-total-cache' ),
			'<acronym title="' . __( 'Content Delivery Network', 'w3-total-cache' ) . '">' . __( 'CDN', 'w3-total-cache' ) . '</acronym>'
		)
	);

	if ( ! $cdnfsd_enabled ) {
		echo '&nbsp;' . wp_kses(
			sprintf(
				// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag,
				// translators: 3 opening HTML a tag to W3TC MaxCDN Signup admin page, 4 closing HTML a tag.
				__(
					'If you do not have a %1$sCDN%2$s provider try StackPath. %3$sSign up now to enjoy a special offer!%4$s.',
					'w3-total-cache'
				),
				'<acronym title="' . esc_attr__( 'Content Delivery Network', 'w3-total-cache' ) . '">',
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

<table class="<?php echo esc_attr( Util_Ui::table_class() ); ?>">
	<?php
	Util_Ui::config_item_pro(
		array(
			'key'            => 'cdnfsd.enabled',
			'label'          => wp_kses(
				sprintf(
					// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag,
					// translators: 3 opening HTML acronym tag, 4 closing HTML acronym tag.
					__(
						'%1$sFSD%2$s %3$sCDN%4$s:',
						'w3-total-cache'
					),
					'<acronym title="' . esc_attr__( 'Full Site Delivery', 'w3-total-cache' ) . '">',
					'</acronym>',
					'<acronym title="' . esc_attr__( 'Content Delivery Network', 'w3-total-cache' ) . '">',
					'</acronym>'
				),
				array(
					'acronym' => array(
						'title' => array(),
					),
				)
			),
			'control'        => 'checkbox',
			'checkbox_label' => __( 'Enable', 'w3-total-cache' ),
			'disabled'       => ( $is_pro ? null : true ),
			'excerpt'        => __( 'Deliver visitors the lowest possible response and load times for all site content including HTML, media (e.g. images or fonts), CSS, and JavaScript.', 'w3-total-cache' ),
			'description'    => array(
				__( 'Want even faster speeds? The full site delivery Content Delivery Network will speed up your website by over 60% to increase conversions, revenue and reach your website visitors globally. With a Full Site Content Delivery Network (CDN), your website and all its assets will be available instantly to your visitors all over the world at blazing fast speeds.', 'w3-total-cache' ),
				wp_kses(
					sprintf(
						// translators: 1 opening HTML a tag to W3TC admin support page, 2 closing HTML a tag.
						__(
							'For even better performance, combine FSD with other powerful features like Browser Cache, Minify, Fragment caching, or Lazy Load! Did you know that we offer premium support, customization and audit services? %1$sClick here for more information%2$s.',
							'w3-total-cache'
						),
						'<a href="' . esc_url( admin_url( 'admin.php?page=w3tc_support' ) ) . '">',
						'</a>'
					),
					array(
						'a' => array(
							'href' => array(),
						),
					)
				),
			),
		)
	);

	Util_Ui::config_item(
		array(
			'key'              => 'cdnfsd.engine',
			'label'            => wp_kses(
				sprintf(
					// translators: 1 opening HTML acronym tag, 2 closing HTML acronym tag,
					// translators: 3 opening HTML acronym tag, 4 closing HTML acronym tag.
					__(
						'%1$sFSD%2$s %3$sCDN%4$s Type:',
						'w3-total-cache'
					),
					'<acronym title="' . esc_attr__( 'Full Site Delivery', 'w3-total-cache' ) . '">',
					'</acronym>',
					'<acronym title="' . esc_attr__( 'Content Delivery Network', 'w3-total-cache' ) . '">',
					'</acronym>'
				),
				array(
					'acronym' => array(
						'title' => array(),
					),
				)
			),
			'control'          => 'selectbox',
			'selectbox_values' => $cdnfsd_engine_values,
			'value'            => $cdnfsd_engine,
			'disabled'         => ( $is_pro ? null : true ),
			'description'      => wp_kses(
				sprintf(
					// translators: 1 opening HTML acronym tag, closing HTML acronym tag,
					// translators: 3 CDNFSD engine extra description.
					__(
						'Select the %1$sCDN%2$s type you wish to use. %3$s',
						'w3-total-cache'
					),
					'<acronym title="' . esc_attr__( 'Content Delivery Network', 'w3-total-cache' ) . '">',
					'</acronym>',
					$cdnfsd_engine_extra_description
				),
				array(
					'acronym' => array(
						'title' => array(),
					),
				)
			),
			'show_in_free'     => false,
		)
	);
	?>
</table>

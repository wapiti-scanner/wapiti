<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}

$c      = Dispatcher::config();
$is_pro = Util_Environment::is_w3tc_pro( $c );

$plugins                 = get_option( 'active_plugins' );
$is_wp_google_maps       = ( in_array( 'wp-google-maps/wpGoogleMaps.php', $plugins, true ) );
$is_wp_google_map_plugin = ( in_array( 'wp-google-map-plugin/wp-google-map-plugin.php', $plugins, true ) );
$is_google_maps_easy     = ( in_array( 'google-maps-easy/gmp.php', $plugins, true ) );

?>
<?php Util_Ui::postbox_header( esc_html__( 'Lazy Loading', 'w3-total-cache' ), '', 'application' ); ?>
<table class="form-table">
	<?php
	Util_Ui::config_item(
		array(
			'key'            => 'lazyload.process_img',
			'control'        => 'checkbox',
			'checkbox_label' => esc_html__( 'Process HTML image tags', 'w3-total-cache' ),
			'description'    => wp_kses(
				sprintf(
					// translators: 1 opening HTML code tag, 2 closing HTML code tag.
					__(
						'Process %1$simg%2$s tags',
						'w3-total-cache'
					),
					'<code>',
					'</code>'
				),
				array(
					'code' => array(),
				)
			),
		)
	);

	Util_Ui::config_item(
		array(
			'key'            => 'lazyload.process_background',
			'control'        => 'checkbox',
			'checkbox_label' => esc_html__( 'Process background images', 'w3-total-cache' ),
			'description'    => wp_kses(
				sprintf(
					// translators: 1 opening HTML code tag, 2 closing HTML code tag.
					__(
						'Process %1$sbackground%2$s styles',
						'w3-total-cache'
					),
					'<code>',
					'</code>'
				),
				array(
					'code' => array(),
				)
			),
		)
	);

	Util_Ui::config_item(
		array(
			'key'         => 'lazyload.exclude',
			'label'       => esc_html__( 'Exclude words:', 'w3-total-cache' ),
			'control'     => 'textarea',
			'description' => esc_html__( 'Exclude tags containing words', 'w3-total-cache' ),
		)
	);

	Util_Ui::config_item(
		array(
			'key'         => 'lazyload.threshold',
			'control'     => 'textbox',
			'label'       => esc_html__( 'Threshold', 'w3-total-cache' ),
			'description' => esc_html__( 'The outer distance off the scrolling area from which to start loading the elements (example: 100px, 10%).', 'w3-total-cache' ),
		)
	);

	Util_Ui::config_item(
		array(
			'key'              => 'lazyload.embed_method',
			'label'            => esc_html__( 'Script Embed method:', 'w3-total-cache' ),
			'control'          => 'selectbox',
			'selectbox_values' => array(
				'async_head'    => esc_attr__( 'async', 'w3-total-cache' ),
				'sync_head'     => esc_attr__( 'sync (to head)', 'w3-total-cache' ),
				'inline_footer' => esc_attr__( 'inline', 'w3-total-cache' ),
			),
			'description'      => wp_kses(
				sprintf(
					// translators: 1 opening HTML code tag, 2 closing HTML code tag.
					__(
						'Use %1$sinline%2$s method only when your website has just a few pages',
						'w3-total-cache'
					),
					'<code>',
					'</code>'
				),
				array(
					'code' => array(),
				)
			),
		)
	);

	?>
</table>
<table class="<?php echo esc_attr( Util_Ui::table_class() ); ?>">
	<tr>
		<th><?php esc_html_e( 'Google Maps', 'w3-total-cache' ); ?></th>
		<td>
			<?php Util_Ui::pro_wrap_maybe_start(); ?>
			<p class="description w3tc-gopro-excerpt" style="padding-bottom: 10px"><?php esc_html_e( 'Lazy load google map', 'w3-total-cache' ); ?></p>
			<div>
				<?php
				Util_Ui::control2(
					Util_Ui::config_item_preprocess(
						array(
							'key'            => 'lazyload.googlemaps.wp_google_map_plugin',
							'control'        => 'checkbox',
							'disabled'       => ( $is_pro ? ! $is_wp_google_map_plugin : true ),
							'checkbox_label' => wp_kses(
								sprintf(
									// translators: 1 opening HTML a tag to WordPress Google Map Plugin, 2 closing HTML a tag.
									__(
										'%1$sWP Google Map Plugin%2$s plugin',
										'w3-total-cache'
									),
									'<a href="' . esc_url( 'https://wordpress.org/plugins/wp-google-map-plugin/' ) . '" target="_blank">',
									'</a>'
								),
								array(
									'a' => array(
										'href'   => array(),
										'target' => array(),
									),
								)
							),
							'label_class'    => 'w3tc_no_trtd',
						)
					)
				);
				?>
			</div>
			<div>
				<?php
				Util_Ui::control2(
					Util_Ui::config_item_preprocess(
						array(
							'key'            => 'lazyload.googlemaps.google_maps_easy',
							'control'        => 'checkbox',
							'disabled'       => ( $is_pro ? ! $is_google_maps_easy : true ),
							'checkbox_label' => wp_kses(
								sprintf(
									// translators: 1 opening HTML a tag to Google Maps Easy plugin, 2 closing HTML a tag.
									__(
										'%1$sGoogle Maps Easy%2$s plugin',
										'w3-total-cache'
									),
									'<a href="' . esc_url( 'https://wordpress.org/plugins/google-maps-easy/' ) . '" target="_blank">',
									'</a>'
								),
								array(
									'a' => array(
										'href'   => array(),
										'target' => array(),
									),
								)
							),
							'label_class'    => 'w3tc_no_trtd',
						)
					)
				);
				?>
			</div>
			<div>
				<?php
				Util_Ui::control2(
					Util_Ui::config_item_preprocess(
						array(
							'key'            => 'lazyload.googlemaps.wp_google_maps',
							'control'        => 'checkbox',
							'disabled'       => ( $is_pro ? ! $is_wp_google_maps : true ),
							'checkbox_label' => wp_kses(
								sprintf(
									// translators: 1 opening HTML a tag to WordPress Google Maps, 2 closing HTML a tag.
									__(
										'%1$sWP Google Maps%2$s plugin',
										'w3-total-cache'
									),
									'<a href="' . esc_url( 'https://wordpress.org/plugins/wp-google-maps/' ) . '" target="_blank">',
									'</a>'
								),
								array(
									'a' => array(
										'href'   => array(),
										'target' => array(),
									),
								)
							),
							'label_class'    => 'w3tc_no_trtd',
						)
					)
				);
				?>
			</div>
			<?php Util_Ui::pro_wrap_maybe_end( 'lazyload_googlemaps' ); ?>
		</td>
	</tr>
</table>
<p class="submit">
	<?php Util_Ui::button_config_save( 'lazyload' ); ?>
</p>

<?php Util_Ui::postbox_footer(); ?>

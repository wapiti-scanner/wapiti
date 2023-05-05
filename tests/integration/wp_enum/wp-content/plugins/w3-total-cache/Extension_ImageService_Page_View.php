<?php
/**
 * File: Extension_ImageService_Page_View.php
 *
 * View for the Image Service extension settings, tools, and statistics page.
 *
 * @since 2.2.0
 *
 * @package W3TC
 *
 * @uses Config      $c      Configuration object.
 * @uses array       $counts Image Service media counts.
 * @uses array|false $usage  API usage statistics.
 */

namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}

?>
<div class="wrap" id="w3tc">

<?php
// Upgrade banner.
if ( ! Util_Environment::is_w3tc_pro( $c ) ) {
	require W3TC_INC_DIR . '/options/parts/dashboard_banner.php';
}
?>

<p>
	Total Cache Image Service is currently
<?php
if ( $c->is_extension_active( 'imageservice' ) ) {
	?>
	<span class="w3tc-enabled">enabled</span>
	<?php
} else {
	?>
	<span class="w3tc-disabled">disabled</span>
	<?php
}
?>
	.
</p>

<form id="w3tc-imageservice-settings" action="upload.php?page=w3tc_extension_page_imageservice" method="post">
<div class="metabox-holder">

	<?php Util_Ui::postbox_header( esc_html__( 'Configuration', 'w3-total-cache' ), '', '' ); ?>

	<table class="form-table" id="w3tc-imageservice-config">
<?php
Util_Ui::config_item(
	array(
		'key'               => array(
			'imageservice',
			'compression',
		),
		'label'             => esc_html__( 'Compression type:', 'w3-total-cache' ),
		'control'           => 'radiogroup',
		'radiogroup_values' => array(
			'lossy'    => 'Lossy',
			'lossless' => 'Lossless',
		),
		'description'       => esc_html__( 'Image compression type.', 'w3-total-cache' ),
		'disabled'          => false,
	)
);

Util_Ui::config_item(
	array(
		'key'               => array(
			'imageservice',
			'auto',
		),
		'label'             => esc_html__( 'Auto-convert:', 'w3-total-cache' ),
		'control'           => 'radiogroup',
		'radiogroup_values' => array(
			'enabled'  => 'Enabled',
			'disabled' => 'Disabled',
		),
		'description'       => esc_html__( 'Auto-convert images on upload.', 'w3-total-cache' ),
		'disabled'          => false,
	)
);

Util_Ui::config_item(
	array(
		'key'              => array(
			'imageservice',
			'visibility',
		),
		'label'            => esc_html__( 'Visibility:', 'w3-total-cache' ),
		'control'          => 'selectbox',
		'selectbox_values' => array(
			'never'     => array( 'label' => __( 'Never', 'w3-total-cache' ) ),
			'extension' => array( 'label' => __( 'If extension is active', 'w3-total-cache' ) ),
			'always'    => array( 'label' => __( 'Always', 'w3-total-cache' ) ),
		),
		'description'      => esc_html__( 'Show converted image attachments in the Media Library.', 'w3-total-cache' ),
		'disabled'         => false,
	)
);
?>
	</table>

<?php
Util_Ui::button_config_save( 'extension_imageservice_configuration' );
Util_Ui::postbox_footer();

Util_Ui::postbox_header( esc_html__( 'Tools', 'w3-total-cache' ), '', '' );
?>

	<table class="form-table" id="w3tc-imageservice-tools">
<?php
Util_Ui::config_item(
	array(
		'key'         => null,
		'label'       => esc_html__( 'Convert all images:', 'w3-total-cache' ),
		'label_class' => 'w3tc-imageservice-all',
		'control'     => 'button',
		'none_label'  => 'Convert All',
		'description' => esc_html__( 'Convert all images in the media library.', 'w3-total-cache' ),
	)
);

Util_Ui::config_item(
	array(
		'key'         => null,
		'label'       => esc_html__( 'Revert all images:', 'w3-total-cache' ),
		'label_class' => 'w3tc-imageservice-revertall',
		'control'     => 'button',
		'none_label'  => 'Revert All',
		'description' => esc_html__( 'Revert all converted images in the media library.', 'w3-total-cache' ),
	)
);
?>
	</table>

<?php

Util_Ui::postbox_footer();

Util_Ui::postbox_header(
	esc_html__( 'Statistics', 'w3-total-cache' ),
	'',
	'w3tc-imageservice-statistics'
);

?>

	<table class="form-table" id="w3tc-imageservice-stats">
		<tr>
			<th><?php esc_html_e( 'Counts and filesizes by status:', 'w3-total-cache' ); ?></th>
			<td>
				<table id="w3tc-imageservice-counts">
					<tr>
						<td><?php esc_html_e( 'Total:', 'w3-total-cache' ); ?></td>
						<td id="w3tc-imageservice-total"><?php echo esc_html( $counts['total'] ); ?></td>
						<td id="w3tc-imageservice-totalbytes"><?php echo esc_html( size_format( $counts['totalbytes'], 2 ) ); ?></td>
					</tr>
					<tr>
						<td><?php esc_html_e( 'Converted:', 'w3-total-cache' ); ?></td>
						<td id="w3tc-imageservice-converted"><?php echo esc_html( $counts['converted'] ); ?></td>
						<td id="w3tc-imageservice-convertedbytes"><?php echo esc_html( size_format( $counts['convertedbytes'], 2 ) ); ?></td>
					</tr>
					<tr>
						<td><?php esc_html_e( 'Sending:', 'w3-total-cache' ); ?></td>
						<td id="w3tc-imageservice-sending"><?php echo esc_html( $counts['sending'] ); ?></td>
						<td id="w3tc-imageservice-sendingbytes"><?php echo esc_html( size_format( $counts['sendingbytes'], 2 ) ); ?></td>
					</tr>
					<tr>
						<td><?php esc_html_e( 'Processing:', 'w3-total-cache' ); ?></td>
						<td id="w3tc-imageservice-processing"><?php echo esc_html( $counts['processing'] ); ?></td>
						<td id="w3tc-imageservice-processingbytes"><?php echo esc_html( size_format( $counts['processingbytes'], 2 ) ); ?></td>
					</tr>
					<tr>
						<td><?php esc_html_e( 'Not converted:', 'w3-total-cache' ); ?></td>
						<td id="w3tc-imageservice-notconverted"><?php echo esc_html( $counts['notconverted'] ); ?></td>
						<td id="w3tc-imageservice-notconvertedbytes"><?php echo esc_html( size_format( $counts['notconvertedbytes'], 2 ) ); ?></td>
					</tr>
					<tr>
						<td><?php esc_html_e( 'Unconverted:', 'w3-total-cache' ); ?></td>
						<td id="w3tc-imageservice-unconverted"><?php echo esc_html( $counts['unconverted'] ); ?></td>
						<td id="w3tc-imageservice-unconvertedbytes"><?php echo esc_html( size_format( $counts['unconvertedbytes'], 2 ) ); ?></td>
					</tr>
					<tr><td height="10"></td></tr>
					<tr>
						<td colspan="3"><input id="w3tc-imageservice-refresh-counts" class="button" type="button" value="<?php esc_attr_e( 'Refresh', 'w3-total-cache' ); ?>" /></td>
					</tr>
				</table>
			</td>
		</tr>
		<tr>
			<th><?php esc_html_e( 'Image Service API usage:', 'w3-total-cache' ); ?></th>
			<td>
				<table id="w3tc-imageservice-usage">
					<tr>
						<td><?php esc_html_e( 'Hourly requests:', 'w3-total-cache' ); ?></td>
						<td id="w3tc-imageservice-usage-hourly"><?php echo esc_html( $usage['usage_hourly'] ); ?></td>
					</tr>
					<tr>
						<td><?php esc_html_e( 'Hourly limit:', 'w3-total-cache' ); ?></td>
						<td id="w3tc-imageservice-limit-hourly"><?php echo esc_html( $usage['limit_hourly'] ); ?></td>
					</tr>
					<tr>
						<td><?php esc_html_e( 'Monthly requests:', 'w3-total-cache' ); ?></td>
						<td id="w3tc-imageservice-usage-monthly"><?php echo esc_html( $usage['usage_monthly'] ); ?></td>
					</tr>
					<tr>
						<td><?php esc_html_e( 'Monthly limit:', 'w3-total-cache' ); ?></td>
						<td id="w3tc-imageservice-limit-monthly"><?php echo esc_html( $usage['limit_monthly'] ); ?></td>
					</tr>
					<tr><td height="10"></td></tr>
					<tr>
						<td colspan="3"><input id="w3tc-imageservice-refresh-usage" class="button" type="button" value="<?php esc_attr_e( 'Refresh', 'w3-total-cache' ); ?>" /></td>
					</tr>
				</table>
			</td>
		</tr>
	</table>

<?php Util_Ui::postbox_footer(); ?>

</div>
</form>

</div>

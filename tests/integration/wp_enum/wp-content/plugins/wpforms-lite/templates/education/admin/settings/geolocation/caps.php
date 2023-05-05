<?php
/**
 * Capabilities for geolocation settings page.
 *
 * @since 1.6.6
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$lists = [
	[
		esc_html__( 'City', 'wpforms-lite' ),
		esc_html__( 'Country', 'wpforms-lite' ),
		esc_html__( 'Postal/Zip Code', 'wpforms-lite' ),
	],
	[
		esc_html__( 'Latitude/Longitude', 'wpforms-lite' ),
		esc_html__( 'Address Autocomplete', 'wpforms-lite' ),
		esc_html__( 'Embedded Map in Forms', 'wpforms-lite' ),
	],
	[
		esc_html__( 'Google Places API', 'wpforms-lite' ),
		esc_html__( 'Mapbox API', 'wpforms-lite' ),
	],
];

?>
	<p><?php esc_html_e( 'Powerful location-based insights and features…', 'wpforms-lite' ); ?></p>

<?php foreach ( $lists as $list ) { ?>
	<ul>
		<?php foreach ( $list as $item ) { ?>
			<li><?php echo esc_html( $item ); ?></li>
		<?php } ?>
	</ul>
<?php } ?>

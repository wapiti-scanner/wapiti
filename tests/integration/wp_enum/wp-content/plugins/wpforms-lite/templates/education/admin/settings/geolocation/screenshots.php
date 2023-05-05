<?php
/**
 * Screenshots for geolocation settings page.
 *
 * @since 1.6.6
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$images_url  = WPFORMS_PLUGIN_URL . 'assets/images/geolocation-education/';
$screenshots = [
	[
		'url'   => $images_url . 'entry-location.jpg',
		'url2x' => $images_url . 'entry-location@2x.jpg',
		'title' => __( 'Location Info in Entries', 'wpforms-lite' ),
	],
	[
		'url'   => $images_url . 'address-autocomplete.jpg',
		'url2x' => $images_url . 'address-autocomplete@2x.jpg',
		'title' => __( 'Address Autocomplete Field', 'wpforms-lite' ),
	],
	[
		'url'   => $images_url . 'smart-address-field.jpg',
		'url2x' => $images_url . 'smart-address-field@2x.jpg',
		'title' => __( 'Smart Address Field', 'wpforms-lite' ),
	],
];

foreach ( $screenshots as $screenshot ) {
	?>
	<div class="cont">
		<img src="<?php echo esc_url( $screenshot['url'] ); ?>" alt="<?php echo esc_attr( $screenshot['title'] ); ?>" />
		<a href="<?php echo esc_url( $screenshot['url2x'] ); ?>" class="hover" data-lity data-lity-desc="<?php echo esc_attr( $screenshot['title'] ); ?>"></a>
		<span><?php echo esc_html( $screenshot['title'] ); ?></span>
	</div>
	<?php
}

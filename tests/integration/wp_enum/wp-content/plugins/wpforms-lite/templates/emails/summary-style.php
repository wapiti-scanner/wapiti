<?php
/**
 * Email Summary style template.
 *
 * This template can be overridden by copying it to yourtheme/wpforms/emails/summary-style.php.
 *
 * @since 1.5.4
 *
 * @version 1.5.4
 *
 * @var string $email_background_color
 */

if ( ! \defined( 'ABSPATH' ) ) {
	exit;
}

require \WPFORMS_PLUGIN_DIR . '/assets/css/emails/summary.min.css';

?>

body, .body {
	background-color: <?php echo \esc_attr( $email_background_color ); ?>;
}

<?php if ( ! empty( $header_image_max_width ) ) : ?>
.header img {
	max-width: <?php echo \esc_attr( $header_image_max_width ); ?>;
}
<?php endif; ?>

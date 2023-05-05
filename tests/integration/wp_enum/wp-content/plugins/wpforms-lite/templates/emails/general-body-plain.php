<?php
/**
 * General body template (plain text).
 *
 * This template can be overridden by copying it to yourtheme/wpforms/emails/general-body-plain.php.
 *
 * @since 1.5.4
 *
 * @version 1.5.4
 *
 * @var string $message
 */

if ( ! \defined( 'ABSPATH' ) ) {
	exit;
}

echo \wp_kses_post( $message );

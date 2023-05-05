<?php
/**
 * Email Summary body template (plain text).
 *
 * This template can be overridden by copying it to yourtheme/wpforms/emails/summary-body-plain.php.
 *
 * @since 1.5.4
 *
 * @var array $entries
 * @var array $info_block
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

echo esc_html__( 'Hi there!', 'wpforms-lite' ) . "\n\n";

if ( wpforms()->is_pro() ) {
	echo esc_html__( 'Let’s see how your forms performed in the past week.', 'wpforms-lite' ) . "\n\n";
} else {
	echo esc_html__( 'Let’s see how your forms performed.', 'wpforms-lite' ) . "\n\n";
	echo esc_html__( 'Below is the total number of submissions for each form, however actual entries are not stored in WPForms Lite.', 'wpforms-lite' ) . "\n\n";
	echo esc_html__( 'To view future entries inside your WordPress dashboard, and get more detailed reports, consider upgrading to Pro:', 'wpforms-lite' );
	echo '&nbsp;';
	echo 'https://wpforms.com/lite-upgrade/?utm_source=WordPress&utm_medium=Weekly%20Summary%20Email&utm_campaign=liteplugin&utm_content=Upgrade&utm_locale=' . wpforms_sanitize_key( get_locale() );
    echo "\n\n\n";
}

echo "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n\n";

echo esc_html__( 'Form', 'wpforms-lite' ) . '   |   ' . esc_html__( 'Entries', 'wpforms-lite' ) . "\n\n";

echo "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n\n";

foreach ( $entries as $row ) {
	echo ( isset( $row['title'] ) ? esc_html( $row['title'] ) : '' ) . '   |   ' . ( isset( $row['count'] ) ? absint( $row['count'] ) : '' ) . "\n\n";
}

if ( empty( $entries ) ) {
	echo esc_html__( 'It appears you do not have any form entries yet.', 'wpforms-lite' ) . "\n\n";
}

echo "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n\n\n";

if ( ! empty( $info_block['title'] ) ) {
	echo esc_html( $info_block['title'] ) . "\n\n";
}

if ( ! empty( $info_block['content'] ) ) {
	echo wp_kses_post( $info_block['content'] ) . "\n\n";
}

if ( ! empty( $info_block['button'] ) && ! empty( $info_block['url'] ) ) {
	echo esc_html( $info_block['button'] ) . ': ' . esc_url( $info_block['url'] ) . "\n\n";
}

<?php
namespace W3TC;

if ( ! defined( 'W3TC' ) ) {
	die();
}

if ( ! isset( $title ) ) {
	$title = 'Untitled';
}

if ( ! isset( $errors ) ) {
	$errors = array();
}

if ( ! isset( $notes ) ) {
	$notes = array();
}
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" <?php do_action( 'admin_xml_ns' ); ?> <?php language_attributes(); ?>>
	<head>
		<link rel="stylesheet" type="text/css" href="<?php echo esc_url( plugins_url( 'pub/css/popup.css?ver=' . W3TC_VERSION, W3TC_FILE ) ); ?>" />
		<script type="text/javascript" src="<?php echo esc_url( site_url( 'wp-includes/js/jquery/jquery.js?ver=' . W3TC_VERSION ) ); ?>"></script>
		<script type="text/javascript" src="<?php echo esc_url( plugins_url( 'pub/js/metadata.js?ver=' . W3TC_VERSION, W3TC_FILE ) ); ?>"></script>
		<script type="text/javascript" src="<?php echo esc_url( plugins_url( 'pub/js/popup.js?ver=' . W3TC_VERSION, W3TC_FILE ) ); ?>"></script>
		<title><?php echo esc_html( $title ); ?> - W3 Total Cache</title>
		<meta http-equiv="Content-Type" content="<?php bloginfo( 'html_type' ); ?>; charset=<?php echo esc_attr( get_option( 'blog_charset' ) ); ?>" />
	</head>
	<body>
		<div id="content">
			<h1><?php echo esc_html( $title ); ?></h1>

			<?php if ( count( $errors ) ) : ?>
				<div class="error">
					<?php foreach ( $errors as $error ) : ?>
						<p><?php echo esc_html( $error ); ?></p>
					<?php endforeach; ?>
				</div>
			<?php endif; ?>

			<?php if ( count( $notes ) ) : ?>
				<div class="updated">
					<?php foreach ( $notes as $note ) : ?>
						<p><?php echo esc_html( $note ); ?></p>
					<?php endforeach; ?>
				</div>
			<?php endif; ?>

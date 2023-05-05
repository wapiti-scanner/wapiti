<?php
/**
 * General header template.
 *
 * This template can be overridden by copying it to yourtheme/wpforms/emails/general-header.php.
 *
 * @since 1.5.4
 *
 * @version 1.5.4
 *
 * @var string $title
 * @var string $header_image
 */

if ( ! \defined( 'ABSPATH' ) ) {
	exit;
}

?>

<!DOCTYPE html>
<html lang="en">
<head>
	<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
	<meta http-equiv="X-UA-Compatible" content="IE=edge">
	<meta name="viewport" content="width=device-width">
	<title><?php echo \esc_html( $title ); ?></title>
</head>
<body>
<table border="0" cellpadding="0" cellspacing="0" width="100%" height="100%" class="body">
	<tr>
		<td align="center" valign="top" class="body-inner">
			<table border="0" cellpadding="0" cellspacing="0" class="container">
				<tr>
					<td align="center" valign="middle" class="header">
						<?php if ( ! empty( $header_image['url'] ) ) : ?>
							<img src="<?php echo \esc_url( $header_image['url'] ); ?>" <?php echo isset( $header_image['width'] ) ? 'width="' . \absint( $header_image['width'] ) . '"' : ''; ?> alt="<?php echo \esc_attr( \get_bloginfo( 'name' ) ); ?>" />
						<?php endif; ?>
					</td>
				</tr>
				<tr>
					<td align="left" valign="top" class="content">

<?php if (!defined('W3TC')) die(); ?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" <?php do_action('admin_xml_ns'); ?> <?php language_attributes(); ?>>
	<head>
		<link rel="stylesheet" type="text/css" href="<?php echo esc_url( plugins_url( 'pub/css/error.css?ver=' . W3TC_VERSION, W3TC_FILE ) ); ?>" />
		<title>Error</title>
		<meta http-equiv="Content-Type" content="<?php bloginfo('html_type'); ?>; charset=<?php echo esc_attr( get_option( 'blog_charset' ) ); ?>" />
	</head>
	<body>
		<p>
			<?php echo esc_html( $error ); ?>
		</p>
	</body>
</html>
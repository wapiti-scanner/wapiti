<?php
/**
** A base module for [captchac] and [captchar]
**/

/* form_tag handler */

add_action( 'wpcf7_init', 'wpcf7_add_form_tag_captcha', 10, 0 );

function wpcf7_add_form_tag_captcha() {
	// CAPTCHA-Challenge (image)
	wpcf7_add_form_tag( 'captchac',
		'wpcf7_captchac_form_tag_handler',
		array(
			'name-attr' => true,
			'zero-controls-container' => true,
			'not-for-mail' => true,
		)
	);

	// CAPTCHA-Response (input)
	wpcf7_add_form_tag( 'captchar',
		'wpcf7_captchar_form_tag_handler',
		array(
			'name-attr' => true,
			'do-not-store' => true,
			'not-for-mail' => true,
		)
	);
}

function wpcf7_captchac_form_tag_handler( $tag ) {
	if ( ! class_exists( 'ReallySimpleCaptcha' ) ) {
		$error = sprintf(
			/* translators: %s: link labeled 'Really Simple CAPTCHA' */
			esc_html( __( "To use CAPTCHA, you need %s plugin installed.", 'contact-form-7' ) ),
			wpcf7_link( 'https://wordpress.org/plugins/really-simple-captcha/', 'Really Simple CAPTCHA' )
		);

		return sprintf( '<em>%s</em>', $error );
	}

	if ( empty( $tag->name ) ) {
		return '';
	}

	$class = wpcf7_form_controls_class( $tag->type );
	$class .= ' wpcf7-captcha-' . str_replace( ':', '', $tag->name );

	$atts = array();
	$atts['class'] = $tag->get_class_option( $class );
	$atts['id'] = $tag->get_id_option();

	$op = array( // Default
		'img_size' => array( 72, 24 ),
		'base' => array( 6, 18 ),
		'font_size' => 14,
		'font_char_width' => 15,
	);

	$op = array_merge( $op, wpcf7_captchac_options( $tag->options ) );

	if ( ! $filename = wpcf7_generate_captcha( $op ) ) {
		return '';
	}

	if ( ! empty( $op['img_size'] ) ) {
		if ( isset( $op['img_size'][0] ) ) {
			$atts['width'] = $op['img_size'][0];
		}

		if ( isset( $op['img_size'][1] ) ) {
			$atts['height'] = $op['img_size'][1];
		}
	}

	$atts['alt'] = 'captcha';
	$atts['src'] = wpcf7_captcha_url( $filename );

	$atts = wpcf7_format_atts( $atts );

	$prefix = substr( $filename, 0, strrpos( $filename, '.' ) );

	$html = sprintf(
		'<input type="hidden" name="%1$s" value="%2$s" /><img %3$s />',
		esc_attr( sprintf( '_wpcf7_captcha_challenge_%s', $tag->name ) ),
		esc_attr( $prefix ),
		$atts
	);

	return $html;
}

function wpcf7_captchar_form_tag_handler( $tag ) {
	if ( empty( $tag->name ) ) {
		return '';
	}

	$validation_error = wpcf7_get_validation_error( $tag->name );

	$class = wpcf7_form_controls_class( $tag->type );

	if ( $validation_error ) {
		$class .= ' wpcf7-not-valid';
	}

	$atts = array();

	$atts['size'] = $tag->get_size_option( '40' );
	$atts['maxlength'] = $tag->get_maxlength_option();
	$atts['minlength'] = $tag->get_minlength_option();

	if ( $atts['maxlength'] and $atts['minlength']
	and $atts['maxlength'] < $atts['minlength'] ) {
		unset( $atts['maxlength'], $atts['minlength'] );
	}

	$atts['class'] = $tag->get_class_option( $class );
	$atts['id'] = $tag->get_id_option();
	$atts['tabindex'] = $tag->get_option( 'tabindex', 'signed_int', true );
	$atts['autocomplete'] = 'off';

	if ( $validation_error ) {
		$atts['aria-invalid'] = 'true';
		$atts['aria-describedby'] = wpcf7_get_validation_error_reference(
			$tag->name
		);
	} else {
		$atts['aria-invalid'] = 'false';
	}

	$value = (string) reset( $tag->values );

	if ( wpcf7_is_posted() ) {
		$value = '';
	}

	if ( $tag->has_option( 'placeholder' )
	or $tag->has_option( 'watermark' ) ) {
		$atts['placeholder'] = $value;
		$value = '';
	}

	$atts['value'] = $value;
	$atts['type'] = 'text';
	$atts['name'] = $tag->name;

	$html = sprintf(
		'<span class="wpcf7-form-control-wrap" data-name="%1$s"><input %2$s />%3$s</span>',
		esc_attr( $tag->name ),
		wpcf7_format_atts( $atts ),
		$validation_error
	);

	return $html;
}


/* Validation filter */

add_filter( 'wpcf7_validate_captchar',
	'wpcf7_captcha_validation_filter', 10, 2 );

function wpcf7_captcha_validation_filter( $result, $tag ) {
	$type = $tag->type;
	$name = $tag->name;

	$captchac = '_wpcf7_captcha_challenge_' . $name;

	$prefix = isset( $_POST[$captchac] ) ? (string) $_POST[$captchac] : '';
	$response = isset( $_POST[$name] ) ? (string) $_POST[$name] : '';
	$response = wpcf7_canonicalize( $response );

	if ( 0 === strlen( $prefix )
	or ! wpcf7_check_captcha( $prefix, $response ) ) {
		$result->invalidate( $tag, wpcf7_get_message( 'captcha_not_match' ) );
	}

	if ( 0 !== strlen( $prefix ) ) {
		wpcf7_remove_captcha( $prefix );
	}

	return $result;
}


/* Ajax echo filter */

add_filter( 'wpcf7_refill_response', 'wpcf7_captcha_ajax_refill', 10, 1 );
add_filter( 'wpcf7_feedback_response', 'wpcf7_captcha_ajax_refill', 10, 1 );

function wpcf7_captcha_ajax_refill( $items ) {
	if ( ! is_array( $items ) ) {
		return $items;
	}

	$tags = wpcf7_scan_form_tags( array( 'type' => 'captchac' ) );

	if ( empty( $tags ) ) {
		return $items;
	}

	$refill = array();

	foreach ( $tags as $tag ) {
		$name = $tag->name;
		$options = $tag->options;

		if ( empty( $name ) ) {
			continue;
		}

		$op = wpcf7_captchac_options( $options );

		if ( $filename = wpcf7_generate_captcha( $op ) ) {
			$captcha_url = wpcf7_captcha_url( $filename );
			$refill[$name] = $captcha_url;
		}
	}

	if ( ! empty( $refill ) ) {
		$items['captcha'] = $refill;
	}

	return $items;
}


/* Messages */

add_filter( 'wpcf7_messages', 'wpcf7_captcha_messages', 10, 1 );

function wpcf7_captcha_messages( $messages ) {
	$messages = array_merge( $messages, array(
		'captcha_not_match' => array(
			'description' =>
				__( "The code that sender entered does not match the CAPTCHA", 'contact-form-7' ),
			'default' =>
				__( 'Your entered code is incorrect.', 'contact-form-7' ),
		),
	) );

	return $messages;
}


/* Tag generator */

add_action( 'wpcf7_admin_init', 'wpcf7_add_tag_generator_captcha', 46, 0 );

function wpcf7_add_tag_generator_captcha() {
	if ( ! wpcf7_use_really_simple_captcha() ) {
		return;
	}

	$tag_generator = WPCF7_TagGenerator::get_instance();
	$tag_generator->add( 'captcha',
		__( 'CAPTCHA (Really Simple CAPTCHA)', 'contact-form-7' ),
		'wpcf7_tag_generator_captcha' );
}

function wpcf7_tag_generator_captcha( $contact_form, $args = '' ) {
	$args = wp_parse_args( $args, array() );

	if ( ! class_exists( 'ReallySimpleCaptcha' ) ) {
?>
<div class="control-box">
<fieldset>
<legend><?php
	echo sprintf(
		/* translators: %s: link labeled 'Really Simple CAPTCHA' */
		esc_html( __( "To use CAPTCHA, you first need to install and activate %s plugin.", 'contact-form-7' ) ),
		wpcf7_link( 'https://wordpress.org/plugins/really-simple-captcha/', 'Really Simple CAPTCHA' )
	);
?></legend>
</fieldset>
</div>
<?php

		return;
	}

	$description = __( "Generate form-tags for a CAPTCHA image and corresponding response input field. For more details, see %s.", 'contact-form-7' );

	$desc_link = wpcf7_link( __( 'https://contactform7.com/captcha/', 'contact-form-7' ), __( 'CAPTCHA', 'contact-form-7' ) );

?>
<div class="control-box">
<fieldset>
<legend><?php echo sprintf( esc_html( $description ), $desc_link ); ?></legend>

<table class="form-table">
<tbody>
	<tr>
	<th scope="row"><label for="<?php echo esc_attr( $args['content'] . '-name' ); ?>"><?php echo esc_html( __( 'Name', 'contact-form-7' ) ); ?></label></th>
	<td><input type="text" name="name" class="tg-name oneline" id="<?php echo esc_attr( $args['content'] . '-name' ); ?>" /></td>
	</tr>
</tbody>
</table>

<table class="form-table scope captchac">
<caption><?php echo esc_html( __( "Image settings", 'contact-form-7' ) ); ?></caption>
<tbody>
	<tr>
	<th scope="row"><label for="<?php echo esc_attr( $args['content'] . '-captchac-id' ); ?>"><?php echo esc_html( __( 'Id attribute', 'contact-form-7' ) ); ?></label></th>
	<td><input type="text" name="id" class="idvalue oneline option" id="<?php echo esc_attr( $args['content'] . '-captchac-id' ); ?>" /></td>
	</tr>

	<tr>
	<th scope="row"><label for="<?php echo esc_attr( $args['content'] . '-captchac-class' ); ?>"><?php echo esc_html( __( 'Class attribute', 'contact-form-7' ) ); ?></label></th>
	<td><input type="text" name="class" class="classvalue oneline option" id="<?php echo esc_attr( $args['content'] . '-captchac-class' ); ?>" /></td>
	</tr>
</tbody>
</table>

<table class="form-table scope captchar">
<caption><?php echo esc_html( __( "Input field settings", 'contact-form-7' ) ); ?></caption>
<tbody>
	<tr>
	<th scope="row"><label for="<?php echo esc_attr( $args['content'] . '-captchar-id' ); ?>"><?php echo esc_html( __( 'Id attribute', 'contact-form-7' ) ); ?></label></th>
	<td><input type="text" name="id" class="idvalue oneline option" id="<?php echo esc_attr( $args['content'] . '-captchar-id' ); ?>" /></td>
	</tr>

	<tr>
	<th scope="row"><label for="<?php echo esc_attr( $args['content'] . '-captchar-class' ); ?>"><?php echo esc_html( __( 'Class attribute', 'contact-form-7' ) ); ?></label></th>
	<td><input type="text" name="class" class="classvalue oneline option" id="<?php echo esc_attr( $args['content'] . '-captchar-class' ); ?>" /></td>
	</tr>
</tbody>
</table>
</fieldset>
</div>

<div class="insert-box">
	<input type="text" name="captcha" class="tag code" readonly="readonly" onfocus="this.select()" />

	<div class="submitbox">
	<input type="button" class="button button-primary insert-tag" value="<?php echo esc_attr( __( 'Insert Tag', 'contact-form-7' ) ); ?>" />
	</div>
</div>
<?php
}


/* Warning message */

add_action( 'wpcf7_admin_warnings',
	'wpcf7_captcha_display_warning_message', 10, 3 );

function wpcf7_captcha_display_warning_message( $page, $action, $object ) {
	if ( $object instanceof WPCF7_ContactForm ) {
		$contact_form = $object;
	} else {
		return;
	}

	$has_tags = (bool) $contact_form->scan_form_tags(
		array( 'type' => array( 'captchac' ) ) );

	if ( ! $has_tags ) {
		return;
	}

	if ( ! class_exists( 'ReallySimpleCaptcha' ) ) {
		return;
	}

	$uploads_dir = wpcf7_captcha_tmp_dir();
	wpcf7_init_captcha();

	if ( ! is_dir( $uploads_dir )
	or ! wp_is_writable( $uploads_dir ) ) {
		$message = sprintf( __( 'This contact form contains CAPTCHA fields, but the temporary folder for the files (%s) does not exist or is not writable. You can create the folder or change its permission manually.', 'contact-form-7' ), $uploads_dir );

		echo '<div class="notice notice-warning"><p>' . esc_html( $message ) . '</p></div>';
	}

	if ( ! function_exists( 'imagecreatetruecolor' )
	or ! function_exists( 'imagettftext' ) ) {
		$message = __( "This contact form contains CAPTCHA fields, but the necessary libraries (GD and FreeType) are not available on your server.", 'contact-form-7' );

		echo '<div class="notice notice-warning"><p>' . esc_html( $message ) . '</p></div>';
	}
}


/* CAPTCHA functions */

function wpcf7_init_captcha() {
	static $captcha = null;

	if ( $captcha ) {
		return $captcha;
	}

	if ( class_exists( 'ReallySimpleCaptcha' ) ) {
		$captcha = new ReallySimpleCaptcha();
	} else {
		return false;
	}

	$dir = trailingslashit( wpcf7_captcha_tmp_dir() );

	$captcha->tmp_dir = $dir;

	if ( is_callable( array( $captcha, 'make_tmp_dir' ) ) ) {
		$result = $captcha->make_tmp_dir();

		if ( ! $result ) {
			return false;
		}

		return $captcha;
	}

	$result = wp_mkdir_p( $dir );

	if ( ! $result ) {
		return false;
	}

	$htaccess_file = path_join( $dir, '.htaccess' );

	if ( file_exists( $htaccess_file ) ) {
		list( $first_line_comment ) = (array) file(
			$htaccess_file,
			FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES
		);

		if ( '# Apache 2.4+' === $first_line_comment ) {
			return $captcha;
		}
	}

	if ( $handle = @fopen( $htaccess_file, 'w' ) ) {
		fwrite( $handle, "# Apache 2.4+\n" );
		fwrite( $handle, "<IfModule authz_core_module>\n" );
		fwrite( $handle, "    Require all denied\n" );
		fwrite( $handle, '    <FilesMatch "^\w+\.(jpe?g|gif|png)$">' . "\n" );
		fwrite( $handle, "        Require all granted\n" );
		fwrite( $handle, "    </FilesMatch>\n" );
		fwrite( $handle, "</IfModule>\n" );
		fwrite( $handle, "\n" );
		fwrite( $handle, "# Apache 2.2\n" );
		fwrite( $handle, "<IfModule !authz_core_module>\n" );
		fwrite( $handle, "    Order deny,allow\n" );
		fwrite( $handle, "    Deny from all\n" );
		fwrite( $handle, '    <FilesMatch "^\w+\.(jpe?g|gif|png)$">' . "\n" );
		fwrite( $handle, "        Allow from all\n" );
		fwrite( $handle, "    </FilesMatch>\n" );
		fwrite( $handle, "</IfModule>\n" );

		fclose( $handle );
	}

	return $captcha;
}


/**
 * Returns the directory path for Really Simple CAPTCHA files.
 *
 * @return string Directory path.
 */
function wpcf7_captcha_tmp_dir() {
	if ( defined( 'WPCF7_CAPTCHA_TMP_DIR' ) ) {
		$dir = path_join( WP_CONTENT_DIR, WPCF7_CAPTCHA_TMP_DIR );
		wp_mkdir_p( $dir );

		if ( wpcf7_is_file_path_in_content_dir( $dir ) ) {
			return $dir;
		}
	}

	$dir = path_join( wpcf7_upload_dir( 'dir' ), 'wpcf7_captcha' );
	wp_mkdir_p( $dir );
	return $dir;
}


function wpcf7_captcha_tmp_url() {
	if ( defined( 'WPCF7_CAPTCHA_TMP_URL' ) ) {
		return WPCF7_CAPTCHA_TMP_URL;
	} else {
		return path_join( wpcf7_upload_dir( 'url' ), 'wpcf7_captcha' );
	}
}

function wpcf7_captcha_url( $filename ) {
	$url = path_join( wpcf7_captcha_tmp_url(), $filename );

	if ( is_ssl()
	and 'http:' == substr( $url, 0, 5 ) ) {
		$url = 'https:' . substr( $url, 5 );
	}

	return apply_filters( 'wpcf7_captcha_url', sanitize_url( $url ) );
}

function wpcf7_generate_captcha( $options = null ) {
	if ( ! $captcha = wpcf7_init_captcha() ) {
		return false;
	}

	if ( ! is_dir( $captcha->tmp_dir )
	or ! wp_is_writable( $captcha->tmp_dir ) ) {
		return false;
	}

	$img_type = imagetypes();

	if ( $img_type & IMG_PNG ) {
		$captcha->img_type = 'png';
	} elseif ( $img_type & IMG_GIF ) {
		$captcha->img_type = 'gif';
	} elseif ( $img_type & IMG_JPG ) {
		$captcha->img_type = 'jpeg';
	} else {
		return false;
	}

	if ( is_array( $options ) ) {
		if ( isset( $options['img_size'] ) ) {
			$captcha->img_size = $options['img_size'];
		}

		if ( isset( $options['base'] ) ) {
			$captcha->base = $options['base'];
		}

		if ( isset( $options['font_size'] ) ) {
			$captcha->font_size = $options['font_size'];
		}

		if ( isset( $options['font_char_width'] ) ) {
			$captcha->font_char_width = $options['font_char_width'];
		}

		if ( isset( $options['fg'] ) ) {
			$captcha->fg = $options['fg'];
		}

		if ( isset( $options['bg'] ) ) {
			$captcha->bg = $options['bg'];
		}
	}

	$prefix = wp_rand();
	$captcha_word = $captcha->generate_random_word();
	return $captcha->generate_image( $prefix, $captcha_word );
}

function wpcf7_check_captcha( $prefix, $response ) {
	if ( ! $captcha = wpcf7_init_captcha() ) {
		return false;
	}

	return $captcha->check( $prefix, $response );
}

function wpcf7_remove_captcha( $prefix ) {
	if ( ! $captcha = wpcf7_init_captcha() ) {
		return false;
	}

	// Contact Form 7 generates $prefix with wp_rand()
	if ( preg_match( '/[^0-9]/', $prefix ) ) {
		return false;
	}

	$captcha->remove( $prefix );
}

add_action( 'shutdown', 'wpcf7_cleanup_captcha_files', 20, 0 );

function wpcf7_cleanup_captcha_files() {
	if ( ! $captcha = wpcf7_init_captcha() ) {
		return false;
	}

	if ( is_callable( array( $captcha, 'cleanup' ) ) ) {
		return $captcha->cleanup();
	}

	$dir = trailingslashit( wpcf7_captcha_tmp_dir() );

	if ( ! is_dir( $dir )
	or ! is_readable( $dir )
	or ! wp_is_writable( $dir ) ) {
		return false;
	}

	if ( $handle = opendir( $dir ) ) {
		while ( false !== ( $file = readdir( $handle ) ) ) {
			if ( ! preg_match( '/^[0-9]+\.(php|txt|png|gif|jpeg)$/', $file ) ) {
				continue;
			}

			$stat = stat( path_join( $dir, $file ) );

			if ( $stat['mtime'] + HOUR_IN_SECONDS < time() ) {
				@unlink( path_join( $dir, $file ) );
			}
		}

		closedir( $handle );
	}
}

function wpcf7_captchac_options( $options ) {
	if ( ! is_array( $options ) ) {
		return array();
	}

	$op = array();
	$image_size_array = preg_grep( '%^size:[smlSML]$%', $options );

	if ( $image_size = array_shift( $image_size_array ) ) {
		preg_match( '%^size:([smlSML])$%', $image_size, $is_matches );

		switch ( strtolower( $is_matches[1] ) ) {
			case 's':
				$op['img_size'] = array( 60, 20 );
				$op['base'] = array( 6, 15 );
				$op['font_size'] = 11;
				$op['font_char_width'] = 13;
				break;
			case 'l':
				$op['img_size'] = array( 84, 28 );
				$op['base'] = array( 6, 20 );
				$op['font_size'] = 17;
				$op['font_char_width'] = 19;
				break;
			case 'm':
			default:
				$op['img_size'] = array( 72, 24 );
				$op['base'] = array( 6, 18 );
				$op['font_size'] = 14;
				$op['font_char_width'] = 15;
		}
	}

	$fg_color_array = preg_grep(
		'%^fg:#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$%', $options );

	if ( $fg_color = array_shift( $fg_color_array ) ) {
		preg_match( '%^fg:#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$%',
			$fg_color, $fc_matches );

		if ( 3 == strlen( $fc_matches[1] ) ) {
			$r = substr( $fc_matches[1], 0, 1 );
			$g = substr( $fc_matches[1], 1, 1 );
			$b = substr( $fc_matches[1], 2, 1 );

			$op['fg'] = array(
				hexdec( $r . $r ),
				hexdec( $g . $g ),
				hexdec( $b . $b ),
			);
		} elseif ( 6 == strlen( $fc_matches[1] ) ) {
			$r = substr( $fc_matches[1], 0, 2 );
			$g = substr( $fc_matches[1], 2, 2 );
			$b = substr( $fc_matches[1], 4, 2 );

			$op['fg'] = array(
				hexdec( $r ),
				hexdec( $g ),
				hexdec( $b ),
			);
		}
	}

	$bg_color_array = preg_grep(
		'%^bg:#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$%', $options );

	if ( $bg_color = array_shift( $bg_color_array ) ) {
		preg_match( '%^bg:#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$%',
			$bg_color, $bc_matches );

		if ( 3 == strlen( $bc_matches[1] ) ) {
			$r = substr( $bc_matches[1], 0, 1 );
			$g = substr( $bc_matches[1], 1, 1 );
			$b = substr( $bc_matches[1], 2, 1 );

			$op['bg'] = array(
				hexdec( $r . $r ),
				hexdec( $g . $g ),
				hexdec( $b . $b ),
			);
		} elseif ( 6 == strlen( $bc_matches[1] ) ) {
			$r = substr( $bc_matches[1], 0, 2 );
			$g = substr( $bc_matches[1], 2, 2 );
			$b = substr( $bc_matches[1], 4, 2 );

			$op['bg'] = array(
				hexdec( $r ),
				hexdec( $g ),
				hexdec( $b ),
			);
		}
	}

	return $op;
}

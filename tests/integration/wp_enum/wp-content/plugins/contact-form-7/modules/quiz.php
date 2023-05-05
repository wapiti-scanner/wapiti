<?php
/**
** A base module for [quiz]
**/

/* form_tag handler */

add_action( 'wpcf7_init', 'wpcf7_add_form_tag_quiz', 10, 0 );

function wpcf7_add_form_tag_quiz() {
	wpcf7_add_form_tag( 'quiz',
		'wpcf7_quiz_form_tag_handler',
		array(
			'name-attr' => true,
			'do-not-store' => true,
			'not-for-mail' => true,
		)
	);
}

function wpcf7_quiz_form_tag_handler( $tag ) {
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
	$atts['aria-required'] = 'true';

	if ( $validation_error ) {
		$atts['aria-invalid'] = 'true';
		$atts['aria-describedby'] = wpcf7_get_validation_error_reference(
			$tag->name
		);
	} else {
		$atts['aria-invalid'] = 'false';
	}

	$pipes = $tag->pipes;

	if ( $pipes instanceof WPCF7_Pipes
	and ! $pipes->zero() ) {
		$pipe = $pipes->random_pipe();
		$question = $pipe->before;
		$answer = $pipe->after;
	} else {
		// default quiz
		$question = '1+1=?';
		$answer = '2';
	}

	$answer = wpcf7_canonicalize( $answer, array(
		'strip_separators' => true,
	) );

	$atts['type'] = 'text';
	$atts['name'] = $tag->name;

	$html = sprintf(
		'<span class="wpcf7-form-control-wrap" data-name="%1$s"><label><span class="wpcf7-quiz-label">%2$s</span> <input %3$s /></label><input type="hidden" name="_wpcf7_quiz_answer_%4$s" value="%5$s" />%6$s</span>',
		esc_attr( $tag->name ),
		esc_html( $question ),
		wpcf7_format_atts( $atts ),
		$tag->name,
		wp_hash( $answer, 'wpcf7_quiz' ),
		$validation_error
	);

	return $html;
}


/* Validation filter */

add_filter( 'wpcf7_validate_quiz', 'wpcf7_quiz_validation_filter', 10, 2 );

function wpcf7_quiz_validation_filter( $result, $tag ) {
	$name = $tag->name;

	$answer = isset( $_POST[$name] ) ? wp_unslash( $_POST[$name] ) : '';

	$answer = wpcf7_canonicalize( $answer, array(
		'strip_separators' => true,
	) );

	$answer_hash = wp_hash( $answer, 'wpcf7_quiz' );

	$expected_hash = isset( $_POST['_wpcf7_quiz_answer_' . $name] )
		? (string) $_POST['_wpcf7_quiz_answer_' . $name]
		: '';

	if ( ! hash_equals( $expected_hash, $answer_hash ) ) {
		$result->invalidate( $tag, wpcf7_get_message( 'quiz_answer_not_correct' ) );
	}

	return $result;
}


/* Ajax echo filter */

add_filter( 'wpcf7_refill_response', 'wpcf7_quiz_ajax_refill', 10, 1 );
add_filter( 'wpcf7_feedback_response', 'wpcf7_quiz_ajax_refill', 10, 1 );

function wpcf7_quiz_ajax_refill( $items ) {
	if ( ! is_array( $items ) ) {
		return $items;
	}

	$fes = wpcf7_scan_form_tags( array( 'type' => 'quiz' ) );

	if ( empty( $fes ) ) {
		return $items;
	}

	$refill = array();

	foreach ( $fes as $fe ) {
		$name = $fe['name'];
		$pipes = $fe['pipes'];

		if ( empty( $name ) ) {
			continue;
		}

		if ( $pipes instanceof WPCF7_Pipes
		and ! $pipes->zero() ) {
			$pipe = $pipes->random_pipe();
			$question = $pipe->before;
			$answer = $pipe->after;
		} else {
			// default quiz
			$question = '1+1=?';
			$answer = '2';
		}

		$answer = wpcf7_canonicalize( $answer, array(
			'strip_separators' => true,
		) );

		$refill[$name] = array( $question, wp_hash( $answer, 'wpcf7_quiz' ) );
	}

	if ( ! empty( $refill ) ) {
		$items['quiz'] = $refill;
	}

	return $items;
}


/* Mail-tag replacement */

add_filter( 'wpcf7_mail_tag_replaced_quiz', 'wpcf7_quiz_mail_tag', 10, 4 );

function wpcf7_quiz_mail_tag( $replaced, $submitted, $html, $mail_tag ) {
	$field_name = $mail_tag->field_name();
	$submitted = isset( $_POST[$field_name] ) ? $_POST[$field_name] : '';
	$replaced = $submitted;

	if ( $html ) {
		$replaced = esc_html( $replaced );
		$replaced = wptexturize( $replaced );
	}

	return $replaced;
}


/* Messages */

add_filter( 'wpcf7_messages', 'wpcf7_quiz_messages', 10, 1 );

function wpcf7_quiz_messages( $messages ) {
	$messages = array_merge( $messages, array(
		'quiz_answer_not_correct' => array(
			'description' =>
				__( "Sender does not enter the correct answer to the quiz", 'contact-form-7' ),
			'default' =>
				__( "The answer to the quiz is incorrect.", 'contact-form-7' ),
		),
	) );

	return $messages;
}


/* Tag generator */

add_action( 'wpcf7_admin_init', 'wpcf7_add_tag_generator_quiz', 40, 0 );

function wpcf7_add_tag_generator_quiz() {
	$tag_generator = WPCF7_TagGenerator::get_instance();
	$tag_generator->add( 'quiz', __( 'quiz', 'contact-form-7' ),
		'wpcf7_tag_generator_quiz' );
}

function wpcf7_tag_generator_quiz( $contact_form, $args = '' ) {
	$args = wp_parse_args( $args, array() );
	$type = 'quiz';

	$description = __( "Generate a form-tag for a question-answer pair. For more details, see %s.", 'contact-form-7' );

	$desc_link = wpcf7_link( __( 'https://contactform7.com/quiz/', 'contact-form-7' ), __( 'Quiz', 'contact-form-7' ) );

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

	<tr>
	<th scope="row"><?php echo esc_html( __( 'Questions and answers', 'contact-form-7' ) ); ?></th>
	<td>
		<fieldset>
		<legend class="screen-reader-text"><?php echo esc_html( __( 'Questions and answers', 'contact-form-7' ) ); ?></legend>
		<textarea name="values" class="values" id="<?php echo esc_attr( $args['content'] . '-values' ); ?>"></textarea><br />
		<label for="<?php echo esc_attr( $args['content'] . '-values' ); ?>"><span class="description"><?php echo esc_html( __( "One pipe-separated question-answer pair (e.g. The capital of Brazil?|Rio) per line.", 'contact-form-7' ) ); ?></span></label>
		</fieldset>
	</td>
	</tr>

	<tr>
	<th scope="row"><label for="<?php echo esc_attr( $args['content'] . '-id' ); ?>"><?php echo esc_html( __( 'Id attribute', 'contact-form-7' ) ); ?></label></th>
	<td><input type="text" name="id" class="idvalue oneline option" id="<?php echo esc_attr( $args['content'] . '-id' ); ?>" /></td>
	</tr>

	<tr>
	<th scope="row"><label for="<?php echo esc_attr( $args['content'] . '-class' ); ?>"><?php echo esc_html( __( 'Class attribute', 'contact-form-7' ) ); ?></label></th>
	<td><input type="text" name="class" class="classvalue oneline option" id="<?php echo esc_attr( $args['content'] . '-class' ); ?>" /></td>
	</tr>

</tbody>
</table>
</fieldset>
</div>

<div class="insert-box">
	<input type="text" name="<?php echo $type; ?>" class="tag code" readonly="readonly" onfocus="this.select()" />

	<div class="submitbox">
	<input type="button" class="button button-primary insert-tag" value="<?php echo esc_attr( __( 'Insert Tag', 'contact-form-7' ) ); ?>" />
	</div>
</div>
<?php
}

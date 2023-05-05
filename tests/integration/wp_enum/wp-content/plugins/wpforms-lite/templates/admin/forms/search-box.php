<?php
/**
 * Search box on forms overview page.
 *
 * @since 1.7.2
 *
 * @var string $term_input_id Term input id.
 * @var string $text          Button text.
 * @var string $search_term   Current search term.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

?>
<p class="search-box wpforms-forms-search-box">

	<label class="screen-reader-text" for="<?php echo esc_attr( $term_input_id ); ?>"><?php echo esc_html( $text ); ?>:</label>
	<input type="search"
		name="search[term]"
		class="wpforms-forms-search-box-term"
		value="<?php echo esc_attr( $search_term ); ?>"
		id="<?php echo esc_attr( $term_input_id ); ?>">

	<button type="submit" class="button"><?php echo esc_html( $text ); ?></button>
</p>

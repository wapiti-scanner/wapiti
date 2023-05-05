<?php //phpcs:ignore WordPress.Files.FileName.InvalidClassFileName
/**
 * MailChimp Subscriber Popup Form shortcode
 *
 * Example:
 * [mailchimp_subscriber_popup baseUrl="mc.us11.list-manage.com" uuid="1ca7856462585a934b8674c71" lid="2d24f1898b"]
 *
 * Embed code example:
 * <script type="text/javascript" src="//downloads.mailchimp.com/js/signup-forms/popup/unique-methods/embed.js" data-dojo-config="usePlainJson: true, isDebug: false"></script><script type="text/javascript">window.dojoRequire(["mojo/signup-forms/Loader"], function(L) { L.start({"baseUrl":"mc.us11.list-manage.com","uuid":"1ca7856462585a934b8674c71","lid":"2d24f1898b","uniqueMethods":true}) })</script>
 */

// phpcs:disable Universal.Files.SeparateFunctionsFromOO.Mixed -- TODO: Move classes to appropriately-named class files.

/**
 * Register [mailchimp_subscriber_popup] shortcode and add a filter to 'pre_kses' queue to reverse MailChimp embed to shortcode.
 *
 * @since 4.5.0
 */
function jetpack_mailchimp_subscriber_popup() {
	add_shortcode(
		'mailchimp_subscriber_popup',
		array(
			'MailChimp_Subscriber_Popup',
			'shortcode',
		)
	);
	add_filter(
		'pre_kses',
		array(
			'MailChimp_Subscriber_Popup',
			'reversal',
		)
	);
}

if ( defined( 'IS_WPCOM' ) && IS_WPCOM ) {
	add_action( 'init', 'jetpack_mailchimp_subscriber_popup' );
} else {
	jetpack_mailchimp_subscriber_popup();
}

/**
 * Class MailChimp_Subscriber_Popup
 *
 * @since 4.5.0
 */
class MailChimp_Subscriber_Popup {

	/**
	 * Regular expressions to reverse script tags to shortcodes.
	 *
	 * @var array
	 */
	private static $reversal_regexes = array(
		/* raw examplejs */
		'/<script type="text\/javascript" src="(https?:)?\/\/downloads\.mailchimp\.com\/js\/signup-forms\/popup\/unique-methods\/embed\.js" data-dojo-config="([^"]*?)"><\/script><script type="text\/javascript">window.dojoRequire\(\["mojo\/signup-forms\/Loader"\]\, function\(L\) { L\.start\({([^}]*?)}\) }\)<\/script>/s', //phpcs:ignore
		/* visual editor */
		'/&lt;script type="text\/javascript" src="(https?:)?\/\/downloads\.mailchimp\.com\/js\/signup-forms\/popup\/unique-methods\/embed\.js" data-dojo-config="([^"]*?)"&gt;&lt;\/script&gt;&lt;script type="text\/javascript"&gt;window.dojoRequire\(\["mojo\/signup-forms\/Loader"]\, function\(L\) { L\.start\({([^}]*?)}\) }\)&lt;\/script&gt;/s',
	);

	/**
	 * Allowed configuration attributes. Used in reversal when checking allowed attributes.
	 *
	 * @var array
	 */
	private static $allowed_config = array(
		'usePlainJson' => 'true',
		'isDebug'      => 'false',
	);

	/**
	 * Allowed JS variables. Used in reversal to whitelist variables.
	 *
	 * @var array
	 */
	private static $allowed_js_vars = array(
		'baseUrl',
		'uuid',
		'lid',
	);

	/**
	 * Runs the whole reversal.
	 *
	 * @since 4.5.0
	 *
	 * @param string $content Post Content.
	 *
	 * @return string Content with embeds replaced
	 */
	public static function reversal( $content ) {
		// Bail without the js src.
		if ( ! is_string( $content ) || false === stripos( $content, 'downloads.mailchimp.com/js/signup-forms/popup/unique-methods/embed.js' ) ) {
			return $content;
		}

		// loop through our rules and find valid embeds.
		foreach ( self::$reversal_regexes as $regex ) {

			if ( ! preg_match_all( $regex, $content, $matches ) ) {
				continue;
			}

			foreach ( $matches[3] as $index => $js_vars ) {
				// the regex rule for a specific embed.
				$replace_regex = sprintf( '#\s*%s\s*#', preg_quote( $matches[0][ $index ], '#' ) );

				$attrs = json_decode( '{' . $js_vars . '}' );

				if ( $matches[2][ $index ] ) {
					$config_attrs = json_decode( '{' . $matches[2][ $index ] . '}' );
					foreach ( $config_attrs as $key => $value ) {
						$attrs->$key = ( 1 === $value ) ? 'true' : 'false';
					}
				}

				$shortcode = self::build_shortcode_from_reversal_attrs( $attrs );

				$content = preg_replace( $replace_regex, "\n\n$shortcode\n\n", $content );

				/** This action is documented in modules/widgets/social-media-icons.php */
				do_action( 'jetpack_bump_stats_extras', 'html_to_shortcode', 'mailchimp_subscriber_popup' );
			}
		}

		return $content;
	}

	/**
	 * Builds the actual shortcode based on passed in attributes.
	 *
	 * @since 4.5.0
	 *
	 * @param array $attrs A valid list of attributes (gets matched against self::$allowed_config and self::$allowed_js_vars).
	 *
	 * @return string
	 */
	private static function build_shortcode_from_reversal_attrs( $attrs ) {
		$shortcode = '[mailchimp_subscriber_popup ';

		foreach ( $attrs as $key => $value ) {
			// skip unsupported keys.
			if (
				! array_key_exists( $key, self::$allowed_config )
				&& ! in_array( $key, self::$allowed_js_vars, true )
			) {
				continue;
			}

			$value      = esc_attr( $value );
			$shortcode .= "$key='$value' ";
		}
		return trim( $shortcode ) . ']';
	}

	/**
	 * Parses the shortcode back out to embedded information.
	 *
	 * @since 4.5.0
	 *
	 * @param array $lcase_attrs Lowercase shortcode attributes.
	 *
	 * @return string
	 */
	public static function shortcode( $lcase_attrs ) {
		static $displayed_once = false;

		// Limit to one form per page load.
		if ( $displayed_once ) {
			return '';
		}

		if ( empty( $lcase_attrs ) ) {
			return '<!-- Missing MailChimp baseUrl, uuid or lid -->';
		}

		$defaults = array_fill_keys( self::$allowed_js_vars, '' );
		$defaults = array_merge( $defaults, self::$allowed_config );

		// Convert $attrs back to proper casing since they come through in all lowercase.
		$attrs = array();
		foreach ( $defaults as $key => $value ) {
			if ( array_key_exists( strtolower( $key ), $lcase_attrs ) ) {
				$attrs[ $key ] = $lcase_attrs[ strtolower( $key ) ];
			}
		}
		$attrs = array_map( 'esc_js', array_filter( shortcode_atts( $defaults, $attrs ) ) );

		// Split config & js vars.
		$js_vars     = array();
		$config_vars = array();
		foreach ( $attrs as $key => $value ) {
			if (
				'baseUrl' === $key
				&& (
					! preg_match( '#mc\.us\d+\.list-manage\d?\.com#', $value, $matches )
					|| $value !== $matches[0]
				)
			) {
				return '<!-- Invalid MailChimp baseUrl -->';
			}

			if ( in_array( $key, self::$allowed_js_vars, true ) ) {
				$js_vars[ $key ] = $value;
			} else {
				$config_vars[] = "$key: $value";
			}
		}

		// If one of these parameters is missing we can't render the form so exist.
		if ( empty( $js_vars['baseUrl'] ) || empty( $js_vars['uuid'] ) || empty( $js_vars['lid'] ) ) {
			return '<!-- Missing MailChimp baseUrl, uuid or lid -->';
		}

		// Add a uniqueMethods parameter if it is missing from the data we got from the embed code.
		$js_vars['uniqueMethods'] = true;

		/** This action is already documented in modules/widgets/gravatar-profile.php */
		do_action( 'jetpack_stats_extra', 'mailchimp_subscriber_popup', 'view' );

		$displayed_once = true;

		return "\n\n" . '<script type="text/javascript" data-dojo-config="' . esc_attr( implode( ', ', $config_vars ) ) . '">jQuery.getScript( "//downloads.mailchimp.com/js/signup-forms/popup/unique-methods/embed.js", function( data, textStatus, jqxhr ) { window.dojoRequire(["mojo/signup-forms/Loader"], function(L) { L.start(' . wp_json_encode( $js_vars ) . ') });} );</script>' . "\n\n";
	}
}
